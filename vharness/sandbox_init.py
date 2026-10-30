"""vharness sandbox init (SPEC 13.1.3). Trusted harness code; Python standard library only.

Run as:  python3 -I -S sandbox_init.py CONFIG_JSON_PATH STATUS_FD

The harness (real root) starts this program. It:
  1. opens the artifacts directory, then unshares mount/net/pid/ipc/uts namespaces;
  2. forks; the child is PID 1 of the new PID namespace and builds a new root:
     read-only nosuid/nodev binds of system directories and the target, a fresh
     size-limited tmpfs at /scratch, a minimal /etc and /dev, and /proc;
  3. runs the command as a fresh unprivileged uid with no_new_privs, rlimits,
     an allowlisted environment and a wall-clock limit;
  4. kills and reaps every process in the namespace, then promotes allowlisted
     scratch files with the no-follow procedure and writes a JSON status.

The target never receives the config path, the status fd, or the artifacts fd.
"""

import ctypes
import errno
import hashlib
import json
import os
import resource
import signal
import stat
import sys
import time

MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE = 32, 4096, 16384, 1 << 18
ST_FLAGS = {1: MS_RDONLY, 2: MS_NOSUID, 4: MS_NODEV, 8: MS_NOEXEC}
PR_SET_PDEATHSIG, PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS = 1, 4, 38
SETUP_EXIT = 125

libc = ctypes.CDLL(None, use_errno=True)


def _b(value):
    return value.encode() if isinstance(value, str) else value


def mount(source, target, fstype, flags, data=None):
    if libc.mount(_b(source), _b(target), _b(fstype), ctypes.c_ulong(flags), _b(data)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"mount {source} -> {target}: {os.strerror(err)}")


def prctl(option, arg):
    if libc.prctl(option, ctypes.c_ulong(arg), 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"prctl {option}: {os.strerror(err)}")


def bind_ro(source, target):
    """Read-only, nosuid, nodev bind mount that keeps the source's other locked flags."""
    mount(source, target, None, MS_BIND | MS_REC)
    flags = MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV
    f_flag = os.statvfs(source).f_flag
    for bit, ms in ST_FLAGS.items():
        if f_flag & bit:
            flags |= ms
    mount(None, target, None, flags)


def build_root(cfg):
    root = cfg["root_dir"]
    uid = cfg["uid"]
    mount("tmpfs", root, "tmpfs", MS_NOSUID | MS_NODEV, "size=16m,mode=0755")
    for name in cfg["system_dirs"]:
        src = "/" + name
        dst = os.path.join(root, name)
        if os.path.islink(src):
            os.symlink(os.readlink(src), dst)
        elif os.path.isdir(src):
            os.makedirs(dst)
            bind_ro(src, dst)
    for path in cfg["extra_binds"]:  # extra read-only toolchain directories, same path inside
        dst = os.path.join(root, path.lstrip("/"))
        os.makedirs(dst, exist_ok=True)
        bind_ro(path, dst)
    # /etc: a minimal synthetic copy, never a bind of the host /etc.
    etc = os.path.join(root, "etc")
    os.makedirs(etc, exist_ok=True)
    files = {
        "passwd": f"root:x:0:0:root:/nonexistent:/usr/sbin/nologin\nsandbox:x:{uid}:{uid}:sandbox:/scratch:/bin/sh\n",
        "group": f"root:x:0:\nsandbox:x:{uid}:\n",
        "hosts": "127.0.0.1 localhost\n::1 localhost\n",
        "nsswitch.conf": "passwd: files\ngroup: files\nhosts: files\n",
    }
    for name, text in files.items():
        with open(os.path.join(etc, name), "w") as fh:
            fh.write(text)
    for name in ("ld.so.cache", "ld.so.conf"):
        if os.path.isfile("/etc/" + name) and not os.path.islink("/etc/" + name):
            with open("/etc/" + name, "rb") as src, open(os.path.join(etc, name), "wb") as dst:
                dst.write(src.read())
    if os.path.isdir("/etc/alternatives"):
        alt = os.path.join(etc, "alternatives")
        os.makedirs(alt)
        for name in os.listdir("/etc/alternatives"):
            link = os.path.join("/etc/alternatives", name)
            if os.path.islink(link):
                os.symlink(os.readlink(link), os.path.join(alt, name))
    # /target read-only.
    target = os.path.join(root, "target")
    os.makedirs(target)
    bind_ro(cfg["target"], target)
    # /scratch: fresh tmpfs with the disk limit, owned by the sandbox uid.
    scratch = os.path.join(root, "scratch")
    os.makedirs(scratch)
    mount("tmpfs", scratch, "tmpfs", MS_NOSUID | MS_NODEV,
          f"size={cfg['limits']['disk_mb']}m,mode=0700,uid={uid},gid={uid},nr_inodes=20000")
    os.symlink("/scratch/tmp", os.path.join(root, "tmp"))
    # /dev: tmpfs with bind-mounted character devices.
    dev = os.path.join(root, "dev")
    os.makedirs(dev)
    mount("tmpfs", dev, "tmpfs", MS_NOSUID | MS_NOEXEC, "size=64k,mode=0755")
    for name in ("null", "zero", "random", "urandom"):
        node = os.path.join(dev, name)
        open(node, "w").close()
        mount("/dev/" + name, node, None, MS_BIND)
    for name, dest in (("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"), ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2")):
        os.symlink(dest, os.path.join(dev, name))
    # /proc of the new PID namespace; other users' processes (PID 1) are hidden.
    proc = os.path.join(root, "proc")
    os.makedirs(proc)
    mount("proc", proc, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=2")
    return root, scratch


def write_inputs(scratch, cfg):
    uid = cfg["uid"]
    for d in ("tmp", ".vh"):
        os.mkdir(os.path.join(scratch, d), 0o700)
        os.chown(os.path.join(scratch, d), uid, uid)
    for item in cfg["files"]:
        rel = item["path"]
        parts = rel.split("/")
        cur = scratch
        for comp in parts[:-1]:
            cur = os.path.join(cur, comp)
            if not os.path.isdir(cur):
                os.mkdir(cur, 0o700)
                os.chown(cur, uid, uid)
        fd = os.open(os.path.join(cur, parts[-1]), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, item["content"].encode("utf-8"))
            os.fchown(fd, uid, uid)
        finally:
            os.close(fd)


def run_target(cfg, out_fd, err_fd):
    """Child: drop to the sandbox uid with limits and exec the command. Never returns."""
    try:
        uid = cfg["uid"]
        lim = cfg["limits"]
        os.dup2(os.open("/dev/null", os.O_RDONLY), 0)
        os.dup2(out_fd, 1)
        os.dup2(err_fd, 2)
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
        prctl(PR_SET_NO_NEW_PRIVS, 1)
        mb = 1024 * 1024
        for res, value in (
            (resource.RLIMIT_CPU, lim["cpu_s"]),
            (resource.RLIMIT_AS, lim["mem_mb"] * mb),
            (resource.RLIMIT_NPROC, lim["nproc"]),
            (resource.RLIMIT_FSIZE, lim["fsize_mb"] * mb),
            (resource.RLIMIT_NOFILE, lim["nofile"]),
            (resource.RLIMIT_CORE, 0),
        ):
            resource.setrlimit(res, (value, value))
        os.chdir(cfg["cwd"])
        os.execve("/bin/sh", ["sh", "-c", cfg["command"]], cfg["env"])
    except BaseException as exc:  # noqa: BLE001 - report setup failure through the exit code
        try:
            os.write(2, f"vharness sandbox: setup failed: {exc}\n".encode())
        finally:
            os._exit(SETUP_EXIT)


def kill_all_and_reap(target_pid):
    """Stop every process in the namespace (we are PID 1), then reap them all."""
    status = None
    try:
        os.kill(-1, signal.SIGKILL)
    except ProcessLookupError:
        pass
    while True:
        try:
            pid, st = os.waitpid(-1, 0)
        except ChildProcessError:
            break
        if pid == target_pid:
            status = st
    return status


def read_head(fd, limit):
    size = os.fstat(fd).st_size
    os.lseek(fd, 0, os.SEEK_SET)
    data = os.read(fd, limit)
    return data.decode("utf-8", "replace"), size


def promote(scratch, art_fd, allow, per_file, total):
    """The no-follow promotion procedure (SPEC 13.1.3 step 12, [REF-2])."""
    promoted, rejected, used = [], [], 0
    root_fd = os.open(scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for rel in allow:
            fds = []
            try:
                parts = rel.split("/")
                if not rel or rel.startswith("/") or any(p in ("", ".", "..") for p in parts):
                    raise ValueError("invalid path")
                cur = root_fd
                for comp in parts[:-1]:  # walk from the retained root, never reopen by path
                    cur = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur)
                    fds.append(cur)
                src = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=cur)
                fds.append(src)
                st = os.fstat(src)
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError("not a regular file")
                if st.st_nlink != 1:
                    raise ValueError("hard-linked file")
                if st.st_size > per_file or used + st.st_size > total:
                    raise ValueError("file exceeds the size limit")
                chunks, got = [], 0
                while got <= st.st_size:
                    chunk = os.read(src, min(65536, st.st_size + 1 - got))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    got += len(chunk)
                data = b"".join(chunks)
                st2 = os.fstat(src)
                if len(data) != st.st_size or (st2.st_ino, st2.st_dev, st2.st_size, st2.st_nlink, st2.st_mode) != (st.st_ino, st.st_dev, st.st_size, st.st_nlink, st.st_mode):
                    raise ValueError("file changed while it was read")
                dst = art_fd
                for comp in parts[:-1]:
                    try:
                        os.mkdir(comp, 0o700, dir_fd=dst)
                    except FileExistsError:
                        pass
                    nxt = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dst)
                    fds.append(nxt)
                    if not stat.S_ISDIR(os.fstat(nxt).st_mode):
                        raise ValueError("destination component is not a directory")
                    dst = nxt
                out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dst)
                fds.append(out)
                ost = os.fstat(out)
                if not stat.S_ISREG(ost.st_mode) or ost.st_nlink != 1:
                    raise ValueError("destination is not a new regular file")
                os.write(out, data)
                used += len(data)
                promoted.append({"path": rel, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            except (OSError, ValueError) as exc:
                reason = str(exc) if isinstance(exc, ValueError) else (
                    "symbolic link" if exc.errno == errno.ELOOP else os.strerror(exc.errno or 0))
                rejected.append({"path": rel, "reason": reason})
            finally:
                for fd in reversed(fds):
                    os.close(fd)
    finally:
        os.close(root_fd)
    return promoted, rejected


def pid1(cfg, art_fd, status_fd):
    prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    prctl(PR_SET_DUMPABLE, 0)
    status = {"setup_error": None}
    try:
        mount(None, "/", None, MS_REC | MS_PRIVATE)
        root, scratch_host = build_root(cfg)
        write_inputs(scratch_host, cfg)
        # Output capture lives on its own small tmpfs outside the new root: the
        # target writes only through inherited fds and cannot reach it by path.
        cap = cfg["capture_dir"]
        mount("tmpfs", cap, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=8m,mode=0700")
        out_fd = os.open(os.path.join(cap, "stdout"), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        err_fd = os.open(os.path.join(cap, "stderr"), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        for fd in (out_fd, err_fd):
            os.fchown(fd, cfg["uid"], cfg["uid"])
        mount(None, root, None, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)
        os.chroot(root)
        os.chdir("/")
    except Exception as exc:  # noqa: BLE001
        status["setup_error"] = f"{type(exc).__name__}: {exc}"
        os.write(status_fd, json.dumps(status).encode())
        return 2

    start = time.monotonic()
    child = os.fork()
    if child == 0:
        os.close(status_fd)
        os.close(art_fd)
        run_target(cfg, out_fd, err_fd)
    deadline = start + cfg["limits"]["wall_s"]
    timed_out, wait_status = False, None
    while True:
        try:
            pid, st = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == child:
            wait_status = st
            break
        if pid == 0:
            if time.monotonic() > deadline:
                timed_out = True
                break
            time.sleep(0.01)
    final = kill_all_and_reap(child)
    if wait_status is None:
        wait_status = final
    duration = int((time.monotonic() - start) * 1000)
    exit_code = signal_num = None
    if wait_status is not None:
        if os.WIFEXITED(wait_status):
            exit_code = os.WEXITSTATUS(wait_status)
        elif os.WIFSIGNALED(wait_status):
            signal_num = os.WTERMSIG(wait_status)
    head = cfg["limits"]["output_bytes"]
    stdout, out_size = read_head(out_fd, head)
    stderr, err_size = read_head(err_fd, head)
    promoted, rejected = promote("/scratch", art_fd, cfg["keep"], cfg["limits"]["artifact_bytes"], cfg["limits"]["artifact_total_bytes"])
    status.update(exit_code=exit_code, signal=signal_num, timed_out=timed_out, duration_ms=duration,
                  stdout=stdout, stderr=stderr, stdout_bytes=out_size, stderr_bytes=err_size,
                  promoted=promoted, rejected=rejected, setup_failed=exit_code == SETUP_EXIT)
    os.write(status_fd, json.dumps(status).encode())
    return 0


def main():
    with open(sys.argv[1], encoding="utf-8") as fh:
        cfg = json.load(fh)
    status_fd = int(sys.argv[2])
    os.set_inheritable(status_fd, False)
    art_fd = os.open(cfg["artifacts_dir"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    os.unshare(os.CLONE_NEWNS | os.CLONE_NEWNET | os.CLONE_NEWPID | os.CLONE_NEWIPC | os.CLONE_NEWUTS)
    pid = os.fork()
    if pid == 0:
        try:
            code = pid1(cfg, art_fd, status_fd)
        except BaseException as exc:  # noqa: BLE001
            os.write(status_fd, json.dumps({"setup_error": f"{type(exc).__name__}: {exc}"}).encode())
            code = 2
        os._exit(code)
    os.close(art_fd)
    os.close(status_fd)
    _, st = os.waitpid(pid, 0)
    sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 3)


if __name__ == "__main__":
    main()
