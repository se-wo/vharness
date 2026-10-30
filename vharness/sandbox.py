"""Sandboxed execution (SPEC 13.1): harness side.

`Sandbox.run()` starts the trusted init program (sandbox_init.py) as real root,
waits with an outer timeout, and returns the init's JSON status. `probe()` is the
start test that checks every control from inside the sandbox (SPEC 13.1.2.2).
"""

import itertools
import json
import os
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field

from .records import safe_relpath

INIT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox_init.py")
SYSTEM_DIRS = ("usr", "bin", "sbin", "lib", "lib32", "lib64", "libx32")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
SECRET_NAME_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|KEY|CREDENTIAL|COOKIE|SESSION|AUTH)", re.I)
BASE_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/scratch",
    "TMPDIR": "/scratch/tmp",
    "LANG": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
}
SHELL_SET = {"PWD", "OLDPWD", "SHLVL", "_"}  # set by /bin/sh itself, not inherited from the host
UID_BASE = 200_000
SETUP_EXIT = 125
_uid_counter = itertools.count()
_uid_lock = threading.Lock()


@dataclass
class Limits:
    cpu_s: int = 60
    mem_mb: int = 2048
    nproc: int = 128
    fsize_mb: int = 64
    nofile: int = 512
    disk_mb: int = 512
    wall_s: int = 120
    output_bytes: int = 16_384
    artifact_bytes: int = 1_048_576
    artifact_total_bytes: int = 4_194_304


@dataclass
class RunSpec:
    command: str
    files: list = field(default_factory=list)  # [{"path": rel, "content": str}]
    keep: list = field(default_factory=list)  # scratch-relative files to promote
    env: dict = field(default_factory=dict)  # extra allowlisted variables
    copy_target: bool = False
    timeout_s: int | None = None


class SandboxError(Exception):
    pass


def validate_spec(spec, limits):
    """Reject unsafe input before anything starts."""
    if not isinstance(spec.command, str) or not spec.command.strip() or len(spec.command) > 8000:
        raise SandboxError("command must be a non-empty string of at most 8000 characters")
    for item in spec.files:
        if not safe_relpath(item.get("path")) or item["path"].startswith(".vh/") or len(item.get("content", "")) > 262_144:
            raise SandboxError(f"invalid input file {item.get('path')!r}")
    for rel in spec.keep:
        if not safe_relpath(rel):
            raise SandboxError(f"invalid keep path {rel!r}")
    for name, value in spec.env.items():
        if not ENV_NAME_RE.match(name) or SECRET_NAME_RE.search(name) or name in ("LD_PRELOAD", "LD_LIBRARY_PATH"):
            raise SandboxError(f"environment variable {name!r} is not allowed")
        if not isinstance(value, str) or len(value) > 1000 or "\x00" in value:
            raise SandboxError(f"environment value of {name!r} is not allowed")
    if spec.timeout_s is not None and not 1 <= spec.timeout_s <= limits.wall_s:
        raise SandboxError(f"timeout_s must be between 1 and {limits.wall_s}")


class Sandbox:
    def __init__(self, work_dir, limits=None, extra_binds=()):
        self.work_dir = os.path.realpath(work_dir)
        self.limits = limits or Limits()
        self.extra_binds = [os.path.realpath(p) for p in extra_binds]
        self.available = False
        self.problems = []
        self.toolchain = {}

    # ------------------------------------------------------------------ one run

    def _uid(self):
        with _uid_lock:
            for _ in range(1000):
                uid = UID_BASE + next(_uid_counter) % 50_000
                try:
                    pwd.getpwuid(uid)
                except KeyError:
                    return uid
        raise SandboxError("no free sandbox uid")

    def run(self, target_root, spec, artifacts_dir):
        """Run one command in a fresh sandbox. Blocking; call through a thread from async code."""
        validate_spec(spec, self.limits)
        if os.geteuid() != 0:
            raise SandboxError("the sandbox needs the root user on the host (SPEC 13.1.2.3)")
        limits = asdict(self.limits)
        if spec.timeout_s:
            limits["wall_s"] = spec.timeout_s
        os.makedirs(self.work_dir, mode=0o700, exist_ok=True)
        os.makedirs(artifacts_dir, mode=0o700, exist_ok=True)
        run_dir = tempfile.mkdtemp(prefix="sbx-", dir=self.work_dir)
        root_dir = os.path.join(run_dir, "root")
        os.mkdir(root_dir, 0o700)
        capture_dir = os.path.join(run_dir, "capture")
        os.mkdir(capture_dir, 0o700)
        command = spec.command
        if spec.copy_target:
            command = "cp -R /target/. /scratch/src && cd /scratch/src && { " + spec.command + "\n}"
        env = dict(BASE_ENV)
        env.update(spec.env)
        cfg = {
            "root_dir": root_dir, "capture_dir": capture_dir, "target": os.path.realpath(target_root), "artifacts_dir": os.path.realpath(artifacts_dir),
            "uid": self._uid(), "system_dirs": list(SYSTEM_DIRS), "extra_binds": self.extra_binds,
            "files": spec.files, "keep": spec.keep, "env": env, "command": command, "cwd": "/scratch", "limits": limits,
        }
        cfg_path = os.path.join(run_dir, "config.json")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
        status_r, status_w = os.pipe()
        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                [sys.executable, "-I", "-S", INIT, cfg_path, str(status_w)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(status_w,), env={"PATH": "/usr/bin:/bin"}, start_new_session=True,
            )
        finally:
            os.close(status_w)
        try:
            out, err = proc.communicate(timeout=limits["wall_s"] + 30)
        except subprocess.TimeoutExpired:
            proc.kill()  # PID 1 has PDEATHSIG=SIGKILL, so the whole namespace dies
            out, err = proc.communicate()
        chunks = []
        while True:
            chunk = os.read(status_r, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
        os.close(status_r)
        shutil.rmtree(run_dir, ignore_errors=True)
        try:
            status = json.loads(b"".join(chunks) or b"{}")
        except ValueError:
            status = {}
        if not status or status.get("setup_error"):
            raise SandboxError(f"sandbox did not start: {status.get('setup_error') or (err or out).decode(errors='replace')[-500:] or 'no status'}"
                               " (in Docker, the container needs seccomp=unconfined and apparmor=unconfined)")
        status["limits"] = limits
        status["env_names"] = sorted(env)
        status["host_duration_ms"] = int((time.monotonic() - start) * 1000)
        return status

    # ------------------------------------------------------------------ start test

    PROBE = r'''
import json, os, resource, socket
r = {}
r["uid"] = os.getuid(); r["gid"] = os.getgid()
r["caps"] = [l.split()[1] for l in open("/proc/self/status") if l.startswith(("CapEff", "CapPrm"))]
r["nnp"] = [l.split()[1] for l in open("/proc/self/status") if l.startswith("NoNewPrivs")]
r["ifaces"] = [l.split(":")[0].strip() for l in open("/proc/net/dev").readlines()[2:]]
def net():
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect(("1.1.1.1", 53)); return "connected"
    except OSError as e:
        return type(e).__name__
r["net"] = net()
r["env"] = sorted(os.environ)
def writable(p):
    try:
        with open(p, "w") as f: f.write("x")
        return True
    except OSError:
        return False
r["w_target"] = writable("/target/vh-probe")
r["w_usr"] = writable("/usr/vh-probe")
r["w_root"] = writable("/vh-probe")
r["w_etc"] = writable("/etc/vh-probe")
r["w_scratch"] = writable("/scratch/vh-probe")
r["host_paths"] = [p for p in ("/root", "/home", "/var/run/docker.sock", "/run", "/sys", "/etc/shadow", "__OUT__") if os.path.exists(p)]
r["pids"] = sorted(int(p) for p in os.listdir("/proc") if p.isdigit())
r["rl"] = {n: resource.getrlimit(getattr(resource, n))[0] for n in ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_NPROC", "RLIMIT_FSIZE", "RLIMIT_NOFILE")}
st = os.statvfs("/scratch"); r["disk"] = st.f_blocks * st.f_frsize
os.makedirs("/scratch/probe", exist_ok=True)
open("/scratch/probe/ok.txt", "w").write("ok")
os.symlink("/etc/passwd", "/scratch/probe/link")
os.mkfifo("/scratch/probe/fifo")
open("/scratch/probe/big.bin", "wb").write(b"0" * 2_000_000)
print(json.dumps(r))
'''

    INVENTORY = ("for t in python3 pip3 node npm go cargo rustc java javac mvn gradle gcc cc make ruby php perl git patch; do "
                 "command -v $t >/dev/null 2>&1 && echo \"tool $t\"; done; "
                 "python3 -c 'import sys; print(\"python\", sys.version.split()[0])' 2>/dev/null; "
                 "for m in pytest unittest; do python3 -c \"import $m\" 2>/dev/null && echo \"pymod $m\"; done; true")

    def inventory(self, target_root, scratch_artifacts):
        """SPEC 13.2.4.4: which tools exist inside the sandbox."""
        st = self.run(target_root, RunSpec(command=self.INVENTORY), scratch_artifacts)
        inv = {"tools": [], "python_modules": [], "python": None}
        for line in st["stdout"].splitlines():
            kind, _, value = line.partition(" ")
            if kind == "tool":
                inv["tools"].append(value)
            elif kind == "pymod":
                inv["python_modules"].append(value)
            elif kind == "python":
                inv["python"] = value
        return inv

    def toolchain_text(self):
        inv = self.toolchain or {}
        mods = inv.get("python_modules", [])
        missing = [m for m in ("pytest",) if m not in mods]
        return (f"Tools in the sandbox: {', '.join(inv.get('tools', [])) or 'unknown'}; Python {inv.get('python') or '-'} "
                f"with {', '.join(mods) or 'no test modules'}" + (f"; NOT available: {', '.join(missing)}" if missing else "")
                + ". Nothing can be installed (no network).")

    def probe(self, target_root, scratch_artifacts):
        """Start test: every control must be observed from inside, or the sandbox is unavailable."""
        self.problems = []
        problems = self.problems
        lim = self.limits
        try:
            out_dir = os.path.dirname(os.path.realpath(scratch_artifacts))
            code = self.PROBE.replace("__OUT__", out_dir)
            st = self.run(target_root, RunSpec(command="python3 -I -c " + shlex.quote(code),
                                               keep=["probe/ok.txt", "probe/link", "probe/fifo", "probe/big.bin"]),
                          scratch_artifacts)
            try:
                r = json.loads(st["stdout"].strip().splitlines()[-1])
            except (ValueError, IndexError):
                raise SandboxError(f"probe produced no result: exit {st.get('exit_code')} {st.get('stderr', '')[-300:]}")
            if r["uid"] == 0 or r["gid"] == 0:
                problems.append("R-SBX-07: the command runs as root")
            if any(int(c, 16) for c in r["caps"]):
                problems.append("R-SBX-08: the command has capabilities")
            if r["nnp"] != ["1"]:
                problems.append("R-SBX-08: no_new_privs is not set")
            if r["net"] == "connected" or set(r["ifaces"]) - {"lo"}:
                problems.append("R-SBX-01: external network is reachable")
            extra = set(r["env"]) - set(BASE_ENV) - SHELL_SET
            if extra:
                problems.append(f"R-SBX-02: unexpected environment variables {sorted(extra)}")
            if r["w_target"] or r["w_usr"] or r["w_root"] or r["w_etc"]:
                problems.append("R-SBX-03/04: a path outside /scratch is writable")
            if not r["w_scratch"]:
                problems.append("R-SBX-04: /scratch is not writable")
            if r["host_paths"]:
                problems.append(f"R-SBX-09: host paths are visible: {r['host_paths']}")
            if len(r["pids"]) > 2:
                problems.append(f"R-SBX-06: other processes are visible: {r['pids']}")
            mb = 1024 * 1024
            want = {"RLIMIT_CPU": lim.cpu_s, "RLIMIT_AS": lim.mem_mb * mb, "RLIMIT_NPROC": lim.nproc,
                    "RLIMIT_FSIZE": lim.fsize_mb * mb, "RLIMIT_NOFILE": lim.nofile}
            for name, value in want.items():
                if r["rl"][name] != value:
                    problems.append(f"R-SBX-05: {name} is {r['rl'][name]}, expected {value}")
            self.toolchain = self.inventory(target_root, scratch_artifacts)
            if not 0 < r["disk"] <= lim.disk_mb * mb * 1.05:
                problems.append("R-SBX-05: the disk limit is not applied")
            promoted = {p["path"] for p in st["promoted"]}
            rejected = {p["path"] for p in st["rejected"]}
            if promoted != {"probe/ok.txt"} or rejected != {"probe/link", "probe/fifo", "probe/big.bin"}:
                problems.append(f"no-follow promotion is wrong: promoted {sorted(promoted)}, rejected {sorted(rejected)}")
            # The wall-clock limit kills a command that does not stop, and its children.
            t0 = time.monotonic()
            st2 = self.run(target_root, RunSpec(command="sleep 30 & sleep 30", timeout_s=1), scratch_artifacts)
            if not st2["timed_out"] or time.monotonic() - t0 > 15:
                problems.append("R-SBX-05: the wall-clock limit is not applied")
        except (SandboxError, OSError, KeyError) as exc:
            problems.append(f"sandbox start test failed: {exc}")
        self.available = not problems
        return self.available, list(problems)


def poc_script(record, patched):
    """Shell script for one PoC run (SPEC 13.1.6). Exit 97/98 mark setup failures."""
    poc = record["poc_test"]
    lines = [
        "cp -R /target/. /scratch/src || exit 98",
        "cd /scratch/src || exit 98",
    ]
    if patched:
        lines.append("patch -p1 -s --no-backup-if-mismatch -r /dev/null < /scratch/.vhin/fix.patch >/dev/null 2>&1 || exit 97")
    lines += [
        f"mkdir -p {shlex.quote(os.path.dirname(poc['file_name']) or '.')} || exit 98",
        f"cp /scratch/.vhin/poc {shlex.quote(poc['file_name'])} || exit 98",
        poc["command"],
    ]
    return "\n".join(lines)


def poc_result(original, patched, has_patch):
    """Classify the two runs (SPEC 13.1.6.3)."""
    def failed(st):
        return st["timed_out"] or st["signal"] is not None or st["exit_code"] not in (0, 97, 98, SETUP_EXIT)
    if original is None or original["exit_code"] in (97, 98, SETUP_EXIT):
        return "error"
    if not failed(original):
        return "not_reproduced"
    if not has_patch or patched is None:
        return "reproduced"
    if patched["exit_code"] in (97, 98, SETUP_EXIT):
        return "error"
    return "fixed" if patched["exit_code"] == 0 and not patched["timed_out"] else "reproduced"
