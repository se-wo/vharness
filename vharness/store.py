"""SQLite state store (SPEC 8.1). All run state lives here; agents are stateless."""

import json
import sqlite3
import time

STAGE_PRIORITY = {"verify": 0, "trace": 1, "validate": 2, "dedup": 3, "gapfill": 4, "hunt": 5, "recon": 6}
OPEN_TASK = ("queued", "running")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, created REAL, status TEXT, reason TEXT, config TEXT
);
CREATE TABLE IF NOT EXISTS targets (
  run_id TEXT, target TEXT, root TEXT, commit_sha TEXT, dirty INTEGER,
  PRIMARY KEY (run_id, target)
);
CREATE TABLE IF NOT EXISTS stages (
  run_id TEXT, target TEXT, stage TEXT, status TEXT, updated REAL,
  PRIMARY KEY (run_id, target, stage)
);
CREATE TABLE IF NOT EXISTS docs (
  run_id TEXT, target TEXT, kind TEXT, content TEXT,
  PRIMARY KEY (run_id, target, kind)
);
CREATE TABLE IF NOT EXISTS units (
  run_id TEXT, target TEXT, coverage_id TEXT, data TEXT, status TEXT, wave INTEGER, priority INTEGER,
  PRIMARY KEY (run_id, target, coverage_id)
);
CREATE TABLE IF NOT EXISTS tasks (
  task_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, target TEXT, stage TEXT,
  payload TEXT, status TEXT, attempts INTEGER DEFAULT 0, agent_id TEXT, model TEXT,
  error TEXT, stage_priority INTEGER, priority INTEGER, created REAL, updated REAL
);
CREATE TABLE IF NOT EXISTS candidates (
  run_id TEXT, target TEXT, fingerprint TEXT, data TEXT, hunter TEXT, units TEXT,
  status TEXT, primary_fp TEXT, created REAL,
  PRIMARY KEY (run_id, target, fingerprint)
);
CREATE TABLE IF NOT EXISTS records (
  run_id TEXT, target TEXT, fingerprint TEXT, verdict TEXT, data TEXT, validator TEXT,
  verifiers TEXT, reachability TEXT, exposure TEXT, priority TEXT, trace_data TEXT,
  final INTEGER DEFAULT 0, removed INTEGER DEFAULT 0, depth INTEGER DEFAULT 0,
  PRIMARY KEY (run_id, target, fingerprint)
);
CREATE TABLE IF NOT EXISTS consumers (
  run_id TEXT, fingerprint TEXT, source_target TEXT, target TEXT, paths TEXT, reason TEXT,
  PRIMARY KEY (run_id, fingerprint, target)
);
CREATE TABLE IF NOT EXISTS notes (
  note_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, target TEXT, kind TEXT,
  attack_class TEXT, coverage_id TEXT, text TEXT, created REAL
);
CREATE TABLE IF NOT EXISTS wishlist (
  item_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, target TEXT, agent_id TEXT,
  task_id INTEGER, need TEXT, reason TEXT, unblocks TEXT, created REAL
);
CREATE TABLE IF NOT EXISTS invocations (
  invocation_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, target TEXT, task_id INTEGER,
  role TEXT, agent_id TEXT, model TEXT, turns INTEGER, input_tokens INTEGER, output_tokens INTEGER,
  cost_usd REAL, duration_ms INTEGER, status TEXT, error TEXT, prompt_tokens_est INTEGER, created REAL
);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER);
"""


def _j(value):
    return json.dumps(value, sort_keys=True)


class Store:
    def __init__(self, path):
        self.path = path
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def x(self, sql, *args):
        return self.db.execute(sql, args)

    def next_seq(self, name):
        self.x("INSERT INTO counters(name, value) VALUES(?, 1) ON CONFLICT(name) DO UPDATE SET value = value + 1", name)
        return self.x("SELECT value FROM counters WHERE name=?", name).fetchone()[0]

    # ---- runs / targets / stages / docs ----
    def create_run(self, run_id, config):
        self.x("INSERT INTO runs VALUES (?,?,?,?,?)", run_id, time.time(), "running", None, _j(config))

    def latest_run(self):
        row = self.x("SELECT * FROM runs ORDER BY created DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def run(self, run_id):
        row = self.x("SELECT * FROM runs WHERE run_id=?", run_id).fetchone()
        return dict(row) if row else None

    def set_run_status(self, run_id, status, reason=None):
        if reason is not None:
            old = self.run(run_id)["reason"]
            reasons = [r for r in (old or "").split("; ") if r]
            if reason not in reasons:
                reasons.append(reason)
            reason = "; ".join(reasons)
            self.x("UPDATE runs SET status=?, reason=? WHERE run_id=?", status, reason, run_id)
        else:
            self.x("UPDATE runs SET status=? WHERE run_id=?", status, run_id)

    def add_target(self, run_id, target, root, commit_sha, dirty):
        self.x("INSERT OR REPLACE INTO targets VALUES (?,?,?,?,?)", run_id, target, root, commit_sha, int(bool(dirty)))

    def targets(self, run_id):
        return [dict(r) for r in self.x("SELECT * FROM targets WHERE run_id=? ORDER BY target", run_id)]

    def target_root(self, run_id, target):
        row = self.x("SELECT root FROM targets WHERE run_id=? AND target=?", run_id, target).fetchone()
        return row["root"] if row else None

    def set_stage(self, run_id, target, stage, status):
        self.x("INSERT OR REPLACE INTO stages VALUES (?,?,?,?,?)", run_id, target, stage, status, time.time())

    def stage(self, run_id, target, stage):
        row = self.x("SELECT status FROM stages WHERE run_id=? AND target=? AND stage=?", run_id, target, stage).fetchone()
        return row["status"] if row else None

    def stages(self, run_id):
        return [dict(r) for r in self.x("SELECT * FROM stages WHERE run_id=? ORDER BY target, stage", run_id)]

    def put_doc(self, run_id, target, kind, content):
        self.x("INSERT OR REPLACE INTO docs VALUES (?,?,?,?)", run_id, target, kind, content if isinstance(content, str) else _j(content))

    def doc(self, run_id, target, kind, parse=False):
        row = self.x("SELECT content FROM docs WHERE run_id=? AND target=? AND kind=?", run_id, target, kind).fetchone()
        if not row:
            return None
        return json.loads(row["content"]) if parse else row["content"]

    # ---- units ----
    def put_unit(self, run_id, target, unit):
        self.x(
            "INSERT OR REPLACE INTO units VALUES (?,?,?,?,?,?,?)",
            run_id, target, unit["coverage_id"], _j(unit), unit["status"], unit.get("wave", 1), unit.get("priority", 0),
        )

    def unit(self, run_id, target, coverage_id):
        row = self.x("SELECT data FROM units WHERE run_id=? AND target=? AND coverage_id=?", run_id, target, coverage_id).fetchone()
        return json.loads(row["data"]) if row else None

    def units(self, run_id, target=None, status=None):
        sql, args = "SELECT data FROM units WHERE run_id=?", [run_id]
        if target is not None:
            sql += " AND target=?"
            args.append(target)
        if status is not None:
            statuses = [status] if isinstance(status, str) else list(status)
            sql += f" AND status IN ({','.join('?' * len(statuses))})"
            args += statuses
        sql += " ORDER BY priority, coverage_id"
        return [json.loads(r["data"]) for r in self.x(sql, *args)]

    # ---- tasks ----
    def add_task(self, run_id, target, stage, payload, priority=0):
        now = time.time()
        cur = self.x(
            "INSERT INTO tasks(run_id, target, stage, payload, status, stage_priority, priority, created, updated) VALUES (?,?,?,?,?,?,?,?,?)",
            run_id, target, stage, _j(payload), "queued", STAGE_PRIORITY.get(stage, 9), priority, now, now,
        )
        return cur.lastrowid

    def task(self, task_id):
        row = self.x("SELECT * FROM tasks WHERE task_id=?", task_id).fetchone()
        return self._task(row) if row else None

    @staticmethod
    def _task(row):
        t = dict(row)
        t["payload"] = json.loads(t["payload"])
        return t

    def next_task(self, run_id, exclude_stages=()):
        sql = "SELECT * FROM tasks WHERE run_id=? AND status='queued'"
        args = [run_id]
        if exclude_stages:
            sql += f" AND stage NOT IN ({','.join('?' * len(exclude_stages))})"
            args += list(exclude_stages)
        row = self.x(sql + " ORDER BY stage_priority, priority, task_id LIMIT 1", *args).fetchone()
        return self._task(row) if row else None

    def update_task(self, task_id, **fields):
        fields["updated"] = time.time()
        if "payload" in fields:
            fields["payload"] = _j(fields["payload"])
        sets = ", ".join(f"{k}=?" for k in fields)
        self.x(f"UPDATE tasks SET {sets} WHERE task_id=?", *fields.values(), task_id)

    def tasks(self, run_id, target=None, stages=None, statuses=None):
        sql, args = "SELECT * FROM tasks WHERE run_id=?", [run_id]
        if target is not None:
            sql += " AND target=?"
            args.append(target)
        for col, vals in (("stage", stages), ("status", statuses)):
            if vals:
                sql += f" AND {col} IN ({','.join('?' * len(vals))})"
                args += list(vals)
        return [self._task(r) for r in self.x(sql + " ORDER BY task_id", *args)]

    def requeue_running(self, run_id):
        """R-PIPE-05."""
        return self.x("UPDATE tasks SET status='queued' WHERE run_id=? AND status='running'", run_id).rowcount

    # ---- candidates ----
    def put_candidate(self, run_id, target, fp, data, hunter, units, status, primary_fp=None):
        self.x(
            "INSERT OR REPLACE INTO candidates VALUES (?,?,?,?,?,?,?,?,?)",
            run_id, target, fp, _j(data), hunter, _j(sorted(set(units))), status, primary_fp, time.time(),
        )

    def candidate(self, run_id, target, fp):
        row = self.x("SELECT * FROM candidates WHERE run_id=? AND target=? AND fingerprint=?", run_id, target, fp).fetchone()
        return self._cand(row) if row else None

    @staticmethod
    def _cand(row):
        c = dict(row)
        c["data"] = json.loads(c["data"])
        c["units"] = json.loads(c["units"])
        return c

    def candidates(self, run_id, target=None, status=None):
        sql, args = "SELECT * FROM candidates WHERE run_id=?", [run_id]
        if target is not None:
            sql += " AND target=?"
            args.append(target)
        if status is not None:
            statuses = [status] if isinstance(status, str) else list(status)
            sql += f" AND status IN ({','.join('?' * len(statuses))})"
            args += statuses
        return [self._cand(r) for r in self.x(sql + " ORDER BY fingerprint", *args)]

    def set_candidate_status(self, run_id, target, fp, status, primary_fp=None):
        self.x("UPDATE candidates SET status=?, primary_fp=? WHERE run_id=? AND target=? AND fingerprint=?", status, primary_fp, run_id, target, fp)

    # ---- records ----
    def put_record(self, run_id, target, record, validator, depth=0):
        self.x(
            "INSERT OR REPLACE INTO records(run_id, target, fingerprint, verdict, data, validator, verifiers, depth) VALUES (?,?,?,?,?,?,?,?)",
            run_id, target, record["fingerprint"], record["verdict"], _j(record), validator, _j([]), depth,
        )

    def record(self, run_id, target, fp):
        row = self.x("SELECT * FROM records WHERE run_id=? AND target=? AND fingerprint=?", run_id, target, fp).fetchone()
        return self._rec(row) if row else None

    @staticmethod
    def _rec(row):
        r = dict(row)
        r["data"] = json.loads(r["data"])
        r["verifiers"] = json.loads(r["verifiers"] or "[]")
        r["trace_data"] = json.loads(r["trace_data"]) if r["trace_data"] else None
        return r

    def records(self, run_id, target=None, verdicts=None, include_removed=False):
        sql, args = "SELECT * FROM records WHERE run_id=?", [run_id]
        if target is not None:
            sql += " AND target=?"
            args.append(target)
        if verdicts:
            sql += f" AND verdict IN ({','.join('?' * len(verdicts))})"
            args += list(verdicts)
        if not include_removed:
            sql += " AND removed=0"
        return [self._rec(r) for r in self.x(sql + " ORDER BY target, fingerprint", *args)]

    def update_record(self, run_id, target, fp, **fields):
        for k in ("data", "verifiers", "trace_data"):
            if k in fields:
                fields[k] = _j(fields[k])
        if "data" in fields:
            fields["verdict"] = json.loads(fields["data"])["verdict"]
        sets = ", ".join(f"{k}=?" for k in fields)
        self.x(f"UPDATE records SET {sets} WHERE run_id=? AND target=? AND fingerprint=?", *fields.values(), run_id, target, fp)

    # ---- consumers / notes / wishlist ----
    def put_consumer(self, run_id, fp, source_target, target, paths, reason):
        self.x("INSERT OR REPLACE INTO consumers VALUES (?,?,?,?,?,?)", run_id, fp, source_target, target, _j(paths), reason)

    def consumers(self, run_id):
        return [dict(r) | {"paths": json.loads(r["paths"])} for r in self.x("SELECT * FROM consumers WHERE run_id=?", run_id)]

    def add_note(self, run_id, target, kind, text, attack_class=None, coverage_id=None):
        self.x(
            "INSERT INTO notes(run_id, target, kind, attack_class, coverage_id, text, created) VALUES (?,?,?,?,?,?,?)",
            run_id, target, kind, attack_class, coverage_id, text, time.time(),
        )

    def notes(self, run_id, target=None, kind=None, attack_class=None, limit=None):
        sql, args = "SELECT * FROM notes WHERE run_id=?", [run_id]
        for col, val in (("target", target), ("kind", kind), ("attack_class", attack_class)):
            if val is not None:
                sql += f" AND {col}=?"
                args.append(val)
        sql += " ORDER BY note_id DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [dict(r) for r in self.x(sql, *args)]

    def add_wish(self, run_id, target, agent_id, task_id, item):
        self.x(
            "INSERT INTO wishlist(run_id, target, agent_id, task_id, need, reason, unblocks, created) VALUES (?,?,?,?,?,?,?,?)",
            run_id, target, agent_id, task_id, item["need"], item["reason"], item["unblocks"], time.time(),
        )

    def wishlist(self, run_id):
        return [dict(r) for r in self.x("SELECT * FROM wishlist WHERE run_id=? ORDER BY item_id", run_id)]

    # ---- invocations ----
    def add_invocation(self, run_id, target, task_id, role, agent_id, model, result, prompt_tokens_est):
        self.x(
            "INSERT INTO invocations(run_id, target, task_id, role, agent_id, model, turns, input_tokens, output_tokens, cost_usd, duration_ms, status, error, prompt_tokens_est, created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            run_id, target, task_id, role, agent_id, model, result.turns, result.input_tokens, result.output_tokens,
            result.cost_usd, result.duration_ms, "ok" if result.ok else result.error_kind, result.error, prompt_tokens_est, time.time(),
        )

    def invocation_count(self, run_id, target):
        return self.x("SELECT COUNT(*) FROM invocations WHERE run_id=? AND target=?", run_id, target).fetchone()[0]

    def cost(self, run_id):
        return self.x("SELECT COALESCE(SUM(cost_usd), 0) FROM invocations WHERE run_id=?", run_id).fetchone()[0]

    def cost_by_role(self, run_id):
        return [dict(r) for r in self.x(
            "SELECT role, model, COUNT(*) AS n, SUM(input_tokens) AS input_tokens, SUM(output_tokens) AS output_tokens, "
            "COALESCE(SUM(cost_usd),0) AS cost_usd, SUM(status='ok') AS ok FROM invocations WHERE run_id=? GROUP BY role, model ORDER BY role",
            run_id,
        )]
