#!/usr/bin/env python3
"""ida_sql_client.py — Direct idasql HTTP client for Remnux.

Replaces the SSH-to-Flare-VM approach. Uses the local `idasql`
CLI on Remnux (v0.0.17, installed at /usr/local/bin/idasql) to
query and write-back IDA databases (.i64 files).

Same pattern as ghidra_sql_client.py:
  - Lazy-start idasql --http server per session
  - urllib POST to /query for reads
  - idasql -w -q for writes (one-shot, persists to .i64)
  - Snapshot copies .i64 + sibling files locally
  - Rollback restores from snapshot

Key difference from Ghidra: the IDA database is a single
.i64 file (plus sibling .id0/.id1/.id2/.nam/.til files),
not a directory. The snapshot is a copy of the .i64 (and
all its sibling files). Rollback restores the snapshot.

IDA bookmark schema: (address, description) — no type/category.
IDA comment schema: (address, comment) — separate table.

Verified on Remnux 2026-07-04:
  - idasql v0.0.17 at /usr/local/bin/idasql
  - idat -B creates .i64 files
  - idasql -s <i64> -q "SELECT count(*) FROM funcs" works
  - idasql -s <i64> -w -q "UPDATE funcs SET name=..." works
  - idasql -s <i64> --http <port> starts HTTP server
"""
from __future__ import annotations
import json
import os
import re
import shutil
import signal
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

# Remnux-side config
SESSIONS_DIR = Path("/opt/samples/sessions")
LOGS_DIR = Path("/opt/samples/logs")
IDA_SESSIONS_DIR = Path("/opt/ida-sessions")
SNAPSHOT_DIR_NAME = "ida-snapshots"

IDASQL_BIN = "/usr/local/bin/idasql"
HOST = "127.0.0.1"
PORT_DEFAULT = 19300
STARTUP_TIMEOUT = 90  # s; idasql loads the .i64 on first start
QUERY_TIMEOUT = 60    # s
SERVER_LIFETIME = 7200  # 2h; idasql --max-runtime cap

# Process-wide singleton
_client_instance: "IdaSqlClient | None" = None

# P0.5: agent/planner SQL must be read-only. Single SELECT (or WITH...SELECT)
# only; no multi-statements, no mutation/pragma/attach keywords anywhere.
_SQL_FORBIDDEN_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|"
    r"vacuum|reindex|grant|revoke|truncate|begin|commit|rollback|savepoint|"
    r"release|analyze)\b",
    re.IGNORECASE,
)


def _blank_string_literals(text: str) -> str:
    """Replace SQL string-literal contents with spaces so checks don't trip
    on ';' or keywords inside quoted analyst search terms."""
    text = re.sub(r"'(?:[^'\\]|\\.|'')*'", " ", text)
    return re.sub(r'"(?:[^"\\]|\\.|"")*"', " ", text)


def validate_readonly_sql(sql: str) -> None:
    """Raise ValueError unless `sql` is a single read-only SELECT statement."""
    if not sql or not sql.strip():
        raise ValueError("empty SQL")
    # Strip SQL comments before checks so they can't smuggle keywords past.
    stripped = re.sub(r"--[^\n]*", " ", sql)
    stripped = re.sub(r"/\*.*?\*/", " ", stripped, flags=re.DOTALL).strip()
    # Single statement only: a semicolon is allowed solely as the last char.
    body = stripped[:-1] if stripped.endswith(";") else stripped
    # Blank string literals for the structural checks (content may contain
    # semicolons or words like 'delete' that are legitimate search terms).
    structural = _blank_string_literals(body)
    if ";" in structural:
        raise ValueError("multi-statement SQL not allowed")
    if not re.match(r"^(select|with)\b", body, re.IGNORECASE):
        raise ValueError("only SELECT queries are allowed")
    m = _SQL_FORBIDDEN_RE.search(structural)
    if m:
        raise ValueError(f"forbidden SQL keyword: {m.group(1).upper()}")


def get_ida_sql_client() -> "IdaSqlClient":
    """Process-wide singleton accessor."""
    global _client_instance
    if _client_instance is None:
        _client_instance = IdaSqlClient()
    return _client_instance


def reset_ida_sql_client() -> None:
    """Test/cleanup hook. Kills the singleton's servers and clears it."""
    global _client_instance
    if _client_instance is not None:
        _client_instance.close_all()
        _client_instance = None


def _port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return s.connect_ex((HOST, port)) == 0


def _probe(url: str, timeout: float = 1.5) -> bool:
    """GET /status on an idasql HTTP server. Returns True if 2xx."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _resolve_session(session_id: str) -> dict:
    """Look up session JSON. Accepts any of:
      - 'ida-<sha256>'  (preferred)
      - '<sha256>'      (just the SHA)
    The session JSON file is always named <sha256>.json.
    """
    # Strip "ida-" prefix if present
    sha = session_id[len("ida-"):] if session_id.startswith("ida-") else session_id
    # Try /opt/samples/sessions first, then /opt/ida-sessions
    for sessions_dir in [SESSIONS_DIR, IDA_SESSIONS_DIR]:
        p = sessions_dir / f"{sha}.json"
        if p.exists():
            return json.loads(p.read_text())
    raise FileNotFoundError(
        f"session {session_id!r} not found at {SESSIONS_DIR} or {IDA_SESSIONS_DIR} "
        f"(run intake_ida_v2 first)"
    )


def _find_i64_for_sha(sha: str) -> Path:
    """Find the .i64 file for a given SHA256.

    Looks in:
      1. /opt/ida-sessions/<sha>/
      2. /opt/samples/sessions/<sha>/ (legacy)
      3. /opt/samples/corpus/<project>/<sha>/ (where intake_v2
         creates it next to the raw binary)

    Returns the first .i64 found (preferring the most recent).
    Raises FileNotFoundError if none found.
    """
    import time
    candidates: list[Path] = []
    # Check session JSON first for the canonical path
    sess_p = SESSIONS_DIR / f"{sha}.json"
    if sess_p.exists():
        try:
            sess = json.loads(sess_p.read_text())
            ida_db = sess.get("ida_db_path")
            if ida_db and Path(ida_db).exists() and Path(ida_db).suffix == ".i64":
                candidates.append(Path(ida_db))
        except Exception:
            pass
    # Check standard dirs
    for base in [IDA_SESSIONS_DIR / sha, SESSIONS_DIR / sha]:
        if base.exists():
            for f in base.iterdir():
                if f.suffix == ".i64" and f not in candidates:
                    candidates.append(f)
    # Check corpus dirs (intake_v2 puts .i64 next to the raw binary)
    corpus_root = Path("/opt/samples/corpus")
    if corpus_root.exists():
        for project_dir in corpus_root.iterdir():
            if not project_dir.is_dir():
                continue
            sample_dir = project_dir / sha
            if sample_dir.exists():
                for f in sample_dir.iterdir():
                    if f.suffix == ".i64" and f not in candidates:
                        candidates.append(f)
    if not candidates:
        raise FileNotFoundError(
            f"no .i64 found for {sha} in {IDA_SESSIONS_DIR}, "
            f"{SESSIONS_DIR}, or /opt/samples/corpus/*/{sha}/"
        )
    # Return the most recently modified one
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _i64_sibling_files(i64_path: Path) -> list[Path]:
    """Return all sibling files for an .i64 (same stem, different extensions)."""
    stem = i64_path.stem
    parent = i64_path.parent
    return [f for f in parent.iterdir() if f.stem == stem and f.is_file()]


class IdaSqlClient:
    """Direct idasql HTTP client. Replaces SSH-to-Flare-VM approach.

    Spawns `idasql --http` lazily per session, holds the proc
    handle in a dict, and tears down on close_all(). The server
    is single-tenant: starting a new session kills any prior
    session's server (mirroring ghidra_sql_client.py behavior).

    THREAD SAFETY: this class is single-tenant — one idasql HTTP
    server at a time. A threading.Lock guards _ensure_server() so
    concurrent callers don't both start competing servers. The
    pipeline (quick_scan_v2 / deep_dive_v2) runs stages serially
    via run_stage() which holds the GIL in a single thread, so
    this lock is mostly defensive. If you need true multi-tenant,
    refactor to one server per session_id on different ports.
    """

    def __init__(self, host: str = HOST, port: int = PORT_DEFAULT):
        import threading as _threading
        self.host = host
        self.port = port
        # session_id -> {"proc": Popen, "port": int, "base_url": str, "i64": str}
        self._servers: dict[str, dict] = {}
        # Serializes _ensure_server() so concurrent callers don't
        # both try to start a competing idasql HTTP server.
        self._ensure_lock = _threading.Lock()

    # ---- public API -----------------------------------------------------

    def ida_query(
        self,
        session_id: str,
        sql: str,
        max_rows: int = 200,
    ) -> dict:
        """Run a SQL query against the open IDA .i64 for `session_id`.

        Returns the same dict shape as the old SSH-based approach.
        P0.5: read-only — only single SELECT statements are executed.
        """
        validate_readonly_sql(sql)
        session = _resolve_session(session_id)
        sha = session_id.replace("ida-", "")
        base_url = self._ensure_server(session, sha)

        # HTTP POST to /query
        req = urllib.request.Request(
            f"{base_url}/query",
            data=sql.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=QUERY_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"idasql HTTP error {e.code}: {e.read().decode(errors='replace')}"
            )
        except urllib.error.URLError as e:
            raise RuntimeError(f"idasql HTTP unreachable: {e}")

        if not payload.get("success"):
            err = (
                payload.get("first_error")
                or payload.get("error")
                or "unknown error"
            )
            results = payload.get("results", [])
            if results and results[0].get("error"):
                err = results[0]["error"]
            raise RuntimeError(f"idasql SQL error: {err}")

        # Parse the response into the same shape as ghidra_sql_client
        results = payload.get("results", [])
        columns = results[0].get("columns", []) if results else []
        rows_lists = results[0].get("rows", []) if results else []
        row_dicts = [dict(zip(columns, r)) for r in rows_lists]

        # Persist full result to audit log (NEVER truncated on disk)
        audit_path = LOGS_DIR / sha / "audit.jsonl"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_record = {
            "ts": time.time(),
            "source": "ida_query",
            "session_id": session_id,
            "sql": sql,
            "max_rows": max_rows,
            "result": payload,
        }
        with audit_path.open("a") as f:
            f.write(json.dumps(audit_record) + "\n")

        # Apply row cap
        truncated = False
        out_rows = row_dicts
        if len(out_rows) > max_rows:
            out_rows = out_rows[:max_rows]
            truncated = True

        return {
            "columns": columns,
            "rows": out_rows,
            "row_count": len(out_rows),
            "total_row_count": len(row_dicts),
            "truncated": truncated,
            "source": "ida_query",
            "session_id": session_id,
            "audit_path": str(audit_path),
        }

    def close(self, session_id: str) -> None:
        """Kill the idasql server for one session."""
        entry = self._servers.pop(session_id, None)
        if entry is None:
            return
        try:
            os.killpg(os.getpgid(entry["proc"].pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    def close_all(self) -> None:
        """Kill all servers (called at process exit or by reset)."""
        for sid in list(self._servers.keys()):
            self.close(sid)

    # ---- internal --------------------------------------------------------

    def _ensure_server(self, session: dict, sha: str) -> str:
        """Start an idasql --http server for `session` if not running.

        Returns the base URL (no trailing slash).

        idasql can analyze raw binaries directly (not just .i64 files),
        so if no .i64 exists, we fall back to sample_path.

        THREAD SAFETY: held under self._ensure_lock so concurrent
        callers serialize on server startup. See class docstring.
        """
        with self._ensure_lock:
            return self._ensure_server_locked(session, sha)

    def _ensure_server_locked(self, session: dict, sha: str) -> str:
        """Inner _ensure_server — caller must hold self._ensure_lock."""
        sid = session.get("session_id", f"ida-{sha}")
        i64 = session.get("ida_db_path")
        if i64 and Path(i64).exists():
            pass  # use it
        else:
            # Try to find .i64 in ida-sessions or sessions dirs
            try:
                i64 = str(_find_i64_for_sha(sha))
            except FileNotFoundError:
                # No .i64 — fall back to raw binary (idasql can analyze it)
                sample_path = session.get("sample_path")
                if sample_path and Path(sample_path).exists():
                    i64 = sample_path
                else:
                    raise FileNotFoundError(
                        f"IDA database not found for session {sid}: "
                        f"no .i64 and sample_path={sample_path}"
                    )
        if not Path(i64).exists():
            raise FileNotFoundError(
                f"IDA database not found for session {sid}: {i64}"
            )

        # 1. Existing live server for THIS session (tracked by us)?
        entry = self._servers.get(sid)
        if entry and entry["proc"] and entry["proc"].poll() is None:
            base_url = entry["base_url"]
            if _probe(f"{base_url}/status", 1.5):
                return base_url
            # dead, kill and restart
            self.close(sid)

        # 2. Kill any other idasql serving a DIFFERENT session
        self._kill_any_idasql()

        # 2b. If an .i64 already exists next to the raw binary
        # (created by a previous idasql -w call), use it instead
        # of the raw binary so that write-back changes persist.
        if not i64.endswith(".i64") and not i64.endswith(".idb"):
            candidate = Path(i64).with_suffix(".i64")
            if candidate.exists():
                i64 = str(candidate)

        # 3. Start a new server on the next free port
        port = self.port
        while _port_in_use(port):
            port += 1
            if port > self.port + 50:
                raise RuntimeError("no free port for idasql HTTP server")

        log_path = LOGS_DIR / sha / "idasql-server.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_fh = open(log_path, "ab")

        cmd = [
            IDASQL_BIN,
            "-s", str(i64),
            "--http", str(port),
            "--bind", self.host,
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # so killpg works
        )
        base_url = f"http://{self.host}:{port}"

        # Wait for /status
        deadline = time.time() + STARTUP_TIMEOUT
        while time.time() < deadline:
            if proc.poll() is not None:
                # died during startup
                tail = log_path.read_text(errors="replace")[-1000:]
                raise RuntimeError(
                    f"idasql server died during startup for {sid} "
                    f"(rc={proc.returncode}); tail of log:\n{tail}"
                )
            if _probe(f"{base_url}/status", 1.5):
                break
            time.sleep(0.5)
        else:
            self.close(sid)
            raise RuntimeError(
                f"idasql server for {sid} did not become healthy "
                f"within {STARTUP_TIMEOUT}s"
            )

        self._servers[sid] = {
            "proc": proc,
            "port": port,
            "base_url": base_url,
            "i64": i64,
        }
        return base_url

    @staticmethod
    def _kill_any_idasql() -> None:
        """Kill any running idasql/idat processes."""
        import subprocess
        # Use -x (exact comm name) so we do not match unrelated processes whose
        # cmdline contains the substring "idat" (e.g. v2_validate.py).
        for pat in ("idasql", "idat"):
            subprocess.run(["pkill", "-9", "-x", pat], check=False)
        time.sleep(1)

    # ---- write-back (rename / bookmark) + snapshot / rollback ----

    def snapshot(self, sha: str) -> dict:
        """Copy the .i64 + sibling files to a timestamped snapshot.

        Returns {"snapshot_id": "2026-07-04T15-50-00", "path": "...",
                 "size_bytes": N, "files_backed_up": [...]}.
        """
        session = _resolve_session(f"ida-{sha}")
        i64_path = session.get("ida_db_path")
        if i64_path and Path(i64_path).exists():
            pass  # use it
        else:
            try:
                i64_path = str(_find_i64_for_sha(sha))
            except FileNotFoundError:
                sample_path = session.get("sample_path")
                if sample_path and Path(sample_path).exists():
                    i64_path = sample_path
                else:
                    raise FileNotFoundError(
                        f"IDA database not found for {sha}: "
                        f"no .i64 and sample_path={sample_path}"
                    )
        i64 = Path(i64_path)
        if not i64.exists():
            raise FileNotFoundError(f"IDA database not found: {i64}")

        snap_dir = LOGS_DIR / sha / SNAPSHOT_DIR_NAME
        snap_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%dT%H-%M-%S", time.gmtime())
        snap_id = f"{ts}__ida-annotate"
        snap_path = snap_dir / snap_id
        snap_path.mkdir(parents=True, exist_ok=True)

        # Kill idasql first so we can copy the locked .i64
        self._kill_any_idasql()
        time.sleep(1)

        # Copy all sibling files
        siblings = _i64_sibling_files(i64)
        total_size = 0
        files_backed_up = []
        for f in siblings:
            dest = snap_path / f.name
            shutil.copy2(f, dest)
            total_size += f.stat().st_size
            files_backed_up.append(f.name)

        return {
            "snapshot_id": snap_id,
            "path": str(snap_path),
            "size_bytes": total_size,
            "original_db": str(i64),
            "files_backed_up": files_backed_up,
            "created_at": ts,
        }

    def annotate(
        self,
        sha: str,
        renames: list[dict] | None = None,
        bookmarks: list[dict] | None = None,
        dry_run: bool = False,
    ) -> dict:
        """Apply function renames and/or bookmarks via idasql CLI.

        Each rename is {"address": int, "new_name": str}.
        Each bookmark is {"address": int, "description": str}.
        With dry_run=True, builds the SQL and returns the plan
        without executing it (no .i64 mutation).

        Uses idasql -w -q for each statement (one-shot mode).
        The -w flag persists changes to the .i64 file.
        """
        renames = renames or []
        bookmarks = bookmarks or []
        if not renames and not bookmarks:
            return {"ok": True, "applied": [], "audit": [], "dry_run": dry_run,
                    "note": "nothing to do"}

        session = _resolve_session(f"ida-{sha}")
        i64_path = session.get("ida_db_path")
        if i64_path and Path(i64_path).exists():
            pass  # use it
        else:
            try:
                i64_path = str(_find_i64_for_sha(sha))
            except FileNotFoundError:
                sample_path = session.get("sample_path")
                if sample_path and Path(sample_path).exists():
                    i64_path = sample_path
                else:
                    raise FileNotFoundError(
                        f"IDA database not found for {sha}: "
                        f"no .i64 and sample_path={sample_path}"
                    )
        i64 = Path(i64_path)
        if not i64.exists():
            raise FileNotFoundError(f"IDA database not found: {i64}")

        # Build SQL statements
        sql_statements: list[str] = []
        for r in renames:
            addr = int(r["address"])
            new_name = str(r["new_name"]).replace("'", "''")
            sql_statements.append(
                f"UPDATE funcs SET name = '{new_name}' WHERE addr = {addr}"
            )
        for b in bookmarks:
            addr = int(b["address"])
            desc = str(b.get("comment") or b.get("description", "")).replace("'", "''")
            sql_statements.append(
                f"INSERT INTO bookmarks(addr, description) VALUES ({addr}, '{desc}')"
            )
        # Comments (separate table from bookmarks)
        for c_dict in bookmarks:
            cmt = str(c_dict.get("comment") or "").strip()
            if not cmt:
                continue
            addr = int(c_dict["address"])
            cmt = cmt.replace("'", "''")
            sql_statements.append(
                f"INSERT INTO comments(addr, comment) VALUES ({addr}, '{cmt}')"
            )

        if dry_run:
            return {
                "ok": True,
                "applied": [],
                "audit": [{"sql": s} for s in sql_statements],
                "dry_run": True,
            }

        # Kill any running idasql server first (we need exclusive access)
        self._kill_any_idasql()

        # Execute each statement via idasql -w -q
        # NOTE: each idasql -w invocation opens the DB, runs the
        # statement, saves, and exits. The first invocation may
        # create a .i64 from a raw binary. Subsequent invocations
        # must wait for the previous one to fully release the file
        # lock. We kill any remaining idasql between calls.
        all_ok = True
        per_stmt_results: list[dict] = []
        for sql in sql_statements:
            cmd = [IDASQL_BIN, "-s", str(i64), "-w", "-q", sql]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300
                )
                output = result.stdout + result.stderr
            except subprocess.TimeoutExpired:
                all_ok = False
                per_stmt_results.append({"sql": sql, "ok": False, "error": "timeout (300s)"})
                self._kill_any_idasql()
                continue
            if result.returncode != 0 or "error" in output.lower():
                all_ok = False
                per_stmt_results.append({"sql": sql, "ok": False, "output": output[-500:]})
            else:
                per_stmt_results.append({"sql": sql, "ok": True})
            # Kill any lingering idasql/idat before the next statement
            self._kill_any_idasql()

        # Log to audit.jsonl
        audit_path = LOGS_DIR / sha / "audit.jsonl"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_record = {
            "ts": time.time(),
            "source": "ida_annotate",
            "sha256": sha,
            "renames": renames,
            "bookmarks": bookmarks,
            "sql_statements": sql_statements,
            "results": per_stmt_results,
        }
        with audit_path.open("a") as f:
            f.write(json.dumps(audit_record) + "\n")

        # FIX: update session.json ida_db_path to point at the .i64
        # that idasql -w just created (or updated). Keeps session
        # state in sync with reality.
        # Pass i64.name (full filename) not i64.stem — idasql
        # appends .i64 to the full filename of the input.
        self._sync_session_ida_db_path(sha, i64.parent, i64.name)

        return {
            "ok": all_ok,
            "applied": [r for r in per_stmt_results if r.get("ok")],
            "failed": [r for r in per_stmt_results if not r.get("ok")],
            "renames": renames,
            "bookmarks": bookmarks,
            "audit_path": str(audit_path),
            "dry_run": False,
        }

    def rollback(self, sha: str, snapshot_id: str | None = None) -> dict:
        """Restore the .i64 from a snapshot directory.

        If snapshot_id is None, uses the most recent snapshot
        under /opt/samples/logs/<sha>/ida-snapshots/.
        After restore, kills the running idasql (if any) so
        the next query reopens with the restored database.
        """
        snap_dir = LOGS_DIR / sha / SNAPSHOT_DIR_NAME
        if not snap_dir.exists():
            raise FileNotFoundError(f"no snapshots dir for {sha}: {snap_dir}")
        if snapshot_id is None:
            snaps = sorted(
                [d for d in snap_dir.iterdir() if d.is_dir()],
                key=lambda p: p.stat().st_mtime, reverse=True,
            )
            if not snaps:
                raise FileNotFoundError(f"no snapshots in {snap_dir}")
            snap = snaps[0]
        else:
            candidates = [d for d in snap_dir.iterdir()
                          if d.is_dir() and d.name.endswith(snapshot_id)]
            if not candidates:
                raise FileNotFoundError(f"no snapshot matching {snapshot_id}")
            snap = candidates[0]

        session = _resolve_session(f"ida-{sha}")
        i64_path = session.get("ida_db_path")
        if i64_path and Path(i64_path).exists():
            pass  # use it
        else:
            try:
                i64_path = str(_find_i64_for_sha(sha))
            except FileNotFoundError:
                sample_path = session.get("sample_path")
                if sample_path and Path(sample_path).exists():
                    i64_path = sample_path
                else:
                    raise FileNotFoundError(
                        f"IDA database not found for {sha}: "
                        f"no .i64 and sample_path={sample_path}"
                    )
        i64 = Path(i64_path)
        i64_dir = i64.parent

        # Kill any running idasql so the file is released
        self._kill_any_idasql()
        time.sleep(1)

        # Delete ALL ida companion files (.i64, .id0, .id1, .id2,
        # .nam, .til) in the live location BEFORE restoring. This
        # ensures stale .i64 files (created by idasql -w after the
        # snapshot was taken) don't persist.
        # IMPORTANT: never delete the raw binary itself. Only delete
        # files with IDA extensions. The raw binary is the source
        # of truth — if we delete it, the rollback is destructive.
        ida_exts = {".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til"}
        for f in i64_dir.iterdir():
            if f.is_file() and f.suffix.lower() in ida_exts:
                try:
                    f.unlink()
                except OSError:
                    pass

        # Copy all files from snapshot dir back to the live db location
        # Make destination writable first (raw binary is often r--r--r--
        # and we need to overwrite it with the snapshot copy).
        for entry in snap.iterdir():
            if entry.is_file():
                dest = i64_dir / entry.name
                if dest.exists():
                    try:
                        dest.chmod(0o644)
                    except OSError:
                        pass
                shutil.copy2(entry, dest)

        # Verify the .i64 was restored
        restored_size = i64.stat().st_size if i64.exists() else 0

        # FIX: update session.json ida_db_path to match reality after
        # rollback. If a .i64 was restored from the snapshot, point
        # at it. If not (snapshot was just the raw binary), set to
        # None so _ensure_server falls back to sample_path.
        # Pass i64.name (full filename) not i64.stem — idasql
        # appends .i64 to the full filename of the input.
        self._sync_session_ida_db_path(sha, i64_dir, i64.name)

        return {
            "ok": True,
            "snapshot": str(snap),
            "restored_to": str(i64),
            "size_bytes": restored_size,
        }

    @staticmethod
    def _sync_session_ida_db_path(sha: str, i64_dir: Path, ref_name: str) -> None:
        """Update session.json ida_db_path to reflect current .i64 state.

        After rollback/annotate, the .i64 on disk may differ from
        what session.json says. This keeps them in sync so subsequent
        pipeline runs don't hit a stale path.

        idasql appends `.i64` to the full input filename (NOT the
        stem). So if the raw binary is `foo.c-abc123`, the .i64 is
        `foo.c-abc123.i64`, not `foo.i64`. We check both naming
        conventions.

        If a .i64 exists in i64_dir matching ref_name + .i64 OR
        ref_name.stem + .i64, point at it. Otherwise set to None
        (so ida_sql_client falls back to sample_path for raw-binary
        analysis).
        """
        session_p = SESSIONS_DIR / f"{sha}.json"
        if not session_p.exists():
            return
        try:
            sess = json.loads(session_p.read_text())
        except Exception:
            return
        # idasql appends .i64 to the full filename
        candidates = [i64_dir / f"{ref_name}.i64"]
        # Also try stem + .i64 (in case someone renamed manually)
        ref_path = Path(ref_name)
        candidates.append(i64_dir / f"{ref_path.stem}.i64")
        found = None
        for c in candidates:
            if c.exists() and c.stat().st_size > 0:
                found = str(c)
                break
        if sess.get("ida_db_path") != found:
            sess["ida_db_path"] = found
            session_p.write_text(json.dumps(sess, indent=2))

    def apply_pending(
        self,
        sha: str,
        annotations: dict,
        snapshot: bool = True,
        dry_run: bool = False,
    ) -> dict:
        """Convenience: snapshot + annotate in one call.

        annotations = {"renames": [...], "bookmarks": [...]}.
        If snapshot=True, copies the .i64 first (so a rollback is
        possible). Returns the combined result + the snapshot id
        (or None if no snapshot was taken).
        """
        snap = None
        if snapshot and not dry_run:
            snap = self.snapshot(sha)
        result = self.annotate(
            sha,
            renames=annotations.get("renames", []),
            bookmarks=annotations.get("bookmarks", []),
            dry_run=dry_run,
        )
        if snap is not None:
            result["snapshot"] = snap
        return result


# Quick smoke test
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: ida_sql_client.py <session_id|stage|annotate|rollback> [sql]")
        sys.exit(1)
    arg = sys.argv[1]
    if arg == "stage":
        # Start a server for a session and exit
        sha = sys.argv[2] if len(sys.argv) > 2 else "85a4ea1b8db25c259fc6c208954ebb3c3a939bddb4856a942fd844be5ac16966"
        c = get_ida_sql_client()
        session = _resolve_session(f"ida-{sha}")
        url = c._ensure_server(session, sha)
        print(f"idasql server up at {url}")
    elif arg == "annotate":
        sha = sys.argv[2] if len(sys.argv) > 2 else "85a4ea1b8db25c259fc6c208954ebb3c3a939bddb4856a942fd844be5ac16966"
        c = get_ida_sql_client()
        ann = {
            "renames": [{"address": 0x100129F6, "new_name": "complex_dispatcher_IDA_TEST"}],
            "bookmarks": [{"address": 0x100129F6, "comment": "IDA write-back test"}],
        }
        r = c.apply_pending(sha, ann, snapshot=True, dry_run=False)
        print(json.dumps(r, indent=2))
    elif arg == "rollback":
        sha = sys.argv[2] if len(sys.argv) > 2 else "85a4ea1b8db25c259fc6c208954ebb3c3a939bddb4856a942fd844be5ac16966"
        c = get_ida_sql_client()
        r = c.rollback(sha)
        print(json.dumps(r, indent=2))
    else:
        sql = sys.argv[2] if len(sys.argv) > 2 else "SELECT count(*) AS funcs FROM funcs"
        c = get_ida_sql_client()
        r = c.ida_query(arg, sql)
        print(json.dumps({
            "columns": r["columns"],
            "row_count": r["row_count"],
            "truncated": r["truncated"],
            "rows": r["rows"],
        }, indent=2, default=str))
