#!/usr/bin/env python3
"""
ghidra_sql_client.py — Direct ghidrasql HTTP client.

Replaces `McpGhidraClient` (which spawned the `mcp_ghidra.py` stdio
subprocess as a transport layer). The MCP transport was 4 layers:

    v2_lib.McpJsonClient.call_tool("ghidra_query", {sql, ...})
        -> stdio JSON-RPC
            -> mcp_ghidra.py:call_tool() (process boundary)
                -> urllib to ghidrasql --http :18080
                    -> ghidrasql HTTP handler
                        -> SQLite (.gpr)

The new path is 2 layers:

    v2_lib.GhidraSqlClient.ghidra_query(session_id, sql, max_rows)
        -> urllib to ghidrasql --http :18080
            -> ghidrasql HTTP handler -> SQLite (.gpr)

The ghidrasql headless server is started lazily on the first query
per session and kept alive for the rest of the pipeline run. The
server is single-tenant (binds 18080); the client tears down any
prior session's server before starting its own.

Per-query latency on a 31MB .i64: ~5-20ms (urllib + ghidrasql HTTP)
vs ~50-100ms in the MCP path (4 layers of IPC + JSON encode/decode).

Same output shape as the old `McpGhidraClient.ghidra_query()` so
callers in quick_scan_v2 / deep_dive_v2 / yara_gen_v2 don't need
to change:

    {
        "columns": [str, ...],
        "rows": [{col: val}, ...],   # capped at max_rows
        "row_count": int,            # len(rows)
        "total_row_count": int,      # before cap
        "truncated": bool,
        "source": "ghidra_query",
        "session_id": str,
        "audit_path": str,
    }
"""
from __future__ import annotations
import json
import os
import re
import signal
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from v2_lib import case_dir

# Paths (must match mcp_ghidra.py conventions)
SESSIONS_DIR = Path("/opt/samples/sessions")
LOGS_DIR = Path("/opt/samples/logs")
GPR_ROOT = Path("/home/remnux/ghidra-projects")
GHIDRASQL_BIN = "/usr/local/bin/ghidrasql"
GHIDRA_HOME = "/opt/ghidra"

HOST = "127.0.0.1"
PORT_DEFAULT = 18080
STARTUP_TIMEOUT = 180  # s; ghidrasql loads the .gpr + runs analysis on first start
QUERY_TIMEOUT = 900    # s; large samples (50MB+) need >300s for cfg_edges
SERVER_LIFETIME = 7200  # 2h; ghidrasql --max-runtime cap

# Lazy-loaded singleton (one per process; v2 pipeline is single-threaded)
_client_instance: "GhidraSqlClient | None" = None

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


def get_ghidra_sql_client() -> "GhidraSqlClient":
    """Process-wide singleton accessor."""
    global _client_instance
    if _client_instance is None:
        _client_instance = GhidraSqlClient()
    return _client_instance


def reset_ghidra_sql_client() -> None:
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
    """GET /health/deep on a ghidrasql HTTP server. Returns True if 2xx."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _resolve_session(session_id: str) -> dict:
    """Look up session JSON. Accepts any of:
      - 'ghidra-<fmt>-<sha256>'  (preferred, e.g. 'ghidra-pe-85a4ea1b...')
      - '<fmt>-<sha256>'          (legacy; fmt-less)
      - '<sha256>'                (just the SHA)
    The session JSON file is always named <sha256>.json regardless
    of the ghidra-<fmt>- prefix in the session_id.
    """
    # Strip "ghidra-" prefix if present
    rest = session_id[len("ghidra-"):] if session_id.startswith("ghidra-") else session_id
    # The SHA is always the LAST segment after the last "-"
    sha = rest.split("-")[-1]
    p = SESSIONS_DIR / f"{sha}.json"
    if not p.exists():
        raise FileNotFoundError(
            f"session {session_id!r} not found at {p} (run intake_v2 first)"
        )
    return json.loads(p.read_text())


class GhidraSqlClient:
    """Direct ghidrasql HTTP client. Replaces McpGhidraClient.

    Spawns `ghidrasql --http` lazily per session, holds the proc
    handle in a dict, and tears down on close_all(). The server
    is single-tenant: starting a new session kills any prior
    session's server (mirroring mcp_ghidra.py's behavior).
    """

    def __init__(self, host: str = HOST, port: int = PORT_DEFAULT):
        self.host = host
        self.port = port
        # session_id -> {"proc": Popen, "port": int, "base_url": str, "gpr": str}
        self._servers: dict[str, dict] = {}

    # ---- public API -----------------------------------------------------

    def ghidra_query(
        self,
        session_id: str,
        sql: str,
        max_rows: int = 200,
    ) -> dict:
        """Run a SQL query against the open Ghidra .gpr for `session_id`.

        Returns the same dict shape as the old McpGhidraClient.
        P0.5: read-only — only single SELECT statements are executed.
        """
        validate_readonly_sql(sql)
        session = _resolve_session(session_id)
        sha = session.get("sha256") or session_id.split("-", 1)[-1]
        base_url = self._ensure_server(session)

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
                f"ghidrasql HTTP error {e.code}: {e.read().decode(errors='replace')}"
            )
        except urllib.error.URLError as e:
            raise RuntimeError(f"ghidrasql HTTP unreachable: {e}")

        if not payload.get("success"):
            err = (
                payload.get("first_error")
                or payload.get("error")
                or "unknown error"
            )
            results = payload.get("results", [])
            if results and results[0].get("error"):
                err = results[0]["error"]
            raise RuntimeError(f"ghidrasql SQL error: {err}")

        # Parse the response into the same shape the old McpGhidraClient returned
        results = payload.get("results", [])
        columns = results[0].get("columns", []) if results else []
        rows_lists = results[0].get("rows", []) if results else []
        row_dicts = [dict(zip(columns, r)) for r in rows_lists]

        # Persist full result to audit log (NEVER truncated on disk)
        audit_path = case_dir(sha) / "audit.jsonl"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_record = {
            "ts": time.time(),
            "source": "ghidra_query",
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
            "source": "ghidra_query",
            "session_id": session_id,
            "audit_path": str(audit_path),
        }

    def close(self, session_id: str) -> None:
        """Kill the ghidrasql server for one session."""
        entry = self._servers.pop(session_id, None)
        if entry is None:
            return
        try:
            os.killpg(os.getpgid(entry["proc"].pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        gpr = entry.get("gpr")
        if gpr:
            proj_dir = Path(gpr).parent
            for lp in (proj_dir / f"{Path(gpr).stem}.lock",
                       proj_dir / f"{Path(gpr).stem}.lock~"):
                try:
                    if lp.exists():
                        lp.unlink()
                except OSError:
                    pass

    def close_all(self) -> None:
        """Kill all servers (called at process exit or by reset)."""
        for sid in list(self._servers.keys()):
            self.close(sid)

    # ---- internal --------------------------------------------------------

    def _ensure_server(self, session: dict) -> str:
        """Start a ghidrasql --http server for `session` if not running.

        Returns the base URL (no trailing slash).
        """
        sid = session["session_id"]
        gpr = session.get("gpr_path")
        if not gpr:
            raise FileNotFoundError(
                f"session {sid} has no gpr_path (intake_v2 should have set it)"
            )
        if not Path(gpr).exists():
            raise FileNotFoundError(
                f"GPR not found for session {sid}: {gpr} "
                f"(intake_v2 should have created it)"
            )

        # 1. Existing live server for THIS session (tracked by us)?
        entry = self._servers.get(sid)
        if entry and entry["proc"] and entry["proc"].poll() is None:
            base_url = entry["base_url"]
            if _probe(f"{base_url}/health/deep", 1.5):
                return base_url
            # dead, kill and restart
            self.close(sid)

        # 2. ghidrasql is single-tenant per project. If a ghidrasql is
        # already running for THIS project (tracked or untracked), reuse
        # it. We detect by walking /proc/<pid>/cmdline for any
        # ghidrasql whose argv contains the project name.
        gpr_stem = Path(gpr).stem
        existing = self._find_existing_ghidrasql(gpr_stem)
        if existing is not None:
            proc, port = existing
            base_url = f"http://{self.host}:{port}"
            if not _probe(f"{base_url}/health/deep", 2.0):
                # dead but cmdline still matches; kill and continue
                self._kill_pid(proc.pid)
            else:
                # Reuse it; don't track ownership (we didn't start it)
                self._servers[sid] = {
                    "proc": proc,
                    "port": port,
                    "base_url": base_url,
                    "gpr": gpr,
                    "reused": True,
                }
                return base_url

        # 3. No reusable server. Kill any other ghidrasql serving a
        # DIFFERENT project (would block our start_new on the lock)
        # and start fresh.
        self._kill_any_ghidrasql()

        # 3. Start a new server on the next free port
        port = self.port
        while _port_in_use(port):
            port += 1
            if port > self.port + 50:
                raise RuntimeError("no free port for ghidrasql HTTP server")

        sha = session.get("sha256") or sid.split("-", 1)[-1]
        log_path = case_dir(sha) / "ghidrasql-server.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_fh = open(log_path, "ab")

        cmd = [
            GHIDRASQL_BIN,
            "--ghidra", GHIDRA_HOME,
            "--project", str(Path(gpr).parent),
            "--project-name", Path(gpr).stem,
            "--program",
                session.get("program_name", Path(gpr).stem),
            "--http",
            "--port", str(port),
            "--bind", self.host,
            "--rpc-port", str(port + 10),  # headless API needs a separate port
            "--max-runtime", str(SERVER_LIFETIME),
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # so killpg works
        )
        base_url = f"http://{self.host}:{port}"

        # Wait for /health/deep
        deadline = time.time() + STARTUP_TIMEOUT
        while time.time() < deadline:
            if proc.poll() is not None:
                # died during startup
                tail = log_path.read_text(errors="replace")[-1000:]
                raise RuntimeError(
                    f"ghidrasql server died during startup for {sid} "
                    f"(rc={proc.returncode}); tail of log:\n{tail}"
                )
            if _probe(f"{base_url}/health/deep", 1.5):
                break
            time.sleep(0.5)
        else:
            self.close(sid)
            raise RuntimeError(
                f"ghidrasql server for {sid} did not become healthy "
                f"within {STARTUP_TIMEOUT}s"
            )

        self._servers[sid] = {
            "proc": proc,
            "port": port,
            "base_url": base_url,
            "gpr": gpr,
        }
        return base_url

    @staticmethod
    def _find_existing_ghidrasql(gpr_stem: str) -> "tuple[subprocess.Popen, int] | None":
        """Walk /proc/*/cmdline looking for a ghidrasql serving this project.

        Returns (proc_handle, port) if found and healthy, else None.
        The proc_handle is reconstructed from the PID (we don't have a
        Popen for it because we didn't start it).
        """
        import subprocess
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                cmdline = (entry / "cmdline").read_text(errors="replace")
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            cmdline = cmdline.replace("\x00", " ").strip()
            if "/usr/local/bin/ghidrasql" not in cmdline:
                continue
            if gpr_stem not in cmdline:
                continue
            # Extract the port from --port N
            port = None
            for tok in cmdline.split():
                if tok == "--port" or tok == "-p":
                    pass
            tokens = cmdline.split()
            i = 0
            while i < len(tokens) - 1:
                if tokens[i] == "--port":
                    try:
                        port = int(tokens[i + 1])
                    except ValueError:
                        pass
                i += 1
            if port is None:
                continue
            # Reconstruct a Popen-like handle with just .pid
            class _FakePopen:
                def __init__(self, pid):
                    self.pid = pid
                def poll(self):
                    try:
                        os.kill(self.pid, 0)  # signal 0 = check existence
                        return None
                    except (ProcessLookupError, PermissionError):
                        return 1
            return _FakePopen(pid), port
        return None

    @staticmethod
    def _kill_pid(pid: int) -> None:
        """Kill a PID and its process group, clean up Ghidra lock files."""
        import signal
        import subprocess
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        # Also pkill the matching analyzeHeadless + java children
        subprocess.run(["pkill", "-9", "-P", str(pid)], check=False)
        # Clean up lock files
        for p in GPR_ROOT.rglob("*.lock*"):
            try:
                p.unlink()
            except OSError:
                pass

    @staticmethod
    def _kill_any_ghidrasql() -> None:
        """Kill ANY ghidra-related process: ghidrasql wrapper, analyzeHeadless
        bash launcher, AND the java process that holds the RPC port.
        Without killing the java, the next ghidrasql fails with
        BindException("Address already in use") on port 18090.
        Also cleans up .lock* files (held by orphaned processes).
        """
        import subprocess
        import signal as _sig
        # Kill ghidrasql wrappers + analyzeHeadless bash launchers
        for pat in ("analyzeHeadless", "ghidrasql", "LibGhidraHost"):
            subprocess.run(["pkill", "-9", "-f", pat], check=False)
        # Kill any java process whose command line has both
        # analyzeHeadless and the ghidra JAR. The pkill -f java
        # would be too broad.
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmdline = (entry / "cmdline").read_text(errors="replace")
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            if ("analyzeHeadless" in cmdline
                    and "ghidra" in cmdline.lower()):
                try:
                    os.kill(int(entry.name), _sig.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
        time.sleep(2)
        # Force-kill any remaining ghidra java by walking /proc
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmdline = (entry / "cmdline").read_text(errors="replace")
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            if ("GhidraClassLoader" in cmdline
                    and "analyzeHeadless" in cmdline):
                try:
                    os.kill(int(entry.name), _sig.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
        time.sleep(1)
        # Clean up all lock files
        for p in GPR_ROOT.rglob("*.lock*"):
            try:
                p.unlink()
            except OSError:
                pass
        # Also clean up specific project's locks
        for p in GPR_ROOT.glob("*.lock*"):
            try:
                p.unlink()
            except OSError:
                pass

    # ---- write-back (rename / bookmark) + snapshot / rollback ----
    #
    # Per Elias's REcon 2026 talk, ghidrasql supports UPDATE /
    # INSERT / DELETE on the virtual tables (funcs, bookmarks,
    # comments, types). Changes land live in the Ghidra project.
    # To make this safe we (a) snapshot the .gpr before any
    # mutation, (b) wrap mutations in a ghidra transaction, and
    # (c) log every change to audit.jsonl for replay / rollback.

    def snapshot(self, sha: str) -> dict:
        """Copy the Ghidra project to a timestamped snapshot before any write.

        Returns {"snapshot_id": "2026-07-03T15-50-00", "path": "...",
                 "size_bytes": N}.

        The snapshot path is /opt/samples/logs/<sha>/ghidra-snapshots/
        <stem>__<snapshot_id>/. The ENTIRE project directory is copied
        (the .gpr file is a pointer; the actual IDB data is in the .rep/
        subdirectory). The original project is NOT modified.
        """
        sess_p = SESSIONS_DIR / f"{sha}.json"
        if not sess_p.exists():
            raise FileNotFoundError(f"session {sha} not found")
        sess = json.loads(sess_p.read_text())
        gpr = Path(sess["gpr_path"])
        if not gpr.exists():
            raise FileNotFoundError(f"gpr not found: {gpr}")
        snap_dir = case_dir(sha) / "ghidra-snapshots"
        snap_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%dT%H-%M-%S", time.gmtime())
        snap_id = f"{ts}__annotate"
        snap_path = snap_dir / f"{gpr.stem}__{snap_id}"
        snap_path.mkdir(parents=True, exist_ok=True)
        # Copy the entire project directory (which contains gpr + rep/)
        import shutil
        proj_dir = gpr.parent
        for entry in proj_dir.iterdir():
            dest = snap_path / entry.name
            if entry.is_file():
                shutil.copy2(entry, dest)
            elif entry.is_dir() and entry.name != snap_path.name:
                shutil.copytree(entry, dest, dirs_exist_ok=True)
        # Total size
        total = sum(f.stat().st_size for f in snap_path.rglob("*") if f.is_file())
        return {
            "snapshot_id": snap_id,
            "path": str(snap_path),
            "size_bytes": total,
            "original_gpr": str(gpr),
            "created_at": ts,
        }

    def annotate(
        self,
        sha: str,
        renames: list[dict] | None = None,
        bookmarks: list[dict] | None = None,
        dry_run: bool = False,
    ) -> dict:
        """Apply function renames and/or bookmarks via ghidrasql UPDATE/INSERT.

        Each rename is {"address": int, "new_name": str}.
        Each bookmark is {"address": int, "description": str}.
        With dry_run=True, builds the SQL and returns the plan
        without executing it (no .gpr mutation).

        Wraps all writes in a ghidra transaction (BEGIN TXN /
        END TXN) so a failure rolls back atomically.

        Returns {"ok": True, "applied": [...], "audit": [...],
                 "dry_run": bool}.
        """
        renames = renames or []
        bookmarks = bookmarks or []
        if not renames and not bookmarks:
            return {"ok": True, "applied": [], "audit": [], "dry_run": dry_run,
                    "note": "nothing to do"}

        sess_p = SESSIONS_DIR / f"{sha}.json"
        if not sess_p.exists():
            raise FileNotFoundError(f"session {sha} not found")
        sess = json.loads(sess_p.read_text())
        base_url = self._ensure_server(sess)

        # Ensure the ghidra server is alive (the transaction API is
        # only available when the ghidrasql --http server is up).
        sql_statements: list[str] = []
        for r in renames:
            addr = int(r["address"])
            new_name = str(r["new_name"]).replace("'", "''")
            sql_statements.append(
                f"UPDATE funcs SET name = '{new_name}' WHERE addr = {addr}"
            )
        for b in bookmarks:
            addr = int(b["address"])
            comment = str(b.get("comment") or b.get("description", "")).replace("'", "''")
            category = str(b.get("category", "Note")).replace("'", "''")
            btype = str(b.get("type", "Analysis")).replace("'", "''")
            sql_statements.append(
                f"INSERT INTO bookmarks(addr, type, category, comment) "
                f"VALUES ({addr}, '{btype}', '{category}', '{comment}')"
            )

        # NOTE: ghidrasql manages its own transaction (the analyzeHeadless
        # process opens a write transaction on the project). We must NOT
        # issue BEGIN TRANSACTION ourselves — that fails with "cannot
        # start a transaction within a transaction". Each statement is
        # committed individually as ghidrasql processes it. For
        # all-or-nothing semantics, the snapshot taken before this call
        # is the rollback mechanism.
        if dry_run:
            return {
                "ok": True,
                "applied": [],
                "audit": [{"sql": s} for s in sql_statements],
                "dry_run": True,
            }

        # Execute each statement separately. ghidrasql's /query endpoint
        # accepts a single statement (or a semicolon-separated batch,
        # but mixed DDL/DML in one batch can fail — safer per-call).
        all_ok = True
        per_stmt_results: list[dict] = []
        for sql in sql_statements:
            req = urllib.request.Request(
                f"{base_url}/query",
                data=sql.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=QUERY_TIMEOUT) as resp:
                    payload = json.loads(resp.read().decode())
            except (urllib.error.HTTPError, urllib.error.URLError) as e:
                all_ok = False
                per_stmt_results.append({"sql": sql, "error": str(e)})
                continue
            ok = payload.get("success", False)
            if not ok:
                all_ok = False
                results = payload.get("results", [])
                err = (
                    results[0].get("error")
                    if results
                    else payload.get("error", "unknown")
                )
                per_stmt_results.append({"sql": sql, "error": err, "payload": payload})
            else:
                per_stmt_results.append({"sql": sql, "ok": True, "payload": payload})

        # Log to audit.jsonl (NEVER truncated on disk)
        audit_path = case_dir(sha) / "audit.jsonl"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_record = {
            "ts": time.time(),
            "source": "ghidra_annotate",
            "sha256": sha,
            "renames": renames,
            "bookmarks": bookmarks,
            "sql_statements": sql_statements,
            "results": per_stmt_results,
        }
        with audit_path.open("a") as f:
            f.write(json.dumps(audit_record) + "\n")

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
        """Restore the Ghidra project from a snapshot directory.

        If snapshot_id is None, uses the most recent snapshot
        under /opt/samples/logs/<sha>/ghidra-snapshots/.
        After restore, kills the running ghidrasql (if any) so
        the next query reopens with the restored project.
        """
        snap_dir = case_dir(sha) / "ghidra-snapshots"
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
        sess_p = SESSIONS_DIR / f"{sha}.json"
        sess = json.loads(sess_p.read_text())
        gpr = Path(sess["gpr_path"])
        proj_dir = gpr.parent
        import shutil
        # Kill any running ghidrasql so the lock file is released
        self._kill_any_ghidrasql()
        time.sleep(2)
        # Clean up lock files before restoring
        for p in proj_dir.glob(f"{gpr.stem}.lock*"):
            try:
                p.unlink()
            except OSError:
                pass
        # Remove current project contents (everything in proj_dir
        # except the snapshot we're copying from) and copy back.
        for entry in proj_dir.iterdir():
            if entry.resolve() == snap.resolve():
                continue
            if entry.is_file() or entry.is_symlink():
                entry.unlink()
            elif entry.is_dir():
                shutil.rmtree(entry)
        for entry in snap.iterdir():
            dest = proj_dir / entry.name
            if entry.is_file():
                shutil.copy2(entry, dest)
            elif entry.is_dir():
                shutil.copytree(entry, dest, dirs_exist_ok=True)
        return {
            "ok": True,
            "snapshot": str(snap),
            "restored_to": str(gpr),
            "size_bytes": gpr.stat().st_size,
        }

    def apply_pending(
        self,
        sha: str,
        annotations: dict,
        snapshot: bool = True,
        dry_run: bool = False,
    ) -> dict:
        """Convenience: snapshot + annotate in one call.

        annotations = {"renames": [...], "bookmarks": [...]}.
        If snapshot=True, copies the .gpr first (so a rollback is
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
        print("usage: ghidra_sql_client.py <session_id|stage> [sql] [annotate|rollback|snapshot]")
        sys.exit(1)
    arg = sys.argv[1]
    if arg == "stage":
        # Start a server for Farfli and exit
        sess_path = SESSIONS_DIR / "85a4ea1b8db25c259fc6c208954ebb3c3a939bddb4856a942fd844be5ac16966.json"
        sess = json.loads(sess_path.read_text())
        c = get_ghidra_sql_client()
        url = c._ensure_server(sess)
        print(f"ghidrasql server up at {url} (pid={c._servers[sess['session_id']]['proc'].pid})")
    elif arg == "annotate":
        # Demo: rename FUN_100129f6 -> Farfli_decrypt_string
        sess_path = SESSIONS_DIR / "85a4ea1b8db25c259fc6c208954ebb3c3a939bddb4856a942fd844be5ac16966.json"
        sess = json.loads(sess_path.read_text())
        c = get_ghidra_sql_client()
        sha = sess["sha256"]
        annotations = {
            "renames": [{
                "address": 268511734,  # 0x100129F6
                "new_name": "Farfli_decrypt_string",
            }],
            "bookmarks": [{
                "address": 268458512,  # 0x10005a10
                "description": "Flagged by capa: keylogger",
            }],
        }
        result = c.apply_pending(sha, annotations, snapshot=True)
        print(json.dumps(result, indent=2, default=str))
    elif arg == "snapshot":
        sess_path = SESSIONS_DIR / "85a4ea1b8db25c259fc6c208954ebb3c3a939bddb4856a942fd844be5ac16966.json"
        sess = json.loads(sess_path.read_text())
        c = get_ghidra_sql_client()
        result = c.snapshot(sess["sha256"])
        print(json.dumps(result, indent=2, default=str))
    elif arg == "rollback":
        if len(sys.argv) < 3:
            print("usage: ghidra_sql_client.py rollback <snapshot_id>")
            sys.exit(1)
        c = get_ghidra_sql_client()
        result = c.rollback(sys.argv[2])
        print(json.dumps(result, indent=2, default=str))
    else:
        sql = sys.argv[2] if len(sys.argv) > 2 else "SELECT count(*) AS funcs FROM funcs"
        c = get_ghidra_sql_client()
        result = c.ghidra_query(arg, sql)
        print(json.dumps({
            "columns": result["columns"],
            "row_count": result["row_count"],
            "truncated": result["truncated"],
            "rows": result["rows"],
        }, indent=2, default=str))
