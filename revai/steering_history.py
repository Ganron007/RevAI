"""revai/steering_history.py — the L3 (post-hoc) steering notes for a case.

L3 steering is an analyst's direction recorded AFTER a run, for the next one.
It shares one merge point with L1 (`steering.effective_steering_note`) so a
stage cannot be steered by two different answers to "what is the current
direction".

Two properties are load-bearing and were easy to get wrong the first time:

1. A read that fails must not take the history with it.
   `read_steering_history` used to swallow a parse error and return []. The
   next append then read [] and OVERWROTE the file -- a truncated write or a
   full disk silently destroyed every note ever recorded for the case, and the
   next POST still returned 201 OK with a clean one-entry history. An
   unparseable store is now preserved beside the file as
   `steering-history.corrupt-<n>.json` and a fresh store is started, so the
   damage is visible and recoverable rather than irreversible.

2. Append is a read-modify-write, so it needs a lock.
   The console serves requests threaded; six concurrent POSTs for the same sha
   each read the same history and each wrote their own record, losing four
   notes while every request still reported success. An `flock` around the
   whole read-modify-write closes that.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, "/opt/scripts")

STEERING_STORE = "steering-history.json"

#: How many notes a case keeps. Older ones are dropped from the active store
#: only; they are never the channel an analyst's latest direction arrives on.
HISTORY_CAP = 50

#: Bound on one note, kept in step with steering.MAX_NOTE_CHARS. Imported when
#: possible so the two cannot drift; the literal is the fallback if the sibling
#: module is not deployed.
try:
    from steering import MAX_NOTE_CHARS as _MAX_NOTE_CHARS
except Exception:  # pragma: no cover - steering.py is deployed beside this
    _MAX_NOTE_CHARS = 8000

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows dev box
    fcntl = None  # type: ignore[assignment]

#: Intra-process serialisation. The console serves requests threaded, and
#: flock() locks are held on an open file DESCRIPTION: two threads that each
#: open() the lock file get two descriptions and therefore two independent
#: locks, which is why six concurrent POSTs in one process each saved their own
#: record and lost five. flock covers cross-process; this covers threads.
_THREAD_LOCK = threading.Lock()


def _store_path(case_dir: Path) -> Path:
    return Path(case_dir) / STEERING_STORE


def _lock_path(case_dir: Path) -> Path:
    """A dedicated lock file, beside the store.

    Locking the store itself is not possible: the atomic write replaces it, and
    a lock held on the replaced inode does not exclude a writer that opened the
    new one.
    """
    return Path(case_dir) / (STEERING_STORE + ".lock")


class _Lock:
    """Best-effort advisory lock around the read-modify-write.

    Never fatal. A reader that cannot lock still gets a consistent file, because
    the write itself is atomic (tmp + os.replace); the lock exists to stop two
    concurrent appends from each saving only their own record.
    """

    def __init__(self, case_dir: Path):
        self.path = _lock_path(case_dir)
        self.fd = None

    def __enter__(self):
        if fcntl is None:
            return self
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        except OSError:
            # A lock we cannot take is reported, not fatal: the caller still
            # performs an atomic write, so the worst case is a lost update, and
            # staying silent about that would be the defect.
            if self.fd is not None:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.fd = None
            print(f"[steering] could not lock {self.path.name}; concurrent "
                  "notes may be lost", file=sys.stderr, flush=True)
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
        return False


def _read_store(path: Path) -> tuple[list[dict], bool]:
    """(records, healthy).

    `healthy` is False when the file exists but could not be parsed. The caller
    decides what to do; returning [] here without saying so is what destroyed
    notes before.
    """
    if not path.is_file():
        return [], True
    try:
        loaded = json.loads(path.read_text(errors="replace"))
    except Exception as exc:
        print(f"[steering] note history unreadable ({exc}); preserving it "
              f"as {path.name}.corrupt-* and starting a new store",
              file=sys.stderr, flush=True)
        return [], False
    if isinstance(loaded, list):
        return [h for h in loaded if isinstance(h, dict)], True
    print(f"[steering] note history is not a list; preserving it and starting "
          "a new store", file=sys.stderr, flush=True)
    return [], False


def _quarantine(path: Path) -> None:
    """Keep an unreadable store instead of overwriting it."""
    try:
        n = 1
        while True:
            cand = path.with_name(f"{path.name}.corrupt-{n}")
            if not cand.exists():
                os.replace(str(path), str(cand))
                return
            n += 1
    except OSError as exc:
        print(f"[steering] could not preserve unreadable history: {exc}",
              file=sys.stderr, flush=True)


def append_steering_note(case_dir: Path, note: str,
                         level: str = "L3-post-hoc") -> dict:
    """Append a post-hoc note to the case's steering history.

    Returns the record appended. Raises ValueError for an empty note: a note that
    is empty cannot steer anything, and silently accepting one would make the UI
    look like it heard something.
    """
    note = (note or "").strip()
    if not note:
        raise ValueError("a steering note cannot be empty")
    if len(note) > _MAX_NOTE_CHARS:
        print(f"[steering] note truncated {len(note)} -> {_MAX_NOTE_CHARS} "
              "chars", file=sys.stderr, flush=True)
        note = note[:_MAX_NOTE_CHARS]
    record = {
        "level": level,
        "note": note,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    case_dir = Path(case_dir)
    path = _store_path(case_dir)
    try:
        case_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OSError(f"cannot create case dir for steering note: {exc}") from exc

    with _THREAD_LOCK, _Lock(case_dir):
        history, healthy = _read_store(path)
        if not healthy:
            _quarantine(path)
            history = []
        history.append(record)
        payload = json.dumps(history[-HISTORY_CAP:], indent=2)
        # Atomic write: a reader never sees a half-written store, and a process
        # killed mid-write leaves the previous store intact rather than a
        # truncated one. Same shape as depth_agent.save_state.
        #
        # The temp name carries the pid AND the thread id: if every guard above
        # somehow fails, two writers still collide on distinct files rather than
        # both renaming one shared temp, and the loser's failure is visible.
        tmp = path.with_name(
            f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(payload)
            _replace_retry(tmp, path)
        except OSError as exc:
            _unlink(tmp)
            raise OSError(f"could not record steering note: {exc}") from exc
    return record


def _unlink(p: Path) -> None:
    try:
        if p.exists():
            p.unlink()
    except OSError:
        pass


def _replace_retry(src: Path, dst: Path, attempts: int = 3) -> None:
    """os.replace with a short retry.

    On Windows a scanner or indexer can hold the destination open for a few
    milliseconds after another thread's write, which surfaces as a permission
    error on a rename that would otherwise succeed. The rename is atomic once it
    lands, so retrying cannot produce a half-written store.
    """
    last = None
    for i in range(attempts):
        try:
            os.replace(str(src), str(dst))
            return
        except OSError as exc:
            last = exc
            if i + 1 < attempts:
                time.sleep(0.05 * (i + 1))
    raise last  # type: ignore[misc]


def read_steering_history(case_dir: Path) -> list[dict]:
    """The steering notes recorded against a case, oldest first.

    An unreadable store quarantines itself on the NEXT append (append is the only
    writer), so a read on its own never destroys anything. Returning [] without
    saying the store is broken is what the docstring above describes.
    """
    records, _ = _read_store(_store_path(Path(case_dir)))
    return records


def latest_steering_note(case_dir: Path) -> str:
    """The most recent note, or "" when none was ever given."""
    history = read_steering_history(case_dir)
    return str(history[-1].get("note") or "") if history else ""
