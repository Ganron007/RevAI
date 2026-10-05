"""L3 post-hoc steering: steer AFTER a run, on the UI.

The operator's framing: the UI must be capable of all three levels. L1 (a note
before the run) and L2 (mid-run chat) are both in hand or deferred; L3 is the one
an examiner actually reaches for — the run finished, the analyst reads the
artifacts, disagrees with where the analysis went, and wants to point the next
pass at something.

What L3 is:
  POST /api/steer/<sha>   {note, level}  — record a note against a case
  GET  /api/steer/<sha>                   — read back what was steered, and when

What L3 is deliberately NOT: a verdict input. The note becomes L1-direction for
the *next* stage run. Re-running a stage consumes it through the same
`steering.load_steering_notes()` path L1 uses, so there is exactly one
implementation of "what direction was given" and it cannot drift between "before
the first run" and "after it".

The re-run itself is the pre-existing /api/run/<sha>/<stage>. L3 adds the note
to it rather than duplicating a re-run path — a second re-run entry point would
be a second thing to keep honest.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, "/opt/scripts")

STEERING_STORE = "steering-history.json"


def _store_path(case_dir: Path) -> Path:
    return Path(case_dir) / STEERING_STORE


def append_steering_note(case_dir: Path, note: str,
                         level: str = "L3-post-hoc") -> dict:
    """Append a post-hoc note to the case's steering history.

    Returns the record appended. Raises ValueError for an empty note: a note that
    is empty cannot steer anything and silently accepting one would make the UI
    look like it heard something.
    """
    note = (note or "").strip()
    if not note:
        raise ValueError("a steering note cannot be empty")
    if len(note) > 8000:
        note = note[:8000]
    record = {
        "level": level,
        "note": note,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    path = _store_path(case_dir)
    history: list[dict] = []
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(errors="replace"))
            if isinstance(loaded, list):
                history = [h for h in loaded if isinstance(h, dict)]
        except Exception:
            history = []
    history.append(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(history[-50:], indent=2), encoding="utf-8")
    return record


def read_steering_history(case_dir: Path) -> list[dict]:
    """The steering notes recorded against a case, oldest first."""
    path = _store_path(case_dir)
    if not path.is_file():
        return []
    try:
        loaded = json.loads(path.read_text(errors="replace"))
    except Exception:
        return []
    return [h for h in loaded if isinstance(h, dict)] if isinstance(
        loaded, list) else []


def latest_steering_note(case_dir: Path) -> str:
    """The most recent note, or "" when none was ever given."""
    history = read_steering_history(case_dir)
    return str(history[-1].get("note") or "") if history else ""