#!/usr/bin/env python3
r"""
frida_api_trace.py — Frida API tracing for Flare-VM dynamic analysis (Frida 17+).

Usage (PowerShell on Flare-VM):
    python C:\tools\flarevm-deploy\dynamic\frida_api_trace.py ^
      --target C:\samples\foo.exe ^
      --apis "CreateFileW,VirtualAlloc,WriteProcessMemory" ^
      --out C:\samples\foo.trace.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description="Frida API tracer for Flare-VM (Frida 17+)")
    ap.add_argument("--target", help="path to PE binary to spawn")
    ap.add_argument("--pid", type=int, help="PID to attach to (instead of --target)")
    ap.add_argument(
        "--apis",
        required=True,
        help="comma-separated API names (e.g. CreateFileW,VirtualAlloc)",
    )
    ap.add_argument("--module", default=None, help="unused (compat); hooks resolve globally")
    ap.add_argument("--out", required=True, help="output JSONL file")
    ap.add_argument("--max-calls", type=int, default=10000)
    ap.add_argument("--max-seconds", type=int, default=60)
    args = ap.parse_args()

    try:
        import frida
    except ImportError:
        print("FATAL: frida not installed. pip install frida frida-tools", file=sys.stderr)
        sys.exit(1)

    api_list = [a.strip() for a in args.apis.split(",") if a.strip()]
    if not api_list:
        print("FATAL: --apis is empty", file=sys.stderr)
        sys.exit(1)

    apis_js = ",\n        ".join(f'"{a}"' for a in api_list)
    js = f"""
'use strict';
const apis = [
        {apis_js}
];
const maxCalls = {args.max_calls};
let callCount = 0;

function resolveExport(name) {{
    try {{
        if (typeof Module.findGlobalExportByName === 'function') {{
            return Module.findGlobalExportByName(name);
        }}
    }} catch (e) {{}}
    try {{
        return Module.findExportByName(null, name);
    }} catch (e2) {{
        return null;
    }}
}}

function attachApi(name) {{
    try {{
        const addr = resolveExport(name);
        if (!addr) {{
            send({{type: 'log', level: 'warn', msg: `API ${{name}} not found`}});
            return;
        }}
        Interceptor.attach(addr, {{
            onEnter: function (args) {{
                if (callCount >= maxCalls) return;
                callCount++;
                send({{
                    type: 'call',
                    ts: Date.now(),
                    api: name,
                    tid: Process.getCurrentThreadId(),
                    args: [
                        args[0] ? args[0].toString() : null,
                        args[1] ? args[1].toString() : null,
                        args[2] ? args[2].toString() : null,
                        args[3] ? args[3].toString() : null
                    ]
                }});
            }},
            onLeave: function (retval) {{
                send({{
                    type: 'ret',
                    ts: Date.now(),
                    api: name,
                    tid: Process.getCurrentThreadId(),
                    retval: retval ? retval.toString() : null
                }});
            }}
        }});
        send({{type: 'log', level: 'info', msg: `hooked ${{name}}`}});
    }} catch (e) {{
        send({{type: 'log', level: 'error', msg: `hook ${{name}} failed: ${{e}}`}});
    }}
}}

apis.forEach(attachApi);
send({{type: 'log', level: 'info', msg: 'hooks installed'}});
"""

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    device = frida.get_local_device()
    spawned_pid = None

    if args.pid:
        print(f"attaching to pid={args.pid}", file=sys.stderr)
        session = device.attach(args.pid)
    elif args.target:
        print(f"spawning {args.target}", file=sys.stderr)
        if not Path(args.target).is_file():
            print(f"FATAL: target not found: {args.target}", file=sys.stderr)
            sys.exit(1)
        # Frida 17+: spawn returns pid (int), not a Session
        spawned_pid = device.spawn([args.target])
        session = device.attach(spawned_pid)
    else:
        print("FATAL: must specify --target or --pid", file=sys.stderr)
        sys.exit(1)

    script = session.create_script(js)
    out_fh = open(out_path, "w", encoding="utf-8")
    write_lock = threading.Lock()
    closed = {"done": False}

    def on_message(msg, data):
        if closed["done"]:
            return
        try:
            if msg["type"] == "send":
                with write_lock:
                    if closed["done"]:
                        return
                    out_fh.write(json.dumps(msg["payload"]) + "\n")
                    out_fh.flush()
            elif msg["type"] == "error":
                sys.stderr.write(f"[frida error] {msg.get('stack', msg)}\n")
        except Exception:
            pass

    def _hard_exit(code: int = 0) -> None:
        closed["done"] = True
        try:
            with write_lock:
                out_fh.flush()
                out_fh.close()
        except Exception:
            pass
        if spawned_pid is not None:
            try:
                device.kill(spawned_pid)
            except Exception:
                pass
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)

    # Watchdog: malware + Frida detach can hang forever over SSH
    def _watchdog() -> None:
        time.sleep(max(5, int(args.max_seconds) + 8))
        print("watchdog: forcing exit", file=sys.stderr)
        _hard_exit(0)

    threading.Thread(target=_watchdog, daemon=True).start()

    script.on("message", on_message)
    script.load()
    time.sleep(0.3)  # let hook install messages flush before resume

    if spawned_pid is not None:
        device.resume(spawned_pid)

    print(f"tracing for up to {args.max_seconds}s (max {args.max_calls} calls)", file=sys.stderr)
    deadline = time.time() + args.max_seconds
    try:
        while time.time() < deadline:
            time.sleep(0.5)
            try:
                if session.is_detached:
                    print("session detached (target exited)", file=sys.stderr)
                    break
            except Exception:
                break
    except KeyboardInterrupt:
        print("interrupted; detaching", file=sys.stderr)

    closed["done"] = True
    # Prefer kill over detach — detach can hang on instrumented malware
    if spawned_pid is not None:
        try:
            device.kill(spawned_pid)
        except Exception:
            pass
    try:
        script.unload()
    except Exception:
        pass
    try:
        # non-blocking best-effort; watchdog covers hang
        session.detach()
    except Exception:
        pass
    try:
        with write_lock:
            out_fh.flush()
            out_fh.close()
    except Exception:
        pass

    print(f"trace complete: {out_path}", file=sys.stderr)
    _hard_exit(0)


if __name__ == "__main__":
    main()
