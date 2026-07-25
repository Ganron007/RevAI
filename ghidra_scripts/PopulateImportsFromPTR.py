# Populates a resolved Ghidra import list from PTR_* data items/labels.
#
# Many compound / packed / binder PEs have an empty top-level import table,
# so the default Ghidra SQL exporter reports 0 imports.  However, Ghidra still
# creates labels like PTR_CreateProcessA for import thunks.  This script walks
# those labels, resolves the API name, guesses the host DLL (with a confidence
# marker), and writes a sidecar JSON that the pipeline can use as a reliable
# Ghidra import source.
#
# Usage (headless):
#   analyzeHeadless ... -preScript TweakAnalyzers.py \
#                       -postScript PopulateImportsFromPTR.py <sha256> <logs_dir>
#
# Output:
#   <logs_dir>/<sha256>/ghidra_imports_resolved.json
#
#@category RevAI
#@author CADRE-RevAI
#@keybinding
#@menupath
#@toolbar

from __future__ import print_function
import json
import os
import sys

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import Data

# ---------------------------------------------------------------------------
# Static DLL mapping / heuristic.  This is a fallback when the symbol namespace
# does not already tell us the source library.
# ---------------------------------------------------------------------------

DLL_PREFIXES = [
    ("kernel32.dll", [
        "create", "open", "close", "read", "write", "get", "set", "load", "free",
        "virtual", "heap", "local", "global", "format", "lstr", "move", "copy",
        "compare", "sleep", "exit", "terminate", "wait", "win", "module",
        "process", "thread", "file", "device", "console", "tls", "crit",
        "initialize", "interlocked", "resume", "suspend", "switch", "systemtime",
        "localtime", "gettick", "query", "output", "input", "isbad", "muldiv",
        "seterror", "geterror", "fls", "flsalloc", "flsfree", "flsgetvalue",
        "flssetvalue", "getcurrent", "setcurrent", "getenvironment",
        "setenvironment", "expandenvironment", "getcommandline", "getversion",
        "getmodule", "getprocaddress", "loadlibrary", "freelibrary",
    ]),
    ("user32.dll", [
        "message", "send", "post", "getwindow", "setwindow", "createwindow",
        "register", "translate", "dispatch", "peek", "show", "movewindow",
        "client", "screen", "draw", "invalidate", "update", "beginpaint",
        "endpaint", "getdc", "releasedc", "setfocus", "getfocus", "enable",
        "disable", "iswindow", "findwindow", "enumwindows", "getclass",
        "setclass", "loadcursor", "loadicon", "loadimage", "createmenu",
        "trackpopup", "dialog", "messagebox", "peekmessage", "waitmessage",
        "getdesktop", "setwindowpos", "setforeground", "getforeground",
    ]),
    ("advapi32.dll", [
        "reg", "crypt", "openprocess", "lookup", "access", "adjust", "getsid",
        "openscm", "createservice", "startservice", "controlservice",
        "enumservices", "queryservice", "changeservice", "closeservice",
        "openservice", "cryptacquire", "cryptrelease", "cryptimportkey",
        "cryptexportkey", "cryptdestroykey", "cryptencrypt", "cryptdecrypt",
        "cryptcreatehash", "cryptgethashparam", "cryptsethashparam",
        "crypthashdata", "cryptderivekey", "cryptgenkey", "cryptgenrandom",
        "openscmanager", "closeeventlog", "openeventlog", "readeventlog",
        "getaclinformation", "setaclinformation", "gettoken", "opentoken",
        "privilegecheck", "lookupprivilege", "adjusttoken", "setsecurity",
    ]),
    ("ws2_32.dll", [
        "wsa", "socket", "connect", "bind", "listen", "accept", "recv", "send",
        "gethost", "getaddr", "inet", "ioctlsocket", "select", "shutdown",
        "setsockopt", "getsockopt", "getpeername", "getsockname", "recvfrom",
        "sendto", "socket", "gethostname",
    ]),
    ("ntdll.dll", [
        "nt", "zw", "rtl", "ldr", "csr", "dbgprint", "ntdll",
    ]),
    ("shell32.dll", [
        "shell", "shapp", "shcreate", "shopen", "shget", "extract", "dragaccept",
        "dragquery", "shbrowse", "shfolder", "shfileop", "shexecute",
        "findexecutable", "shellabout", "shellexecute",
    ]),
    ("shlwapi.dll", [
        "path", "url", "shlwapi", "strformat", "strcspa", "strcspnw", "strtrim",
        "strset", "strchr", "strncmp", "strrchr", "strncat", "strncpy", "shque",
        "ish", "pathfind", "pathcanonicalize", "pathcombine", "pathfileexists",
    ]),
    ("wininet.dll", [
        "internet", "ftp", "http", "url",
    ]),
    ("dnsapi.dll", [
        "dns",
    ]),
    ("iphlpapi.dll", [
        "getadapters", "getnetwork", "getip", "iphlp", "getifentry", "getiftable",
    ]),
    ("gdi32.dll", [
        "create", "delete", "select", "get", "set", "bitblt", "stretchblt",
        "patblt", "rectangle", "ellipse", "line", "move", "text", "font",
        "brush", "pen", "region", "gdi", "poly", "roundrect", "arc", "pie",
    ]),
    ("ole32.dll", [
        "co", "ole", "clsid", "iid", "progid", "cocreate", "coinit", "coget",
        "comarshal", "counmarshal", "cofree", "cocreateinstance", "cotaskmem",
        "stringfromclsid", "stringfromiid",
    ]),
    ("oleaut32.dll", [
        "variant", "sys", "safe", "disp", "bstr", "variantinit", "variantclear",
        "variantcopy", "systalloc", "sysfreestring", "sysstringlen", "dispinvoke",
    ]),
    ("comctl32.dll", [
        "comctl", "image", "initcommoncontrols",
    ]),
    ("version.dll", [
        "getfileversion", "ver", "getversionex",
    ]),
    ("winmm.dll", [
        "mci", "wave", "midi", "time", "joy", "playsound",
    ]),
    ("psapi.dll", [
        "enumprocess", "getmodule", "getprocess", "psapi", "getmoduleinformation",
    ]),
    ("imagehlp.dll", [
        "imagehlp", "imageget", "mapfileandcheck", "checksum",
    ]),
    ("dbghelp.dll", [
        "sym", "stack", "image", "unhandledexception", "enummodules",
    ]),
    ("msvcrt.dll", [
        "printf", "scanf", "sprintf", "memcpy", "memset", "strcpy", "strlen",
        "malloc", "free", "calloc", "realloc", "fopen", "fread", "fwrite",
        "fclose", "gets", "puts", "exit", "abort", "system", "getenv", "setenv",
        "qsort", "bsearch", "time", "clock", "rand", "srand", "memmove",
        "strncpy", "strncmp", "strcat", "strchr", "strrchr", "strstr", "strtok",
        "wcscpy", "wcsncpy", "wcslen", "wcscmp",
    ]),
    ("ucrtbase.dll", [
        "_", "__acrt", "__stdio", "_errno", "_invalid_parameter",
    ]),
]


def _build_prefix_map():
    """Flatten DLL_PREFIXES into a lookup dict (longest prefix wins)."""
    m = {}
    for dll, prefixes in DLL_PREFIXES:
        for p in prefixes:
            m[p] = dll
    return m


_PREFIX_MAP = _build_prefix_map()


def resolve_dll_heuristic(api_name):
    """Return best-guess DLL for a Windows API name."""
    lower = api_name.lower()
    # Some exact overrides
    exact = {
        "loadlibrarya": "kernel32.dll",
        "loadlibraryw": "kernel32.dll",
        "loadlibraryexa": "kernel32.dll",
        "loadlibraryexw": "kernel32.dll",
        "getprocaddress": "kernel32.dll",
        "freelibrary": "kernel32.dll",
        "getmodulehandlea": "kernel32.dll",
        "getmodulehandlew": "kernel32.dll",
        "getmodulefilenamea": "kernel32.dll",
        "getmodulefilenamew": "kernel32.dll",
        "virtualalloc": "kernel32.dll",
        "virtualallocex": "kernel32.dll",
        "virtualfree": "kernel32.dll",
        "virtualfreeex": "kernel32.dll",
        "virtualprotect": "kernel32.dll",
        "virtualprotectex": "kernel32.dll",
        "virtualquery": "kernel32.dll",
        "virtualqueryex": "kernel32.dll",
        "createprocessa": "kernel32.dll",
        "createprocessw": "kernel32.dll",
        "createprocessasusera": "advapi32.dll",
        "createprocessasuserw": "advapi32.dll",
        "winexec": "kernel32.dll",
        "shellexecutea": "shell32.dll",
        "shellexecutew": "shell32.dll",
        "shellexecuteexa": "shell32.dll",
        "shellexecuteexw": "shell32.dll",
        "regopenkeya": "advapi32.dll",
        "regopenkeyexa": "advapi32.dll",
        "regclosekey": "advapi32.dll",
        "regqueryvalueexa": "advapi32.dll",
        "regsetvalueexa": "advapi32.dll",
        "regcreatekeya": "advapi32.dll",
        "regcreatekeyexa": "advapi32.dll",
        "cryptacquirecontexta": "advapi32.dll",
        "cryptreleasecontext": "advapi32.dll",
        "cryptencrypt": "advapi32.dll",
        "cryptdecrypt": "advapi32.dll",
        "cryptcreatehash": "advapi32.dll",
        "crypthashdata": "advapi32.dll",
        "cryptgethashparam": "advapi32.dll",
        "cryptgenrandom": "advapi32.dll",
        "internetopena": "wininet.dll",
        "internetopenurla": "wininet.dll",
        "internetreadfile": "wininet.dll",
        "internetclosehandle": "wininet.dll",
        "urldownloadtofilea": "urlmon.dll",
        "urldownloadtocachefilea": "urlmon.dll",
        "dnsquery_a": "dnsapi.dll",
        "dnsquery_utf8": "dnsapi.dll",
        "wsastartup": "ws2_32.dll",
        "wsacleanup": "ws2_32.dll",
    }
    if lower in exact:
        return exact[lower]
    # Try longest prefix match
    best = None
    best_len = 0
    for prefix, dll in _PREFIX_MAP.items():
        if lower.startswith(prefix) and len(prefix) > best_len:
            best = dll
            best_len = len(prefix)
    return best if best else "UNKNOWN.dll"


def symbol_dll_from_namespace(sym):
    """If the symbol lives in a library namespace, return that library name."""
    try:
        ns = sym.getParentNamespace()
        if ns is None:
            return None
        name = ns.getName()
        if name is None:
            return None
        # Ghidra library namespaces often end with .dll already
        n = name.lower()
        if n.endswith(".dll") or n.endswith(".exe"):
            return name
        # Otherwise append .dll if it looks like a library
        if " " not in n and "." not in n:
            return name + ".dll"
        return name
    except Exception:
        return None


def addr_to_hex(addr):
    return "0x" + addr.toString()


def main():
    args = getScriptArgs()
    sha = args[0] if len(args) > 0 else currentProgram.getName()
    logs_dir = args[1] if len(args) > 1 else "/opt/samples/logs"

    out_dir = os.path.join(logs_dir, sha)
    try:
        os.makedirs(out_dir)
    except OSError:
        pass
    out_path = os.path.join(out_dir, "ghidra_imports_resolved.json")

    sym_tab = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    ref_mgr = currentProgram.getReferenceManager()

    imports = []
    seen = set()

    # -----------------------------------------------------------------------
    # 1. Walk defined data items (this is the usual source of PTR_* labels).
    # -----------------------------------------------------------------------
    data_it = listing.getDefinedData(True)
    while data_it.hasNext() and not monitor.isCancelled():
        data = data_it.next()
        addr = data.getAddress()
        symbols = sym_tab.getSymbols(addr)
        for sym in symbols:
            name = sym.getName()
            if not name or not name.startswith("PTR_"):
                continue
            api_name = name[4:]
            if api_name in seen or not api_name:
                continue
            seen.add(api_name)

            # Prefer library from namespace / external references
            dll = symbol_dll_from_namespace(sym)
            confidence = "namespace"
            if dll is None:
                # Try external references at this address
                try:
                    refs = ref_mgr.getReferencesTo(addr)
                    for ref in refs:
                        if ref.isExternalReference():
                            ext = ref.getExternalReference()
                            lib = ext.getLibraryName()
                            if lib:
                                dll = lib if lib.lower().endswith(".dll") else lib + ".dll"
                                confidence = "external_reference"
                                break
                except Exception:
                    pass
            if dll is None:
                dll = resolve_dll_heuristic(api_name)
                confidence = "heuristic"

            imports.append({
                "address": addr_to_hex(addr),
                "name": api_name,
                "module": dll,
                "confidence": confidence,
                "source_label": name,
            })

    # -----------------------------------------------------------------------
    # 2. Also walk all symbols to catch any PTR_* labels not on defined data.
    # -----------------------------------------------------------------------
    sym_it = sym_tab.getAllSymbols(False)
    while sym_it.hasNext() and not monitor.isCancelled():
        sym = sym_it.next()
        name = sym.getName()
        if not name or not name.startswith("PTR_"):
            continue
        api_name = name[4:]
        if api_name in seen or not api_name:
            continue
        seen.add(api_name)
        addr = sym.getAddress()
        dll = symbol_dll_from_namespace(sym)
        confidence = "namespace"
        if dll is None:
            dll = resolve_dll_heuristic(api_name)
            confidence = "heuristic"
        imports.append({
            "address": addr_to_hex(addr),
            "name": api_name,
            "module": dll,
            "confidence": confidence,
            "source_label": name,
        })

    imports.sort(key=lambda x: x["name"])

    with open(out_path, "w") as f:
        json.dump(imports, f, indent=2)

    print("PopulateImportsFromPTR: wrote %d resolved imports to %s" % (len(imports), out_path))


if __name__ == "__main__":
    main()
