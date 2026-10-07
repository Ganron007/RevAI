# -*- coding: utf-8 -*-
"""AST scanner: any test that reaches a code file through the repo layout.

The first version of this gate was a substring check on `Name(id='ROOT`. It was
defeated by four ordinary code shapes, all of which were demonstrated against it:

  p = ROOT / "revai" / "x.py"      -> p.read_text()      (indirection)
  open(ROOT / "revai" / "x.py")    -> .read()            (`open` is ast.Name)
  REPO_ROOT / "scripts" / "x.py"   -> ...                (root named REPO_ROOT)
  subprocess.run([sys.executable,
      str(ROOT / "scripts" / "x.py")])                   (no reader at all)

The last one is how the harness itself invokes scripts, so it was not a
hypothetical. A gate with those holes certifies 13 prior fixes while a 14th
walks through, so the scan below is a two-pass taint analysis instead:

  pass 1 -- find every expression that BUILDS a repo-rooted path (a `/` chain
            containing a code-dir constant, rooted at a module-level "root"
            name), and record the local names it is assigned to as tainted.
  pass 2 -- flag any use of a tainted name, or any inline rooted expression,
            that reaches a filesystem reader, a subprocess, or a compiler.

A root name is any name assigned a `Path(...).resolve().parent...` chain or
spelled with one of the conventional root names, so a test that calls its root
`HERE` or `PROJECT_ROOT` is still covered.
"""
from __future__ import annotations

import ast
import re
import warnings

# Repo subdirectories whose files are deployed FLAT, so a repo-layout path does
# not exist on the VM. Anything else is data, not code.
_CODE_DIRS = ("revai", "scripts", "install", "config", "extensions")

#: Attribute reads that touch the filesystem and therefore need a real path.
_READERS = frozenset({
    "read_text", "read_bytes", "is_file", "exists", "glob", "rglob",
    "iterdir", "stat", "absolute", "resolve", "samefile", "open",
})

#: Builtins that take a path and reach the filesystem or a child process.
_RAW_READERS = frozenset({"open", "compile", "exec", "eval"})

#: Modules/functions that launch another interpreter with a path.
_SUBPROCESS_NAMES = frozenset({
    "run", "check_output", "check_call", "call", "Popen", "getoutput",
    "getstatusoutput", "compile",
})

#: Names a test plausibly binds its repo root to.
_ROOT_NAMES = frozenset({
    "ROOT", "REPO_ROOT", "REPO", "HERE", "BASE", "BASEDIR", "PROJECT_ROOT",
    "ROOT_DIR", "REPO_DIR", "TESTS_ROOT",
})

#: The sanctioned accessor.
_LAYOUT_MODULE = "_layout"


def _seg(node: ast.AST) -> str:
    try:
        return ast.dump(node)
    except RecursionError:  # pragma: no cover
        return ""


def _has_code_dir(node: ast.AST) -> bool:
    """True when the expression contains a code-dir string constant.

    Matches an exact constant (`"revai"`) AND a path-shaped one
    (`"revai/v2_lib.py"`): the literal-string form is how a test that never
    builds a root still reaches into the code tree directly, and an exact-only
    match let it through the gate entirely.
    """
    seg = _seg(node)
    if any(f"Constant(value='{d}')" in seg or f'Constant(value="{d}")' in seg
           for d in _CODE_DIRS):
        return True
    try:
        for n in ast.walk(node):
            if (isinstance(n, ast.Constant) and isinstance(n.value, str)
                    and any(n.value == d or n.value.startswith(d + "/")
                            for d in _CODE_DIRS)):
                return True
    except RecursionError:  # pragma: no cover
        return False
    return False


def _is_root_name(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in _ROOT_NAMES
    # Path(__file__).resolve().parent.parent -- a root built from __file__
    seg = _seg(node)
    if "__file__" in seg and ("parent" in seg or "resolve" in seg):
        return True
    return False


def _rooted_path_expr(node: ast.AST) -> bool:
    """An expression that BUILDS a path rooted in the repo and into a code dir."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left, right = node.left, node.right
        if _is_root_name(left) and _has_code_dir(right):
            return True
        # chain: (ROOT / "revai") / "x.py" -- the code dir is on the left
        if _has_code_dir(left) and _is_root_name_root(left):
            return True
    return False


def _is_root_name_root(node: ast.AST) -> bool:
    """Whether `node` is a rooted chain: descend its left spine for a root name."""
    cur = node
    for _ in range(8):  # bounded; pathological nesting is someone's problem
        if isinstance(cur, ast.Name):
            return cur.id in _ROOT_NAMES
        if not (isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Div)):
            return False
        cur = cur.left
    return False


def _collect_tainted(tree: ast.AST) -> set[str]:
    """Local names assigned a repo-rooted code path, anywhere in the module."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None:
                continue
            if _rooted_path_expr(value) or (
                    isinstance(value, ast.Call) and _rooted_path_expr(value)):
                targets = (node.targets if isinstance(node, ast.Assign)
                           else [node.target])
                for t in targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                            out.add(n.id)
            # p = str(ROOT / "revai" / "x.py")  -> str() of a rooted expr
            if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                    and value.func.id in ("str", "Path", "os.path.join")
                    and value.args):
                inner = value.args[0] if len(value.args) == 1 else value.args[-1]
                if _rooted_path_expr(inner) or (
                        isinstance(inner, ast.BinOp) and isinstance(inner.op, ast.Div)
                        and _has_code_dir(inner) and _is_root_name(inner.left)):
                    targets = (node.targets if isinstance(node, ast.Assign)
                               else [node.target])
                    for t in targets:
                        for n in ast.walk(t):
                            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                                out.add(n.id)
    return out


def _uses_tainted(node: ast.AST, tainted: set[str]) -> bool:
    if not tainted:
        return False
    seg = _seg(node)
    return any(f"Name(id='{t}'" in seg for t in tainted)


def _reaches_filesystem(node: ast.Call) -> bool:
    """Does this call touch the filesystem or launch a process with its args?"""
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr in _READERS or f.attr in _SUBPROCESS_NAMES
    if isinstance(f, ast.Name):
        return f.id in _RAW_READERS or f.id in _SUBPROCESS_NAMES
    return False


class _SanitiseLayout(ast.NodeTransformer):
    """Replace the sanctioned accessor calls with an opaque name.

    Handles BOTH import forms, because the second one is what a test actually
    writes and missing it flagged every compliant test:

      import _layout            -> _layout.resolve("revai/x.py")
      from _layout import resolve -> resolve("revai/x.py")

    Also replaces `git ls-files` style METADATA queries. Asking git which files
    the repo owns never opens a repo path -- the paths travel as arguments to
    git, not to the filesystem -- so treating one as a repo-rooted read flagged
    a test that reads nothing. Without this, a gate that cannot tell a metadata
    query from a file open fails on the sanctioned pattern.
    """

    _GIT_QUERY = re.compile(r"^\s*git\s+(?:ls-files|ls-tree|rev-parse|status)\b")

    def _is_git_query(self, call: ast.Call) -> bool:
        if not call.args:
            return False
        first = call.args[0]
        elts = first.elts if isinstance(first, ast.List) else [first]
        words = [e.value for e in elts[:2]
                 if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        if not words:
            return False
        return bool(self._GIT_QUERY.match(" ".join(words)))

    def __init__(self) -> None:
        self.aliases: set[str] = set()

    def _collect_aliases(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (
                    node.module == _LAYOUT_MODULE
                    or (node.module or "").endswith("._layout")):
                for a in node.names:
                    if a.name in ("resolve", "source"):
                        self.aliases.add(a.asname or a.name)

    def visit_Call(self, node: ast.Call) -> ast.AST:
        f = node.func
        if (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                and f.value.id == _LAYOUT_MODULE
                and f.attr in ("resolve", "source")):
            return ast.copy_location(ast.Name(id="_SANITISED_PATH_", ctx=ast.Load()),
                                     node)
        if isinstance(f, ast.Name) and f.id in self.aliases:
            return ast.copy_location(ast.Name(id="_SANITISED_PATH_", ctx=ast.Load()),
                                     node)
        if self._is_git_query(node):
            return ast.copy_location(ast.Name(id="_GIT_QUERY_", ctx=ast.Load()),
                                     node)
        return self.generic_visit(node)


def file_reads_repo_source(path) -> list[int]:
    """Line numbers in `path` that reach a code file through the repo layout."""
    from pathlib import Path

    path = Path(path)
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(src)
    except SyntaxError as exc:
        print(f"  {path.name}: PARSE ERROR {exc}")
        return [exc.lineno or 0]

    _san = _SanitiseLayout()
    _san._collect_aliases(tree)
    tree = _san.visit(tree)
    tainted = _collect_tainted(tree)
    mentions_code_dir = _has_code_dir(tree)
    if not mentions_code_dir and not tainted:
        return []

    bad: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _reaches_filesystem(node):
            continue
        seg = _seg(node)
        inline_rooted = _rooted_path_expr(node) or any(
            _rooted_path_expr(a) for a in node.args if isinstance(a, ast.AST))
        literal_code = any(f"Constant(value='{d}" in seg
                           or f'Constant(value="{d}' in seg
                           for d in _CODE_DIRS)
        if _uses_tainted(node, tainted) or inline_rooted or literal_code:
            bad.append(node.lineno)
    return sorted(set(bad))
