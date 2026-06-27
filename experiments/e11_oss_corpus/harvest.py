"""E11 harvester: extract delegation DAGs from REAL third-party LangGraph apps.

We shallow-clone a curated set of real, open-source multi-agent applications that
use LangGraph, then statically extract each application's delegation graph by
parsing the framework's graph-construction calls (``add_node``, ``add_edge``,
``add_conditional_edges``) with the Python AST. Both ``.py`` files and Jupyter
notebooks (``.ipynb`` code cells) are scanned.

This is a corpus of agent applications "in the wild" -- not patterns we wrote.
Static extraction only recovers edges with string-literal endpoints (the common
case); dynamically-built edges are missed, so reported graphs are a lower bound
on each app's connectivity. We keep each file's graph that has >= MIN_NODES nodes
and >= 1 edge.

Output: corpus_graphs.json -> list of {repo, file, nodes:[...], edges:[[p,c],...]}.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

OUT = Path(__file__).parent / "corpus_graphs.json"
MANIFEST = Path(__file__).parent / "sampling_manifest.json"
REPOLIST = Path(__file__).parent / "repos.json"   # cached discovered repo list
CLONE_ROOT = Path("/tmp/e11_corpus")
MIN_NODES = 3
MAX_REPOS = 40

# Seed apps known to use LangGraph (always included), plus repos discovered via
# the GitHub repository-search API (sorted by stars) so the corpus is "in the
# wild" rather than hand-picked.
SEED_REPOS = [
    "https://github.com/assafelovic/gpt-researcher",
    "https://github.com/langchain-ai/open_deep_research",
]

SEARCH_QUERIES = [
    "langgraph multi agent",
    "langgraph StateGraph agent",
    "langgraph supervisor agents",
]

SENTINELS = {"START", "END", "__start__", "__end__"}
EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "build",
    "dist",
    "example",
    "examples",
    "notebook",
    "notebooks",
    "test",
    "tests",
    "tutorial",
    "tutorials",
}


def discover_repos() -> list[str]:
    """Use GitHub repo search (unauthenticated) to find real LangGraph apps."""
    if REPOLIST.exists():
        return json.loads(REPOLIST.read_text())
    found: dict[str, None] = {}
    for q in SEARCH_QUERIES:
        qstr = urllib.parse.quote(q + " language:python")
        url = (f"https://api.github.com/search/repositories?q={qstr}"
               "&sort=stars&order=desc&per_page=30")
        try:
            out = subprocess.run(["curl", "-sL", "--max-time", "25",
                                  "-H", "Accept: application/vnd.github+json", url],
                                 capture_output=True, check=True)
            data = json.loads(out.stdout.decode())
            for item in data.get("items", []):
                found[item["clone_url"]] = None
        except Exception as exc:  # noqa: BLE001
            print(f"  search failed ({q}): {exc}", file=sys.stderr)
    repos = SEED_REPOS + [r for r in found if r not in SEED_REPOS]
    repos = repos[:MAX_REPOS]
    REPOLIST.write_text(json.dumps(repos, indent=2))
    return repos


def _str(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    # bare name like END / START
    if isinstance(node, ast.Name) and node.id in SENTINELS:
        return node.id
    if isinstance(node, ast.Attribute) and node.attr in SENTINELS:
        return node.attr
    return None


def extract_from_source(src: str) -> tuple[set[str], list[tuple[str, str]]]:
    """Return (nodes, edges) extracted from one source string."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return set(), []
    nodes: set[str] = set()
    edges: list[tuple[str, str]] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call) or not isinstance(n.func, ast.Attribute):
            continue
        meth = n.func.attr
        args = n.args
        if meth == "add_node" and args:
            s = _str(args[0])
            if s:
                nodes.add(s)
        elif meth == "add_edge" and len(args) >= 2:
            a, b = _str(args[0]), _str(args[1])
            if a and b:
                edges.append((a, b))
        elif meth == "add_conditional_edges" and args:
            src_n = _str(args[0])
            if not src_n:
                continue
            # targets appear as dict values (mapping), list path_map, keyword
            # path_map=, or bare constant strings.
            targets: set[str] = set()

            def _collect(a, targets=targets) -> None:
                if isinstance(a, ast.Dict):
                    for v in a.values:
                        t = _str(v)
                        if t:
                            targets.add(t)
                elif isinstance(a, (ast.List, ast.Tuple, ast.Set)):
                    for el in a.elts:
                        t = _str(el)
                        if t:
                            targets.add(t)
                else:
                    t = _str(a)
                    if t:
                        targets.add(t)

            for a in args[1:]:
                _collect(a)
            for kw in n.keywords:
                if kw.arg in ("path_map", "then", None):
                    _collect(kw.value)
            for t in targets:
                edges.append((src_n, t))
    return nodes, edges


def iter_sources(repo_dir: Path):
    for p in repo_dir.rglob("*.py"):
        if any(part.lower() in EXCLUDED_PARTS for part in p.relative_to(repo_dir).parts):
            continue
        try:
            yield p, p.read_text(errors="replace")
        except Exception:  # noqa: BLE001
            continue
    for p in repo_dir.rglob("*.ipynb"):
        if any(part.lower() in EXCLUDED_PARTS for part in p.relative_to(repo_dir).parts):
            continue
        try:
            nb = json.loads(p.read_text(errors="replace"))
        except Exception:  # noqa: BLE001
            continue
        for i, cell in enumerate(nb.get("cells", [])):
            if cell.get("cell_type") == "code":
                src = "".join(cell.get("source", []))
                yield p.with_suffix(f".ipynb#cell{i}"), src


def clone(url: str) -> Path | None:
    name = url.rstrip("/").split("/")[-1]
    dest = CLONE_ROOT / name
    if dest.exists():
        return dest
    CLONE_ROOT.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
                       capture_output=True)
    if r.returncode != 0:
        print(f"  clone failed {url}: {r.stderr.decode()[:120]}", file=sys.stderr)
        return None
    return dest


def main() -> None:
    repos = discover_repos()
    print(f"  discovered {len(repos)} candidate repos", file=sys.stderr)
    graphs = []
    repo_audit = []
    for url in repos:
        repo = url.rstrip("/").split("/")[-1]
        d = clone(url)
        if d is None:
            repo_audit.append({"url": url, "status": "clone_failed"})
            continue
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=d, text=True, capture_output=True
        ).stdout.strip()
        kept = 0
        for path, src in iter_sources(d):
            if "add_edge" not in src and "add_conditional_edges" not in src:
                continue
            nodes, edges = extract_from_source(src)
            # include edge endpoints as nodes; drop sentinels
            for a, b in edges:
                nodes.add(a)
                nodes.add(b)
            nodes -= SENTINELS
            edges = [(a, b) for a, b in edges
                     if a not in SENTINELS and b not in SENTINELS and a != b]
            # dedup edges
            edges = sorted(set(edges))
            if len(nodes) >= MIN_NODES and edges:
                graphs.append({
                    "repo": repo,
                    "file": str(path.relative_to(d)),
                    "nodes": sorted(nodes),
                    "edges": [list(e) for e in edges],
                })
                kept += 1
        print(f"  {repo}: {kept} delegation graphs extracted", file=sys.stderr)
        repo_audit.append(
            {"url": url, "repo": repo, "commit": commit, "graphs_kept": kept}
        )

    OUT.write_text(json.dumps(graphs, indent=2))
    MANIFEST.write_text(
        json.dumps(
            {
                "retrieved_at_utc": datetime.now(UTC).isoformat(),
                "search_queries": [q + " language:python" for q in SEARCH_QUERIES],
                "search_order": "stars descending, first 30 results per query",
                "candidate_cap": MAX_REPOS,
                "minimum_nodes": MIN_NODES,
                "excluded_path_parts": sorted(EXCLUDED_PARTS),
                "extractable_calls": ["add_node", "add_edge", "add_conditional_edges"],
                "dynamic_endpoint_policy": "excluded; reported topology is a lower bound",
                "repositories": repo_audit,
            },
            indent=2,
        )
        + "\n"
    )
    n_repos = len({g["repo"] for g in graphs})
    print(f"wrote {OUT}: {len(graphs)} graphs from {n_repos} real OSS apps")
    print(f"wrote {MANIFEST}")


if __name__ == "__main__":
    main()
