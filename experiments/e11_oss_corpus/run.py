"""E11 - Multi-parent structure & failure modes across a corpus of REAL OSS apps.

Loads delegation graphs statically extracted from real third-party LangGraph
applications (corpus_graphs.json, produced by harvest.py from GitHub repos
discovered via the repository-search API) and reports, across the corpus:

  - how many apps / graphs, and how prevalent multi-parent structure is;
  - tree-cascade over-revocation vs the disjunctive semantic target;
  - batch non-compositionality on real alternate-parent pairs.

This is the in-the-wild grounding: not patterns we wrote, but delegation graphs
mined from real agent applications. Static extraction recovers only
string-literal edges, so connectivity (and multi-parent prevalence) is a lower
bound.
"""

from __future__ import annotations

import json
import random
import statistics as stats
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

from revocation.dag import AgentNode, DelegationDAG, DelegationEdge  # noqa: E402
from revocation.granularity import target_set_l2  # noqa: E402
from revocation.prototype import compute_batch_target  # noqa: E402
from revocation.revocation import apply_tree_cascade, over_revocation  # noqa: E402

CORPUS = Path(__file__).parent / "corpus_graphs.json"


def bootstrap_repo_mean(values: list[float], seed: int, repeats: int = 5000) -> list[float]:
    rng = random.Random(seed)
    means = sorted(stats.mean(rng.choices(values, k=len(values))) for _ in range(repeats))
    return [means[round(0.025 * (repeats - 1))], means[round(0.975 * (repeats - 1))]]


def build(g: dict) -> DelegationDAG:
    dag = DelegationDAG()
    for n in g["nodes"]:
        dag.add_node(AgentNode(node_id=n, deployer_id=g["repo"]))
    eid = 0
    seen = set()
    for p, c in g["edges"]:
        if p not in g["nodes"] or c not in g["nodes"]:
            continue
        if (p, c) in seen or p == c:
            continue
        seen.add((p, c))
        dag.add_edge(DelegationEdge(edge_id=f"e{eid}", parent_id=p, child_id=c))
        eid += 1
    return dag


def main() -> None:
    corpus = json.loads(CORPUS.read_text())
    apps = {g["repo"] for g in corpus}

    total_nodes = total_edges = total_mp = 0
    graphs_with_mp = 0
    over_vals: list[int] = []
    batch_gaps: list[int] = []
    per_graph_mp_pct: list[float] = []
    repo_over: dict[str, list[int]] = defaultdict(list)
    repo_batch: dict[str, list[int]] = defaultdict(list)
    repo_graph_mp: dict[str, list[int]] = defaultdict(list)

    for g in corpus:
        dag = build(g)
        nodes = dag.all_nodes()
        edges = dag.all_edges()
        if not nodes:
            continue
        mp = [n for n in nodes if dag.is_multi_parent(n.node_id)]
        total_nodes += len(nodes)
        total_edges += len(edges)
        total_mp += len(mp)
        per_graph_mp_pct.append(100 * len(mp) / len(nodes))
        if mp:
            graphs_with_mp += 1
        repo_graph_mp[g["repo"]].append(int(bool(mp)))
        for e in edges:
            intended = target_set_l2(dag, e.edge_id)
            over = over_revocation(apply_tree_cascade(dag, e.child_id), intended)
            over_vals.append(over)
            repo_over[g["repo"]].append(over)
        for n in mp:
            inc = dag.incoming_edges(n.node_id)
            for i in range(len(inc)):
                for j in range(i + 1, len(inc)):
                    pair = {inc[i].edge_id, inc[j].edge_id}
                    batch = compute_batch_target(dag, pair)
                    union = (target_set_l2(dag, inc[i].edge_id)
                             | target_set_l2(dag, inc[j].edge_id))
                    gap = len(batch - union)
                    batch_gaps.append(gap)
                    repo_batch[g["repo"]].append(gap)

    n_over = len(over_vals)
    over_fail = sum(1 for v in over_vals if v > 0)
    batch_fail = sum(1 for v in batch_gaps if v > 0)
    repo_mp_rates = [100 * stats.mean(values) for values in repo_graph_mp.values()]
    repo_over_rates = [
        100 * sum(value > 0 for value in values) / len(values)
        for values in repo_over.values()
    ]
    repo_batch_rates = [
        100 * sum(value > 0 for value in values) / len(values)
        for values in repo_batch.values()
        if values
    ]

    print("=" * 70)
    print("E11: Multi-parent structure & failure modes across real OSS agent apps")
    print("=" * 70)
    print(f"  apps={len(apps)}  graphs={len(corpus)}  "
          f"nodes={total_nodes}  edges={total_edges}")
    print(f"  graphs with >=1 multi-parent node: {graphs_with_mp}/{len(corpus)} "
          f"({100*graphs_with_mp/len(corpus):.1f}%)")
    print(f"  aggregate multi-parent nodes: {total_mp}/{total_nodes} "
          f"({100*total_mp/total_nodes:.1f}%)")
    print(f"  tree-cascade OVER-revocation over {n_over} edges: "
          f"fail={100*over_fail/n_over:.1f}%  "
          f"mean={stats.mean(over_vals):.2f}  max={max(over_vals)}")
    if batch_gaps:
        print(f"  batch non-compositionality over {len(batch_gaps)} real pairs: "
              f"fail={100*batch_fail/len(batch_gaps):.1f}%  max={max(batch_gaps)}")

    out = {
        "apps": len(apps), "graphs": len(corpus),
        "nodes": total_nodes, "edges": total_edges,
        "graphs_with_mp": graphs_with_mp,
        "graphs_with_mp_pct": 100*graphs_with_mp/len(corpus),
        "aggregate_mp_pct": 100*total_mp/total_nodes,
        "tree_over_fail_pct": 100*over_fail/n_over,
        "tree_over_mean": stats.mean(over_vals), "tree_over_max": max(over_vals),
        "batch_pairs": len(batch_gaps),
        "batch_fail_pct": 100*batch_fail/len(batch_gaps) if batch_gaps else 0.0,
        "batch_max": max(batch_gaps) if batch_gaps else 0,
        "repository_clustered": {
            "independent_unit": "GitHub repository",
            "repositories": len(apps),
            "mean_repo_graphs_with_multiparent_pct": stats.mean(repo_mp_rates),
            "mean_repo_graphs_with_multiparent_pct_ci95": bootstrap_repo_mean(
                repo_mp_rates, 1101
            ),
            "mean_repo_tree_failure_pct": stats.mean(repo_over_rates),
            "mean_repo_tree_failure_pct_ci95": bootstrap_repo_mean(repo_over_rates, 1102),
            "repositories_with_batch_candidates": len(repo_batch_rates),
            "mean_repo_batch_failure_pct": stats.mean(repo_batch_rates),
            "mean_repo_batch_failure_pct_ci95": bootstrap_repo_mean(repo_batch_rates, 1103),
        },
    }
    (Path(__file__).parent / "e11_results.json").write_text(json.dumps(out, indent=2))
    print("\n[OK] E11 complete; wrote e11_results.json")


if __name__ == "__main__":
    main()
