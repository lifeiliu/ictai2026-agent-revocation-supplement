"""E6 — Semantic stress tests for the rewritten Paper A narrative.

This experiment adds two checks that are not covered by the original E1-E5:

1. Batch non-compositionality:
   Compare the correct batch target reach(G)-reach(G\R) against the union of
   independently computed single-edge targets. The gap is an under-revocation
   that appears even when each single-edge target is exact.

2. Event-selection sensitivity:
   Measure tree-cascade OverRev under several edge selection policies, to avoid
   depending on one cherry-picked "first non-root edge" rule.
"""

from __future__ import annotations

import itertools
import json
import random
import statistics as stats
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).parents[1] / "e5_case_study"))

from run import build_k8s_rbac_dag  # noqa: E402

from revocation.dag import DelegationDAG, DelegationEdge  # noqa: E402
from revocation.granularity import target_set_l2  # noqa: E402
from revocation.revocation import apply_tree_cascade, over_revocation  # noqa: E402
from revocation.trace_gen import generate_multiparent_dag  # noqa: E402


def batch_target(dag: DelegationDAG, edge_ids: set[str]) -> set[str]:
    """T_intent(R,G) = reach(G) - reach(G\R)."""
    full = dag.reachable_from_roots()
    without = dag.reachable_from_roots(exclude_edges=frozenset(edge_ids))
    return full - without


def union_single_targets(dag: DelegationDAG, edge_ids: set[str]) -> set[str]:
    result: set[str] = set()
    for eid in edge_ids:
        result |= target_set_l2(dag, eid)
    return result


def alternate_parent_pairs(dag: DelegationDAG) -> list[set[str]]:
    """All 2-edge incoming pairs for multi-parent nodes."""
    pairs: list[set[str]] = []
    for node in dag.all_nodes():
        incoming = dag.incoming_edges(node.node_id)
        if len(incoming) < 2:
            continue
        for i in range(len(incoming)):
            for j in range(i + 1, len(incoming)):
                pairs.append({incoming[i].edge_id, incoming[j].edge_id})
    return pairs


def summarize(values: list[int]) -> tuple[float, int, int]:
    if not values:
        return 0.0, 0, 0
    return stats.mean(values), max(values), sum(1 for v in values if v > 0)


def add_extra_parents(dag: DelegationDAG, rng: random.Random, max_parents: int = 4) -> None:
    """Add earlier-ID parents while preserving the generator's topological order."""
    nodes = sorted(dag.all_nodes(), key=lambda node: int(node.node_id[1:]))
    edge_counter = len(dag.all_edges())
    for child in nodes[2:]:
        current = {edge.parent_id for edge in dag.incoming_edges(child.node_id)}
        desired = rng.randint(1, min(max_parents, int(child.node_id[1:])))
        candidates = [
            node.node_id
            for node in nodes
            if int(node.node_id[1:]) < int(child.node_id[1:]) and node.node_id not in current
        ]
        rng.shuffle(candidates)
        for parent in candidates[: max(0, desired - len(current))]:
            dag.add_edge(
                DelegationEdge(
                    edge_id=f"extra_{edge_counter}_{parent}_{child.node_id}",
                    parent_id=parent,
                    child_id=child.node_id,
                )
            )
            edge_counter += 1


def bootstrap_mean_ci(values: list[float], seed: int, repeats: int = 5000) -> list[float]:
    rng = random.Random(seed)
    means = sorted(stats.mean(rng.choices(values, k=len(values))) for _ in range(repeats))
    return [means[round(0.025 * (repeats - 1))], means[round(0.975 * (repeats - 1))]]


def run_batch_random_dags(
    n_graphs: int = 200,
    num_nodes: int = 80,
    shared_ratio: float = 0.45,
) -> dict[str, object]:
    graph_rows = []

    for seed in range(n_graphs):
        dag = generate_multiparent_dag(num_nodes, shared_ratio=shared_ratio, seed=seed)
        rng = random.Random(70000 + seed)
        add_extra_parents(dag, rng)
        candidate_sets = []
        for node in dag.all_nodes():
            incoming = dag.incoming_edges(node.node_id)
            for size in range(2, min(4, len(incoming)) + 1):
                candidate_sets.extend(
                    {edge.edge_id for edge in chosen}
                    for chosen in itertools.combinations(incoming, size)
                )
        if len(candidate_sets) > 200:
            candidate_sets = rng.sample(candidate_sets, 200)
        gaps = []
        for revoked in candidate_sets:
            batch = batch_target(dag, revoked)
            unioned = union_single_targets(dag, revoked)
            gaps.append(len(batch - unioned))
        graph_rows.append(
            {
                "seed": seed,
                "candidate_sets": len(candidate_sets),
                "failure_fraction": sum(gap > 0 for gap in gaps) / len(gaps) if gaps else 0.0,
                "mean_missed": stats.mean(gaps) if gaps else 0.0,
                "max_missed": max(gaps, default=0),
            }
        )

    failure_fractions = [row["failure_fraction"] for row in graph_rows]
    mean_missed = [row["mean_missed"] for row in graph_rows]
    return {
        "estimand": "mean per-graph fraction of sampled 2-4 edge sets for which union(single targets) misses the batch target",
        "independent_unit": "generated graph seed",
        "graphs": n_graphs,
        "sampled_sets": sum(row["candidate_sets"] for row in graph_rows),
        "mean_graph_failure_pct": 100 * stats.mean(failure_fractions),
        "mean_graph_failure_pct_ci95": [
            100 * value for value in bootstrap_mean_ci(failure_fractions, 20260622)
        ],
        "mean_graph_missed_nodes": stats.mean(mean_missed),
        "max_missed_nodes": max(row["max_missed"] for row in graph_rows),
        "per_graph": graph_rows,
    }


def run_batch_k8s() -> dict[str, object]:
    dag = build_k8s_rbac_dag()
    cases = {
        "backend-sa parents": {"e1_be1", "e2_be2"},
        "ci-bot parents": {"e1_ci1", "e3_ci2"},
        "ci-step-deploy parents": {"e7_csd", "e8_sd"},
    }
    rows = []
    for name, edge_ids in cases.items():
        batch = batch_target(dag, edge_ids)
        unioned = union_single_targets(dag, edge_ids)
        rows.append({
            "case": name,
            "batch": len(batch),
            "union": len(unioned),
            "under_gap": len(batch - unioned),
            "missed": sorted(batch - unioned),
        })
    return {"rows": rows}


def edge_depth(dag: DelegationDAG, edge: DelegationEdge) -> int:
    """Approximate depth by shortest root-to-parent edge count."""
    roots = {n.node_id for n in dag.roots()}
    if edge.parent_id in roots:
        return 0
    frontier = list(roots)
    seen = set(roots)
    depth = 0
    while frontier:
        next_frontier = []
        for nid in frontier:
            if nid == edge.parent_id:
                return depth
            for out in dag.outgoing_edges(nid):
                if out.child_id not in seen:
                    seen.add(out.child_id)
                    next_frontier.append(out.child_id)
        frontier = next_frontier
        depth += 1
    return depth


def select_edges(dag: DelegationDAG, rng: random.Random) -> dict[str, DelegationEdge | None]:
    edges = dag.all_edges()
    if not edges:
        return {}

    into_mp = [e for e in edges if dag.is_multi_parent(e.child_id)]
    root_adjacent = [e for e in edges if e.parent_id in {r.node_id for r in dag.roots()}]
    deep_edges = sorted(edges, key=lambda e: edge_depth(dag, e), reverse=True)
    large_cascade = sorted(edges, key=lambda e: len(dag.descendants_of(e.child_id)), reverse=True)

    return {
        "random": rng.choice(edges),
        "into_multi_parent": rng.choice(into_mp) if into_mp else None,
        "root_adjacent": rng.choice(root_adjacent) if root_adjacent else None,
        "deepest_parent": deep_edges[0] if deep_edges else None,
        "largest_cascade": large_cascade[0] if large_cascade else None,
    }


def run_event_selection(
    n_graphs: int = 200,
    num_nodes: int = 120,
    shared_ratio: float = 0.45,
) -> dict[str, dict[str, float]]:
    rng = random.Random(20260620)
    buckets: dict[str, list[int]] = {
        "random": [],
        "into_multi_parent": [],
        "root_adjacent": [],
        "deepest_parent": [],
        "largest_cascade": [],
    }

    for seed in range(n_graphs):
        dag = generate_multiparent_dag(num_nodes, shared_ratio=shared_ratio, seed=seed)
        choices = select_edges(dag, rng)
        for strategy, edge in choices.items():
            if edge is None:
                continue
            intended = target_set_l2(dag, edge.edge_id)
            cascade = apply_tree_cascade(dag, edge.child_id)
            buckets[strategy].append(over_revocation(cascade, intended))

    result: dict[str, dict[str, float]] = {}
    for strategy, values in buckets.items():
        mean_gap, max_gap, failing = summarize(values)
        result[strategy] = {
            "n": len(values),
            "failure_pct": 100 * failing / len(values) if values else 0.0,
            "mean_overrev": mean_gap,
            "max_overrev": max_gap,
        }
    return result


def main() -> None:
    print("\nE6a: Batch non-compositionality on random multi-parent DAGs")
    batch_random = run_batch_random_dags()
    print(
        "  graphs={graphs}, sampled_sets={sampled_sets}, "
        "mean_graph_failure={mean_graph_failure_pct:.1f}% "
        "CI={mean_graph_failure_pct_ci95}, mean_missed={mean_graph_missed_nodes:.2f}, "
        "max_missed={max_missed_nodes}".format(
            **batch_random
        )
    )

    print("\nE6b: Batch non-compositionality on RBAC-inspired DAG")
    for row in run_batch_k8s()["rows"]:
        print(
            f"  {row['case']}: batch={row['batch']}, union={row['union']}, "
            f"under_gap={row['under_gap']}, missed={row['missed']}"
        )

    print("\nE6c: Event-selection sensitivity for tree cascade")
    selection = run_event_selection()
    print(f"  {'strategy':<20} {'n':>5} {'fail%':>8} {'meanOR':>9} {'maxOR':>7}")
    for strategy, s in selection.items():
        print(
            f"  {strategy:<20} {int(s['n']):>5} {s['failure_pct']:>7.1f}% "
            f"{s['mean_overrev']:>9.2f} {int(s['max_overrev']):>7}"
        )

    output = Path(__file__).parents[2] / "results" / "e6_semantic_stress.json"
    output.write_text(
        json.dumps(
            {
                "batch_random": batch_random,
                "batch_rbac": run_batch_k8s(),
                "event_selection": selection,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nwrote {output}")


if __name__ == "__main__":
    main()
