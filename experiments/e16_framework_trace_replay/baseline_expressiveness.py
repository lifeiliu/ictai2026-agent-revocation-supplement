"""Derive E16 baseline-expressiveness results from normalized framework traces.

This is a target-language experiment, not a new trace collection pass. It asks
which adjacent revocation families can express the E16 event "revoke edge e while
preserving an agent that still has an alternate runtime parent."
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from common import EXP_DIR, NORMALIZED_TRACE_PATH, read_jsonl, write_json
from replay import build_dag, display_path, shared_nodes

from revocation.dag import DelegationDAG, DelegationEdge
from revocation.prototype import compute_batch_target
from revocation.revocation import (
    apply_credential_path_revalidation,
    apply_tree_cascade,
    apply_tree_cascade_deployer_scoped,
    over_revocation,
    under_revocation,
)

OUTPUT_JSON = EXP_DIR / "e16_baseline_expressiveness.json"
OUTPUT_CSV = EXP_DIR / "e16_baseline_expressiveness.csv"
OUTPUT_TEX = EXP_DIR / "e16_baseline_expressiveness_table.tex"


def pct(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else numerator / denominator


def pct_string(numerator: int, denominator: int) -> str:
    return f"{100 * pct(numerator, denominator):.1f}\\%"


def sorted_incoming(dag: DelegationDAG, node_id: str) -> list[DelegationEdge]:
    return sorted(dag.incoming_edges(node_id), key=lambda edge: edge.edge_id)


def selected_alternate_parent_cases(dag: DelegationDAG) -> list[tuple[str, DelegationEdge]]:
    """Match E16's single-edge conformance design: one withdrawal per MP node."""

    cases = []
    multiparent, _ = shared_nodes(dag)
    for node_id in multiparent:
        edge = sorted_incoming(dag, node_id)[0]
        target = compute_batch_target(dag, {edge.edge_id})
        if node_id not in target:
            cases.append((node_id, edge))
    return cases


def baseline_targets(dag: DelegationDAG, edge: DelegationEdge) -> dict[str, set[str]]:
    parent_domain = dag.node(edge.parent_id).deployer_id
    return {
        "edge_contract": compute_batch_target(dag, {edge.edge_id}),
        "complete_graph_revalidation": apply_credential_path_revalidation(
            dag, {edge.edge_id}
        ),
        "holder_node_revocation": {edge.child_id},
        "aps_tree_cascade": apply_tree_cascade(dag, edge.child_id),
        "deployer_scoped_cascade": apply_tree_cascade_deployer_scoped(
            dag, edge.child_id, parent_domain
        ),
    }


def empty_stats() -> dict[str, int]:
    return {
        "cases": 0,
        "exact_matches": 0,
        "over_total": 0,
        "under_total": 0,
        "cases_with_over": 0,
        "cases_with_under": 0,
    }


def update_stats(stats: dict[str, int], observed: set[str], intended: set[str]) -> None:
    over = over_revocation(observed, intended)
    under = under_revocation(observed, intended)
    stats["cases"] += 1
    stats["exact_matches"] += int(observed == intended)
    stats["over_total"] += over
    stats["under_total"] += under
    stats["cases_with_over"] += int(over > 0)
    stats["cases_with_under"] += int(under > 0)


def finalize_stats(stats: dict[str, int]) -> dict[str, Any]:
    cases = stats["cases"]
    return {
        **stats,
        "exact_rate": pct(stats["exact_matches"], cases),
        "over_case_rate": pct(stats["cases_with_over"], cases),
        "under_case_rate": pct(stats["cases_with_under"], cases),
    }


def analyze() -> dict[str, Any]:
    rows = read_jsonl(NORMALIZED_TRACE_PATH)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["trace_id"]].append(row)

    all_edge_stats = defaultdict(empty_stats)
    alternate_stats = defaultdict(empty_stats)
    alternate_preserve = defaultdict(lambda: {"cases": 0, "preserved": 0})
    cross_domain_under = {"cases": 0, "scoped_under_cases": 0}

    per_trace = []
    for trace_id, events in sorted(grouped.items()):
        dag = build_dag(events)
        edge_count = 0
        for edge in sorted(dag.all_edges(), key=lambda item: item.edge_id):
            edge_count += 1
            targets = baseline_targets(dag, edge)
            intended = targets["edge_contract"]
            for baseline, observed in targets.items():
                update_stats(all_edge_stats[baseline], observed, intended)

            parent_domain = dag.node(edge.parent_id).deployer_id
            if any(dag.node(node_id).deployer_id != parent_domain for node_id in intended):
                cross_domain_under["cases"] += 1
                scoped = targets["deployer_scoped_cascade"]
                cross_domain_under["scoped_under_cases"] += int(
                    under_revocation(scoped, intended) > 0
                )

        ap_cases = selected_alternate_parent_cases(dag)
        for node_id, edge in ap_cases:
            targets = baseline_targets(dag, edge)
            intended = targets["edge_contract"]
            for baseline, observed in targets.items():
                update_stats(alternate_stats[baseline], observed, intended)
                alternate_preserve[baseline]["cases"] += 1
                alternate_preserve[baseline]["preserved"] += int(node_id not in observed)

        multiparent, cross_shared = shared_nodes(dag)
        per_trace.append(
            {
                "trace_id": trace_id,
                "workflow": events[0]["workflow"],
                "input_cell": events[0]["input_cell"],
                "edges": edge_count,
                "multiparent_agents": len(multiparent),
                "cross_deployer_multiparent_agents": len(cross_shared),
                "alternate_parent_cases": len(ap_cases),
            }
        )

    baseline_metadata = {
        "edge_contract": {
            "label": "Signed edge target (this paper)",
            "target_unit": "edge target set",
            "target_language": "reach(G)-reach(G\\R)",
            "requires_complete_graph_at_verifier": False,
            "verifier_independent": True,
            "modeled": True,
        },
        "complete_graph_revalidation": {
            "label": "Credential revocation + full graph revalidation",
            "target_unit": "revoked edge credential",
            "target_language": "complete reachability recomputation",
            "requires_complete_graph_at_verifier": True,
            "verifier_independent": False,
            "modeled": True,
        },
        "holder_node_revocation": {
            "label": "Holder/node credential revocation",
            "target_unit": "agent identity or holder token",
            "target_language": "one node",
            "requires_complete_graph_at_verifier": False,
            "verifier_independent": True,
            "modeled": True,
        },
        "aps_tree_cascade": {
            "label": "APS-style tree cascade",
            "target_unit": "subtree",
            "target_language": "child plus descendants",
            "requires_complete_graph_at_verifier": False,
            "verifier_independent": True,
            "modeled": True,
        },
        "deployer_scoped_cascade": {
            "label": "Deployer-scoped cascade",
            "target_unit": "local registry subtree",
            "target_language": "same-deployer child plus descendants",
            "requires_complete_graph_at_verifier": False,
            "verifier_independent": True,
            "modeled": True,
        },
        "token_protocols_no_target_set": {
            "label": "CRL/OCSP/OAuth/MCP/AIP token or chain revocation",
            "target_unit": "credential, token, or delegation chain",
            "target_language": "no multi-parent DAG target set",
            "requires_complete_graph_at_verifier": None,
            "verifier_independent": None,
            "modeled": False,
            "note": (
                "These mechanisms can invalidate a credential/token/chain, but do not "
                "define a verifier-checkable set of all agents that lose authority in "
                "a multi-parent runtime DAG."
            ),
        },
    }

    modeled = {}
    for baseline in baseline_metadata:
        if not baseline_metadata[baseline]["modeled"]:
            continue
        ap = alternate_preserve[baseline]
        modeled[baseline] = {
            "metadata": baseline_metadata[baseline],
            "all_edge_revocations": finalize_stats(all_edge_stats[baseline]),
            "alternate_parent_cases": {
                **finalize_stats(alternate_stats[baseline]),
                "preserved_shared_agent": ap["preserved"],
                "preserve_rate": pct(ap["preserved"], ap["cases"]),
            },
        }

    return {
        "experiment": "E16 baseline expressiveness",
        "input": display_path(NORMALIZED_TRACE_PATH),
        "trace_units": len(grouped),
        "signed_delegation_events": len(rows),
        "all_edge_revocation_cases": sum(item["edges"] for item in per_trace),
        "alternate_parent_cases": sum(item["alternate_parent_cases"] for item in per_trace),
        "traces_with_alternate_parent_case": sum(
            item["alternate_parent_cases"] > 0 for item in per_trace
        ),
        "cross_domain_target_cases": cross_domain_under,
        "baselines": modeled,
        "unmodeled_target_language_gaps": {
            "token_protocols_no_target_set": baseline_metadata["token_protocols_no_target_set"]
        },
        "per_trace": per_trace,
    }


def write_csv(path: Path, results: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "baseline",
                "label",
                "target_unit",
                "all_edge_cases",
                "all_edge_exact_matches",
                "all_edge_exact_rate",
                "alternate_parent_cases",
                "alternate_parent_preserved",
                "alternate_parent_preserve_rate",
                "alternate_parent_exact_matches",
                "alternate_parent_exact_rate",
                "over_case_rate",
                "under_case_rate",
            ]
        )
        for baseline, row in results["baselines"].items():
            all_edges = row["all_edge_revocations"]
            alternate = row["alternate_parent_cases"]
            writer.writerow(
                [
                    baseline,
                    row["metadata"]["label"],
                    row["metadata"]["target_unit"],
                    all_edges["cases"],
                    all_edges["exact_matches"],
                    f"{all_edges['exact_rate']:.6f}",
                    alternate["cases"],
                    alternate["preserved_shared_agent"],
                    f"{alternate['preserve_rate']:.6f}",
                    alternate["exact_matches"],
                    f"{alternate['exact_rate']:.6f}",
                    f"{all_edges['over_case_rate']:.6f}",
                    f"{all_edges['under_case_rate']:.6f}",
                ]
            )


def write_tex_table(path: Path, results: dict[str, Any]) -> None:
    rows = results["baselines"]
    order = [
        "edge_contract",
        "complete_graph_revalidation",
        "holder_node_revocation",
        "aps_tree_cascade",
        "deployer_scoped_cascade",
    ]
    labels = {
        "edge_contract": "Edge contract",
        "complete_graph_revalidation": "Full-graph reval.",
        "holder_node_revocation": "Node/token",
        "aps_tree_cascade": "Tree/APS",
        "deployer_scoped_cascade": "Deployer-scoped",
    }
    lines = [
        "% Auto-generated by experiments/e16_framework_trace_replay/baseline_expressiveness.py",
        "\\begin{tabular}{lccc}",
        "\\toprule",
        "Baseline & Target unit & AP preserved & All-edge exact \\\\",
        "\\midrule",
    ]
    for key in order:
        row = rows[key]
        all_edges = row["all_edge_revocations"]
        alternate = row["alternate_parent_cases"]
        lines.append(
            f"{labels[key]} & {row['metadata']['target_unit']} & "
            f"{alternate['preserved_shared_agent']}/{alternate['cases']} & "
            f"{pct_string(all_edges['exact_matches'], all_edges['cases'])} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    path.write_text("\n".join(lines))


def main() -> None:
    results = analyze()
    write_json(OUTPUT_JSON, results)
    write_csv(OUTPUT_CSV, results)
    write_tex_table(OUTPUT_TEX, results)
    edge = results["baselines"]["edge_contract"]["alternate_parent_cases"]
    tree = results["baselines"]["aps_tree_cascade"]["alternate_parent_cases"]
    scoped = results["baselines"]["deployer_scoped_cascade"]["all_edge_revocations"]
    print(
        "E16 baseline expressiveness: "
        f"alternate_parent={results['alternate_parent_cases']} "
        f"edge_preserved={edge['preserved_shared_agent']}/{edge['cases']} "
        f"tree_preserved={tree['preserved_shared_agent']}/{tree['cases']} "
        f"scoped_exact={scoped['exact_matches']}/{scoped['cases']} "
        f"output={OUTPUT_JSON}"
    )


if __name__ == "__main__":
    main()
