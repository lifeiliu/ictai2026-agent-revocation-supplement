"""Replay signed framework traces against the edge-revocation contract."""

from __future__ import annotations

import os
import random
import statistics
import time
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any

from common import (
    EPOCH_ID,
    EXP_DIR,
    NORMALIZED_TRACE_PATH,
    RAW_TRACE_PATH,
    RESULTS_PATH,
    canonical_bytes,
    deterministic_keypair,
    read_jsonl,
    write_json,
)
from normalize import decision_payload

from revocation.crypto import verify
from revocation.dag import AgentNode, DelegationDAG, DelegationEdge
from revocation.envelope import create_envelope
from revocation.prototype import (
    SignedDelegationGraph,
    build_snapshot,
    build_target_proof,
    compute_batch_target,
    verify_revocation_authority,
    verify_target_proof_partial,
)
from revocation.revocation import (
    apply_tree_cascade,
    apply_tree_cascade_deployer_scoped,
    over_revocation,
    under_revocation,
)

RAW_INPUT_PATH = Path(os.getenv("E16_RAW_INPUT", RAW_TRACE_PATH))
NORMALIZED_INPUT_PATH = Path(os.getenv("E16_NORMALIZED_INPUT", NORMALIZED_TRACE_PATH))
OUTPUT_PATH = Path(os.getenv("E16_RESULTS_OUTPUT", RESULTS_PATH))
BOOTSTRAP_REPEATS = int(os.getenv("E16_BOOTSTRAP_REPEATS", "5000"))


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(EXP_DIR))
    except ValueError:
        return str(path)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def bootstrap_mean_ci(values: list[float], seed: int) -> list[float]:
    if not values:
        return [0.0, 0.0]
    rng = random.Random(seed)
    means = [
        statistics.mean(rng.choices(values, k=len(values)))
        for _ in range(BOOTSTRAP_REPEATS)
    ]
    return [percentile(means, 0.025), percentile(means, 0.975)]


def summarize(values: list[float], seed: int) -> dict[str, Any]:
    if not values:
        return {"n": 0, "mean": 0.0, "ci95_bootstrap": [0.0, 0.0]}
    return {
        "n": len(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "ci95_bootstrap": bootstrap_mean_ci(values, seed),
    }


def verify_signed_event(event: dict[str, Any]) -> bool:
    edge_id = event["edge_id"]
    payload = decision_payload(
        {
            "trace_id": event["trace_id"],
            "seq": event["seq"],
            "framework": event["framework"],
            "caller": event["caller"],
            "callee": event["callee"],
            "caller_deployer": event["parent_domain"],
            "callee_deployer": event["child_domain"],
            "permission": event["permission"],
        },
        edge_id,
    )
    key = deterministic_keypair(event["parent_domain"])
    return (
        event["issuer_key_id"] == key.key_id
        and verify(key.public, canonical_bytes(payload), event["decision_signature"])
    )


def build_dag(events: list[dict[str, Any]]) -> DelegationDAG:
    nodes: dict[str, str] = {}
    edges: dict[str, DelegationEdge] = {}
    for event in events:
        nodes.setdefault(event["caller"], event["parent_domain"])
        nodes.setdefault(event["callee"], event["child_domain"])
        permission = event["permission"]
        edge = DelegationEdge(
            edge_id=event["edge_id"],
            parent_id=event["caller"],
            child_id=event["callee"],
            resource=permission["resource"],
            action=permission["action"],
            tenant=permission["tenant"],
            constraints=tuple(sorted(permission.get("constraints", []))),
            signature=event["edge_signature"],
        )
        if event["edge_id"] in edges and edges[event["edge_id"]] != edge:
            raise ValueError(f"conflicting normalized edge {event['edge_id']}")
        edges[event["edge_id"]] = edge

    dag = DelegationDAG()
    for node_id, deployer in sorted(nodes.items()):
        dag.add_node(AgentNode(node_id=node_id, deployer_id=deployer))
    for edge in sorted(edges.values(), key=lambda item: item.edge_id):
        dag.add_edge(edge)
    if not dag.is_acyclic():
        raise ValueError("normalized trace produced a cyclic DAG")
    return dag


def shared_nodes(dag: DelegationDAG) -> tuple[list[str], list[str]]:
    multiparent = sorted(node.node_id for node in dag.all_nodes() if dag.is_multi_parent(node.node_id))
    cross_deployer = []
    for node_id in multiparent:
        parent_domains = {
            dag.node(edge.parent_id).deployer_id for edge in dag.incoming_edges(node_id)
        }
        if len(parent_domains) >= 2:
            cross_deployer.append(node_id)
    return multiparent, cross_deployer


def choose_batch(dag: DelegationDAG, multiparent: list[str]) -> set[str]:
    for node_id in multiparent:
        incoming = dag.incoming_edges(node_id)
        candidate = {edge.edge_id for edge in incoming}
        if compute_batch_target(dag, candidate):
            return candidate
    for edge in dag.all_edges():
        candidate = {edge.edge_id}
        if compute_batch_target(dag, candidate):
            return candidate
    return {dag.all_edges()[0].edge_id}


def trace_edge_metrics(dag: DelegationDAG) -> dict[str, float]:
    edges = dag.all_edges()
    tree_failures = 0
    scoped_failures = 0
    tree_over = []
    scoped_under = []
    for edge in edges:
        intended = compute_batch_target(dag, {edge.edge_id})
        tree = apply_tree_cascade(dag, edge.child_id)
        tree_value = over_revocation(tree, intended)
        tree_over.append(float(tree_value))
        tree_failures += tree_value > 0
        parent_domain = dag.node(edge.parent_id).deployer_id
        scoped = apply_tree_cascade_deployer_scoped(dag, edge.child_id, parent_domain)
        scoped_value = under_revocation(scoped, intended)
        scoped_under.append(float(scoped_value))
        scoped_failures += scoped_value > 0
    return {
        "tree_over_failure_fraction": tree_failures / len(edges),
        "scoped_under_failure_fraction": scoped_failures / len(edges),
        "tree_over_mean": statistics.mean(tree_over),
        "scoped_under_mean": statistics.mean(scoped_under),
    }


def single_edge_conformance(dag: DelegationDAG, multiparent: list[str]) -> dict[str, int]:
    semantic_survivors = 0
    tree_wrongly_revoked = 0
    for node_id in multiparent:
        incoming = dag.incoming_edges(node_id)
        edge = incoming[0]
        semantic_target = compute_batch_target(dag, {edge.edge_id})
        tree_target = apply_tree_cascade(dag, edge.child_id)
        semantic_survivors += node_id not in semantic_target
        tree_wrongly_revoked += node_id in tree_target
    return {
        "single_edge_cases": len(multiparent),
        "semantic_survivors": semantic_survivors,
        "tree_wrongly_revoked": tree_wrongly_revoked,
    }


def authorized_entries(graph: SignedDelegationGraph, edge_ids: set[str]):
    entries = []
    for edge_id in sorted(edge_ids):
        edge = graph.dag.edge(edge_id)
        domain = graph.dag.node(edge.parent_id).deployer_id
        entries.append(
            create_envelope(
                edge_id,
                "edge",
                graph.deployer_keys[domain],
                revoked_at=1.0,
                epoch_id=EPOCH_ID,
            )
        )
    return entries


def omission_attack_rejected(
    graph: SignedDelegationGraph,
    snapshot,
    federation_public_key: bytes,
    multiparent: list[str],
) -> bool | None:
    for victim in multiparent:
        incoming = graph.dag.incoming_edges(victim)
        if len(incoming) < 2:
            continue
        revoked = {incoming[0].edge_id}
        if victim in compute_batch_target(graph.dag, revoked):
            continue
        forged = deepcopy(build_target_proof(graph, revoked, snapshot))
        forged.survivor_paths.pop(victim, None)
        if victim not in forged.target:
            forged.target.append(victim)
        forged.cut_in_edges[victim] = [incoming[0]]
        forged.in_commitments[victim] = snapshot.commitments[victim]
        return not verify_target_proof_partial(
            snapshot.manifest,
            forged,
            revoked,
            federation_public_key,
            graph.public_keys(),
        )
    return None


def analyze_trace(trace_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    started = time.perf_counter_ns()
    valid_events = sum(verify_signed_event(event) for event in events)
    dag = build_dag(events)
    domains = {node.deployer_id for node in dag.all_nodes()}
    graph = SignedDelegationGraph(
        dag=dag,
        deployer_keys={domain: deterministic_keypair(domain) for domain in domains},
    )
    edge_signatures_valid = all(graph.edge_authentic(edge) for edge in dag.all_edges())
    federation_key = deterministic_keypair("federation")
    snapshot = build_snapshot(graph, federation_key, epoch_id=EPOCH_ID)
    multiparent, cross_shared = shared_nodes(dag)
    batch = choose_batch(dag, multiparent)
    target = compute_batch_target(dag, batch)
    proof = build_target_proof(graph, batch, snapshot)
    proof_ok = verify_target_proof_partial(
        snapshot.manifest,
        proof,
        batch,
        federation_key.public_bytes,
        graph.public_keys(),
    )
    authority_ok = verify_revocation_authority(
        authorized_entries(graph, batch),
        proof,
        snapshot.manifest,
        graph.public_keys(),
    )
    attacker_entry = create_envelope(
        next(iter(batch)),
        "edge",
        deterministic_keypair("unauthorized-attacker"),
        revoked_at=1.0,
        epoch_id=EPOCH_ID,
    )
    unauthorized_rejected = not verify_revocation_authority(
        [attacker_entry], proof, snapshot.manifest, graph.public_keys()
    )

    cross_authority_ok = None
    if cross_shared:
        cross_batch = {edge.edge_id for edge in dag.incoming_edges(cross_shared[0])}
        cross_proof = build_target_proof(graph, cross_batch, snapshot)
        cross_authority_ok = verify_revocation_authority(
            authorized_entries(graph, cross_batch),
            cross_proof,
            snapshot.manifest,
            graph.public_keys(),
        ) and verify_target_proof_partial(
            snapshot.manifest,
            cross_proof,
            cross_batch,
            federation_key.public_bytes,
            graph.public_keys(),
        )

    conformance = single_edge_conformance(dag, multiparent)
    edge_metrics = trace_edge_metrics(dag)
    omission_rejected = omission_attack_rejected(
        graph, snapshot, federation_key.public_bytes, multiparent
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1e6
    first = events[0]
    return {
        "trace_id": trace_id,
        "workflow": first["workflow"],
        "input_cell": first["input_cell"],
        "repeat": first["repeat"],
        "signed_events": len(events),
        "valid_signed_events": valid_events,
        "nodes": len(dag.all_nodes()),
        "edges": len(dag.all_edges()),
        "cross_deployer_edges": sum(
            dag.node(edge.parent_id).deployer_id != dag.node(edge.child_id).deployer_id
            for edge in dag.all_edges()
        ),
        "multiparent_agents": len(multiparent),
        "cross_deployer_multiparent_agents": len(cross_shared),
        "batch_size": len(batch),
        "batch_target_size": len(target),
        "edge_signatures_valid": edge_signatures_valid,
        "proof_verified": proof_ok,
        "authorized_revocation_verified": authority_ok,
        "cross_deployer_revocation_verified": cross_authority_ok,
        "unauthorized_rejected": unauthorized_rejected,
        "omission_rejected": omission_rejected,
        "proof_bytes": proof.size_bytes(snapshot.manifest),
        "replay_ms": elapsed_ms,
        **conformance,
        **edge_metrics,
    }


def workflow_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["workflow"]].append(row)
    summary = {}
    for workflow, items in sorted(grouped.items()):
        summary[workflow] = {
            "traces": len(items),
            "mean_edges": statistics.mean(item["edges"] for item in items),
            "traces_with_multiparent": sum(item["multiparent_agents"] > 0 for item in items),
            "traces_with_cross_deployer_multiparent": sum(
                item["cross_deployer_multiparent_agents"] > 0 for item in items
            ),
        }
    return summary


def cell_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["input_cell"]].append(row)
    cells = []
    for input_cell, items in sorted(grouped.items()):
        first = items[0]
        cells.append(
            {
                "input_cell": input_cell,
                "workflow": first["workflow"],
                "executions": len(items),
                "nodes": statistics.mean(item["nodes"] for item in items),
                "edges": statistics.mean(item["edges"] for item in items),
                "multiparent_agents": statistics.mean(
                    item["multiparent_agents"] for item in items
                ),
                "cross_deployer_multiparent_agents": statistics.mean(
                    item["cross_deployer_multiparent_agents"] for item in items
                ),
                "has_multiparent": any(item["multiparent_agents"] > 0 for item in items),
                "has_cross_deployer_multiparent": any(
                    item["cross_deployer_multiparent_agents"] > 0 for item in items
                ),
                "tree_over_failure_fraction": statistics.mean(
                    item["tree_over_failure_fraction"] for item in items
                ),
                "scoped_under_failure_fraction": statistics.mean(
                    item["scoped_under_failure_fraction"] for item in items
                ),
                "all_proofs_verified": all(item["proof_verified"] for item in items),
                "all_unauthorized_rejected": all(
                    item["unauthorized_rejected"] for item in items
                ),
            }
        )
    return cells


def main() -> None:
    raw_rows = read_jsonl(RAW_INPUT_PATH)
    normalized_rows = read_jsonl(NORMALIZED_INPUT_PATH)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in normalized_rows:
        grouped[row["trace_id"]].append(row)
    per_trace = [
        analyze_trace(trace_id, events)
        for trace_id, events in sorted(grouped.items())
    ]

    raw_counts = Counter(row["kind"] for row in raw_rows)
    omission_applicable = [
        row for row in per_trace if row["omission_rejected"] is not None
    ]
    cross_applicable = [
        row for row in per_trace if row["cross_deployer_revocation_verified"] is not None
    ]
    per_cell = cell_rows(per_trace)
    results = {
        "experiment": "E16 framework trace replay",
        "epoch_id": EPOCH_ID,
        "design": {
            "framework": "LangGraph",
            "independent_unit": "one complete compiled-framework execution trace",
            "topology_cluster_unit": "one workflow/input cell",
            "bootstrap_resamples": BOOTSTRAP_REPEATS,
            "raw_trace_path": display_path(RAW_INPUT_PATH),
            "normalized_trace_path": display_path(NORMALIZED_INPUT_PATH),
        },
        "collection": {
            "raw_events": len(raw_rows),
            "raw_event_kinds": dict(raw_counts),
            "trace_units": len(grouped),
            "framework_trace_units": len(
                {row["trace_id"] for row in raw_rows if row.get("kind") == "framework"}
            ),
        },
        "normalization": {
            "signed_delegation_events": len(normalized_rows),
            "valid_signed_delegation_events": sum(
                row["valid_signed_events"] for row in per_trace
            ),
        },
        "outcomes": {
            "traces": len(per_trace),
            "traces_with_multiparent": sum(row["multiparent_agents"] > 0 for row in per_trace),
            "traces_with_cross_deployer_multiparent": sum(
                row["cross_deployer_multiparent_agents"] > 0 for row in per_trace
            ),
            "nodes": summarize([float(row["nodes"]) for row in per_trace], 101),
            "edges": summarize([float(row["edges"]) for row in per_trace], 102),
            "multiparent_agents": summarize(
                [float(row["multiparent_agents"]) for row in per_trace], 103
            ),
            "cross_deployer_multiparent_agents": summarize(
                [float(row["cross_deployer_multiparent_agents"]) for row in per_trace],
                104,
            ),
            "tree_over_failure_fraction": summarize(
                [row["tree_over_failure_fraction"] for row in per_trace], 105
            ),
            "scoped_under_failure_fraction": summarize(
                [row["scoped_under_failure_fraction"] for row in per_trace], 106
            ),
            "proof_verified": {
                "passed": sum(row["proof_verified"] for row in per_trace),
                "total": len(per_trace),
            },
            "authorized_revocation_verified": {
                "passed": sum(row["authorized_revocation_verified"] for row in per_trace),
                "total": len(per_trace),
            },
            "cross_deployer_revocation_verified": {
                "passed": sum(
                    row["cross_deployer_revocation_verified"] for row in cross_applicable
                ),
                "total": len(cross_applicable),
            },
            "unauthorized_rejected": {
                "passed": sum(row["unauthorized_rejected"] for row in per_trace),
                "total": len(per_trace),
            },
            "omission_rejected": {
                "passed": sum(row["omission_rejected"] for row in omission_applicable),
                "total": len(omission_applicable),
            },
            "single_edge_conformance": {
                "cases": sum(row["single_edge_cases"] for row in per_trace),
                "semantic_survivors": sum(row["semantic_survivors"] for row in per_trace),
                "tree_wrongly_revoked": sum(row["tree_wrongly_revoked"] for row in per_trace),
            },
            "proof_bytes": summarize([float(row["proof_bytes"]) for row in per_trace], 107),
            "replay_ms": summarize([float(row["replay_ms"]) for row in per_trace], 108),
        },
        "cell_outcomes": {
            "cells": len(per_cell),
            "cells_with_multiparent": sum(row["has_multiparent"] for row in per_cell),
            "cells_with_cross_deployer_multiparent": sum(
                row["has_cross_deployer_multiparent"] for row in per_cell
            ),
            "nodes": summarize([float(row["nodes"]) for row in per_cell], 201),
            "edges": summarize([float(row["edges"]) for row in per_cell], 202),
            "multiparent_agents": summarize(
                [float(row["multiparent_agents"]) for row in per_cell], 203
            ),
            "cross_deployer_multiparent_agents": summarize(
                [float(row["cross_deployer_multiparent_agents"]) for row in per_cell],
                204,
            ),
            "tree_over_failure_fraction": summarize(
                [row["tree_over_failure_fraction"] for row in per_cell], 205
            ),
            "scoped_under_failure_fraction": summarize(
                [row["scoped_under_failure_fraction"] for row in per_cell], 206
            ),
            "proofs_verified_in_all_executions": sum(
                row["all_proofs_verified"] for row in per_cell
            ),
            "unauthorized_rejected_in_all_executions": sum(
                row["all_unauthorized_rejected"] for row in per_cell
            ),
        },
        "workflow_summary": workflow_summary(per_trace),
        "per_cell": per_cell,
        "per_trace": per_trace,
    }
    write_json(OUTPUT_PATH, results)
    print(
        "E16 replay: "
        f"traces={len(per_trace)} "
        f"mp={results['outcomes']['traces_with_multiparent']} "
        f"cross_mp={results['outcomes']['traces_with_cross_deployer_multiparent']} "
        f"proofs={results['outcomes']['proof_verified']['passed']}/"
        f"{results['outcomes']['proof_verified']['total']} "
        f"unauthorized_rejected={results['outcomes']['unauthorized_rejected']['passed']}/"
        f"{results['outcomes']['unauthorized_rejected']['total']} "
        f"output={OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()
