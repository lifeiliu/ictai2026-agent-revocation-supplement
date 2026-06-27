"""E8: protocol feasibility, nested benchmarks, and adversarial mutations."""

from __future__ import annotations

import json
import os
import platform
import random
import statistics
import sys
import time
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

import cryptography

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "src"))

from revocation.crypto import generate_keypair  # noqa: E402
from revocation.envelope import create_envelope  # noqa: E402
from revocation.granularity import target_set_l2  # noqa: E402
from revocation.prototype import (  # noqa: E402
    RevocationLog,
    SignedDelegationGraph,
    build_snapshot,
    build_target_proof,
    compute_batch_target,
    verify_checkpoint,
    verify_revocation_authority,
    verify_target_proof_partial,
)
from revocation.trace_gen import generate_multiparent_dag  # noqa: E402

GRAPH_SEEDS = int(os.getenv("E8_GRAPH_SEEDS", "30"))
TIMED_REPEATS = int(os.getenv("E8_TIMED_REPEATS", "10"))
WARMUPS = int(os.getenv("E8_WARMUPS", "3"))
PROOF_BUILD_REPEATS = int(os.getenv("E8_PROOF_BUILD_REPEATS", "1"))
ATTACK_SEEDS = int(os.getenv("E8_ATTACK_SEEDS", "100"))
BOOTSTRAP_REPEATS = int(os.getenv("E8_BOOTSTRAP_REPEATS", "5000"))
OUTPUT_PATH = Path(os.getenv("E8_OUTPUT", "results/e8_protocol_results.json"))


def timed_samples(
    fn: Callable[[], Any], *, repeats: int = TIMED_REPEATS, warmups: int = WARMUPS
) -> list[float]:
    for _ in range(warmups):
        fn()
    samples = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - start) / 1e6)
    return samples


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def bootstrap_median_ci(values: list[float], seed: int) -> list[float]:
    rng = random.Random(seed)
    medians = [
        statistics.median(rng.choices(values, k=len(values)))
        for _ in range(BOOTSTRAP_REPEATS)
    ]
    return [percentile(medians, 0.025), percentile(medians, 0.975)]


def summarize(values: list[float], seed: int) -> dict[str, Any]:
    return {
        "n_graphs": len(values),
        "median": statistics.median(values),
        "iqr": [percentile(values, 0.25), percentile(values, 0.75)],
        "p95": percentile(values, 0.95),
        "median_ci95_graph_bootstrap": bootstrap_median_ci(values, seed),
    }


def disconnecting_batch(dag) -> set[str]:
    for node in dag.all_nodes():
        incoming = dag.incoming_edges(node.node_id)
        if len(incoming) >= 2:
            candidate = {edge.edge_id for edge in incoming}
            if compute_batch_target(dag, candidate):
                return candidate
    for edge in dag.all_edges():
        if target_set_l2(dag, edge.edge_id):
            return {edge.edge_id}
    raise ValueError("graph has no disconnecting batch")


def full_bundle_bytes(graph, snapshot) -> int:
    blob = {
        "manifest": snapshot.manifest.wire(),
        "domain_manifests": {
            domain: manifest.wire()
            for domain, manifest in snapshot.domain_manifests.items()
        },
        "commitments": {
            node: commitment.wire()
            for node, commitment in snapshot.commitments.items()
        },
        "edges": [
            {
                "edge_id": edge.edge_id,
                "parent_id": edge.parent_id,
                "child_id": edge.child_id,
                "scope": edge.scope,
                "resource": edge.resource,
                "action": edge.action,
                "tenant": edge.tenant,
                "constraints": sorted(edge.constraints),
                "signature": edge.signature,
            }
            for edge in graph.dag.all_edges()
        ],
    }
    return len(json.dumps(blob, sort_keys=True, separators=(",", ":")).encode())


def verify_full_view(graph: SignedDelegationGraph, revoked: set[str], expected: set[str]) -> bool:
    graph.clear_sig_cache()
    if not all(graph.edge_authentic(edge) for edge in graph.dag.all_edges()):
        return False
    return compute_batch_target(graph.dag, revoked) == expected


def scaling() -> list[dict[str, Any]]:
    print("\n[M1] Nested graph-seed benchmark")
    rows = []
    for size_index, n in enumerate([200, 500, 1000, 2000]):
        per_graph = []
        for seed in range(GRAPH_SEEDS):
            dag = generate_multiparent_dag(n, shared_ratio=0.45, seed=seed)
            graph = SignedDelegationGraph.from_dag(dag)
            federation_key = generate_keypair()
            snapshot = build_snapshot(graph, federation_key, epoch_id="e1")
            revoked = disconnecting_batch(dag)
            expected = compute_batch_target(dag, revoked)
            proof = build_target_proof(graph, revoked, snapshot)
            verify_args = (
                snapshot.manifest,
                proof,
                revoked,
                federation_key.public_bytes,
                graph.public_keys(),
            )
            assert verify_target_proof_partial(*verify_args)
            assert verify_full_view(graph, revoked, expected)

            target_samples = timed_samples(
                lambda dag=dag, revoked=revoked: compute_batch_target(dag, revoked)
            )
            proof_samples = timed_samples(
                lambda graph=graph, revoked=revoked, snapshot=snapshot: build_target_proof(
                    graph, revoked, snapshot
                ),
                repeats=PROOF_BUILD_REPEATS,
                warmups=0,
            )
            partial_samples = timed_samples(
                lambda verify_args=verify_args: verify_target_proof_partial(*verify_args)
            )
            full_samples = timed_samples(
                lambda graph=graph, revoked=revoked, expected=expected: verify_full_view(
                    graph, revoked, expected
                )
            )
            proof_bytes = proof.size_bytes(snapshot.manifest)
            complete_bytes = full_bundle_bytes(graph, snapshot)
            per_graph.append(
                {
                    "seed": seed,
                    "edges": len(dag.all_edges()),
                    "target_median_ms": statistics.median(target_samples),
                    "proof_build_median_ms": statistics.median(proof_samples),
                    "partial_verify_median_ms": statistics.median(partial_samples),
                    "full_view_median_ms": statistics.median(full_samples),
                    "proof_bytes": proof_bytes,
                    "full_bundle_bytes": complete_bytes,
                    "wire_ratio": proof_bytes / complete_bytes,
                }
            )

        row = {
            "nodes": n,
            "graph_seeds": GRAPH_SEEDS,
            "timed_repeats_per_graph": TIMED_REPEATS,
            "warmups_per_graph": WARMUPS,
            "proof_build_repeats_per_graph": PROOF_BUILD_REPEATS,
            "edges": summarize([float(item["edges"]) for item in per_graph], 100 + size_index),
            "target_ms": summarize(
                [item["target_median_ms"] for item in per_graph], 200 + size_index
            ),
            "proof_build_ms": summarize(
                [item["proof_build_median_ms"] for item in per_graph], 300 + size_index
            ),
            "partial_verify_ms": summarize(
                [item["partial_verify_median_ms"] for item in per_graph], 400 + size_index
            ),
            "full_view_ms": summarize(
                [item["full_view_median_ms"] for item in per_graph], 500 + size_index
            ),
            "wire_ratio": summarize(
                [item["wire_ratio"] for item in per_graph], 600 + size_index
            ),
            "per_graph": per_graph,
        }
        rows.append(row)
        print(
            f"  n={n:4d} graphs={GRAPH_SEEDS} "
            f"target={row['target_ms']['median']:.3f}ms "
            f"build={row['proof_build_ms']['median']:.1f}ms "
            f"partial={row['partial_verify_ms']['median']:.1f}ms "
            f"full={row['full_view_ms']['median']:.1f}ms "
            f"wire={row['wire_ratio']['median']:.3f}"
        )
    return rows


def batch_correctness() -> dict[str, int]:
    dag = generate_multiparent_dag(200, shared_ratio=0.45, seed=3)
    mismatches = 0
    total = 0
    for node in dag.all_nodes():
        incoming = dag.incoming_edges(node.node_id)
        for i, first in enumerate(incoming):
            for second in incoming[i + 1 :]:
                pair = {first.edge_id, second.edge_id}
                batch = compute_batch_target(dag, pair)
                union = target_set_l2(dag, first.edge_id) | target_set_l2(dag, second.edge_id)
                total += 1
                mismatches += batch != union
    print(f"\n[M2] batch-vs-union mismatches (expected non-compositionality): {mismatches}/{total}")
    return {"pairs": total, "mismatches": mismatches}


def _verify(graph, key, snapshot, revoked, proof) -> bool:
    return verify_target_proof_partial(
        snapshot.manifest,
        proof,
        revoked,
        key.public_bytes,
        graph.public_keys(),
    )


def adversarial_matrix() -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}

    def record(name: str, rejected: bool) -> None:
        row = counts.setdefault(name, {"generated": 0, "rejected": 0})
        row["generated"] += 1
        row["rejected"] += int(rejected)

    for seed in range(ATTACK_SEEDS):
        dag = generate_multiparent_dag(120, shared_ratio=0.45, seed=seed)
        graph = SignedDelegationGraph.from_dag(dag)
        federation_key = generate_keypair()
        old = build_snapshot(graph, federation_key, epoch_id="e1")
        victim = next(
            node.node_id for node in dag.all_nodes() if len(dag.incoming_edges(node.node_id)) >= 2
        )
        incoming = dag.incoming_edges(victim)

        one_revoked = {incoming[0].edge_id}
        survivor_proof = build_target_proof(graph, one_revoked, old)
        forged = deepcopy(survivor_proof)
        forged.survivor_paths.pop(victim)
        record("omit_roster_principal", not _verify(graph, federation_key, old, one_revoked, forged))

        forged = deepcopy(survivor_proof)
        forged.domain_manifests.pop(next(iter(forged.domain_manifests)))
        record("omit_domain_manifest", not _verify(graph, federation_key, old, one_revoked, forged))

        forged = deepcopy(survivor_proof)
        edge_id = next(iter(forged.edge_positions))
        forged.edge_positions[edge_id] = (forged.edge_positions[edge_id] + 1) % old.manifest.edge_count
        record("alter_merkle_position", not _verify(graph, federation_key, old, one_revoked, forged))

        target_revoked = {edge.edge_id for edge in incoming}
        target_proof = build_target_proof(graph, target_revoked, old)
        forged = deepcopy(target_proof)
        forged.cut_in_edges[victim] = forged.cut_in_edges[victim][1:]
        record("omit_target_in_edge", not _verify(graph, federation_key, old, target_revoked, forged))

        new = build_snapshot(
            graph,
            federation_key,
            epoch_id="e2",
            previous_manifest_hash=old.manifest.digest(),
            commitment_version=2,
        )
        new_proof = build_target_proof(graph, target_revoked, new)
        forged = deepcopy(new_proof)
        forged.in_commitments[victim] = old.commitments[victim]
        record("replay_stale_commitment", not _verify(graph, federation_key, new, target_revoked, forged))

        forged = deepcopy(new_proof)
        domain = next(iter(forged.domain_manifests))
        forged.domain_manifests[domain] = old.domain_manifests[domain]
        record("mix_epoch_domain_manifest", not _verify(graph, federation_key, new, target_revoked, forged))

        forged = deepcopy(target_proof)
        forged.revoked_edges[0] = replace(forged.revoked_edges[0], resource="tampered")
        record("alter_signed_edge_scope", not _verify(graph, federation_key, old, target_revoked, forged))

        authorized_proof = build_target_proof(graph, one_revoked, old)
        unauthorized = create_envelope(
            incoming[0].edge_id,
            "edge",
            generate_keypair(),
            revoked_at=1.0,
            epoch_id="e1",
        )
        record(
            "unauthorized_revocation_signer",
            not verify_revocation_authority(
                [unauthorized], authorized_proof, old.manifest, graph.public_keys()
            ),
        )

        checkpoint_key = generate_keypair()
        log = RevocationLog(checkpoint_key, "e1")
        edges = dag.all_edges()[:3]
        log.revoke_edge(edges[0].edge_id, graph, revoked_at=1.0)
        first = log.checkpoint()
        log.revoke_edge(edges[1].edge_id, graph, revoked_at=2.0)
        second = log.checkpoint()
        entries = log.entries()
        replacement_domain = dag.node(edges[2].parent_id).deployer_id
        replacement = create_envelope(
            edges[2].edge_id,
            "edge",
            graph.deployer_keys[replacement_domain],
            revoked_at=2.0,
            epoch_id="e1",
        )
        record(
            "same_count_log_substitution",
            not verify_checkpoint([entries[0], replacement], second, checkpoint_key.public_bytes, previous=first),
        )
        record(
            "log_reordering",
            not verify_checkpoint(list(reversed(entries)), second, checkpoint_key.public_bytes, previous=first),
        )
        record(
            "log_truncation",
            not verify_checkpoint(entries[:1], second, checkpoint_key.public_bytes, previous=first),
        )

    unexpected = {
        name: row["generated"] - row["rejected"]
        for name, row in counts.items()
        if row["generated"] != row["rejected"]
    }
    if unexpected:
        raise AssertionError(f"unexpected accepted mutations: {unexpected}")
    total = sum(row["generated"] for row in counts.values())
    print(f"\n[M3] adversarial matrix: rejected {total}/{total} generated mutations")
    return counts


def main() -> None:
    results = {
        "protocol": "epoch-domain-manifest-v1",
        "benchmark_environment": {
            "platform": platform.platform(),
            "processor": platform.processor() or platform.machine(),
            "python": platform.python_version(),
            "cryptography": cryptography.__version__,
            "graph_seeds": GRAPH_SEEDS,
            "timed_repeats_per_graph": TIMED_REPEATS,
            "warmups_per_graph": WARMUPS,
            "proof_build_repeats_per_graph": PROOF_BUILD_REPEATS,
            "bootstrap_repeats": BOOTSTRAP_REPEATS,
        },
        "scaling": scaling(),
        "batch": batch_correctness(),
        "attack_matrix": adversarial_matrix(),
    }
    output = OUTPUT_PATH if OUTPUT_PATH.is_absolute() else ROOT / OUTPUT_PATH
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n")
    print(f"\n[OK] wrote {output}")


if __name__ == "__main__":
    main()
