"""Adversarial checks for epoch-bound partial target proofs."""

from revocation.crypto import generate_keypair
from revocation.dag import AgentNode, DelegationDAG, DelegationEdge, Permission
from revocation.envelope import create_envelope
from revocation.prototype import (
    RevocationLog,
    SignedDelegationGraph,
    build_snapshot,
    build_target_proof,
    compute_batch_target,
    verify_checkpoint,
    verify_revocation_authority,
    verify_snapshot_extension,
    verify_target_proof_partial,
)
from revocation.trace_gen import generate_adversarial_shared_subdag, generate_cross_deployer_dag


def _snapshot(graph: SignedDelegationGraph, epoch: str = "epoch-1", **kwargs):
    federation_key = generate_keypair()
    material = build_snapshot(graph, federation_key, epoch_id=epoch, **kwargs)
    return federation_key, material


def _cross_proof():
    graph = SignedDelegationGraph.from_dag(generate_cross_deployer_dag())
    federation_key, snapshot = _snapshot(graph)
    revoked = {"e_A_C"}
    proof = build_target_proof(graph, revoked, snapshot)
    return graph, federation_key, snapshot, revoked, proof


def _verify(graph, federation_key, snapshot, revoked, proof, permission=None):
    return verify_target_proof_partial(
        snapshot.manifest,
        proof,
        revoked,
        federation_key.public_bytes,
        graph.public_keys(),
        permission,
    )


def test_honest_partial_target_proof_verifies_without_graph_argument():
    graph, federation_key, snapshot, revoked, proof = _cross_proof()
    assert _verify(graph, federation_key, snapshot, revoked, proof)


def test_target_member_requires_cut_and_commitment():
    graph, federation_key, snapshot, revoked, proof = _cross_proof()
    proof.cut_in_edges.pop(proof.target[0])
    assert not _verify(graph, federation_key, snapshot, revoked, proof)


def test_proof_cannot_omit_disconnected_roster_node():
    graph, federation_key, snapshot, revoked, proof = _cross_proof()
    omitted = proof.target.pop()
    proof.cut_in_edges.pop(omitted)
    proof.in_commitments.pop(omitted)
    assert not _verify(graph, federation_key, snapshot, revoked, proof)


def test_empty_survivor_path_is_valid_only_for_root():
    graph = SignedDelegationGraph.from_dag(generate_adversarial_shared_subdag())
    federation_key, snapshot = _snapshot(graph)
    revoked = {"e_A_C"}
    proof = build_target_proof(graph, revoked, snapshot)
    proof.survivor_paths["C"] = []
    assert not _verify(graph, federation_key, snapshot, revoked, proof)


def test_domain_manifest_omission_is_rejected():
    graph, federation_key, snapshot, revoked, proof = _cross_proof()
    proof.domain_manifests.pop(next(iter(proof.domain_manifests)))
    assert not _verify(graph, federation_key, snapshot, revoked, proof)


def test_edge_merkle_tampering_is_rejected():
    graph, federation_key, snapshot, revoked, proof = _cross_proof()
    edge_id = next(iter(proof.edge_positions))
    proof.edge_positions[edge_id] = (proof.edge_positions[edge_id] + 1) % snapshot.manifest.edge_count
    assert not _verify(graph, federation_key, snapshot, revoked, proof)


def test_old_commitment_replay_fails_in_new_epoch():
    graph = SignedDelegationGraph.from_dag(generate_cross_deployer_dag())
    federation_key = generate_keypair()
    old = build_snapshot(graph, federation_key, epoch_id="epoch-1")
    new = build_snapshot(
        graph,
        federation_key,
        epoch_id="epoch-2",
        previous_manifest_hash=old.manifest.digest(),
        commitment_version=2,
    )
    assert verify_snapshot_extension(old.manifest, new.manifest, federation_key.public_bytes)
    revoked = {"e_A_C"}
    proof = build_target_proof(graph, revoked, new)
    victim = proof.target[0]
    proof.in_commitments[victim] = old.commitments[victim]
    assert not _verify(graph, federation_key, new, revoked, proof)


def test_count_preserving_log_substitution_is_rejected():
    graph = SignedDelegationGraph.from_dag(generate_adversarial_shared_subdag())
    checkpoint_key = generate_keypair()
    log = RevocationLog(checkpoint_key, "epoch-1")
    log.revoke_edge("e_A_C", graph, revoked_at=1.0)
    first = log.checkpoint()
    log.revoke_edge("e_B_C", graph, revoked_at=2.0)
    second = log.checkpoint()
    assert verify_checkpoint(log.entries(), second, checkpoint_key.public_bytes, previous=first)

    replacement = create_envelope(
        "e_C_D",
        "edge",
        graph.deployer_keys[graph.dag.node("C").deployer_id],
        revoked_at=2.0,
        epoch_id="epoch-1",
    )
    substituted = [log.entries()[0], replacement]
    assert not verify_checkpoint(substituted, second, checkpoint_key.public_bytes, previous=first)


def test_unauthorized_revocation_signer_is_rejected():
    graph, federation_key, snapshot, revoked, proof = _cross_proof()
    log = RevocationLog(generate_keypair(), "epoch-1")
    legitimate = log.revoke_edge("e_A_C", graph, revoked_at=1.0)
    assert verify_revocation_authority(
        [legitimate], proof, snapshot.manifest, graph.public_keys()
    )
    forged = create_envelope(
        "e_A_C", "edge", generate_keypair(), revoked_at=1.0, epoch_id="epoch-1"
    )
    assert not verify_revocation_authority(
        [forged], proof, snapshot.manifest, graph.public_keys()
    )


def test_scoped_target_differs_from_unlabeled_reachability():
    dag = DelegationDAG()
    for node, domain in [("root", "d0"), ("A", "d1"), ("B", "d2"), ("C", "d3")]:
        dag.add_node(AgentNode(node, domain))
    dag.add_edge(DelegationEdge("r-a", "root", "A"))
    dag.add_edge(DelegationEdge("r-b", "root", "B"))
    dag.add_edge(DelegationEdge("a-c", "A", "C", resource="records", action="read"))
    dag.add_edge(DelegationEdge("b-c", "B", "C", resource="records", action="write"))
    read = Permission("records", "read", "*")
    assert compute_batch_target(dag, {"a-c"}) == set()
    assert compute_batch_target(dag, {"a-c"}, read) == {"C"}

    graph = SignedDelegationGraph.from_dag(dag)
    federation_key, snapshot = _snapshot(graph, permissions=[read])
    proof = build_target_proof(graph, {"a-c"}, snapshot, read)
    assert _verify(graph, federation_key, snapshot, {"a-c"}, proof, read)


def test_wire_size_contains_full_signed_survivor_edges():
    graph = SignedDelegationGraph.from_dag(generate_adversarial_shared_subdag())
    federation_key, snapshot = _snapshot(graph)
    proof = build_target_proof(graph, {"e_A_C"}, snapshot)
    wire = proof.wire_bytes(snapshot.manifest)
    survivor_edge = next(edge for path in proof.survivor_paths.values() for edge in path)
    assert survivor_edge.signature.encode() in wire
    assert survivor_edge.parent_id.encode() in wire
    assert survivor_edge.child_id.encode() in wire
