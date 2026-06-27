"""Offline-verifiable scoped edge revocation for federated delegation DAGs.

The protocol binds each epoch to signed per-domain rosters, current in-edge
commitments, an edge Merkle root, and a history-linked federation manifest.
Target proofs are checked without access to the undisclosed graph.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyPair, generate_keypair, sha256_hex, sign, verify
from .dag import DelegationDAG, DelegationEdge, Permission
from .envelope import RevocationEnvelope, create_envelope, verify_envelope


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _public_key(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def _key_id(raw: bytes) -> str:
    return sha256_hex(raw)[:16]


def _edge_wire(edge: DelegationEdge) -> dict[str, Any]:
    return {
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


def _edge_leaf(edge: DelegationEdge) -> str:
    return sha256_hex(b"edge:" + _json_bytes(_edge_wire(edge)))


def _merkle_parent(left: str, right: str) -> str:
    return sha256_hex(b"node:" + bytes.fromhex(left) + bytes.fromhex(right))


def _merkle_tree(
    edges: list[DelegationEdge],
) -> tuple[str, dict[str, list[tuple[str, bool]]], dict[str, int]]:
    ordered = sorted(edges, key=lambda edge: edge.edge_id)
    if not ordered:
        return sha256_hex(b"empty-edge-set"), {}, {}
    ids = [edge.edge_id for edge in ordered]
    level = [_edge_leaf(edge) for edge in ordered]
    proofs: dict[str, list[tuple[str, bool]]] = {edge_id: [] for edge_id in ids}
    positions = {edge_id: index for index, edge_id in enumerate(ids)}
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        for edge_id, index in positions.items():
            sibling = index - 1 if index % 2 else index + 1
            proofs[edge_id].append((level[sibling], sibling < index))
            positions[edge_id] = index // 2
        level = [_merkle_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0], proofs, {edge_id: index for index, edge_id in enumerate(ids)}


def _verify_merkle(edge: DelegationEdge, proof: list[tuple[str, bool]], root: str) -> bool:
    value = _edge_leaf(edge)
    for sibling, sibling_is_left in proof:
        value = _merkle_parent(sibling, value) if sibling_is_left else _merkle_parent(value, sibling)
    return value == root


@dataclass
class InEdgeCommitment:
    epoch_id: str
    version: int
    node_id: str
    in_edge_ids: list[str]
    issuer_key_id: str
    signature: str

    def signable_bytes(self) -> bytes:
        return _json_bytes(
            {
                "epoch_id": self.epoch_id,
                "version": self.version,
                "node_id": self.node_id,
                "in_edge_ids": sorted(self.in_edge_ids),
                "issuer_key_id": self.issuer_key_id,
            }
        )

    def digest(self) -> str:
        return sha256_hex(self.signable_bytes() + bytes.fromhex(self.signature))

    def wire(self) -> dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "version": self.version,
            "node_id": self.node_id,
            "in_edge_ids": sorted(self.in_edge_ids),
            "issuer_key_id": self.issuer_key_id,
            "signature": self.signature,
        }


@dataclass
class DomainManifest:
    epoch_id: str
    domain_id: str
    node_commitments: dict[str, str]
    issuer_key_id: str
    signature: str

    def signable_bytes(self) -> bytes:
        return _json_bytes(
            {
                "epoch_id": self.epoch_id,
                "domain_id": self.domain_id,
                "node_commitments": self.node_commitments,
                "issuer_key_id": self.issuer_key_id,
            }
        )

    def digest(self) -> str:
        return sha256_hex(self.signable_bytes() + bytes.fromhex(self.signature))

    def wire(self) -> dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "domain_id": self.domain_id,
            "node_commitments": self.node_commitments,
            "issuer_key_id": self.issuer_key_id,
            "signature": self.signature,
        }


@dataclass
class SnapshotManifest:
    epoch_id: str
    previous_manifest_hash: str
    roots: list[str]
    domain_manifest_digests: dict[str, str]
    authorization_rosters: dict[str, list[str]]
    edge_root: str
    edge_count: int
    issuer_key_id: str
    signature: str

    def signable_bytes(self) -> bytes:
        return _json_bytes(
            {
                "epoch_id": self.epoch_id,
                "previous_manifest_hash": self.previous_manifest_hash,
                "roots": sorted(self.roots),
                "domain_manifest_digests": self.domain_manifest_digests,
                "authorization_rosters": self.authorization_rosters,
                "edge_root": self.edge_root,
                "edge_count": self.edge_count,
                "issuer_key_id": self.issuer_key_id,
            }
        )

    def digest(self) -> str:
        return sha256_hex(self.signable_bytes() + bytes.fromhex(self.signature))

    def wire(self) -> dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "previous_manifest_hash": self.previous_manifest_hash,
            "roots": sorted(self.roots),
            "domain_manifest_digests": self.domain_manifest_digests,
            "authorization_rosters": self.authorization_rosters,
            "edge_root": self.edge_root,
            "edge_count": self.edge_count,
            "issuer_key_id": self.issuer_key_id,
            "signature": self.signature,
        }


@dataclass
class SnapshotMaterial:
    manifest: SnapshotManifest
    domain_manifests: dict[str, DomainManifest]
    commitments: dict[str, InEdgeCommitment]
    edge_proofs: dict[str, list[tuple[str, bool]]]
    edge_positions: dict[str, int]


@dataclass
class SignedDelegationGraph:
    dag: DelegationDAG
    deployer_keys: dict[str, KeyPair] = field(default_factory=dict)
    _sig_cache: set[tuple[str, str]] = field(default_factory=set)

    def clear_sig_cache(self) -> None:
        self._sig_cache.clear()

    @classmethod
    def from_dag(cls, dag: DelegationDAG) -> SignedDelegationGraph:
        graph = cls(dag=dag)
        for domain in {node.deployer_id for node in dag.all_nodes()}:
            graph.deployer_keys[domain] = generate_keypair()
        for edge in list(dag.all_edges()):
            parent = dag.node(edge.parent_id)
            key = graph.deployer_keys[parent.deployer_id]
            unsigned = DelegationEdge(
                edge_id=edge.edge_id,
                parent_id=edge.parent_id,
                child_id=edge.child_id,
                scope=edge.scope,
                resource=edge.resource,
                action=edge.action,
                tenant=edge.tenant,
                constraints=edge.constraints,
            )
            dag._edges[edge.edge_id] = DelegationEdge(  # noqa: SLF001
                **{**unsigned.__dict__, "signature": sign(key.private, unsigned.canonical_bytes())}
            )
        return graph

    def public_keys(self) -> dict[str, bytes]:
        return {domain: key.public_bytes for domain, key in self.deployer_keys.items()}

    def edge_authentic(self, edge: DelegationEdge) -> bool:
        cache_key = (edge.edge_id, edge.signature)
        if cache_key in self._sig_cache:
            return True
        try:
            domain = self.dag.node(edge.parent_id).deployer_id
        except KeyError:
            return False
        key = self.deployer_keys.get(domain)
        ok = key is not None and verify(key.public, edge.canonical_bytes(), edge.signature)
        if ok:
            self._sig_cache.add(cache_key)
        return ok

    def in_edge_commitment(
        self, node_id: str, *, epoch_id: str = "epoch-0", version: int = 1
    ) -> InEdgeCommitment:
        node = self.dag.node(node_id)
        key = self.deployer_keys[node.deployer_id]
        commitment = InEdgeCommitment(
            epoch_id=epoch_id,
            version=version,
            node_id=node_id,
            in_edge_ids=sorted(edge.edge_id for edge in self.dag.incoming_edges(node_id)),
            issuer_key_id=key.key_id,
            signature="",
        )
        commitment.signature = sign(key.private, commitment.signable_bytes())
        return commitment


def _permission_key(permission: Permission | None) -> str:
    if permission is None:
        return "__all__"
    constraints = ",".join(sorted(permission.constraints))
    return f"{permission.tenant}|{permission.resource}|{permission.action}|{constraints}"


def build_snapshot(
    graph: SignedDelegationGraph,
    federation_key: KeyPair,
    *,
    epoch_id: str,
    previous_manifest_hash: str = "",
    permissions: list[Permission] | None = None,
    commitment_version: int = 1,
) -> SnapshotMaterial:
    commitments = {
        node.node_id: graph.in_edge_commitment(
            node.node_id, epoch_id=epoch_id, version=commitment_version
        )
        for node in graph.dag.all_nodes()
    }
    domain_manifests: dict[str, DomainManifest] = {}
    for domain, key in graph.deployer_keys.items():
        node_commitments = {
            node.node_id: commitments[node.node_id].digest()
            for node in graph.dag.all_nodes()
            if node.deployer_id == domain
        }
        domain_manifest = DomainManifest(
            epoch_id=epoch_id,
            domain_id=domain,
            node_commitments=node_commitments,
            issuer_key_id=key.key_id,
            signature="",
        )
        domain_manifest.signature = sign(key.private, domain_manifest.signable_bytes())
        domain_manifests[domain] = domain_manifest

    edge_root, edge_proofs, edge_positions = _merkle_tree(graph.dag.all_edges())
    rosters = {"__all__": sorted(graph.dag.reachable_from_roots())}
    for permission in permissions or []:
        rosters[_permission_key(permission)] = sorted(
            graph.dag.reachable_from_roots(permission=permission)
        )
    manifest = SnapshotManifest(
        epoch_id=epoch_id,
        previous_manifest_hash=previous_manifest_hash,
        roots=sorted(root.node_id for root in graph.dag.roots()),
        domain_manifest_digests={
            domain: domain_manifest.digest()
            for domain, domain_manifest in domain_manifests.items()
        },
        authorization_rosters=rosters,
        edge_root=edge_root,
        edge_count=len(graph.dag.all_edges()),
        issuer_key_id=federation_key.key_id,
        signature="",
    )
    manifest.signature = sign(federation_key.private, manifest.signable_bytes())
    return SnapshotMaterial(
        manifest, domain_manifests, commitments, edge_proofs, edge_positions
    )


def verify_snapshot_extension(
    previous: SnapshotManifest,
    current: SnapshotManifest,
    federation_public_key: bytes,
) -> bool:
    """Verify epoch chaining and the federation signature on a newer manifest."""
    if current.previous_manifest_hash != previous.digest():
        return False
    if current.issuer_key_id != _key_id(federation_public_key):
        return False
    return verify(
        _public_key(federation_public_key), current.signable_bytes(), current.signature
    )


@dataclass
class SignedCheckpoint:
    epoch_id: str
    count: int
    history_hash: str
    previous_checkpoint_hash: str
    issuer_key_id: str
    signature: str

    def signable_bytes(self) -> bytes:
        return _json_bytes(
            {
                "epoch_id": self.epoch_id,
                "count": self.count,
                "history_hash": self.history_hash,
                "previous_checkpoint_hash": self.previous_checkpoint_hash,
                "issuer_key_id": self.issuer_key_id,
            }
        )

    def digest(self) -> str:
        return sha256_hex(self.signable_bytes() + bytes.fromhex(self.signature))


def _envelope_wire(envelope: RevocationEnvelope) -> dict[str, Any]:
    return {
        "target_id": envelope.target_id,
        "target_type": envelope.target_type,
        "revoked_at": envelope.revoked_at,
        "epoch_id": envelope.epoch_id,
        "issuer_key_id": envelope.issuer_key_id,
        "signature": envelope.signature,
    }


def _history_hash(entries: list[RevocationEnvelope], count: int | None = None) -> str:
    value = sha256_hex(b"revocation-log-v1")
    for envelope in entries[:count]:
        value = sha256_hex(bytes.fromhex(value) + _json_bytes(_envelope_wire(envelope)))
    return value


class RevocationLog:
    def __init__(self, checkpoint_key: KeyPair, epoch_id: str = "epoch-0") -> None:
        self._key = checkpoint_key
        self.epoch_id = epoch_id
        self._entries: list[RevocationEnvelope] = []
        self._last_checkpoint_hash = ""

    def revoke_edge(
        self,
        edge_id: str,
        graph: SignedDelegationGraph | None = None,
        *,
        revoked_at: float | None = None,
    ) -> RevocationEnvelope:
        signer = self._key
        if graph is not None:
            edge = graph.dag.edge(edge_id)
            domain = graph.dag.node(edge.parent_id).deployer_id
            signer = graph.deployer_keys[domain]
        envelope = create_envelope(
            edge_id,
            "edge",
            signer,
            revoked_at=revoked_at,
            epoch_id=self.epoch_id,
        )
        self._entries.append(envelope)
        return envelope

    def entries(self) -> list[RevocationEnvelope]:
        return list(self._entries)

    def revoked_edge_ids(self) -> set[str]:
        return {entry.target_id for entry in self._entries}

    def checkpoint(self) -> SignedCheckpoint:
        checkpoint = SignedCheckpoint(
            epoch_id=self.epoch_id,
            count=len(self._entries),
            history_hash=_history_hash(self._entries),
            previous_checkpoint_hash=self._last_checkpoint_hash,
            issuer_key_id=self._key.key_id,
            signature="",
        )
        checkpoint.signature = sign(self._key.private, checkpoint.signable_bytes())
        self._last_checkpoint_hash = checkpoint.digest()
        return checkpoint


def verify_checkpoint(
    entries: list[RevocationEnvelope],
    checkpoint: SignedCheckpoint,
    checkpoint_public_key: bytes,
    *,
    previous: SignedCheckpoint | None = None,
) -> bool:
    if checkpoint.issuer_key_id != _key_id(checkpoint_public_key):
        return False
    if not verify(_public_key(checkpoint_public_key), checkpoint.signable_bytes(), checkpoint.signature):
        return False
    if checkpoint.count != len(entries) or checkpoint.history_hash != _history_hash(entries):
        return False
    if previous is None:
        return checkpoint.previous_checkpoint_hash == ""
    if checkpoint.epoch_id != previous.epoch_id or checkpoint.count < previous.count:
        return False
    if checkpoint.previous_checkpoint_hash != previous.digest():
        return False
    return previous.history_hash == _history_hash(entries, previous.count)


@dataclass
class TargetProof:
    target: list[str]
    survivor_paths: dict[str, list[DelegationEdge]]
    cut_in_edges: dict[str, list[DelegationEdge]]
    in_commitments: dict[str, InEdgeCommitment]
    domain_manifests: dict[str, DomainManifest] = field(default_factory=dict)
    edge_positions: dict[str, int] = field(default_factory=dict)
    merkle_siblings: dict[str, str] = field(default_factory=dict)
    revoked_edges: list[DelegationEdge] = field(default_factory=list)

    def disclosed_edges(self) -> dict[str, DelegationEdge]:
        edges: dict[str, DelegationEdge] = {}
        for path in self.survivor_paths.values():
            edges.update((edge.edge_id, edge) for edge in path)
        for cut in self.cut_in_edges.values():
            edges.update((edge.edge_id, edge) for edge in cut)
        edges.update((edge.edge_id, edge) for edge in self.revoked_edges)
        return edges

    def wire_bytes(self, manifest: SnapshotManifest) -> bytes:
        edges = self.disclosed_edges()
        blob = {
            "manifest": manifest.wire(),
            "domain_manifests": {
                domain: domain_manifest.wire()
                for domain, domain_manifest in self.domain_manifests.items()
            },
            "target": sorted(self.target),
            "survivor_paths": {
                node: [edge.edge_id for edge in path]
                for node, path in self.survivor_paths.items()
            },
            "cut_in_edges": {
                node: [edge.edge_id for edge in cut]
                for node, cut in self.cut_in_edges.items()
            },
            "commitments": {
                node: commitment.wire()
                for node, commitment in self.in_commitments.items()
            },
            "edges": {edge_id: _edge_wire(edge) for edge_id, edge in edges.items()},
            "edge_positions": self.edge_positions,
            "merkle_siblings": self.merkle_siblings,
            "revoked_edges": sorted(edge.edge_id for edge in self.revoked_edges),
        }
        return _json_bytes(blob)

    def size_bytes(self, manifest: SnapshotManifest | None = None) -> int:
        if manifest is None:
            return len(_json_bytes({"edges": [_edge_wire(e) for e in self.disclosed_edges().values()]}))
        return len(self.wire_bytes(manifest))


def compute_batch_target(
    dag: DelegationDAG,
    revoked: set[str],
    permission: Permission | None = None,
) -> set[str]:
    full = dag.reachable_from_roots(permission=permission)
    surviving = dag.reachable_from_roots(
        exclude_edges=frozenset(revoked), permission=permission
    )
    return full - surviving


def build_target_proof(
    graph: SignedDelegationGraph,
    revoked: set[str],
    snapshot: SnapshotMaterial,
    permission: Permission | None = None,
) -> TargetProof:
    dag = graph.dag
    full = dag.reachable_from_roots(permission=permission)
    surviving = dag.reachable_from_roots(
        exclude_edges=frozenset(revoked), permission=permission
    )
    target = full - surviving
    roots = {root.node_id for root in dag.roots()}
    survivor_paths = {
        node: [] if node in roots else _one_rfree_path(dag, node, revoked, roots, permission)
        for node in surviving
    }
    if any(path is None for path in survivor_paths.values()):
        raise ValueError("failed to construct survivor path")
    cut_in_edges = {node: dag.incoming_edges(node) for node in target}
    revoked_edges = [dag.edge(edge_id) for edge_id in revoked]
    disclosed_ids = {
        edge.edge_id
        for path in survivor_paths.values()
        for edge in path or []
    }
    disclosed_ids |= {
        edge.edge_id for cut in cut_in_edges.values() for edge in cut
    }
    disclosed_ids |= revoked
    positions = {edge_id: snapshot.edge_positions[edge_id] for edge_id in disclosed_ids}
    siblings: dict[str, str] = {}
    active = set(disclosed_ids)
    for edge_id in disclosed_ids:
        index = snapshot.edge_positions[edge_id]
        width = snapshot.manifest.edge_count
        for level, (sibling_hash, sibling_is_left) in enumerate(snapshot.edge_proofs[edge_id]):
            sibling_index = index - 1 if sibling_is_left else index + 1
            if sibling_index < width and not any(
                snapshot.edge_positions[other] >> level == sibling_index for other in active
            ):
                siblings[f"{level}:{sibling_index}"] = sibling_hash
            index //= 2
            width = (width + 1) // 2
    return TargetProof(
        target=sorted(target),
        survivor_paths={node: path or [] for node, path in survivor_paths.items()},
        cut_in_edges=cut_in_edges,
        in_commitments={node: snapshot.commitments[node] for node in target},
        domain_manifests=snapshot.domain_manifests,
        edge_positions=positions,
        merkle_siblings=siblings,
        revoked_edges=revoked_edges,
    )


def _one_rfree_path(
    dag: DelegationDAG,
    target_id: str,
    revoked: set[str],
    roots: set[str],
    permission: Permission | None,
) -> list[DelegationEdge] | None:
    parent_edge: dict[str, DelegationEdge] = {}
    seen = set(roots)
    frontier = list(roots)
    while frontier:
        node = frontier.pop(0)
        for edge in dag.outgoing_edges(node):
            if edge.edge_id in revoked or edge.child_id in seen:
                continue
            if permission is not None and not edge.authorizes(permission):
                continue
            seen.add(edge.child_id)
            parent_edge[edge.child_id] = edge
            frontier.append(edge.child_id)
    if target_id not in seen:
        return None
    path: list[DelegationEdge] = []
    current = target_id
    while current in parent_edge:
        edge = parent_edge[current]
        path.append(edge)
        current = edge.parent_id
    return list(reversed(path))


def _verify_snapshot(
    manifest: SnapshotManifest,
    proof: TargetProof,
    federation_public_key: bytes,
    deployer_public_keys: dict[str, bytes],
) -> tuple[bool, dict[str, str]]:
    if manifest.issuer_key_id != _key_id(federation_public_key):
        return False, {}
    if not verify(_public_key(federation_public_key), manifest.signable_bytes(), manifest.signature):
        return False, {}
    if set(proof.domain_manifests) != set(manifest.domain_manifest_digests):
        return False, {}
    roster: dict[str, str] = {}
    for domain, domain_manifest in proof.domain_manifests.items():
        raw_key = deployer_public_keys.get(domain)
        if raw_key is None or domain_manifest.issuer_key_id != _key_id(raw_key):
            return False, {}
        if domain_manifest.epoch_id != manifest.epoch_id:
            return False, {}
        if not verify(_public_key(raw_key), domain_manifest.signable_bytes(), domain_manifest.signature):
            return False, {}
        if domain_manifest.digest() != manifest.domain_manifest_digests[domain]:
            return False, {}
        for node in domain_manifest.node_commitments:
            if node in roster:
                return False, {}
            roster[node] = domain
    return True, roster


def _verify_merkle_multiproof(
    edges: dict[str, DelegationEdge],
    positions: dict[str, int],
    siblings: dict[str, str],
    leaf_count: int,
    root: str,
) -> bool:
    if set(edges) != set(positions) or leaf_count <= 0:
        return False
    current = {positions[edge_id]: _edge_leaf(edge) for edge_id, edge in edges.items()}
    if len(current) != len(edges) or any(index < 0 or index >= leaf_count for index in current):
        return False
    width = leaf_count
    level = 0
    while width > 1:
        parents = {index // 2 for index in current}
        next_level: dict[int, str] = {}
        for parent in parents:
            left_index = parent * 2
            right_index = min(left_index + 1, width - 1)
            left = current.get(left_index) or siblings.get(f"{level}:{left_index}")
            if right_index == left_index:
                right = left
            else:
                right = current.get(right_index) or siblings.get(f"{level}:{right_index}")
            if left is None or right is None:
                return False
            next_level[parent] = _merkle_parent(left, right)
        current = next_level
        width = (width + 1) // 2
        level += 1
    return current.get(0) == root


def verify_target_proof_partial(
    manifest: SnapshotManifest,
    proof: TargetProof,
    revoked: set[str],
    federation_public_key: bytes,
    deployer_public_keys: dict[str, bytes],
    permission: Permission | None = None,
) -> bool:
    snapshot_ok, roster = _verify_snapshot(
        manifest, proof, federation_public_key, deployer_public_keys
    )
    if not snapshot_ok:
        return False
    baseline = set(manifest.authorization_rosters.get(_permission_key(permission), []))
    if not baseline or not baseline.issubset(roster):
        return False
    target = set(proof.target)
    survivors = set(proof.survivor_paths)
    if len(target) != len(proof.target) or target & survivors or target | survivors != baseline:
        return False
    if target != set(proof.cut_in_edges) or target != set(proof.in_commitments):
        return False
    if target & set(manifest.roots):
        return False

    edges = proof.disclosed_edges()
    if revoked != {edge.edge_id for edge in proof.revoked_edges}:
        return False
    for edge in edges.values():
        if edge.parent_id not in roster or edge.child_id not in roster:
            return False
        domain = roster[edge.parent_id]
        raw_key = deployer_public_keys.get(domain)
        if raw_key is None or not verify(_public_key(raw_key), edge.canonical_bytes(), edge.signature):
            return False
    if not _verify_merkle_multiproof(
        edges,
        proof.edge_positions,
        proof.merkle_siblings,
        manifest.edge_count,
        manifest.edge_root,
    ):
        return False

    roots = set(manifest.roots)
    for node, path in proof.survivor_paths.items():
        if not path:
            if node not in roots:
                return False
            continue
        if path[0].parent_id not in roots or path[-1].child_id != node:
            return False
        for first, second in zip(path, path[1:], strict=False):
            if first.child_id != second.parent_id:
                return False
        for edge in path:
            if edge.edge_id in revoked:
                return False
            if permission is not None and not edge.authorizes(permission):
                return False

    for node, commitment in proof.in_commitments.items():
        domain = roster.get(node)
        raw_key = deployer_public_keys.get(domain or "")
        domain_manifest = proof.domain_manifests.get(domain or "")
        if raw_key is None or domain_manifest is None:
            return False
        if commitment.node_id != node or commitment.epoch_id != manifest.epoch_id:
            return False
        if commitment.issuer_key_id != _key_id(raw_key):
            return False
        if not verify(_public_key(raw_key), commitment.signable_bytes(), commitment.signature):
            return False
        if domain_manifest.node_commitments.get(node) != commitment.digest():
            return False
        cut = proof.cut_in_edges[node]
        if sorted(edge.edge_id for edge in cut) != sorted(commitment.in_edge_ids):
            return False
        for edge in cut:
            if edge.child_id != node:
                return False
            if permission is not None and not edge.authorizes(permission):
                continue
            if edge.edge_id not in revoked and edge.parent_id not in target:
                return False
    return True


def verify_revocation_authority(
    entries: list[RevocationEnvelope],
    proof: TargetProof,
    manifest: SnapshotManifest,
    deployer_public_keys: dict[str, bytes],
) -> bool:
    roster = {
        node: domain
        for domain, domain_manifest in proof.domain_manifests.items()
        for node in domain_manifest.node_commitments
    }
    edges = proof.disclosed_edges()
    for entry in entries:
        edge = edges.get(entry.target_id)
        if edge is None or entry.epoch_id != manifest.epoch_id:
            return False
        domain = roster.get(edge.parent_id)
        raw_key = deployer_public_keys.get(domain or "")
        if raw_key is None or entry.issuer_key_id != _key_id(raw_key):
            return False
        if not verify_envelope(entry, _public_key(raw_key)):
            return False
    return True
