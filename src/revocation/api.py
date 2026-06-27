"""Small public API for the signed-DAG revocation contract.

The core prototype exposes low-level proof builders and verifiers.  This module
wraps them in the shape an agent runtime or artifact reviewer would use:
load normalized delegation events, issue an edge revocation, export a portable
proof bundle, and verify that bundle without the original graph.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .crypto import KeyPair, generate_keypair, sha256_hex
from .dag import AgentNode, DelegationDAG, DelegationEdge
from .envelope import RevocationEnvelope
from .prototype import (
    DomainManifest,
    InEdgeCommitment,
    RevocationLog,
    SignedDelegationGraph,
    SnapshotManifest,
    SnapshotMaterial,
    TargetProof,
    build_snapshot,
    build_target_proof,
    verify_revocation_authority,
    verify_target_proof_partial,
)

BundleDict = dict[str, Any]
EventDict = dict[str, Any]


def load_jsonl_events(path: str | Path) -> list[EventDict]:
    """Load newline-delimited normalized agent delegation events."""
    with Path(path).open() as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _domain_from_node(node_id: str) -> str:
    if ":" in node_id:
        return node_id.split(":", 1)[0]
    return "default"


def _permission_field(event: EventDict, key: str, default: str) -> str:
    permission = event.get("permission") or {}
    value = permission.get(key, default)
    return str(value)


def _constraints(event: EventDict) -> tuple[str, ...]:
    permission = event.get("permission") or {}
    return tuple(str(item) for item in permission.get("constraints", ()))


def _edge_id(event: EventDict, index: int) -> str:
    if event.get("edge_id"):
        return str(event["edge_id"])
    payload = json.dumps(
        {
            "caller": event.get("caller"),
            "callee": event.get("callee"),
            "seq": event.get("seq", index),
            "trace_id": event.get("trace_id"),
        },
        sort_keys=True,
    ).encode()
    return sha256_hex(payload)[:24]


def dag_from_events(events: Iterable[EventDict]) -> DelegationDAG:
    """Build a delegation DAG from normalized AI-agent handoff events.

    Required event fields are ``caller`` and ``callee``.  ``parent_domain`` and
    ``child_domain`` are used when present; otherwise the prefix before ``:`` is
    used as a conservative framework/domain label.
    """
    dag = DelegationDAG()
    node_domains: dict[str, str] = {}
    edge_defs: list[DelegationEdge] = []
    seen_edges: dict[str, tuple[str, str]] = {}

    for index, event in enumerate(events):
        if "caller" not in event or "callee" not in event:
            continue
        parent = str(event["caller"])
        child = str(event["callee"])
        parent_domain = str(event.get("parent_domain") or _domain_from_node(parent))
        child_domain = str(event.get("child_domain") or _domain_from_node(child))

        for node_id, domain in [(parent, parent_domain), (child, child_domain)]:
            previous = node_domains.get(node_id)
            if previous is not None and previous != domain:
                raise ValueError(
                    f"node {node_id!r} appears in both {previous!r} and {domain!r}"
                )
            node_domains[node_id] = domain

        edge_id = _edge_id(event, index)
        endpoints = (parent, child)
        previous_edge = seen_edges.get(edge_id)
        if previous_edge is not None:
            if previous_edge != endpoints:
                raise ValueError(f"edge_id {edge_id!r} is reused for different endpoints")
            continue
        seen_edges[edge_id] = endpoints
        edge_defs.append(
            DelegationEdge(
                edge_id=edge_id,
                parent_id=parent,
                child_id=child,
                scope=str(event.get("scope", "agent-handoff")),
                resource=_permission_field(event, "resource", "*"),
                action=_permission_field(event, "action", "*"),
                tenant=_permission_field(event, "tenant", "*"),
                constraints=_constraints(event),
            )
        )

    if not edge_defs:
        raise ValueError("no delegation edges found in events")

    for node_id, domain in sorted(node_domains.items()):
        dag.add_node(AgentNode(node_id, domain))
    for edge in edge_defs:
        dag.add_edge(edge)
    return dag


def _envelope_wire(envelope: RevocationEnvelope) -> dict[str, Any]:
    return {
        "target_id": envelope.target_id,
        "target_type": envelope.target_type,
        "revoked_at": envelope.revoked_at,
        "epoch_id": envelope.epoch_id,
        "issuer_key_id": envelope.issuer_key_id,
        "signature": envelope.signature,
    }


def _envelope_from_wire(data: dict[str, Any]) -> RevocationEnvelope:
    return RevocationEnvelope(
        target_id=str(data["target_id"]),
        target_type=data["target_type"],
        revoked_at=float(data["revoked_at"]),
        epoch_id=str(data["epoch_id"]),
        issuer_key_id=str(data["issuer_key_id"]),
        signature=str(data["signature"]),
    )


def _manifest_from_wire(data: dict[str, Any]) -> SnapshotManifest:
    return SnapshotManifest(
        epoch_id=str(data["epoch_id"]),
        previous_manifest_hash=str(data.get("previous_manifest_hash", "")),
        roots=list(data["roots"]),
        domain_manifest_digests=dict(data["domain_manifest_digests"]),
        authorization_rosters={
            str(key): list(value) for key, value in data["authorization_rosters"].items()
        },
        edge_root=str(data["edge_root"]),
        edge_count=int(data["edge_count"]),
        issuer_key_id=str(data["issuer_key_id"]),
        signature=str(data["signature"]),
    )


def _domain_manifest_from_wire(data: dict[str, Any]) -> DomainManifest:
    return DomainManifest(
        epoch_id=str(data["epoch_id"]),
        domain_id=str(data["domain_id"]),
        node_commitments=dict(data["node_commitments"]),
        issuer_key_id=str(data["issuer_key_id"]),
        signature=str(data["signature"]),
    )


def _commitment_from_wire(data: dict[str, Any]) -> InEdgeCommitment:
    return InEdgeCommitment(
        epoch_id=str(data["epoch_id"]),
        version=int(data["version"]),
        node_id=str(data["node_id"]),
        in_edge_ids=list(data["in_edge_ids"]),
        issuer_key_id=str(data["issuer_key_id"]),
        signature=str(data["signature"]),
    )


def _edge_from_wire(data: dict[str, Any]) -> DelegationEdge:
    return DelegationEdge(
        edge_id=str(data["edge_id"]),
        parent_id=str(data["parent_id"]),
        child_id=str(data["child_id"]),
        scope=str(data.get("scope", "agent-handoff")),
        resource=str(data.get("resource", "*")),
        action=str(data.get("action", "*")),
        tenant=str(data.get("tenant", "*")),
        constraints=tuple(data.get("constraints", ())),
        signature=str(data.get("signature", "")),
    )


def _proof_from_wire(data: dict[str, Any]) -> TargetProof:
    edges = {
        edge_id: _edge_from_wire(edge_wire)
        for edge_id, edge_wire in data["edges"].items()
    }
    return TargetProof(
        target=list(data["target"]),
        survivor_paths={
            node: [edges[edge_id] for edge_id in edge_ids]
            for node, edge_ids in data["survivor_paths"].items()
        },
        cut_in_edges={
            node: [edges[edge_id] for edge_id in edge_ids]
            for node, edge_ids in data["cut_in_edges"].items()
        },
        in_commitments={
            node: _commitment_from_wire(commitment)
            for node, commitment in data["commitments"].items()
        },
        domain_manifests={
            domain: _domain_manifest_from_wire(domain_manifest)
            for domain, domain_manifest in data["domain_manifests"].items()
        },
        edge_positions={
            edge_id: int(position) for edge_id, position in data["edge_positions"].items()
        },
        merkle_siblings=dict(data["merkle_siblings"]),
        revoked_edges=[edges[edge_id] for edge_id in data["revoked_edges"]],
    )


@dataclass
class RevocationBundle:
    """Portable revocation proof bundle that can be verified without the DAG."""

    manifest: SnapshotManifest
    proof: TargetProof
    revocations: list[RevocationEnvelope]
    federation_public_key: bytes
    deployer_public_keys: dict[str, bytes]

    @property
    def revoked_edges(self) -> list[str]:
        return [entry.target_id for entry in self.revocations]

    @property
    def target(self) -> list[str]:
        return list(self.proof.target)

    def verify(self) -> bool:
        revoked = set(self.revoked_edges)
        return verify_target_proof_partial(
            self.manifest,
            self.proof,
            revoked,
            self.federation_public_key,
            self.deployer_public_keys,
        ) and verify_revocation_authority(
            self.revocations,
            self.proof,
            self.manifest,
            self.deployer_public_keys,
        )

    def to_dict(self) -> BundleDict:
        return {
            "format": "signed-dag-revocation-bundle-v1",
            "revocations": [_envelope_wire(entry) for entry in self.revocations],
            "revoked_edges": self.revoked_edges,
            "target": self.target,
            "verified": self.verify(),
            "public_keys": {
                "federation": self.federation_public_key.hex(),
                "deployers": {
                    domain: key.hex()
                    for domain, key in sorted(self.deployer_public_keys.items())
                },
            },
            "proof": json.loads(self.proof.wire_bytes(self.manifest)),
        }

    @classmethod
    def from_dict(cls, data: BundleDict) -> RevocationBundle:
        if data.get("format") != "signed-dag-revocation-bundle-v1":
            raise ValueError("unsupported revocation bundle format")
        proof_wire = data["proof"]
        keys = data["public_keys"]
        return cls(
            manifest=_manifest_from_wire(proof_wire["manifest"]),
            proof=_proof_from_wire(proof_wire),
            revocations=[
                _envelope_from_wire(entry) for entry in data["revocations"]
            ],
            federation_public_key=bytes.fromhex(keys["federation"]),
            deployer_public_keys={
                str(domain): bytes.fromhex(raw)
                for domain, raw in keys["deployers"].items()
            },
        )

    def to_path(self, path: str | Path, *, indent: int = 2) -> None:
        with Path(path).open("w") as handle:
            json.dump(self.to_dict(), handle, indent=indent, sort_keys=True)
            handle.write("\n")

    @classmethod
    def from_path(cls, path: str | Path) -> RevocationBundle:
        with Path(path).open() as handle:
            return cls.from_dict(json.load(handle))


@dataclass
class RevocationContract:
    """Reference integration layer for AI-agent runtime revocation."""

    graph: SignedDelegationGraph
    federation_key: KeyPair
    epoch_id: str = "epoch-0"
    snapshot: SnapshotMaterial | None = None

    @classmethod
    def from_events(
        cls,
        events: Iterable[EventDict],
        *,
        epoch_id: str | None = None,
        federation_key: KeyPair | None = None,
    ) -> RevocationContract:
        events = list(events)
        if epoch_id is None:
            epoch_id = str(next((event["epoch_id"] for event in events if event.get("epoch_id")), "epoch-0"))
        graph = SignedDelegationGraph.from_dag(dag_from_events(events))
        return cls(
            graph=graph,
            federation_key=federation_key or generate_keypair(),
            epoch_id=epoch_id,
        )

    @classmethod
    def from_jsonl(
        cls,
        path: str | Path,
        *,
        epoch_id: str | None = None,
        federation_key: KeyPair | None = None,
    ) -> RevocationContract:
        return cls.from_events(
            load_jsonl_events(path),
            epoch_id=epoch_id,
            federation_key=federation_key,
        )

    def checkpoint(self, *, epoch_id: str | None = None) -> SnapshotMaterial:
        if epoch_id is not None:
            self.epoch_id = epoch_id
        self.snapshot = build_snapshot(
            self.graph,
            self.federation_key,
            epoch_id=self.epoch_id,
        )
        return self.snapshot

    def issue_revocation(
        self,
        edge_id: str,
        *,
        revoked_at: float | None = None,
    ) -> RevocationEnvelope:
        log = RevocationLog(self.federation_key, self.epoch_id)
        return log.revoke_edge(edge_id, self.graph, revoked_at=revoked_at)

    def prove(self, revocation: RevocationEnvelope | str) -> RevocationBundle:
        if isinstance(revocation, str):
            revocation = self.issue_revocation(revocation)
        if self.snapshot is None:
            self.checkpoint()
        assert self.snapshot is not None
        proof = build_target_proof(
            self.graph,
            {revocation.target_id},
            self.snapshot,
        )
        return RevocationBundle(
            manifest=self.snapshot.manifest,
            proof=proof,
            revocations=[revocation],
            federation_public_key=self.federation_key.public_bytes,
            deployer_public_keys=self.graph.public_keys(),
        )

    def revoke_and_prove(
        self,
        edge_id: str,
        *,
        revoked_at: float | None = None,
    ) -> RevocationBundle:
        return self.prove(self.issue_revocation(edge_id, revoked_at=revoked_at))
