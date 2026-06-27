"""Revocation predicates, mechanism simulators, and OverRev/UnderRev counters.

Formal definitions per paper-a-plan.md §2.2–§2.3:

  REV(v, t)        = ∃ e ∈ incoming(v) : e ∈ R ∧ revoked_at(e) ≤ t
  chain_is_valid   = ∀ e ∈ C : ¬REV(e, t)          [T4 GraphRevocationSoundness predicate]
  OverRev(M,G,S)   = |{v : M revokes v ∧ v ∉ S}|   [collateral revocations]
  UnderRev(M,G,S)  = |{v : v ∈ S ∧ M doesn't revoke v}|  [missed revocations; security-critical]

Mechanism simulators (all compared against L2 as the canonical correct target):
  apply_l2_revocation              — graph-aware edge revocation; always sound
  apply_tree_cascade               — APS-style full BFS; over-revokes on multi-parent DAGs
  apply_tree_cascade_deployer_scoped — cascade bounded to one deployer domain;
                                      under-revokes cross-deployer descendants
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .dag import DelegationDAG, DelegationEdge, Permission
from .granularity import target_set_l2


@dataclass
class RevocationState:
    """Tracks revoked edges and their effective timestamps."""

    _revoked: dict[str, float] = field(default_factory=dict)  # edge_id → revoked_at

    def revoke_edge(self, edge_id: str, timestamp: float) -> None:
        self._revoked[edge_id] = timestamp

    def is_revoked(self, edge_id: str, at_time: float) -> bool:
        t = self._revoked.get(edge_id)
        return t is not None and t <= at_time

    def revoked_edge_ids(self) -> frozenset[str]:
        return frozenset(self._revoked)


def rev_predicate(
    node_id: str,
    dag: DelegationDAG,
    state: RevocationState,
    at_time: float,
) -> bool:
    """REV(v, t): True if any incoming edge to v is revoked by time t."""
    return any(state.is_revoked(e.edge_id, at_time) for e in dag.incoming_edges(node_id))


def chain_is_valid(
    chain_edges: list[DelegationEdge],
    state: RevocationState,
    at_time: float,
) -> bool:
    """T4 chain-validity predicate: True iff no edge in the chain is revoked at t.

    A root node with no incoming edges trivially satisfies this (vacuously True).
    """
    return not any(state.is_revoked(e.edge_id, at_time) for e in chain_edges)


# ---------- Mechanism simulators ----------

def apply_l2_revocation(dag: DelegationDAG, edge_id: str) -> set[str]:
    """L2 graph-aware edge revocation: revoke exactly T_2(edge_id, dag).

    Returns only nodes that lose ALL root-paths when edge_id is removed.
    Nodes reachable via alternate parent paths are NOT included.
    Always sound: OverRev=0, UnderRev=0 relative to L2 intended target.
    """
    return target_set_l2(dag, edge_id)


def apply_credential_path_revalidation(
    dag: DelegationDAG,
    revoked_edge_ids: set[str],
    permission: Permission | None = None,
) -> set[str]:
    """PKIX/SPKI-style baseline: invalidate credentials, then revalidate paths.

    This baseline is semantically exact when the verifier already holds a complete
    scoped credential graph. The paper's protocol contribution is authenticating
    that epoch graph and proving the result from partial evidence.
    """
    before = dag.reachable_from_roots(permission=permission)
    after = dag.reachable_from_roots(
        exclude_edges=frozenset(revoked_edge_ids), permission=permission
    )
    return before - after


def apply_tree_cascade(dag: DelegationDAG, start_node_id: str) -> set[str]:
    """APS-style tree cascade: revoke start_node and ALL descendants via forward BFS.

    Failure mode: OVER-REVOCATION on multi-parent DAGs.
    When a descendant has an alternate parent path that does not pass through
    start_node, that descendant's authority survives — but tree cascade revokes
    it anyway, producing OverRev > 0.
    """
    revoked = {start_node_id}
    revoked |= dag.descendants_of(start_node_id)
    return revoked


def apply_tree_cascade_deployer_scoped(
    dag: DelegationDAG,
    start_node_id: str,
    deployer_id: str,
) -> set[str]:
    """Cascade bounded to nodes belonging to deployer_id (cross-domain cascade).

    Failure mode: UNDER-REVOCATION in federated settings.
    Nodes that received authority from start_node but belong to a different
    deployer domain are NOT in this deployer's registry and are missed,
    leaving their authority active despite a revocation event.

    This simulates APS's explicit limitation: "We do not address cross-domain
    revocation where no shared registry exists" (agent-passport-readthrough.md §4).
    """
    revoked: set[str] = set()
    queue = [start_node_id]
    while queue:
        node_id = queue.pop()
        if dag.node(node_id).deployer_id != deployer_id:
            continue  # outside this deployer's domain → NOT in registry → missed
        revoked.add(node_id)
        for out_edge in dag.outgoing_edges(node_id):
            if out_edge.child_id not in revoked:
                queue.append(out_edge.child_id)
    return revoked


# ---------- OverRev / UnderRev ----------

def over_revocation(revoked_set: set[str], target_set: set[str]) -> int:
    """|{v : revoked ∧ v ∉ target}| — collateral revocations."""
    return len(revoked_set - target_set)


def under_revocation(revoked_set: set[str], target_set: set[str]) -> int:
    """|{v : v ∈ target ∧ not revoked}| — missed revocations (security-critical)."""
    return len(target_set - revoked_set)
