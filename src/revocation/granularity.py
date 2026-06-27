"""L0–L3 revocation target-set functions T_k(v, G).

Per paper-a-plan.md §2.1:
  L0 deployer  — T_0(deployer_id) = nodes with that deployer + all descendants
  L1 chain     — T_1(path_edge_ids) = nodes on named path + terminal's descendants
  L2 edge      — T_2(edge_id) = nodes that lose ALL root paths when edge is removed
  L3 segment   — T_3(node_id, seg_hash) = {node_id}

L2 is the minimum-viable granularity: it neither over-revokes (drops nodes with
alternate parent paths) nor under-revokes (misses exclusively-dependent nodes).
"""

from __future__ import annotations

from .dag import DelegationDAG


def target_set_l0(dag: DelegationDAG, deployer_id: str) -> set[str]:
    """L0: all nodes issued by deployer_id plus all their descendants."""
    deployer_roots = {n.node_id for n in dag.all_nodes() if n.deployer_id == deployer_id}
    result = set(deployer_roots)
    for nid in deployer_roots:
        result |= dag.descendants_of(nid)
    return result


def target_set_l1(dag: DelegationDAG, path_edge_ids: list[str]) -> set[str]:
    """L1: all nodes on the named root→leaf path plus the terminal node's descendants.

    path_edge_ids: ordered edge IDs forming one root→leaf delegation path.
    """
    if not path_edge_ids:
        return set()
    result: set[str] = set()
    for eid in path_edge_ids:
        e = dag.edge(eid)
        result.add(e.parent_id)
        result.add(e.child_id)
    last_child = dag.edge(path_edge_ids[-1]).child_id
    result |= dag.descendants_of(last_child)
    return result


def target_set_l2(dag: DelegationDAG, edge_id: str) -> set[str]:
    """L2: nodes that lose ALL root-paths when edge_id is removed.

    Algorithm:
      reachable_with    = reachable from roots in full DAG
      reachable_without = reachable from roots with edge_id excluded
      T_2 = reachable_with − reachable_without

    Nodes reachable via an alternate parent path survive: T_2 does NOT include them.
    This is the key property that makes L2 sound on multi-parent DAGs where
    tree cascade (which ignores alternate paths) fails.
    """
    reachable_with = dag.reachable_from_roots()
    reachable_without = dag.reachable_from_roots(exclude_edges=frozenset({edge_id}))
    return reachable_with - reachable_without


def target_set_l3(dag: DelegationDAG, node_id: str, segment_hash: str) -> set[str]:  # noqa: ARG001
    """L3: exactly one (node, segment) pair — represented as {node_id}.

    L3 revokes one attested output segment; the node's other authority and
    all descendants are unaffected.
    """
    return {node_id}
