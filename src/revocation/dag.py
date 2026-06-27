"""Multi-parent delegation DAG: G = (V, E, σ).

Paper 1's SignedDAGBackend verifies linear chains. Paper A needs a true
multi-parent DAG where |parents_of(v)| > 1 is the normal case. This module
provides that data structure from scratch.

V: AgentNode  — agent identity + deployer
E: DelegationEdge — directed parent→child with Ed25519 sig (empty in synthetic traces)
σ: DelegationEdge.signature
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentNode:
    node_id: str
    deployer_id: str

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {"node_id": self.node_id, "deployer_id": self.deployer_id},
            sort_keys=True,
        ).encode()


@dataclass(frozen=True)
class DelegationEdge:
    edge_id: str
    parent_id: str
    child_id: str
    scope: str = "full"
    resource: str = "*"
    action: str = "*"
    tenant: str = "*"
    constraints: tuple[str, ...] = ()
    signature: str = ""  # Ed25519 hex; empty in synthetic traces

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "edge_id": self.edge_id,
                "parent_id": self.parent_id,
                "child_id": self.child_id,
                "scope": self.scope,
                "resource": self.resource,
                "action": self.action,
                "tenant": self.tenant,
                "constraints": sorted(self.constraints),
            },
            sort_keys=True,
        ).encode()

    def authorizes(self, permission: Permission) -> bool:
        """Return whether this edge carries the requested permission."""
        return (
            self.resource in {"*", permission.resource}
            and self.action in {"*", permission.action}
            and self.tenant in {"*", permission.tenant}
            and set(self.constraints).issubset(permission.constraints)
        )


@dataclass(frozen=True)
class Permission:
    resource: str
    action: str
    tenant: str
    constraints: frozenset[str] = frozenset()


class DelegationDAG:
    """Multi-parent directed acyclic graph of delegation relationships."""

    def __init__(self) -> None:
        self._nodes: dict[str, AgentNode] = {}
        self._edges: dict[str, DelegationEdge] = {}
        self._out_edges: dict[str, set[str]] = {}  # parent_id → {edge_id}
        self._in_edges: dict[str, set[str]] = {}   # child_id  → {edge_id}

    # ---------- Mutation ----------

    def add_node(self, node: AgentNode) -> None:
        self._nodes[node.node_id] = node
        self._out_edges.setdefault(node.node_id, set())
        self._in_edges.setdefault(node.node_id, set())

    def add_edge(self, edge: DelegationEdge) -> None:
        if edge.parent_id not in self._nodes:
            raise ValueError(f"parent {edge.parent_id!r} not in DAG")
        if edge.child_id not in self._nodes:
            raise ValueError(f"child {edge.child_id!r} not in DAG")
        self._edges[edge.edge_id] = edge
        self._out_edges[edge.parent_id].add(edge.edge_id)
        self._in_edges[edge.child_id].add(edge.edge_id)

    # ---------- Basic queries ----------

    def node(self, node_id: str) -> AgentNode:
        return self._nodes[node_id]

    def edge(self, edge_id: str) -> DelegationEdge:
        return self._edges[edge_id]

    def all_nodes(self) -> list[AgentNode]:
        return list(self._nodes.values())

    def all_edges(self) -> list[DelegationEdge]:
        return list(self._edges.values())

    def outgoing_edges(self, node_id: str) -> list[DelegationEdge]:
        return [self._edges[eid] for eid in self._out_edges.get(node_id, set())]

    def incoming_edges(self, node_id: str) -> list[DelegationEdge]:
        return [self._edges[eid] for eid in self._in_edges.get(node_id, set())]

    def parents_of(self, node_id: str) -> list[AgentNode]:
        """Direct parents — may be >1 for multi-parent nodes."""
        return [self._nodes[e.parent_id] for e in self.incoming_edges(node_id)]

    def children_of(self, node_id: str) -> list[AgentNode]:
        return [self._nodes[e.child_id] for e in self.outgoing_edges(node_id)]

    def roots(self) -> list[AgentNode]:
        """Nodes with no incoming edges."""
        return [n for n in self._nodes.values() if not self._in_edges[n.node_id]]

    def is_multi_parent(self, node_id: str) -> bool:
        return len(self._in_edges.get(node_id, set())) > 1

    # ---------- Reachability ----------

    def descendants_of(
        self,
        node_id: str,
        *,
        exclude_edges: frozenset[str] = frozenset(),
        permission: Permission | None = None,
    ) -> set[str]:
        """All descendants via BFS forward, optionally skipping some edges."""
        visited: set[str] = set()
        queue = [node_id]
        while queue:
            cur = queue.pop()
            for e in self.outgoing_edges(cur):
                if e.edge_id in exclude_edges:
                    continue
                if permission is not None and not e.authorizes(permission):
                    continue
                if e.child_id not in visited:
                    visited.add(e.child_id)
                    queue.append(e.child_id)
        return visited

    def ancestors_of(self, node_id: str) -> set[str]:
        """All ancestors via BFS backward."""
        visited: set[str] = set()
        queue = [node_id]
        while queue:
            cur = queue.pop()
            for e in self.incoming_edges(cur):
                if e.parent_id not in visited:
                    visited.add(e.parent_id)
                    queue.append(e.parent_id)
        return visited

    def reachable_from_roots(
        self,
        *,
        exclude_edges: frozenset[str] = frozenset(),
        permission: Permission | None = None,
    ) -> set[str]:
        """All nodes reachable from any root, optionally excluding edges."""
        reachable: set[str] = set()
        for root in self.roots():
            reachable.add(root.node_id)
            reachable |= self.descendants_of(
                root.node_id,
                exclude_edges=exclude_edges,
                permission=permission,
            )
        return reachable

    # ---------- Path enumeration ----------

    def all_paths_to(
        self,
        target_id: str,
        max_paths: int = 200,
    ) -> list[list[DelegationEdge]]:
        """All root→target paths as ordered edge sequences.

        Uses backward DFS. Stops after max_paths to avoid exponential blowup
        on large multi-parent DAGs (Paper A bounds N≤20 nodes in experiments;
        max_paths guards against accidental large-graph calls).
        """
        results: list[list[DelegationEdge]] = []
        self._dfs_backward(target_id, [], results, max_paths)
        return results

    def _dfs_backward(
        self,
        node_id: str,
        path: list[DelegationEdge],
        results: list[list[DelegationEdge]],
        max_paths: int,
    ) -> None:
        if len(results) >= max_paths:
            return
        in_edges = self.incoming_edges(node_id)
        if not in_edges:
            results.append(list(reversed(path)))
            return
        for e in in_edges:
            if len(results) >= max_paths:
                return
            self._dfs_backward(e.parent_id, path + [e], results, max_paths)

    # ---------- Validation ----------

    def is_acyclic(self) -> bool:
        """Kahn's algorithm cycle check."""
        in_deg = {nid: len(edges) for nid, edges in self._in_edges.items()}
        queue = [nid for nid, d in in_deg.items() if d == 0]
        count = 0
        while queue:
            nid = queue.pop()
            count += 1
            for e in self.outgoing_edges(nid):
                in_deg[e.child_id] -= 1
                if in_deg[e.child_id] == 0:
                    queue.append(e.child_id)
        return count == len(self._nodes)
