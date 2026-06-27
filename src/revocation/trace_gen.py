"""Synthetic delegation trace generators for Paper A experiments.

Four topology families:
  tree           — perfect k-ary tree; each node has exactly one parent
  multiparent    — random layered DAG; shared_ratio fraction of nodes get ≥2 parents
  adversarial    — hand-crafted worst-case showing tree cascade over-revocation
  cross_deployer — two-deployer DAG showing deployer-scoped cascade under-revocation
"""

from __future__ import annotations

import random
from typing import Literal

from .dag import AgentNode, DelegationDAG, DelegationEdge

TopologyType = Literal["tree", "multiparent", "adversarial", "cross_deployer"]


def _eid(parent: str, child: str, counter: list[int]) -> str:
    eid = f"e{counter[0]}_{parent}_{child}"
    counter[0] += 1
    return eid


def generate_tree(
    depth: int,
    branching_factor: int = 2,
    deployer_id: str = "deployer0",
) -> DelegationDAG:
    """Perfect k-ary tree: each node has exactly one parent.

    Control condition for E1/E3: on a tree, tree cascade == L2 (both correct).
    """
    dag = DelegationDAG()
    counter = [0]
    ec = [0]

    def nid() -> str:
        v = f"n{counter[0]}"
        counter[0] += 1
        return v

    root = nid()
    dag.add_node(AgentNode(node_id=root, deployer_id=deployer_id))
    frontier = [root]

    for _ in range(depth):
        next_frontier: list[str] = []
        for parent in frontier:
            for _ in range(branching_factor):
                child = nid()
                dag.add_node(AgentNode(node_id=child, deployer_id=deployer_id))
                dag.add_edge(DelegationEdge(
                    edge_id=_eid(parent, child, ec),
                    parent_id=parent,
                    child_id=child,
                ))
                next_frontier.append(child)
        frontier = next_frontier

    return dag


def generate_multiparent_dag(
    num_nodes: int,
    shared_ratio: float = 0.3,
    seed: int | None = None,
    deployer_id: str = "deployer0",
) -> DelegationDAG:
    """Random layered DAG with multi-parent nodes.

    Construction: layered (guarantees acyclicity); each node gets one primary
    parent from the layer above plus a secondary parent (prob=shared_ratio) from
    any earlier layer.
    """
    rng = random.Random(seed)
    dag = DelegationDAG()
    ec = [0]

    node_ids = [f"n{i}" for i in range(num_nodes)]
    layer_count = max(2, int(num_nodes ** 0.5))
    sizes: list[int] = [1]
    remaining = num_nodes - 1
    for i in range(1, layer_count):
        if remaining <= 0:
            break
        sz = max(1, remaining // (layer_count - i)) if i < layer_count - 1 else remaining
        sizes.append(sz)
        remaining -= sz

    layers: list[list[str]] = []
    idx = 0
    for sz in sizes:
        layer: list[str] = []
        for _ in range(sz):
            if idx >= num_nodes:
                break
            dag.add_node(AgentNode(node_id=node_ids[idx], deployer_id=deployer_id))
            layer.append(node_ids[idx])
            idx += 1
        if layer:
            layers.append(layer)

    for li in range(1, len(layers)):
        for child in layers[li]:
            primary = rng.choice(layers[li - 1])
            dag.add_edge(DelegationEdge(
                edge_id=_eid(primary, child, ec),
                parent_id=primary,
                child_id=child,
            ))
            if rng.random() < shared_ratio and li >= 2:
                earlier = layers[rng.randint(0, li - 2)]
                secondary = rng.choice(earlier)
                existing = {e.parent_id for e in dag.incoming_edges(child)}
                if secondary not in existing:
                    dag.add_edge(DelegationEdge(
                        edge_id=_eid(secondary, child, ec),
                        parent_id=secondary,
                        child_id=child,
                    ))

    return dag


def generate_adversarial_shared_subdag(deployer_id: str = "deployer0") -> DelegationDAG:
    """Hand-crafted DAG for over-revocation demonstration.

        root
        /  \\
       A    B
        \\  /
         C      ← two parents: A and B
         |
         D

    Revoking edge A→C:
      L2 correct: T_2(e_A_C) = {} (C still reachable via B→C)
      Tree cascade from C: {C, D} → OverRev = 2
    """
    dag = DelegationDAG()
    for nid in ["root", "A", "B", "C", "D"]:
        dag.add_node(AgentNode(node_id=nid, deployer_id=deployer_id))
    dag.add_edge(DelegationEdge(edge_id="e_root_A", parent_id="root", child_id="A"))
    dag.add_edge(DelegationEdge(edge_id="e_root_B", parent_id="root", child_id="B"))
    dag.add_edge(DelegationEdge(edge_id="e_A_C",    parent_id="A",    child_id="C"))
    dag.add_edge(DelegationEdge(edge_id="e_B_C",    parent_id="B",    child_id="C"))
    dag.add_edge(DelegationEdge(edge_id="e_C_D",    parent_id="C",    child_id="D"))
    return dag


def generate_cross_deployer_dag() -> DelegationDAG:
    """Two-deployer DAG for under-revocation demonstration.

        root (deployer1)
         |
         A (deployer1)
         |
         C (deployer1)
         |
         D (deployer2)  ← cross-domain node

    Revoking A→C via deployer1-scoped cascade:
      L2 correct: T_2(e_A_C) = {C, D} (both exclusively reachable via A→C)
      Deployer1-scoped cascade from C: {C} only (D is deployer2, not in registry)
      UnderRev = 1 (D is missed; retains authority)

    This is APS's explicit limitation in federated settings: cross-domain nodes
    are not in the initiating deployer's registry.
    """
    dag = DelegationDAG()
    dag.add_node(AgentNode(node_id="root", deployer_id="deployer1"))
    dag.add_node(AgentNode(node_id="A",    deployer_id="deployer1"))
    dag.add_node(AgentNode(node_id="C",    deployer_id="deployer1"))
    dag.add_node(AgentNode(node_id="D",    deployer_id="deployer2"))  # cross-domain
    dag.add_edge(DelegationEdge(edge_id="e_root_A", parent_id="root", child_id="A"))
    dag.add_edge(DelegationEdge(edge_id="e_A_C",    parent_id="A",    child_id="C"))
    dag.add_edge(DelegationEdge(edge_id="e_C_D",    parent_id="C",    child_id="D"))
    return dag


def count_multiparent_nodes(dag: DelegationDAG) -> int:
    """Return the number of nodes with ≥2 parents (for experiment validation)."""
    return sum(1 for n in dag.all_nodes() if dag.is_multi_parent(n.node_id))
