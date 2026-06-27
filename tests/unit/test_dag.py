"""Unit tests for DelegationDAG: multi-parent structure, reachability, path enumeration."""

import pytest
from revocation.dag import AgentNode, DelegationDAG, DelegationEdge
from revocation.trace_gen import generate_adversarial_shared_subdag, generate_tree


def _adv_dag() -> DelegationDAG:
    return generate_adversarial_shared_subdag()


def test_roots_single_root():
    dag = _adv_dag()
    roots = dag.roots()
    assert len(roots) == 1
    assert roots[0].node_id == "root"


def test_parents_of_multi_parent():
    dag = _adv_dag()
    # C has two parents: A and B
    parents = {p.node_id for p in dag.parents_of("C")}
    assert parents == {"A", "B"}


def test_parents_of_single_parent():
    dag = _adv_dag()
    assert {p.node_id for p in dag.parents_of("A")} == {"root"}
    assert {p.node_id for p in dag.parents_of("D")} == {"C"}


def test_is_multi_parent():
    dag = _adv_dag()
    assert dag.is_multi_parent("C")
    assert not dag.is_multi_parent("A")
    assert not dag.is_multi_parent("D")


def test_children_of():
    dag = _adv_dag()
    assert {c.node_id for c in dag.children_of("root")} == {"A", "B"}
    assert {c.node_id for c in dag.children_of("C")} == {"D"}
    assert dag.children_of("D") == []


def test_descendants_of():
    dag = _adv_dag()
    assert dag.descendants_of("root") == {"A", "B", "C", "D"}
    assert dag.descendants_of("A") == {"C", "D"}
    assert dag.descendants_of("C") == {"D"}
    assert dag.descendants_of("D") == set()


def test_descendants_exclude_edge():
    dag = _adv_dag()
    # Excluding e_A_C: A can no longer reach C directly, but C is still reachable via B
    desc_A_without_AC = dag.descendants_of("A", exclude_edges=frozenset({"e_A_C"}))
    assert "C" not in desc_A_without_AC
    assert "D" not in desc_A_without_AC


def test_reachable_from_roots_full():
    dag = _adv_dag()
    assert dag.reachable_from_roots() == {"root", "A", "B", "C", "D"}


def test_reachable_from_roots_exclude_e_A_C():
    dag = _adv_dag()
    # Remove e_A_C: C is still reachable via root→B→C
    reachable = dag.reachable_from_roots(exclude_edges=frozenset({"e_A_C"}))
    assert "C" in reachable
    assert "D" in reachable


def test_reachable_from_roots_exclude_both_edges_to_C():
    dag = _adv_dag()
    # Remove both e_A_C and e_B_C: C and D become unreachable
    reachable = dag.reachable_from_roots(exclude_edges=frozenset({"e_A_C", "e_B_C"}))
    assert "C" not in reachable
    assert "D" not in reachable


def test_all_paths_to_C():
    dag = _adv_dag()
    paths = dag.all_paths_to("C")
    # Two paths: root→A→C and root→B→C
    assert len(paths) == 2
    path_summaries = {tuple(e.edge_id for e in p) for p in paths}
    assert ("e_root_A", "e_A_C") in path_summaries
    assert ("e_root_B", "e_B_C") in path_summaries


def test_all_paths_to_D():
    dag = _adv_dag()
    paths = dag.all_paths_to("D")
    # Two paths (through A or B to C, then C→D)
    assert len(paths) == 2


def test_all_paths_to_root():
    dag = _adv_dag()
    # root has no incoming edges → paths list has one entry: the empty path
    paths = dag.all_paths_to("root")
    assert paths == [[]]


def test_is_acyclic_true():
    dag = _adv_dag()
    assert dag.is_acyclic()


def test_is_acyclic_detects_cycle():
    dag = DelegationDAG()
    for nid in ["X", "Y"]:
        dag.add_node(AgentNode(node_id=nid, deployer_id="d"))
    dag.add_edge(DelegationEdge(edge_id="e_X_Y", parent_id="X", child_id="Y"))
    dag.add_edge(DelegationEdge(edge_id="e_Y_X", parent_id="Y", child_id="X"))
    assert not dag.is_acyclic()


def test_tree_has_no_multi_parent():
    dag = generate_tree(depth=3, branching_factor=2)
    for node in dag.all_nodes():
        assert not dag.is_multi_parent(node.node_id), (
            f"tree node {node.node_id!r} should have exactly one parent"
        )


def test_add_edge_unknown_parent_raises():
    dag = DelegationDAG()
    dag.add_node(AgentNode(node_id="child", deployer_id="d"))
    with pytest.raises(ValueError, match="parent"):
        dag.add_edge(DelegationEdge(edge_id="e", parent_id="ghost", child_id="child"))
