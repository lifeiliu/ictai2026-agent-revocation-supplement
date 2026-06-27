"""Unit tests for L0–L3 target-set functions."""

from revocation.granularity import (
    target_set_l0,
    target_set_l1,
    target_set_l2,
    target_set_l3,
)
from revocation.trace_gen import generate_adversarial_shared_subdag, generate_tree


def _adv() -> object:
    return generate_adversarial_shared_subdag()


# ---------- L2 (most critical for Paper A) ----------

def test_l2_e_A_C_is_empty_due_to_alternate_path():
    """Revoking A→C should NOT exclusively remove C because C is still reachable via B→C."""
    dag = _adv()
    target = target_set_l2(dag, "e_A_C")
    # C and D are still reachable via root→B→C→D, so T_2(e_A_C) = ∅
    assert target == set(), f"expected empty target set, got {target}"


def test_l2_e_B_C_is_empty_due_to_alternate_path():
    """Revoking B→C should also NOT exclusively remove C (path via A remains)."""
    dag = _adv()
    target = target_set_l2(dag, "e_B_C")
    assert target == set()


def test_l2_both_edges_to_C_gives_C_and_D():
    """Only when BOTH edges to C are revoked does C (and D) lose all paths."""
    dag = _adv()
    # Simulate revoking both: T_2 of each is ∅, but combined exclusion shows C unreachable
    reachable_without_both = dag.reachable_from_roots(
        exclude_edges=frozenset({"e_A_C", "e_B_C"})
    )
    all_nodes = {n.node_id for n in dag.all_nodes()}
    lost = all_nodes - reachable_without_both
    assert "C" in lost
    assert "D" in lost


def test_l2_on_tree_edge_cascades_to_subtree():
    """On a tree (no alternate paths), L2 of an edge = its child's full subtree."""
    dag = generate_tree(depth=2, branching_factor=2)
    # Find any non-root edge
    roots = {r.node_id for r in dag.roots()}
    non_root_edge = next(e for e in dag.all_edges() if e.parent_id not in roots)
    target = target_set_l2(dag, non_root_edge.edge_id)
    # Should include the child and all its descendants
    assert non_root_edge.child_id in target
    for desc in dag.descendants_of(non_root_edge.child_id):
        assert desc in target


def test_l2_root_edge_excludes_alternate_branch():
    """On the adversarial DAG, revoking root→A should remove A but NOT C or D
    (C is still reachable via root→B→C)."""
    dag = _adv()
    target = target_set_l2(dag, "e_root_A")
    # A is only reachable via root→A, so A is in T_2
    assert "A" in target
    # C is reachable via root→B→C, so C is NOT in T_2
    assert "C" not in target
    assert "D" not in target


# ---------- L0 ----------

def test_l0_deployer_includes_all_descendants():
    dag = _adv()
    target = target_set_l0(dag, "deployer0")
    all_ids = {n.node_id for n in dag.all_nodes()}
    assert target == all_ids


def test_l0_unknown_deployer_is_empty():
    dag = _adv()
    assert target_set_l0(dag, "nonexistent") == set()


# ---------- L1 ----------

def test_l1_single_edge_path():
    dag = _adv()
    target = target_set_l1(dag, ["e_root_A"])
    assert "root" in target
    assert "A" in target
    # descendants of A: C (via e_A_C) and D
    assert "C" in target
    assert "D" in target


def test_l1_empty_path():
    dag = _adv()
    assert target_set_l1(dag, []) == set()


# ---------- L3 ----------

def test_l3_is_singleton():
    dag = _adv()
    target = target_set_l3(dag, "C", "hash_abc")
    assert target == {"C"}


def test_l3_does_not_include_descendants():
    dag = _adv()
    target = target_set_l3(dag, "A", "seg0")
    assert "C" not in target
    assert "D" not in target
