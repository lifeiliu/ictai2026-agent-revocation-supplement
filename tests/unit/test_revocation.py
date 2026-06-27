"""Unit tests for revocation predicates, mechanism simulators, and OverRev/UnderRev.

Key claims tested:
  1. Tree cascade → OverRev>0 on multi-parent DAG (E1a)
  2. Deployer-scoped cascade → UnderRev>0 on cross-deployer DAG (E1d)
  3. L2 always OverRev=UnderRev=0 (by construction)
  4. T4 chain_is_valid: alternate path survives single-edge revocation
"""

from revocation.revocation import (
    RevocationState,
    apply_credential_path_revalidation,
    apply_l2_revocation,
    apply_tree_cascade,
    apply_tree_cascade_deployer_scoped,
    chain_is_valid,
    over_revocation,
    rev_predicate,
    under_revocation,
)
from revocation.trace_gen import (
    generate_adversarial_shared_subdag,
    generate_cross_deployer_dag,
    generate_tree,
)


def _adv():
    return generate_adversarial_shared_subdag()


# ---------- RevocationState ----------

def test_revocation_state_is_revoked():
    state = RevocationState()
    state.revoke_edge("e1", timestamp=100.0)
    assert state.is_revoked("e1", at_time=100.0)
    assert state.is_revoked("e1", at_time=200.0)
    assert not state.is_revoked("e1", at_time=99.9)
    assert not state.is_revoked("e2", at_time=100.0)


# ---------- rev_predicate ----------

def test_rev_predicate_false_before_revocation():
    dag = _adv()
    state = RevocationState()
    assert not rev_predicate("C", dag, state, at_time=0.0)


def test_rev_predicate_true_after_one_edge_revoked():
    dag = _adv()
    state = RevocationState()
    state.revoke_edge("e_A_C", timestamp=10.0)
    assert rev_predicate("C", dag, state, at_time=10.0)


def test_rev_predicate_root_always_false():
    dag = _adv()
    state = RevocationState()
    assert not rev_predicate("root", dag, state, at_time=1e9)


# ---------- chain_is_valid (T4) ----------

def test_chain_is_valid_unrevoked():
    dag = _adv()
    state = RevocationState()
    path = dag.all_paths_to("D")[0]
    assert chain_is_valid(path, state, at_time=0.0)


def test_chain_is_valid_one_edge_revoked():
    dag = _adv()
    state = RevocationState()
    state.revoke_edge("e_C_D", timestamp=5.0)
    for path in dag.all_paths_to("D"):
        assert not chain_is_valid(path, state, at_time=5.0)


def test_chain_is_valid_alternate_path_survives():
    """T4 soundness: revoking A→C invalidates that path but not the B→C path."""
    dag = _adv()
    state = RevocationState()
    state.revoke_edge("e_A_C", timestamp=5.0)
    paths = dag.all_paths_to("C")
    path_via_B = next(p for p in paths if any(e.edge_id == "e_B_C" for e in p))
    path_via_A = next(p for p in paths if any(e.edge_id == "e_A_C" for e in p))
    assert chain_is_valid(path_via_B, state, at_time=5.0)
    assert not chain_is_valid(path_via_A, state, at_time=5.0)


def test_chain_is_valid_empty_chain():
    state = RevocationState()
    assert chain_is_valid([], state, at_time=0.0)


# ---------- Tree cascade OVER-revocation (E1a) ----------

def test_tree_cascade_over_revokes_on_multiparent_dag():
    """Core E1a claim: tree cascade from C gives OverRev=2; T_2(e_A_C)=∅."""
    dag = _adv()
    revoked  = apply_tree_cascade(dag, "C")
    intended = apply_l2_revocation(dag, "e_A_C")
    assert "C" in revoked and "D" in revoked
    assert intended == set()
    assert over_revocation(revoked, intended) >= 2


def test_l2_revocation_on_tree_is_correct():
    """On a tree, L2 == tree cascade (both sound; no alternate paths)."""
    dag = generate_tree(depth=2, branching_factor=2)
    root_node = dag.roots()[0]
    first_child = dag.children_of(root_node.node_id)[0].node_id
    in_edge = dag.incoming_edges(first_child)[0]
    l2_target  = apply_l2_revocation(dag, in_edge.edge_id)
    tree_result = apply_tree_cascade(dag, first_child)
    assert l2_target == tree_result


# ---------- Deployer-scoped cascade UNDER-revocation (E1d) ----------

def test_deployer_scoped_cascade_under_revokes_cross_domain():
    """Core E1d claim: deployer1-scoped cascade misses D (deployer2) → UnderRev=1."""
    dag = generate_cross_deployer_dag()
    intended  = apply_l2_revocation(dag, "e_A_C")   # T_2 = {C, D}
    d_scoped  = apply_tree_cascade_deployer_scoped(dag, "C", "deployer1")
    assert "C" in intended and "D" in intended
    assert "C" in d_scoped
    assert "D" not in d_scoped          # D is in deployer2 → missed
    assert under_revocation(d_scoped, intended) == 1


def test_deployer_scoped_cascade_same_deployer_is_complete():
    """If all nodes are in the same deployer, scoped cascade == full cascade."""
    dag = generate_adversarial_shared_subdag(deployer_id="d1")
    full     = apply_tree_cascade(dag, "C")
    scoped   = apply_tree_cascade_deployer_scoped(dag, "C", "d1")
    assert full == scoped


def test_cross_deployer_dag_t2_includes_both_nodes():
    """T_2(e_A_C) on the cross-deployer DAG must include both C and D."""
    dag = generate_cross_deployer_dag()
    target = apply_l2_revocation(dag, "e_A_C")
    assert "C" in target
    assert "D" in target


def test_credential_path_revalidation_matches_batch_target():
    dag = _adv()
    revoked = {"e_A_C", "e_B_C"}
    expected = dag.reachable_from_roots() - dag.reachable_from_roots(
        exclude_edges=frozenset(revoked)
    )
    assert apply_credential_path_revalidation(dag, revoked) == expected


# ---------- OverRev / UnderRev counters ----------

def test_over_under_revocation_counters():
    revoked  = {"A", "B", "C"}
    intended = {"B", "C", "D"}
    assert over_revocation(revoked, intended) == 1   # A
    assert under_revocation(revoked, intended) == 1  # D


def test_over_revocation_zero_when_subset():
    assert over_revocation({"A", "B"}, {"A", "B", "C"}) == 0


def test_under_revocation_zero_when_superset():
    assert under_revocation({"A", "B", "C"}, {"A", "B"}) == 0
