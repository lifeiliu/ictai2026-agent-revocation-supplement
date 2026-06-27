"""
E5 — Kubernetes RBAC Delegation Case Study

Constructs an architecture-faithful delegation DAG derived from Kubernetes RBAC
documentation (ClusterRole, RoleBinding, ServiceAccount hierarchies).

In K8s RBAC, ClusterRoles are granted to ServiceAccounts via ClusterRoleBindings.
A ServiceAccount can hold multiple RoleBindings from different controllers,
creating multi-parent delegation edges. Cross-namespace delegation (where a
ServiceAccount in ns-A is granted access via a ClusterRoleBinding owned by
controller in ns-B) creates cross-deployer topology.

We model:
  - ClusterAdmin → namespace controllers → workload service accounts
  - Multi-parent: service accounts bound by both deployment-controller AND
    namespace-admin (common pattern in shared cluster environments)
  - Cross-deployer: system:masters (deployer d1) → DevOps SA (d1) →
    cross-team SA (d2) (cross-namespace pattern)

This is an illustrative scenario based on documented K8s RBAC architecture,
not measured from a production cluster. Graph statistics are representative
of the patterns described in Kubernetes RBAC documentation and published
cluster studies.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

from revocation.dag import DelegationDAG, AgentNode, DelegationEdge
from revocation.granularity import target_set_l2
from revocation.revocation import (
    apply_tree_cascade, apply_tree_cascade_deployer_scoped,
    over_revocation, under_revocation
)

def build_k8s_rbac_dag() -> DelegationDAG:
    """
    Kubernetes RBAC delegation DAG (architecture-faithful scenario).

    Topology (29 nodes, 30 edges):

      cluster-admin (d1)
      ├─→ deployment-ctrl (d1)
      │   ├─→ frontend-sa (d1)
      │   ├─→ backend-sa (d1)   ← also from ns-admin (multi-parent #1)
      │   └─→ ci-bot (d1)       ← also from devops-ctrl (multi-parent #2)
      ├─→ ns-admin (d1)
      │   ├─→ backend-sa (d1)   (second parent)
      │   ├─→ db-proxy (d1)
      │   └─→ monitoring (d1)
      ├─→ devops-ctrl (d1)
      │   ├─→ ci-bot (d1)       (second parent)
      │   ├─→ scanner-sa (d1)
      │   └─→ cross-team-sa (d2) ← cross-namespace (d2)
      └─→ system-sa (d1)
          └─→ log-collector (d2) ← cross-namespace (d2)

    Plus downstream leaf agents.
    """
    dag = DelegationDAG()

    def node(nid, dep):
        return AgentNode(node_id=nid, deployer_id=dep)

    def edge(eid, parent, child):
        return DelegationEdge(edge_id=eid, parent_id=parent, child_id=child)

    nodes = [
        # Layer 0: root
        node("cluster-admin", "d1"),
        # Layer 1: controllers
        node("deployment-ctrl", "d1"),
        node("ns-admin", "d1"),
        node("devops-ctrl", "d1"),
        node("system-sa", "d1"),
        # Layer 2: workload SAs (some multi-parent)
        node("frontend-sa", "d1"),
        node("backend-sa", "d1"),    # multi-parent: deployment-ctrl + ns-admin
        node("ci-bot", "d1"),         # multi-parent: deployment-ctrl + devops-ctrl
        node("db-proxy", "d1"),
        node("monitoring", "d1"),
        node("scanner-sa", "d1"),
        node("cross-team-sa", "d2"), # cross-deployer
        node("log-collector", "d2"), # cross-deployer
        # Layer 3: downstream leaf agents
        node("frontend-worker1", "d1"),
        node("frontend-worker2", "d1"),
        node("backend-worker1", "d1"),
        node("backend-worker2", "d1"),
        node("ci-step-build", "d1"),
        node("ci-step-test", "d1"),
        node("ci-step-deploy", "d1"), # also from scanner-sa (multi-parent #3)
        node("db-reader", "d1"),
        node("db-writer", "d1"),
        node("metrics-agent", "d1"),
        node("alert-manager", "d1"),
        node("vuln-reporter", "d1"),
        node("cross-worker1", "d2"),
        node("cross-worker2", "d2"),
        node("log-processor", "d2"),
        node("log-archiver", "d2"),
    ]

    edges = [
        # L0→L1
        edge("e0_dc",  "cluster-admin",   "deployment-ctrl"),
        edge("e0_na",  "cluster-admin",   "ns-admin"),
        edge("e0_dv",  "cluster-admin",   "devops-ctrl"),
        edge("e0_ss",  "cluster-admin",   "system-sa"),
        edge("e1_fe",  "deployment-ctrl", "frontend-sa"),
        edge("e1_be1", "deployment-ctrl", "backend-sa"),     # parent 1
        edge("e1_ci1", "deployment-ctrl", "ci-bot"),          # parent 1
        edge("e2_be2", "ns-admin",        "backend-sa"),      # parent 2 ← MULTI
        edge("e2_db",  "ns-admin",        "db-proxy"),
        edge("e2_mon", "ns-admin",        "monitoring"),
        edge("e3_ci2", "devops-ctrl",     "ci-bot"),          # parent 2 ← MULTI
        edge("e3_sc",  "devops-ctrl",     "scanner-sa"),
        edge("e3_ct",  "devops-ctrl",     "cross-team-sa"),   # cross-deployer
        edge("e4_lc",  "system-sa",       "log-collector"),   # cross-deployer
        edge("e5_fw1", "frontend-sa",     "frontend-worker1"),
        edge("e5_fw2", "frontend-sa",     "frontend-worker2"),
        edge("e6_bw1", "backend-sa",      "backend-worker1"),
        edge("e6_bw2", "backend-sa",      "backend-worker2"),
        edge("e7_csb", "ci-bot",          "ci-step-build"),
        edge("e7_cst", "ci-bot",          "ci-step-test"),
        edge("e7_csd", "ci-bot",          "ci-step-deploy"),  # parent 1
        edge("e8_sd",  "scanner-sa",      "ci-step-deploy"),  # parent 2 ← MULTI
        edge("e9_dr",  "db-proxy",        "db-reader"),
        edge("e9_dw",  "db-proxy",        "db-writer"),
        edge("e10_ma", "monitoring",      "metrics-agent"),
        edge("e10_al", "monitoring",      "alert-manager"),
        edge("e11_vr", "scanner-sa",      "vuln-reporter"),
        edge("e12_c1", "cross-team-sa",   "cross-worker1"),
        edge("e12_c2", "cross-team-sa",   "cross-worker2"),
        edge("e13_lp", "log-collector",   "log-processor"),
        edge("e13_la", "log-collector",   "log-archiver"),
    ]

    for n in nodes:
        dag.add_node(n)
    for e in edges:
        dag.add_edge(e)

    return dag


def analyse_revocation_targets(dag):
    """Analyse T2 and cascade behaviour on key delegation edges."""
    results = []

    # Identify multi-parent nodes
    multi_parent = {
        n.node_id for n in dag.all_nodes()
        if dag.is_multi_parent(n.node_id)
    }

    # Key edges to analyse
    test_cases = [
        ("e1_be1", "Remove deployment-ctrl→backend-sa",
         "backend-sa has alternate path via ns-admin→backend-sa"),
        ("e7_csd", "Remove ci-bot→ci-step-deploy",
         "ci-step-deploy has alternate parent via scanner-sa"),
        ("e3_ct",  "Remove devops-ctrl→cross-team-sa",
         "Cross-deployer: cross-team-sa(d2) and workers should be in T2"),
        ("e0_dv",  "Remove cluster-admin→devops-ctrl",
         "Bottleneck: devops-ctrl has only one parent"),
    ]

    for edge_id, description, expected in test_cases:
        intended = target_set_l2(dag, edge_id)
        cascade = apply_tree_cascade(dag, dag.edge(edge_id).child_id)
        scope_d1 = apply_tree_cascade_deployer_scoped(dag, dag.edge(edge_id).child_id, "d1")

        over = over_revocation(cascade, intended)
        under = under_revocation(cascade, intended)
        under_scope = under_revocation(scope_d1, intended)

        results.append({
            "edge_id": edge_id,
            "description": description,
            "expected": expected,
            "T2_size": len(intended),
            "T2_nodes": sorted(intended),
            "cascade_size": len(cascade),
            "OverRev": over,
            "UnderRev": under,
            "UnderRev_scope": under_scope,
        })

    return multi_parent, results


def main():
    dag = build_k8s_rbac_dag()

    n_nodes = len(dag.all_nodes())
    n_edges = len(dag.all_edges())

    multi_parent, results = analyse_revocation_targets(dag)

    print(f"\nKubernetes RBAC Delegation DAG")
    print(f"  Nodes: {n_nodes}, Edges: {n_edges}")
    print(f"  Multi-parent nodes ({len(multi_parent)}): {sorted(multi_parent)}")
    print(f"  Multi-parent rate: {100*len(multi_parent)/(n_nodes-1):.1f}% of non-root nodes")
    print()

    for r in results:
        print(f"Edge: {r['edge_id']} — {r['description']}")
        print(f"  Expected: {r['expected']}")
        print(f"  T2 = {r['T2_nodes']} (size={r['T2_size']})")
        print(f"  Tree cascade size = {r['cascade_size']}")
        print(f"  OverRev = {r['OverRev']}  UnderRev(cascade) = {r['UnderRev']}")
        if r['UnderRev_scope'] > 0:
            print(f"  UnderRev(d1-scoped) = {r['UnderRev_scope']} [CROSS-DOMAIN MISS]")
        print()

    return multi_parent, results, n_nodes, n_edges


if __name__ == "__main__":
    main()
