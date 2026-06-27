"""Cross-framework agent-shaped delegation demo for Paper A.

E16 is the primary executed LangGraph evidence. This experiment is a small
portability artifact: it models AutoGen- and CrewAI-shaped task handoffs as
caller-to-callee runtime events, normalizes them into the same signed delegation
schema, and replays the edge target against tree and deployer-scoped baselines.

The demo does not claim to run production AutoGen/CrewAI stacks. Its purpose is
to test whether the contract is tied to LangGraph instrumentation.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from revocation.crypto import KeyPair, sha256_hex, sign, verify  # noqa: E402
from revocation.dag import AgentNode, DelegationDAG, DelegationEdge  # noqa: E402
from revocation.prototype import compute_batch_target  # noqa: E402
from revocation.revocation import (  # noqa: E402
    apply_tree_cascade,
    apply_tree_cascade_deployer_scoped,
    over_revocation,
    under_revocation,
)

HERE = Path(__file__).resolve().parent
TRACE_DIR = HERE / "traces"
RAW_PATH = TRACE_DIR / "cross_framework_raw.jsonl"
NORMALIZED_PATH = TRACE_DIR / "normalized_events.jsonl"
RESULTS_PATH = HERE / "e18_results.json"
EPOCH_ID = "e18-cross-framework-agent-demo"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def stable_hash(value: Any) -> str:
    return sha256_hex(canonical_bytes(value))


def deterministic_keypair(label: str) -> KeyPair:
    seed = hashlib.sha256(f"signed-edge-revocation:e18:{label}".encode()).digest()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key()
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return KeyPair(private=private, public=public, key_id=sha256_hex(public_bytes)[:16])


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def edge_identifier(parent: str, child: str, permission: dict[str, Any]) -> str:
    return stable_hash(
        {
            "epoch_id": EPOCH_ID,
            "parent": parent,
            "child": child,
            "permission": permission,
        }
    )[:24]


def handoff(
    framework: str,
    trace_id: str,
    workflow: str,
    input_cell: str,
    seq: int,
    caller: str,
    callee: str,
    caller_deployer: str,
    callee_deployer: str,
    permission: dict[str, Any],
) -> dict[str, Any]:
    return {
        "kind": "agent_task_handoff",
        "event_type": "delegate_task",
        "framework": framework,
        "trace_id": trace_id,
        "workflow": workflow,
        "input_cell": input_cell,
        "repeat": 0,
        "seq": seq,
        "caller": caller,
        "callee": callee,
        "caller_deployer": caller_deployer,
        "callee_deployer": callee_deployer,
        "permission": permission,
    }


def raw_handoffs() -> list[dict[str, Any]]:
    support_permission = {
        "tenant": "support",
        "resource": "tickets",
        "action": "resolve",
        "constraints": ["case-scoped"],
    }
    procurement_permission = {
        "tenant": "retail",
        "resource": "purchase-order",
        "action": "negotiate",
        "constraints": ["po-scoped"],
    }
    return [
        handoff(
            "autogen-shaped",
            "autogen-shared-specialist-r000",
            "autogen-shared-specialist",
            "shared-specialist",
            1,
            "autogen:user_proxy",
            "autogen:support_planner",
            "customer_org",
            "support_team",
            support_permission,
        ),
        handoff(
            "autogen-shaped",
            "autogen-shared-specialist-r000",
            "autogen-shared-specialist",
            "shared-specialist",
            2,
            "autogen:support_planner",
            "autogen:refund_agent",
            "support_team",
            "support_team",
            support_permission,
        ),
        handoff(
            "autogen-shaped",
            "autogen-shared-specialist-r000",
            "autogen-shared-specialist",
            "shared-specialist",
            3,
            "autogen:support_planner",
            "autogen:policy_checker",
            "support_team",
            "governance_vendor",
            support_permission,
        ),
        handoff(
            "autogen-shaped",
            "autogen-shared-specialist-r000",
            "autogen-shared-specialist",
            "shared-specialist",
            4,
            "autogen:billing_orchestrator",
            "autogen:policy_checker",
            "billing_team",
            "governance_vendor",
            support_permission,
        ),
        handoff(
            "autogen-shaped",
            "autogen-shared-specialist-r000",
            "autogen-shared-specialist",
            "shared-specialist",
            5,
            "autogen:policy_checker",
            "autogen:customer_reply_agent",
            "governance_vendor",
            "support_team",
            support_permission,
        ),
        handoff(
            "crewai-shaped",
            "crewai-cross-org-procurement-r000",
            "crewai-cross-org-procurement",
            "cross-org-procurement",
            1,
            "crewai:ops_lead",
            "crewai:researcher",
            "retail_ops",
            "retail_ops",
            procurement_permission,
        ),
        handoff(
            "crewai-shaped",
            "crewai-cross-org-procurement-r000",
            "crewai-cross-org-procurement",
            "cross-org-procurement",
            2,
            "crewai:researcher",
            "crewai:supplier_agent",
            "retail_ops",
            "supplier_vendor",
            procurement_permission,
        ),
        handoff(
            "crewai-shaped",
            "crewai-cross-org-procurement-r000",
            "crewai-cross-org-procurement",
            "cross-org-procurement",
            3,
            "crewai:supplier_agent",
            "crewai:shipping_agent",
            "supplier_vendor",
            "logistics_vendor",
            procurement_permission,
        ),
        handoff(
            "crewai-shaped",
            "crewai-cross-org-procurement-r000",
            "crewai-cross-org-procurement",
            "cross-org-procurement",
            4,
            "crewai:finance_lead",
            "crewai:invoice_agent",
            "finance_ops",
            "finance_ops",
            procurement_permission,
        ),
        handoff(
            "crewai-shaped",
            "crewai-cross-org-procurement-r000",
            "crewai-cross-org-procurement",
            "cross-org-procurement",
            5,
            "crewai:invoice_agent",
            "crewai:supplier_agent",
            "finance_ops",
            "supplier_vendor",
            procurement_permission,
        ),
    ]


def decision_payload(row: dict[str, Any], edge_id: str) -> dict[str, Any]:
    return {
        "epoch_id": EPOCH_ID,
        "trace_id": row["trace_id"],
        "seq": row["seq"],
        "framework": row["framework"],
        "caller": row["caller"],
        "callee": row["callee"],
        "parent_domain": row["caller_deployer"],
        "child_domain": row["callee_deployer"],
        "permission": row["permission"],
        "edge_id": edge_id,
    }


def normalize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for row in rows:
        edge_id = edge_identifier(row["caller"], row["callee"], row["permission"])
        signer = deterministic_keypair(row["caller_deployer"])
        edge = DelegationEdge(
            edge_id=edge_id,
            parent_id=row["caller"],
            child_id=row["callee"],
            resource=row["permission"]["resource"],
            action=row["permission"]["action"],
            tenant=row["permission"]["tenant"],
            constraints=tuple(sorted(row["permission"].get("constraints", []))),
        )
        payload = decision_payload(row, edge_id)
        normalized.append(
            {
                **payload,
                "input_cell": row["input_cell"],
                "workflow": row["workflow"],
                "repeat": row["repeat"],
                "event_id": stable_hash(payload)[:24],
                "issuer_key_id": signer.key_id,
                "decision_signature": sign(signer.private, canonical_bytes(payload)),
                "edge_signature": sign(signer.private, edge.canonical_bytes()),
            }
        )
    return normalized


def signature_valid(event: dict[str, Any]) -> bool:
    payload = {
        key: event[key]
        for key in [
            "epoch_id",
            "trace_id",
            "seq",
            "framework",
            "caller",
            "callee",
            "parent_domain",
            "child_domain",
            "permission",
            "edge_id",
        ]
    }
    key = deterministic_keypair(event["parent_domain"])
    return (
        event["issuer_key_id"] == key.key_id
        and verify(key.public, canonical_bytes(payload), event["decision_signature"])
    )


def build_dag(events: list[dict[str, Any]]) -> DelegationDAG:
    dag = DelegationDAG()
    nodes: dict[str, str] = {}
    for event in events:
        nodes[event["caller"]] = event["parent_domain"]
        nodes[event["callee"]] = event["child_domain"]
    for node_id, deployer in sorted(nodes.items()):
        dag.add_node(AgentNode(node_id=node_id, deployer_id=deployer))
    for event in events:
        permission = event["permission"]
        dag.add_edge(
            DelegationEdge(
                edge_id=event["edge_id"],
                parent_id=event["caller"],
                child_id=event["callee"],
                resource=permission["resource"],
                action=permission["action"],
                tenant=permission["tenant"],
                constraints=tuple(sorted(permission.get("constraints", []))),
                signature=event["edge_signature"],
            )
        )
    return dag


def analyze_trace(trace_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    dag = build_dag(events)
    multiparent_nodes = [
        node.node_id for node in dag.all_nodes() if dag.is_multi_parent(node.node_id)
    ]
    cross_domain_edges = [
        edge for edge in dag.all_edges()
        if dag.node(edge.parent_id).deployer_id != dag.node(edge.child_id).deployer_id
    ]

    alternate_parent_preserved = 0
    tree_wrongly_revoked = 0
    for node_id in multiparent_nodes:
        edge = sorted(dag.incoming_edges(node_id), key=lambda item: item.edge_id)[0]
        intended = compute_batch_target(dag, {edge.edge_id})
        tree = apply_tree_cascade(dag, edge.child_id)
        alternate_parent_preserved += int(node_id not in intended)
        tree_wrongly_revoked += int(node_id in tree)

    scoped_cases = 0
    scoped_under = 0
    for edge in dag.all_edges():
        intended = compute_batch_target(dag, {edge.edge_id})
        parent_domain = dag.node(edge.parent_id).deployer_id
        if any(dag.node(node_id).deployer_id != parent_domain for node_id in intended):
            scoped_cases += 1
            scoped = apply_tree_cascade_deployer_scoped(dag, edge.child_id, parent_domain)
            scoped_under += int(under_revocation(scoped, intended) > 0)

    all_edge_cases = 0
    tree_exact = 0
    scoped_exact = 0
    for edge in dag.all_edges():
        intended = compute_batch_target(dag, {edge.edge_id})
        tree = apply_tree_cascade(dag, edge.child_id)
        parent_domain = dag.node(edge.parent_id).deployer_id
        scoped = apply_tree_cascade_deployer_scoped(dag, edge.child_id, parent_domain)
        all_edge_cases += 1
        tree_exact += int(
            over_revocation(tree, intended) == 0 and under_revocation(tree, intended) == 0
        )
        scoped_exact += int(
            over_revocation(scoped, intended) == 0
            and under_revocation(scoped, intended) == 0
        )

    return {
        "trace_id": trace_id,
        "framework": events[0]["framework"],
        "workflow": events[0]["workflow"],
        "input_cell": events[0]["input_cell"],
        "signed_delegation_events": len(events),
        "valid_signed_delegation_events": sum(signature_valid(event) for event in events),
        "nodes": len(dag.all_nodes()),
        "edges": len(dag.all_edges()),
        "cross_domain_edges": len(cross_domain_edges),
        "multiparent_agents": len(multiparent_nodes),
        "alternate_parent_cases": len(multiparent_nodes),
        "alternate_parent_preserved_by_edge_target": alternate_parent_preserved,
        "alternate_parent_wrongly_revoked_by_tree": tree_wrongly_revoked,
        "cross_domain_target_cases": scoped_cases,
        "cross_domain_under_revoked_by_scoped": scoped_under,
        "all_edge_cases": all_edge_cases,
        "tree_exact_cases": tree_exact,
        "deployer_scoped_exact_cases": scoped_exact,
    }


def main() -> None:
    raw = raw_handoffs()
    normalized = normalize(raw)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in normalized:
        grouped.setdefault(row["trace_id"], []).append(row)
    per_trace = [
        analyze_trace(trace_id, sorted(events, key=lambda item: item["seq"]))
        for trace_id, events in sorted(grouped.items())
    ]
    results = {
        "experiment": "E18 cross-framework agent-shaped portability demo",
        "purpose": (
            "Show that AutoGen- and CrewAI-shaped task handoffs can emit the same "
            "normalized signed delegation schema used by E16; not a statistical "
            "prevalence study and not a production framework deployment."
        ),
        "raw_trace_path": "traces/cross_framework_raw.jsonl",
        "normalized_trace_path": "traces/normalized_events.jsonl",
        "trace_units": len(per_trace),
        "frameworks": sorted({row["framework"] for row in normalized}),
        "signed_delegation_events": len(normalized),
        "valid_signed_delegation_events": sum(
            row["valid_signed_delegation_events"] for row in per_trace
        ),
        "alternate_parent_cases": sum(row["alternate_parent_cases"] for row in per_trace),
        "alternate_parent_preserved_by_edge_target": sum(
            row["alternate_parent_preserved_by_edge_target"] for row in per_trace
        ),
        "alternate_parent_wrongly_revoked_by_tree": sum(
            row["alternate_parent_wrongly_revoked_by_tree"] for row in per_trace
        ),
        "cross_domain_target_cases": sum(row["cross_domain_target_cases"] for row in per_trace),
        "cross_domain_under_revoked_by_scoped": sum(
            row["cross_domain_under_revoked_by_scoped"] for row in per_trace
        ),
        "per_trace": per_trace,
    }
    write_jsonl(RAW_PATH, raw)
    write_jsonl(NORMALIZED_PATH, normalized)
    write_json(RESULTS_PATH, results)
    print(
        "E18 cross-framework demo: "
        f"traces={results['trace_units']} "
        f"frameworks={','.join(results['frameworks'])} "
        f"signed={results['valid_signed_delegation_events']}/"
        f"{results['signed_delegation_events']} "
        f"ap={results['alternate_parent_preserved_by_edge_target']}/"
        f"{results['alternate_parent_cases']} "
        f"scoped_under={results['cross_domain_under_revoked_by_scoped']}/"
        f"{results['cross_domain_target_cases']} "
        f"output={RESULTS_PATH}"
    )


if __name__ == "__main__":
    main()
