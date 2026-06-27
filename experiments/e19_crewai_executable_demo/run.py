"""Tiny executable CrewAI delegation replay for Paper A.

E16 is the primary executed LangGraph evidence. E19 is a smaller portability
artifact that runs real CrewAI objects with a deterministic local LLM. It records
CrewAI task callbacks and task-context handoffs, normalizes those handoffs into
the same signed delegation schema, and replays edge targets against approximate
revocation baselines.

The experiment is intentionally small. It is evidence that the schema can be
attached to an executable CrewAI workflow, not a production deployment or a
prevalence estimate.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import warnings
from collections.abc import Iterable
from pathlib import Path
from typing import Any

os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
warnings.filterwarnings(
    "ignore",
    message="function callbacks cannot be serialized.*",
    category=UserWarning,
)

try:
    import crewai
    from crewai import Agent, Crew, Process, Task
    from crewai.llms.base_llm import BaseLLM
except ImportError as exc:  # pragma: no cover - exercised by missing environment
    raise SystemExit(
        "CrewAI is required for E19. Run: "
        "python3 -m venv .venv && "
        ".venv/bin/python -m pip install -r requirements.txt"
    ) from exc

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
RAW_PATH = TRACE_DIR / "crewai_runtime_raw.jsonl"
NORMALIZED_PATH = TRACE_DIR / "normalized_events.jsonl"
RESULTS_PATH = HERE / "e19_results.json"
EPOCH_ID = "e19-crewai-executable-demo"
TRACE_ID = "crewai-executable-procurement-r000"
WORKFLOW = "crewai-cross-org-procurement-executable"
INPUT_CELL = "purchase-order-reconciliation"

AGENT_DEPLOYERS = {
    "ops_lead": "retail_ops",
    "researcher": "retail_ops",
    "supplier_agent": "supplier_vendor",
    "shipping_agent": "logistics_vendor",
    "finance_lead": "finance_ops",
    "invoice_agent": "finance_ops",
    "compliance_reviewer": "governance_vendor",
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def stable_hash(value: Any) -> str:
    return sha256_hex(canonical_bytes(value))


def deterministic_keypair(label: str) -> KeyPair:
    seed = hashlib.sha256(f"signed-edge-revocation:e19:{label}".encode()).digest()
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


class DeterministicLLM(BaseLLM):
    """Offline CrewAI LLM that makes the artifact executable without API keys."""

    def __init__(self, llm_calls: list[dict[str, Any]]) -> None:
        super().__init__(model="deterministic-offline-crewai")
        self._llm_calls = llm_calls

    def call(
        self,
        messages: str | list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        callbacks: list[Any] | None = None,
        available_functions: dict[str, Any] | None = None,
        from_task: Task | None = None,
        from_agent: Agent | None = None,
        response_model: Any | None = None,
    ) -> str:
        self._llm_calls.append(
            {
                "kind": "crewai_runtime_event",
                "event_type": "llm_call",
                "framework": f"crewai-{crewai.__version__}",
                "trace_id": TRACE_ID,
                "workflow": WORKFLOW,
                "input_cell": INPUT_CELL,
                "agent_role": getattr(from_agent, "role", None),
                "task_name": getattr(from_task, "name", None),
                "tools_available": len(tools or []),
            }
        )
        return "Final Answer: deterministic offline CrewAI task result"


def permission(resource: str, action: str, constraints: list[str]) -> dict[str, Any]:
    return {
        "tenant": "retail",
        "resource": resource,
        "action": action,
        "constraints": constraints,
    }


TASK_SPECS = [
    {
        "name": "scope_purchase",
        "agent": "ops_lead",
        "contexts": [],
        "permission": permission("purchase-order", "scope", ["case-scoped"]),
    },
    {
        "name": "research_vendor",
        "agent": "researcher",
        "contexts": ["scope_purchase"],
        "permission": permission("supplier-profile", "read", ["case-scoped"]),
    },
    {
        "name": "quote_supplier",
        "agent": "supplier_agent",
        "contexts": ["research_vendor"],
        "permission": permission("purchase-order", "quote", ["po-scoped"]),
    },
    {
        "name": "shipping_check",
        "agent": "shipping_agent",
        "contexts": ["quote_supplier"],
        "permission": permission("shipment", "estimate", ["po-scoped"]),
    },
    {
        "name": "finance_terms",
        "agent": "finance_lead",
        "contexts": [],
        "permission": permission("invoice", "scope", ["case-scoped"]),
    },
    {
        "name": "invoice_review",
        "agent": "invoice_agent",
        "contexts": ["finance_terms"],
        "permission": permission("invoice", "review", ["case-scoped"]),
    },
    {
        "name": "supplier_reconcile",
        "agent": "supplier_agent",
        "contexts": ["research_vendor", "invoice_review"],
        "permission": permission("purchase-order", "reconcile", ["po-scoped"]),
    },
    {
        "name": "compliance_signoff",
        "agent": "compliance_reviewer",
        "contexts": ["supplier_reconcile"],
        "permission": permission("purchase-order", "approve", ["po-scoped"]),
    },
]


def agent_node(agent_label: str) -> str:
    return f"crewai:{agent_label}"


def edge_identifier(row: dict[str, Any]) -> str:
    return stable_hash(
        {
            "epoch_id": EPOCH_ID,
            "source_task": row["source_task"],
            "target_task": row["target_task"],
            "parent": row["caller"],
            "child": row["callee"],
            "permission": row["permission"],
        }
    )[:24]


def build_crewai_workflow() -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    llm_calls: list[dict[str, Any]] = []
    task_callbacks: list[dict[str, Any]] = []
    llm = DeterministicLLM(llm_calls)

    agents = {
        label: Agent(
            role=label,
            goal=f"Complete the {label} part of the procurement workflow.",
            backstory=f"{label} is operated by {AGENT_DEPLOYERS[label]}.",
            llm=llm,
            verbose=False,
            allow_delegation=False,
        )
        for label in AGENT_DEPLOYERS
    }

    tasks: dict[str, Task] = {}

    def callback_for(task_name: str, agent_label: str):
        def _callback(output: Any) -> None:
            task_callbacks.append(
                {
                    "kind": "crewai_runtime_event",
                    "event_type": "task_callback",
                    "framework": f"crewai-{crewai.__version__}",
                    "trace_id": TRACE_ID,
                    "workflow": WORKFLOW,
                    "input_cell": INPUT_CELL,
                    "task_name": task_name,
                    "agent": agent_node(agent_label),
                    "agent_deployer": AGENT_DEPLOYERS[agent_label],
                    "output": getattr(output, "raw", str(output)),
                }
            )

        return _callback

    for spec in TASK_SPECS:
        contexts = [tasks[name] for name in spec["contexts"]]
        tasks[spec["name"]] = Task(
            name=spec["name"],
            description=(
                f"Execute {spec['name']} for a cross-organization procurement "
                "workflow. Return a concise deterministic result."
            ),
            expected_output="A concise deterministic result.",
            agent=agents[spec["agent"]],
            context=contexts,
            callback=callback_for(spec["name"], spec["agent"]),
        )

    crew = Crew(
        name="e19_crewai_procurement",
        agents=list(agents.values()),
        tasks=[tasks[spec["name"]] for spec in TASK_SPECS],
        process=Process.sequential,
        verbose=False,
        memory=False,
        tracing=False,
    )
    output = crew.kickoff(inputs={})

    handoffs: list[dict[str, Any]] = []
    executed_tasks = {row["task_name"] for row in task_callbacks}
    seq = 0
    specs_by_name = {spec["name"]: spec for spec in TASK_SPECS}
    for spec in TASK_SPECS:
        if spec["name"] not in executed_tasks:
            continue
        for source_name in spec["contexts"]:
            if source_name not in executed_tasks:
                continue
            source = specs_by_name[source_name]
            seq += 1
            caller_label = source["agent"]
            callee_label = spec["agent"]
            handoffs.append(
                {
                    "kind": "crewai_runtime_event",
                    "event_type": "context_handoff",
                    "framework": f"crewai-{crewai.__version__}",
                    "trace_id": TRACE_ID,
                    "workflow": WORKFLOW,
                    "input_cell": INPUT_CELL,
                    "repeat": 0,
                    "seq": seq,
                    "source_task": source_name,
                    "target_task": spec["name"],
                    "caller": agent_node(caller_label),
                    "callee": agent_node(callee_label),
                    "caller_deployer": AGENT_DEPLOYERS[caller_label],
                    "callee_deployer": AGENT_DEPLOYERS[callee_label],
                    "permission": spec["permission"],
                    "runtime_evidence": {
                        "crew_kickoff_completed": True,
                        "source_task_callback_seen": True,
                        "target_task_callback_seen": True,
                    },
                }
            )

    raw = llm_calls + task_callbacks + handoffs
    return raw, handoffs, str(output)


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
        "source_task": row["source_task"],
        "target_task": row["target_task"],
    }


def normalize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for row in rows:
        edge_id = edge_identifier(row)
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
            "source_task",
            "target_task",
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
        permission_data = event["permission"]
        dag.add_edge(
            DelegationEdge(
                edge_id=event["edge_id"],
                parent_id=event["caller"],
                child_id=event["callee"],
                resource=permission_data["resource"],
                action=permission_data["action"],
                tenant=permission_data["tenant"],
                constraints=tuple(sorted(permission_data.get("constraints", []))),
                signature=event["edge_signature"],
            )
        )
    return dag


def analyze_trace(events: list[dict[str, Any]]) -> dict[str, Any]:
    dag = build_dag(events)
    multiparent_nodes = [
        node.node_id for node in dag.all_nodes() if dag.is_multi_parent(node.node_id)
    ]
    cross_domain_edges = [
        edge
        for edge in dag.all_edges()
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
        "trace_id": TRACE_ID,
        "framework": events[0]["framework"],
        "workflow": WORKFLOW,
        "input_cell": INPUT_CELL,
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
    raw, handoffs, crew_output = build_crewai_workflow()
    normalized = normalize(handoffs)
    per_trace = analyze_trace(normalized)
    task_callbacks = [row for row in raw if row["event_type"] == "task_callback"]
    llm_calls = [row for row in raw if row["event_type"] == "llm_call"]
    results = {
        "experiment": "E19 CrewAI tiny executable artifact",
        "purpose": (
            "Run real CrewAI objects with a deterministic local BaseLLM, then "
            "normalize task-context handoffs into signed delegation decisions. "
            "This is portability evidence, not production prevalence evidence."
        ),
        "crewai_version": crewai.__version__,
        "raw_trace_path": "traces/crewai_runtime_raw.jsonl",
        "normalized_trace_path": "traces/normalized_events.jsonl",
        "trace_units": 1,
        "crew_kickoff_completed": True,
        "crew_output": crew_output,
        "tasks_configured": len(TASK_SPECS),
        "task_callbacks_observed": len(task_callbacks),
        "llm_calls_observed": len(llm_calls),
        "signed_delegation_events": len(normalized),
        "valid_signed_delegation_events": per_trace["valid_signed_delegation_events"],
        "alternate_parent_cases": per_trace["alternate_parent_cases"],
        "alternate_parent_preserved_by_edge_target": per_trace[
            "alternate_parent_preserved_by_edge_target"
        ],
        "alternate_parent_wrongly_revoked_by_tree": per_trace[
            "alternate_parent_wrongly_revoked_by_tree"
        ],
        "cross_domain_target_cases": per_trace["cross_domain_target_cases"],
        "cross_domain_under_revoked_by_scoped": per_trace[
            "cross_domain_under_revoked_by_scoped"
        ],
        "per_trace": [per_trace],
    }
    write_jsonl(RAW_PATH, raw)
    write_jsonl(NORMALIZED_PATH, normalized)
    write_json(RESULTS_PATH, results)
    print(
        "E19 CrewAI executable demo: "
        f"crewai={results['crewai_version']} "
        f"tasks={results['task_callbacks_observed']}/"
        f"{results['tasks_configured']} "
        f"llm_calls={results['llm_calls_observed']} "
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
