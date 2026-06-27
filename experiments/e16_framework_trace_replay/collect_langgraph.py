"""Collect raw LangGraph runtime traces for E16.

The collector runs compiled LangGraph workflows and records two evidence layers:

1. framework events emitted by LangGraph's runtime event stream; and
2. application-level delegation events observed when one agent/tool invokes
   another inside a framework execution.

The output is raw JSONL. It contains no normalized edge signatures; those are
created by normalize.py so collection and signing remain auditable steps.
"""

from __future__ import annotations

import asyncio
import json
import operator
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, TypedDict

from common import DEFAULT_PERMISSION, RAW_TRACE_PATH, write_jsonl
from langgraph.graph import END, START, StateGraph

REPEATS = int(os.getenv("E16_REPEATS", "20"))
OUTPUT_PATH = Path(os.getenv("E16_RAW_OUTPUT", RAW_TRACE_PATH))


class TraceState(TypedDict):
    log: Annotated[list[str], operator.add]
    inp: dict[str, Any]


@dataclass
class TraceContext:
    trace_id: str
    workflow: str
    input_cell: str
    repeat: int
    inputs: dict[str, Any]
    framework: str = "langgraph"
    seq: int = 0
    stack: list[str] = field(default_factory=list)
    nodes: dict[str, str] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def emit(self, kind: str, event_type: str, **fields: Any) -> None:
        self.seq += 1
        self.events.append(
            {
                "trace_id": self.trace_id,
                "workflow": self.workflow,
                "input_cell": self.input_cell,
                "repeat": self.repeat,
                "framework": self.framework,
                "seq": self.seq,
                "ts_ns": time.time_ns(),
                "kind": kind,
                "event_type": event_type,
                **fields,
            }
        )


_CTX: TraceContext | None = None


def current_context() -> TraceContext:
    if _CTX is None:
        raise RuntimeError("trace context is not active")
    return _CTX


def safe_json(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(key): safe_json(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [safe_json(item) for item in value]
        return repr(value)


def permission_from_state(state: TraceState) -> dict[str, Any]:
    return dict(state.get("inp", {}).get("permission", DEFAULT_PERMISSION))


def agent(name: str, deployer: str):
    """Decorate a callable as a runtime-observed agent/tool."""

    def decorate(fn: Callable[[TraceState], Any]):
        def wrapped(state: TraceState):
            ctx = current_context()
            caller = ctx.stack[-1] if ctx.stack else None
            ctx.nodes[name] = deployer
            ctx.emit("agent", "agent_start", agent=name, deployer=deployer, caller=caller)
            if caller is not None and caller != name:
                ctx.emit(
                    "delegation",
                    "delegate",
                    caller=caller,
                    callee=name,
                    caller_deployer=ctx.nodes[caller],
                    callee_deployer=deployer,
                    permission=permission_from_state(state),
                )
            ctx.stack.append(name)
            try:
                return fn(state)
            finally:
                ctx.stack.pop()
                ctx.emit("agent", "agent_end", agent=name, deployer=deployer)

        wrapped._agent_name = name  # type: ignore[attr-defined]
        return wrapped

    return decorate


def emit_framework_event(event: dict[str, Any]) -> None:
    metadata = event.get("metadata") or {}
    selected_metadata = {
        key: safe_json(value)
        for key, value in metadata.items()
        if key == "ls_integration" or key.startswith("langgraph_")
    }
    data = event.get("data") or {}
    current_context().emit(
        "framework",
        str(event.get("event", "unknown")),
        framework_name=event.get("name"),
        framework_run_id=str(event.get("run_id", "")),
        parent_ids=[str(item) for item in event.get("parent_ids", [])],
        tags=safe_json(event.get("tags", [])),
        metadata=selected_metadata,
        data_keys=sorted(str(key) for key in data),
    )


async def run_in_langgraph(entry: Callable[[TraceState], Any], inputs: dict[str, Any]) -> None:
    graph = StateGraph(TraceState)

    def node(state: TraceState) -> dict[str, list[str]]:
        entry(state)
        return {"log": [entry._agent_name]}  # type: ignore[attr-defined]

    graph.add_node("run", node)
    graph.add_edge(START, "run")
    graph.add_edge("run", END)
    compiled = graph.compile()
    async for event in compiled.astream_events({"log": [], "inp": inputs}, version="v2"):
        emit_framework_event(event)


def permission(resource: str, action: str, tenant: str = "tenant-a") -> dict[str, Any]:
    return {
        "tenant": tenant,
        "resource": resource,
        "action": action,
        "constraints": [],
    }


async def wf_research(prefix: str, inputs: dict[str, Any]) -> None:
    summarize = agent(f"{prefix}:summarizer", "tool_vendor")(lambda state: state)
    web = agent(f"{prefix}:web_reader", "org_alpha")(lambda state: summarize(state))
    docs = agent(f"{prefix}:doc_reader", "org_alpha")(lambda state: summarize(state))
    writer = agent(f"{prefix}:writer", "org_alpha")(lambda state: state)

    @agent(f"{prefix}:planner", "org_alpha")
    def planner(state: TraceState):
        web(state)
        docs(state)
        writer(state)

    await run_in_langgraph(planner, inputs)


async def wf_code(prefix: str, inputs: dict[str, Any]) -> None:
    lint = agent(f"{prefix}:lint_tool", "ci_vendor")(lambda state: state)
    coder = agent(f"{prefix}:coder", "eng_team")(lambda state: lint(state))
    reviewer = agent(f"{prefix}:reviewer", "eng_team")(lambda state: lint(state))
    merger = agent(f"{prefix}:merger", "eng_team")(lambda state: state)

    @agent(f"{prefix}:supervisor", "eng_team")
    def supervisor(state: TraceState):
        coder(state)
        reviewer(state)
        merger(state)

    await run_in_langgraph(supervisor, inputs)


async def wf_support(prefix: str, inputs: dict[str, Any]) -> None:
    kb = agent(f"{prefix}:kb_lookup", "tool_vendor")(lambda state: state)
    human = agent(f"{prefix}:human_handoff", "ops_vendor")(lambda state: state)

    def billing_body(state: TraceState):
        kb(state)
        if int(state["inp"].get("severity", 0)) >= 5:
            human(state)

    billing = agent(f"{prefix}:billing_agent", "support_a")(billing_body)

    def tech_body(state: TraceState):
        kb(state)
        if int(state["inp"].get("severity", 0)) >= 5:
            human(state)

    tech = agent(f"{prefix}:tech_agent", "support_b")(tech_body)

    @agent(f"{prefix}:router", "support_root")
    def router(state: TraceState):
        issue = state["inp"].get("issue", "billing")
        if issue == "billing":
            billing(state)
        elif issue == "tech":
            tech(state)
        else:
            billing(state)
            tech(state)

    await run_in_langgraph(router, inputs)


async def wf_etl(prefix: str, inputs: dict[str, Any]) -> None:
    validate = agent(f"{prefix}:schema_validator", "tool_vendor")(lambda state: state)
    reducer = agent(f"{prefix}:reducer", "data_org")(lambda state: state)
    parsers = [
        agent(f"{prefix}:parser_{index}", "data_org")(
            lambda state, validator=validate, reduce=reducer: (validator(state), reduce(state))
        )
        for index in (1, 2, 3)
    ]

    @agent(f"{prefix}:ingest", "data_org")
    def ingest(state: TraceState):
        for parser in parsers:
            parser(state)

    await run_in_langgraph(ingest, inputs)


async def wf_multitenant(prefix: str, inputs: dict[str, Any]) -> None:
    db = agent(f"{prefix}:db_agent", "infra_vendor")(lambda state: state)
    cache = agent(f"{prefix}:cache_agent", "infra_vendor")(lambda state: state)
    infra = agent(f"{prefix}:infra_worker", "infra_vendor")(lambda state: (db(state), cache(state)))
    tenant_a = agent(f"{prefix}:tenant_a_orchestrator", "tenant_a")(lambda state: infra(state))
    tenant_b = agent(f"{prefix}:tenant_b_orchestrator", "tenant_b")(lambda state: infra(state))

    @agent(f"{prefix}:tenant_scheduler", "federation_root")
    def scheduler(state: TraceState):
        tenant_a(state)
        tenant_b(state)

    await run_in_langgraph(scheduler, inputs)


async def wf_rag(prefix: str, inputs: dict[str, Any]) -> None:
    rerank = agent(f"{prefix}:reranker", "tool_vendor")(lambda state: state)
    dense = agent(f"{prefix}:retriever_dense", "rag_org")(lambda state: rerank(state))
    sparse = agent(f"{prefix}:retriever_sparse", "rag_org")(lambda state: rerank(state))
    generator = agent(f"{prefix}:generator", "rag_org")(lambda state: state)

    @agent(f"{prefix}:query_planner", "rag_org")
    def query_planner(state: TraceState):
        dense(state)
        sparse(state)
        generator(state)

    await run_in_langgraph(query_planner, inputs)


async def wf_travel(prefix: str, inputs: dict[str, Any]) -> None:
    pay = agent(f"{prefix}:payment_tool", "payments_vendor")(lambda state: state)
    flight = agent(f"{prefix}:flight_agent", "travel_org")(lambda state: pay(state))
    hotel = agent(f"{prefix}:hotel_agent", "travel_org")(lambda state: pay(state))
    car = agent(f"{prefix}:car_agent", "travel_org")(lambda state: pay(state))
    confirm = agent(f"{prefix}:confirmation", "travel_org")(lambda state: state)

    @agent(f"{prefix}:coordinator", "travel_org")
    def coordinator(state: TraceState):
        flight(state)
        hotel(state)
        car(state)
        confirm(state)

    await run_in_langgraph(coordinator, inputs)


async def wf_incident(prefix: str, inputs: dict[str, Any]) -> None:
    runbook = agent(f"{prefix}:runbook_executor", "sre_tools")(lambda state: state)
    triage_net = agent(f"{prefix}:triage_net", "sre_team_a")(lambda state: runbook(state))
    triage_app = agent(f"{prefix}:triage_app", "sre_team_b")(lambda state: runbook(state))
    reporter = agent(f"{prefix}:reporter", "sre_root")(lambda state: state)

    @agent(f"{prefix}:detector", "sre_root")
    def detector(state: TraceState):
        triage_net(state)
        triage_app(state)
        reporter(state)

    await run_in_langgraph(detector, inputs)


WorkflowBuilder = Callable[[str, dict[str, Any]], Any]

FIXED_WORKFLOWS: list[tuple[str, WorkflowBuilder, dict[str, Any]]] = [
    ("research", wf_research, {"permission": permission("documents", "read")}),
    ("code", wf_code, {"permission": permission("repository", "write")}),
    ("etl", wf_etl, {"permission": permission("records", "transform")}),
    ("multitenant", wf_multitenant, {"permission": permission("records", "read")}),
    ("rag", wf_rag, {"permission": permission("documents", "read")}),
    ("travel", wf_travel, {"permission": permission("payments", "charge")}),
    ("incident", wf_incident, {"permission": permission("incidents", "execute")}),
]


def support_specs() -> list[tuple[str, WorkflowBuilder, dict[str, Any]]]:
    specs = []
    for issue in ("billing", "tech", "ambiguous"):
        for severity in range(1, 7):
            specs.append(
                (
                    f"support-{issue}-sev{severity}",
                    wf_support,
                    {
                        "issue": issue,
                        "severity": severity,
                        "permission": permission("tickets", "resolve", "support"),
                    },
                )
            )
    return specs


async def collect() -> list[dict[str, Any]]:
    global _CTX
    rows: list[dict[str, Any]] = []
    specs = FIXED_WORKFLOWS + support_specs()
    for repeat in range(REPEATS):
        for name, builder, inputs in specs:
            trace_id = f"langgraph-{name}-r{repeat:03d}"
            _CTX = TraceContext(
                trace_id=trace_id,
                workflow=name.split("-")[0],
                input_cell=name,
                repeat=repeat,
                inputs=inputs,
            )
            try:
                await builder(name, inputs)
                _CTX.emit(
                    "trace",
                    "trace_summary",
                    inputs=inputs,
                    observed_nodes=dict(sorted(_CTX.nodes.items())),
                    observed_node_count=len(_CTX.nodes),
                    observed_delegation_count=sum(
                        event["kind"] == "delegation" for event in _CTX.events
                    ),
                    observed_framework_event_count=sum(
                        event["kind"] == "framework" for event in _CTX.events
                    ),
                )
                rows.extend(_CTX.events)
            finally:
                _CTX = None
    return rows


def main() -> None:
    rows = asyncio.run(collect())
    write_jsonl(OUTPUT_PATH, rows)
    trace_ids = {row["trace_id"] for row in rows}
    delegation_events = sum(row["kind"] == "delegation" for row in rows)
    framework_events = sum(row["kind"] == "framework" for row in rows)
    print(
        "E16 collect: "
        f"traces={len(trace_ids)} raw_events={len(rows)} "
        f"framework_events={framework_events} delegation_events={delegation_events} "
        f"output={OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()

