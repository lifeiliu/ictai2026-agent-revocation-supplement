"""Tiny agent-runtime adapter example for the revocation contract API.

Run from the artifact root with:

    PYTHONPATH=src python examples/agent_runtime_adapter.py
"""

from __future__ import annotations

import json
from pathlib import Path

from revocation import RevocationContract, load_jsonl_events


ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "experiments/e19_crewai_executable_demo/traces/normalized_events.jsonl"


def main() -> None:
    events = load_jsonl_events(TRACE)
    revoked_edge = events[-1]["edge_id"]
    contract = RevocationContract.from_events(events)
    bundle = contract.revoke_and_prove(revoked_edge, revoked_at=1.0)
    print(
        json.dumps(
            {
                "trace": str(TRACE.relative_to(ROOT)),
                "revoked_edge": revoked_edge,
                "target": bundle.target,
                "verified_without_graph": bundle.verify(),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
