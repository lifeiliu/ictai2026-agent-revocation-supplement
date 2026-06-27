"""Normalize raw E16 framework traces into signed delegation events."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from common import (
    EPOCH_ID,
    NORMALIZED_TRACE_PATH,
    PUBLIC_KEYS_PATH,
    RAW_TRACE_PATH,
    canonical_bytes,
    deterministic_keypair,
    edge_identifier,
    read_jsonl,
    stable_hash,
    write_json,
    write_jsonl,
)

from revocation.crypto import sign
from revocation.dag import DelegationEdge

INPUT_PATH = Path(os.getenv("E16_RAW_INPUT", RAW_TRACE_PATH))
OUTPUT_PATH = Path(os.getenv("E16_NORMALIZED_OUTPUT", NORMALIZED_TRACE_PATH))
KEYS_PATH = Path(os.getenv("E16_PUBLIC_KEYS_OUTPUT", PUBLIC_KEYS_PATH))


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


def normalize(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    normalized = []
    domains = set()
    for row in rows:
        if row.get("kind") != "delegation" or row.get("event_type") != "delegate":
            continue
        domains.add(row["caller_deployer"])
        domains.add(row["callee_deployer"])
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
    public_keys = {
        domain: {
            "key_id": deterministic_keypair(domain).key_id,
            "public_key": deterministic_keypair(domain).public_bytes.hex(),
        }
        for domain in sorted(domains)
    }
    return normalized, public_keys


def main() -> None:
    rows = read_jsonl(INPUT_PATH)
    normalized, public_keys = normalize(rows)
    write_jsonl(OUTPUT_PATH, normalized)
    write_json(KEYS_PATH, {"epoch_id": EPOCH_ID, "domains": public_keys})
    print(
        "E16 normalize: "
        f"raw_events={len(rows)} signed_delegation_events={len(normalized)} "
        f"domains={len(public_keys)} output={OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()

