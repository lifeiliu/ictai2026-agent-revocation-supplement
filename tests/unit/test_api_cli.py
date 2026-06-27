from __future__ import annotations

import json

from revocation.api import RevocationBundle, RevocationContract
from revocation.cli import main as cli_main


def _events() -> list[dict[str, object]]:
    return [
        {
            "caller": "root:a",
            "callee": "agent:a",
            "parent_domain": "root_domain",
            "child_domain": "domain_a",
            "edge_id": "e-root-a",
            "epoch_id": "api-demo-epoch",
            "permission": {"tenant": "t", "resource": "case", "action": "read"},
        },
        {
            "caller": "root:b",
            "callee": "agent:b",
            "parent_domain": "root_domain",
            "child_domain": "domain_b",
            "edge_id": "e-root-b",
            "epoch_id": "api-demo-epoch",
            "permission": {"tenant": "t", "resource": "case", "action": "read"},
        },
        {
            "caller": "agent:a",
            "callee": "agent:shared",
            "parent_domain": "domain_a",
            "child_domain": "shared_domain",
            "edge_id": "e-a-shared",
            "epoch_id": "api-demo-epoch",
            "permission": {"tenant": "t", "resource": "case", "action": "read"},
        },
        {
            "caller": "agent:b",
            "callee": "agent:shared",
            "parent_domain": "domain_b",
            "child_domain": "shared_domain",
            "edge_id": "e-b-shared",
            "epoch_id": "api-demo-epoch",
            "permission": {"tenant": "t", "resource": "case", "action": "read"},
        },
        {
            "caller": "agent:shared",
            "callee": "agent:leaf",
            "parent_domain": "shared_domain",
            "child_domain": "leaf_domain",
            "edge_id": "e-shared-leaf",
            "epoch_id": "api-demo-epoch",
            "permission": {"tenant": "t", "resource": "case", "action": "write"},
        },
    ]


def test_revocation_contract_exports_offline_verifiable_bundle(tmp_path):
    contract = RevocationContract.from_events(_events())
    bundle = contract.revoke_and_prove("e-shared-leaf", revoked_at=1.0)

    assert bundle.target == ["agent:leaf"]
    assert bundle.verify()

    proof_path = tmp_path / "proof.json"
    bundle.to_path(proof_path)
    loaded = RevocationBundle.from_path(proof_path)
    assert loaded.target == ["agent:leaf"]
    assert loaded.verify()


def test_revocation_cli_revoke_and_verify_round_trip(tmp_path, capsys):
    trace_path = tmp_path / "events.jsonl"
    trace_path.write_text("\n".join(json.dumps(event) for event in _events()) + "\n")
    proof_path = tmp_path / "proof.json"

    assert cli_main(
        [
            "revoke",
            "--trace",
            str(trace_path),
            "--edge",
            "e-shared-leaf",
            "--out",
            str(proof_path),
            "--revoked-at",
            "1.0",
        ]
    ) == 0
    revoke_summary = json.loads(capsys.readouterr().out)
    assert revoke_summary["target"] == ["agent:leaf"]
    assert revoke_summary["verified"] is True

    assert cli_main(["verify", "--proof", str(proof_path)]) == 0
    verify_summary = json.loads(capsys.readouterr().out)
    assert verify_summary["target"] == ["agent:leaf"]
    assert verify_summary["verified"] is True
