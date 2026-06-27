"""Command-line wrapper for the signed-DAG revocation contract API."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .api import RevocationBundle, RevocationContract


def _summary(bundle: RevocationBundle) -> dict[str, object]:
    return {
        "verified": bundle.verify(),
        "revoked_edges": bundle.revoked_edges,
        "target": bundle.target,
        "target_count": len(bundle.target),
        "epoch_id": bundle.manifest.epoch_id,
    }


def _cmd_revoke(args: argparse.Namespace) -> int:
    contract = RevocationContract.from_jsonl(args.trace, epoch_id=args.epoch)
    bundle = contract.revoke_and_prove(args.edge, revoked_at=args.revoked_at)
    bundle.to_path(args.out)
    print(json.dumps({**_summary(bundle), "proof": str(Path(args.out))}, sort_keys=True))
    return 0 if bundle.verify() else 1


def _cmd_verify(args: argparse.Namespace) -> int:
    bundle = RevocationBundle.from_path(args.proof)
    print(json.dumps(_summary(bundle), sort_keys=True))
    return 0 if bundle.verify() else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m revocation.cli",
        description="Issue and verify proof-carrying signed-DAG edge revocations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    revoke = subparsers.add_parser(
        "revoke",
        help="load normalized agent events and export a revocation proof bundle",
    )
    revoke.add_argument("--trace", required=True, help="normalized JSONL delegation trace")
    revoke.add_argument("--edge", required=True, help="edge_id to revoke")
    revoke.add_argument("--out", required=True, help="path for the proof bundle JSON")
    revoke.add_argument("--epoch", default=None, help="override the trace epoch id")
    revoke.add_argument(
        "--revoked-at",
        type=float,
        default=1.0,
        help="revocation timestamp; defaults to 1.0 for reproducible artifacts",
    )
    revoke.set_defaults(func=_cmd_revoke)

    verify = subparsers.add_parser(
        "verify",
        help="verify a proof bundle without the original DAG",
    )
    verify.add_argument("--proof", required=True, help="proof bundle JSON from revoke")
    verify.set_defaults(func=_cmd_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
