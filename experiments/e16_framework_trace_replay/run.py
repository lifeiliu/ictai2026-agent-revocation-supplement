"""Run the full E16 collection, normalization, and replay pipeline."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(script: str) -> None:
    subprocess.run([sys.executable, str(HERE / script)], check=True)


def main() -> None:
    run("collect_langgraph.py")
    run("normalize.py")
    run("replay.py")
    run("baseline_expressiveness.py")


if __name__ == "__main__":
    main()
