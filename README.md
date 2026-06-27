# Anonymous Artifact for ICTAI 2026 Review

This artifact accompanies the submission on authority-preserving edge
revocation for federated AI-agent workflows. It contains the code and data
needed to reproduce the main reported measurements without exposing author
identity or local machine paths.

The artifact is intentionally scoped to the experiments used by the paper:

- E6: batch non-compositionality and event-selection sensitivity.
- E8: signed revocation prototype, proof verification, and mutation rejection.
- E11: static LangGraph corpus summary used as lower-bound topology evidence.
- E16: executed LangGraph trace replay and baseline expressiveness.
- E17/E18: A2A-, AutoGen-, and CrewAI-shaped portability artifacts.
- E19: tiny executable CrewAI artifact with a deterministic local LLM.

It excludes local virtual environments, caches, personal paths, and deployment
logs that are not used as evidence in the submitted paper.

## Quick Check

From the artifact root:

```bash
python3 scripts/check_artifact.py
```

This checks the existing result files against the paper's key reported numbers.
It does not require installing dependencies.

## Core Environment

For core experiments and unit tests:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements-dev.txt
PYTHONPATH=src .venv/bin/python -m pytest tests
```

## Reproducing Selected Experiments

The result files used by the paper are already included. To rerun selected
lightweight experiments:

```bash
PYTHONPATH=src .venv/bin/python experiments/e17_a2a_protocol_demo/run.py
PYTHONPATH=src .venv/bin/python experiments/e18_cross_framework_agent_demo/run.py
```

E19 uses CrewAI and has its own pinned dependency file:

```bash
cd experiments/e19_crewai_executable_demo
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=../../src .venv/bin/python run.py
```

E16 includes the recorded raw and normalized LangGraph traces used in the paper.
The full rerun requires installing LangGraph in addition to the core
dependencies, but the included `e16_results.json`,
`e16_baseline_expressiveness.json`, and trace files are sufficient to audit the
reported table values.

## Reference API and CLI

The artifact also includes a small reference API/CLI for the signed-DAG
revocation contract. It is a reviewer-facing integration layer, not a production
authorization service.

Run the tiny E19 adapter example:

```bash
PYTHONPATH=src .venv/bin/python examples/agent_runtime_adapter.py
```

Generate and verify a portable proof bundle from the E19 CrewAI trace:

```bash
PYTHONPATH=src .venv/bin/python -m revocation.cli revoke \
  --trace experiments/e19_crewai_executable_demo/traces/normalized_events.jsonl \
  --edge 404b317115476b4224e04937 \
  --out /tmp/e19-revocation-proof.json

PYTHONPATH=src .venv/bin/python -m revocation.cli verify \
  --proof /tmp/e19-revocation-proof.json
```

Both commands should report `verified: true`; the proof verification does not
require the original graph.

## Expected Key Results

- E16: 500 traces, 10,500 raw runtime events, 2,000 valid signed delegation
  decisions, 320 alternate-parent cases, 760/760 replay-level attacks rejected.
- E17--E19: 5 portability traces, 25/25 valid signed delegation events, 4/4
  alternate-parent cases preserved by the edge target, and 11/11 cross-domain
  target cases missed by deployer-scoped cascade.
- E6: 39,991 sampled batch revocation sets, 21.25% mean per-graph
  non-compositionality failure, mean missed nodes 0.24, max missed nodes 5.
- E8: target computation 0.17--2.15 ms up to 2,000 nodes, proof/full wire ratio
  64.7--69.0%, and 1,100/1,100 malformed cases rejected.

## Files

See `MANIFEST.md` for a directory-level map of the artifact.
