# E19 CrewAI Executable Demo

This artifact is a tiny executable CrewAI workflow. It uses pinned CrewAI
objects and a deterministic local `BaseLLM`, so it does not require an external
LLM API key. The purpose is portability evidence: CrewAI task execution and
task-context handoffs can be normalized into the same signed delegation-event
schema used by E16/E17/E18.

It is not a production deployment or a prevalence study.

Setup:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

Run:

```bash
.venv/bin/python run.py
```

Outputs:

- `traces/crewai_runtime_raw.jsonl`
- `traces/normalized_events.jsonl`
- `e19_results.json`

The script constructs a small cross-org procurement crew, runs
`Crew.kickoff()`, records task callbacks and context handoffs, signs the
normalized handoffs as delegation credentials, and replays exact edge targets
against tree and deployer-scoped cascades.
