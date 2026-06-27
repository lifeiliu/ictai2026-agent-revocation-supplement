# E18 Cross-Framework Agent Demo

This artifact checks whether the signed delegation-event schema used in E16 can
also represent task handoffs shaped like other agent frameworks.

It is deliberately small and is not a production AutoGen or CrewAI deployment.
The raw events model the framework-level caller-to-callee facts that such
systems expose or that an application-level instrumentation layer can record.
Only events with a caller, callee, permission tuple, and deployer labels are
normalized into signed delegation decisions.

Run:

```bash
python3 run.py
```

Outputs:

- `traces/cross_framework_raw.jsonl`
- `traces/normalized_events.jsonl`
- `e18_results.json`

