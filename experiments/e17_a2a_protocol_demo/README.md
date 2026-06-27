# E17 A2A-Shaped Protocol Demo

E17 is a small artifact-level portability demo. It does not implement the full
A2A protocol stack and is not a prevalence study. It models A2A-style task
handoffs as caller-to-callee messages, then emits the same normalized signed
delegation-event schema used by E16.

Run:

```sh
python3 experiments/e17_a2a_protocol_demo/run.py
```

Outputs:

- `traces/a2a_raw.jsonl`: A2A-shaped task-handoff events.
- `traces/normalized_events.jsonl`: signed delegation decisions with the same
  core fields as E16 (`trace_id`, `framework`, `caller`, `callee`,
  `parent_domain`, `child_domain`, `permission`, `edge_id`, signatures).
- `e17_results.json`: edge-target and approximation checks.

Current result:

- 2 trace units.
- 8/8 signed delegation decisions validate.
- 1/1 alternate-parent case is preserved by the edge target and wrongly revoked
  by tree cascade.
- 6/6 cross-domain target cases are under-revoked by deployer-scoped cascade.

Interpretation: E17 supports schema portability. The paper should not use it as
statistical evidence about A2A deployments.
