# E16 Framework Trace Replay Schema

E16 separates three evidence layers.

## Raw Trace

`traces/langgraph_raw.jsonl` is emitted by `collect_langgraph.py`.

- `kind=framework`: runtime event from LangGraph `astream_events`.
- `kind=agent`: local start/end marker for an instrumented agent or tool.
- `kind=delegation`: observed application-level invocation from caller to
  callee inside a compiled LangGraph execution.
- `kind=trace`: per-trace summary.

Raw traces are not signed. They are the input to the normalization stage.

## Normalized Signed Events

`traces/normalized_events.jsonl` is emitted by `normalize.py`.

Each row is one signed delegation decision with:

- `trace_id`, `seq`, `framework`, `caller`, `callee`
- `parent_domain`, `child_domain`
- `permission`
- `edge_id`
- `issuer_key_id`
- `decision_signature`
- `edge_signature`

Deterministic experiment keys are used so the anonymous artifact can reproduce
the same signatures. They are not production secrets.

## Replay Result

`e16_results.json` is emitted by `replay.py`.

The replay unit is one complete framework execution trace. Statistics and
bootstrap intervals are computed over trace units, not over individual edges.

## Baseline Expressiveness Result

`e16_baseline_expressiveness.json`, `e16_baseline_expressiveness.csv`, and
`e16_baseline_expressiveness_table.tex` are emitted by
`baseline_expressiveness.py`.

This is a derived target-language analysis over the normalized E16 traces. It
does not collect new framework events. For each single-edge withdrawal it
compares the exact edge target against executable approximations: full-graph
credential revalidation, holder/node revocation, APS-style tree cascade, and
deployer-scoped cascade. Token and chain protocols that do not define a
multi-parent DAG target set are recorded as expressiveness gaps rather than
forced into an executable baseline.
