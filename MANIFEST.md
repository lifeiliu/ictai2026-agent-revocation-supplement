# Artifact Manifest

## Top Level

- `README.md`: reviewer-facing setup and reproduction guide.
- `MANIFEST.md`: this file.
- `requirements-core.txt`: core runtime dependencies.
- `requirements-dev.txt`: core dependencies plus `pytest`.
- `scripts/check_artifact.py`: dependency-free result consistency check.

## Source

- `src/revocation/`: signed delegation DAGs, revocation targets, prototype
  verifier, cryptographic helpers, and trace generators.
- `src/revocation/api.py`: small reviewer-facing API for loading normalized
  agent events, issuing edge revocations, exporting proof bundles, and verifying
  them without the original graph.
- `src/revocation/cli.py`: command-line wrapper around the API.
- `examples/agent_runtime_adapter.py`: tiny E19 adapter example that turns
  normalized CrewAI handoff events into a verified revocation proof.
- `tests/unit/`: unit tests for graph, granularity, revocation, and prototype
  behavior, including the API/CLI smoke tests.

## Experiments

- `experiments/e4_ba_scale/`: generated DAG stress-test scripts.
- `experiments/e5_case_study/`: RBAC-inspired multi-parent case study.
- `experiments/e6_semantic_stress/`: batch revocation and edge-selection
  sensitivity.
- `experiments/e8_prototype/`: proof-carrying target prototype and mutation
  tests.
- `experiments/e11_oss_corpus/`: static LangGraph corpus extraction outputs.
- `experiments/e16_framework_trace_replay/`: executed LangGraph trace replay,
  normalized signed events, and baseline expressiveness results.
- `experiments/e17_a2a_protocol_demo/`: A2A-shaped portability artifact.
- `experiments/e18_cross_framework_agent_demo/`: AutoGen/CrewAI-shaped
  portability artifact.
- `experiments/e19_crewai_executable_demo/`: pinned CrewAI executable artifact.

## Results

- `results/e6_semantic_stress.json`
- `results/e8_protocol_results.json`
- `results/e13_sensitivity.json`

Experiment-local result files are kept next to the corresponding experiment
directories.
