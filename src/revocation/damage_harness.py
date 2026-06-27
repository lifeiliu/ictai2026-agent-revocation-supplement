"""Parametric sweep driver for stale-authority damage measurement (Paper A E2/E3).

Damage formula:
  worst case:    unauthorized_ops = agent_velocity × (TTL + delta_prop)
  expected case: unauthorized_ops = agent_velocity × (TTL/2 + delta_prop)
  (both clamped to 0). The expected case assumes revocation arrives uniformly
  in the credential period and is what the Poisson stream simulation validates.

E3 harness design (corrected):
  ALL granularity mechanisms are compared against T_2 (L2) as the canonical ideal.
  This correctly shows:
    L2          → OverRev=0, UnderRev=0  (by definition — it IS the ideal)
    tree_cascade → OverRev>0 on multi-parent DAGs (alternate-path nodes wrongly revoked)
    L0, L1      → OverRev>0 (coarser than L2; revoke more than necessary)
    L3          → UnderRev>0 when T_2 is non-empty (only revokes the single node)
    deployer_scoped → UnderRev>0 when T_2 includes cross-deployer descendants
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass
from itertools import product
from typing import Literal

from .dag import DelegationDAG
from .granularity import target_set_l0, target_set_l1, target_set_l2, target_set_l3
from .revocation import (
    apply_l2_revocation,
    apply_tree_cascade,
    apply_tree_cascade_deployer_scoped,
    over_revocation,
    under_revocation,
)
from .trace_gen import (
    TopologyType,
    count_multiparent_nodes,
    generate_adversarial_shared_subdag,
    generate_cross_deployer_dag,
    generate_multiparent_dag,
    generate_tree,
)

GranularityLabel = Literal["L0", "L1", "L2", "L3", "tree_cascade", "deployer_scoped"]


@dataclass(frozen=True)
class SweepParams:
    ttl: float
    agent_velocity: float
    chain_depth: int
    topology: TopologyType
    granularity: GranularityLabel
    delta_prop: float = 0.0


@dataclass
class SweepResult:
    params: SweepParams
    unauthorized_ops: float
    w_eff: float
    over_rev_count: int
    under_rev_count: int
    num_nodes: int
    num_edges: int
    num_multiparent_nodes: int
    wall_time_ms: float


def w_eff(ttl: float, velocity: float = 0.0, delta_prop: float = 0.0) -> float:
    """Worst-case effective staleness window.

    The worst case is a revocation issued the instant a credential is granted:
    the agent then acts for the entire credential lifetime plus the propagation
    delay before any relying party observes the revocation. Hence
        W_eff = TTL + delta_prop.
    The ``velocity`` argument is accepted for call-site compatibility but is not
    used (the earlier ``- 1/v`` correction term was removed: it conflated
    "time to first operation" with the window and made code, text, and figure
    disagree).
    """
    return max(0.0, ttl + delta_prop)


def w_eff_expected(ttl: float, delta_prop: float = 0.0) -> float:
    """Expected staleness window under a revocation arriving uniformly in the
    credential period: E[remaining TTL] = TTL/2, plus propagation delay."""
    return max(0.0, ttl / 2.0 + delta_prop)


def unauthorized_ops(ttl: float, velocity: float, delta_prop: float = 0.0) -> float:
    """Worst-case unauthorized operations = velocity x (TTL + delta_prop)."""
    return velocity * w_eff(ttl, delta_prop=delta_prop)


def unauthorized_ops_expected(ttl: float, velocity: float, delta_prop: float = 0.0) -> float:
    """Expected unauthorized operations under uniform revocation arrival.

    Matches the mean of the Poisson stream simulation in
    ``simulate_ops_empirical``: velocity x (TTL/2 + delta_prop)."""
    return velocity * w_eff_expected(ttl, delta_prop=delta_prop)


def simulate_ops_empirical(
    ttl: float,
    velocity: float,
    n_trials: int = 1000,
    seed: int = 42,
    delta_prop: float = 0.0,
) -> list[float]:
    """Empirically simulate unauthorized_ops via Poisson operation stream.

    Model:
      - Agent performs operations as a Poisson process with rate=velocity ops/s.
      - Revocation event fires at a random time t_rev ~ Uniform(0, TTL).
      - Enforcement propagates in delta_prop seconds after t_rev.
      - Count operations that land in (t_rev, t_rev + delta_prop + remaining_TTL].
      - Repeat n_trials times; return raw counts.

    The mean of this distribution should match the analytical formula
    unauthorized_ops = velocity × W_eff.
    """
    rng = random.Random(seed)
    results: list[float] = []

    for _ in range(n_trials):
        t_rev = rng.uniform(0.0, ttl)
        # Operations after t_rev until enforcement (t_rev + delta_prop + leftover TTL)
        # Simplified: stale window = delta_prop + (TTL - t_rev), min 0
        stale_window = max(0.0, delta_prop + (ttl - t_rev))
        # Poisson: number of events in [t_rev, t_rev + stale_window]
        # E[N] = velocity × stale_window, actual N ~ Poisson(λ=velocity × stale_window)
        lam = velocity * stale_window
        # Poisson sample via Knuth's algorithm (exact for modest λ)
        if lam > 30:
            count = max(0.0, rng.gauss(lam, math.sqrt(lam)))
        else:
            count = 0.0
            p = math.exp(-lam) if lam < 700 else 0.0
            F = p
            u = rng.random()
            while F < u and count < lam * 10:
                count += 1
                p *= lam / count
                F += p
        results.append(float(count))

    return results


# ---------- DAG factory ----------

def _build_dag(params: SweepParams, seed: int) -> DelegationDAG:
    if params.topology == "tree":
        return generate_tree(depth=params.chain_depth, branching_factor=2)
    if params.topology == "multiparent":
        n = 2 ** (params.chain_depth + 1) - 1
        return generate_multiparent_dag(num_nodes=n, shared_ratio=0.35, seed=seed)
    if params.topology == "adversarial":
        return generate_adversarial_shared_subdag()
    if params.topology == "cross_deployer":
        return generate_cross_deployer_dag()
    raise ValueError(f"unknown topology: {params.topology!r}")


# ---------- Single sweep cell ----------

def run_single(params: SweepParams, seed: int = 42) -> SweepResult:
    """Run one sweep cell.

    IMPORTANT: ALL mechanisms are compared against T_2 (L2) as the canonical
    intended target for the chosen edge. This is the corrected design: it
    answers "what happens if you use mechanism X when L2 precision is needed?"
    """
    t0 = time.perf_counter()
    dag = _build_dag(params, seed)
    nodes = dag.all_nodes()
    edges = dag.all_edges()
    roots = dag.roots()
    mp_count = count_multiparent_nodes(dag)

    root_ids = {r.node_id for r in roots}
    candidate = next(
        (e for e in edges if e.parent_id not in root_ids),
        edges[0] if edges else None,
    )

    zero = SweepResult(
        params=params, unauthorized_ops=0.0, w_eff=0.0,
        over_rev_count=0, under_rev_count=0,
        num_nodes=len(nodes), num_edges=len(edges),
        num_multiparent_nodes=mp_count, wall_time_ms=0.0,
    )
    if not candidate:
        return zero

    child_id = candidate.child_id
    # Canonical intended target: L2 for the chosen edge
    intended = target_set_l2(dag, candidate.edge_id)

    if params.granularity == "L2":
        revoked_set = apply_l2_revocation(dag, candidate.edge_id)

    elif params.granularity == "tree_cascade":
        revoked_set = apply_tree_cascade(dag, child_id)

    elif params.granularity == "deployer_scoped":
        deployer_id = dag.node(candidate.parent_id).deployer_id
        revoked_set = apply_tree_cascade_deployer_scoped(dag, child_id, deployer_id)

    elif params.granularity == "L0":
        deployer_id = dag.node(candidate.parent_id).deployer_id
        revoked_set = target_set_l0(dag, deployer_id)

    elif params.granularity == "L1":
        paths = dag.all_paths_to(child_id)
        if paths:
            path = next(
                (p for p in paths if any(e.edge_id == candidate.edge_id for e in p)),
                paths[0],
            )
            revoked_set = target_set_l1(dag, [e.edge_id for e in path])
        else:
            revoked_set = {child_id}

    elif params.granularity == "L3":
        # L3: only the single node — under-revokes descendants relative to L2
        revoked_set = target_set_l3(dag, child_id, "seg0")

    else:
        revoked_set = set()

    unauth = unauthorized_ops(params.ttl, params.agent_velocity, params.delta_prop)
    weff = w_eff(params.ttl, params.agent_velocity, params.delta_prop)
    over = over_revocation(revoked_set, intended)
    under = under_revocation(revoked_set, intended)
    ms = (time.perf_counter() - t0) * 1000

    return SweepResult(
        params=params,
        unauthorized_ops=unauth,
        w_eff=weff,
        over_rev_count=over,
        under_rev_count=under,
        num_nodes=len(nodes),
        num_edges=len(edges),
        num_multiparent_nodes=mp_count,
        wall_time_ms=ms,
    )


# ---------- Full sweep ----------

DEFAULT_TTL: list[float] = [5.0, 30.0, 60.0, 300.0, 900.0]
DEFAULT_VELOCITY: list[float] = [0.1, 1.0, 10.0, 100.0]
DEFAULT_DEPTH: list[int] = [2, 5, 10, 20]
DEFAULT_TOPOLOGIES: list[TopologyType] = ["tree", "multiparent", "adversarial"]
DEFAULT_GRANULARITIES: list[GranularityLabel] = [
    "L0", "L1", "L2", "L3", "tree_cascade", "deployer_scoped"
]


def run_sweep(
    ttl_values: list[float] = DEFAULT_TTL,
    velocity_values: list[float] = DEFAULT_VELOCITY,
    depth_values: list[int] = DEFAULT_DEPTH,
    topologies: list[TopologyType] = DEFAULT_TOPOLOGIES,
    granularities: list[GranularityLabel] = DEFAULT_GRANULARITIES,
    seed: int = 42,
) -> list[SweepResult]:
    results: list[SweepResult] = []
    for ttl, vel, depth, topo, gran in product(
        ttl_values, velocity_values, depth_values, topologies, granularities
    ):
        p = SweepParams(ttl=ttl, agent_velocity=vel, chain_depth=depth,
                        topology=topo, granularity=gran)
        try:
            results.append(run_single(p, seed=seed))
        except Exception as exc:
            print(f"WARN: cell {p} failed: {exc}")
    return results
