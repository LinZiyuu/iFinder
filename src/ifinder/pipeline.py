"""Explicit per pattern × target pipeline.

A thin driver runs **DA → VA → EA** and persists the JSON artifacts
(``DiscoveryResult`` → ``VettingResult`` → ``ExploitationResult``).

Supports running a single ``stage`` (downstream stages load the upstream artifact from disk) and a
single ``target`` from the scope.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel

from ifinder import config
from ifinder.agents import DiscoveryAgent, ExploitationAgent, VettingAgent
from ifinder.models import DiscoveryResult, ScopeTarget, VettingResult, VettingVerdict
from ifinder.testbed import TestbedDriver, discover_nf_endpoints

logger = logging.getLogger("ifinder.pipeline")

STAGES = ("discovery", "vetting", "exploitation")


def _write_model(path: Path, model: BaseModel) -> Path:
    """Persist a pydantic artifact as pretty JSON (creates parent dirs)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(model.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


def read_discovery(target: str, pattern_id: str, paths: config.Paths = config.DEFAULT_PATHS) -> DiscoveryResult:
    p = paths.discovery_out(target, pattern_id)
    if not p.exists():
        raise FileNotFoundError(f"discovery artifact required first: {p}")
    return DiscoveryResult.model_validate_json(p.read_text(encoding="utf-8"))


def read_vetting(target: str, pattern_id: str, paths: config.Paths = config.DEFAULT_PATHS) -> VettingResult:
    p = paths.vetting_out(target, pattern_id)
    if not p.exists():
        raise FileNotFoundError(f"vetting artifact required first: {p}")
    return VettingResult.model_validate_json(p.read_text(encoding="utf-8"))


def build_coverage_map(procedures: dict, schema: dict) -> dict[str, Any]:
    """Derive the message × IE audit space DA must cover, from the message schema.

    Granularity: message -> its top-level IE names (DA descends into grouped IEs during analysis).
    """
    messages_in = (schema.get("message_schemas") or {}).get("messages", {})
    out_messages: dict[str, Any] = {}
    total_ies = 0
    for mname, mdef in messages_in.items():
        ies = list((mdef or {}).get("ies", {}).keys())
        out_messages[mname] = {"ies": ies}
        total_ies += len(ies)
    return {"total_messages": len(out_messages), "total_ies": total_ies, "messages": out_messages}


async def run_pattern_target(
    *,
    pattern_id: str,
    target: ScopeTarget,
    procedures: dict,
    schema: dict,
    testbed: Optional[TestbedDriver] = None,
    paths: config.Paths = config.DEFAULT_PATHS,
    run_exploitation: bool = True,
    stage: Optional[str] = None,
    model: str = config.DEFAULT_MODEL,
    nf_hosts: Optional[dict[str, str]] = None,
    nf_log_services: Optional[dict[str, str]] = None,
    candidate_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Run one (pattern, target). ``stage`` = None runs the full pipeline; otherwise only that stage
    (downstream stages load their input artifact from disk)."""
    want_da = stage in (None, "discovery")
    want_va = stage in (None, "vetting")
    want_ea = (testbed is not None) and (stage == "exploitation" or (stage is None and run_exploitation))
    if stage == "exploitation" and testbed is None:
        logger.warning("exploitation requested for %s/%s but no testbed; skipping", target.name, pattern_id)

    discovery: Optional[DiscoveryResult] = None
    vetting: Optional[VettingResult] = None
    exploitation_results = []

    if want_da:
        pattern = config.load_pattern(pattern_id, paths)
        coverage_map = build_coverage_map(procedures, schema)
        discovery = await DiscoveryAgent(model=model, paths=paths).run(
            pattern=pattern, target=target, coverage_map=coverage_map
        )
        _write_model(paths.discovery_out(target.name, pattern_id), discovery)
        logger.info("DA %s/%s: %d candidates", target.name, pattern_id, len(discovery.candidates))
    elif stage in ("vetting", "exploitation"):
        discovery = read_discovery(target.name, pattern_id, paths)

    if want_va:
        vetting = await VettingAgent(model=model, paths=paths).run(
            discovery=discovery, target=target, procedures=procedures
        )
        _write_model(paths.vetting_out(target.name, pattern_id), vetting)
        logger.info("VA %s/%s: %d feasible", target.name, pattern_id, vetting.statistics.feasible)
    elif stage == "exploitation":
        vetting = read_vetting(target.name, pattern_id, paths)


    if want_ea:
        ea = ExploitationAgent(model=model, paths=paths)
        by_id = {c.id: c for c in discovery.candidates}
        for decision in vetting.results:
            if decision.verdict is not VettingVerdict.FEASIBLE:
                continue
            if candidate_ids and decision.candidate_id not in candidate_ids:
                continue  # --candidate filter: only exploit the requested id(s)
            candidate = by_id.get(decision.candidate_id)
            if candidate is None:
                continue
            result = await ea.run(
                candidate=candidate, decision=decision, target=target, testbed=testbed,
                schema=schema, nf_hosts=nf_hosts, nf_log_services=nf_log_services,
            )
            _write_model(paths.exploitation_out(target.name, decision.candidate_id), result)
            exploitation_results.append(result)

    return {"discovery": discovery, "vetting": vetting, "exploitation": exploitation_results}


def _find_compose(target: ScopeTarget, paths: config.Paths) -> Optional[Path]:
    """Locate a target's docker-compose by convention; return None if not found."""
    candidates = [
        paths.target_dir / target.name / "docker-compose.yaml",
        paths.target_dir / target.name / "docker-compose.yml",
        paths.root / "testbed" / target.name / "docker-compose.yaml",
        paths.root / "testbed" / target.name / "docker-compose.yml",
    ]
    return next((p for p in candidates if p.exists()), None)


async def run_scope(
    *,
    scope_file: str | Path,
    pattern_ids: list[str],
    paths: config.Paths = config.DEFAULT_PATHS,
    run_exploitation: bool = True,
    target: Optional[str] = None,
    stage: Optional[str] = None,
    model: str = config.DEFAULT_MODEL,
    compose_file: Optional[str | Path] = None,
    env_file: Optional[str | Path] = None,
    manage_testbed: bool = True,
    candidate_ids: Optional[list[str]] = None,
) -> None:
    """Run ``pattern_ids`` across the scope. ``target`` selects one target by name; ``stage`` runs only
    that stage (DA → VA → EA when None).

    ``compose_file`` / ``env_file`` / ``manage_testbed`` configure the EA testbed: an explicit compose
    path (overriding auto-discovery), an optional docker-compose env-file, and whether to manage the
    stack lifecycle (False = reuse an already-running one). Per-NF routing (N4 host + container to
    restart/scrape) is auto-derived from the compose file via
    :func:`ifinder.testbed.discover_nf_endpoints` and pinned by ``candidate.network_function``."""
    if stage is not None and stage not in STAGES:
        raise ValueError(f"stage must be one of {STAGES}, got {stage!r}")

    scope = config.load_scope(scope_file, paths)

    # Each scope target carries its own protocol (pfcp / gtpc); load + cache the matching
    # schema/procedure KB per protocol so a single scope may even mix protocols.
    _kb: dict[str, tuple[config.Paths, dict, dict]] = {}

    def kb_for(protocol: str) -> tuple[config.Paths, dict, dict]:
        if protocol not in _kb:
            pp = paths.for_protocol(protocol)
            _kb[protocol] = (pp, config.load_procedures(pp), config.load_schema(pp))
        return _kb[protocol]

    targets = scope.targets
    if target is not None:
        targets = [t for t in targets if t.name == target]
        if not targets:
            raise ValueError(f"target {target!r} not in scope ({[t.name for t in scope.targets]})")

    need_testbed = stage == "exploitation" or (stage is None and run_exploitation)

    for tgt in targets:
        tpaths, procedures, schema = kb_for(tgt.protocol)
        testbed: Optional[TestbedDriver] = None
        nf_hosts: Optional[dict[str, str]] = None
        nf_log_services: Optional[dict[str, str]] = None
        if need_testbed:
            compose = Path(compose_file) if compose_file else _find_compose(tgt, paths)
            if compose is None:
                logger.warning("no docker-compose for target %s; EA will be skipped", tgt.name)
            elif not Path(compose).exists():
                logger.warning("compose file %s not found; EA will be skipped", compose)
            else:
                # Auto-derive per-NF routing from the compose file for this target's protocol
                # (PFCP: UPF/SMF; GTP-C: SGW-C/PGW-C/MME) — service name + ipv4.
                endpoints = discover_nf_endpoints(Path(compose), tgt.protocol)
                nf_hosts = {nf: info["host"] for nf, info in endpoints.items()}
                nf_log_services = {nf: info["service"] for nf, info in endpoints.items()}
                default_nf = "UPF" if tgt.protocol == "pfcp" else "SGW-C"
                default_log = (endpoints.get(default_nf) or next(iter(endpoints.values()), {})).get(
                    "service", default_nf.lower()
                )
                logger.info("EA NF routing for %s (from %s): %s", tgt.name, compose, endpoints)
                testbed = TestbedDriver(
                    target=tgt.name,
                    compose_file=Path(compose),
                    log_service=default_log,
                    env_file=Path(env_file) if env_file else None,
                    manage=manage_testbed,
                )

        if testbed is not None:
            await testbed.up()
        try:
            for pattern_id in pattern_ids:
                await run_pattern_target(
                    pattern_id=pattern_id,
                    target=tgt,
                    procedures=procedures,
                    schema=schema,
                    testbed=testbed,
                    paths=tpaths,
                    run_exploitation=run_exploitation,
                    stage=stage,
                    model=model,
                    nf_hosts=nf_hosts,
                    nf_log_services=nf_log_services,
                    candidate_ids=candidate_ids,
                )
        finally:
            if testbed is not None:
                await testbed.down()
