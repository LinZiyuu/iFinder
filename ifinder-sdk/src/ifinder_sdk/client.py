from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ifinder_sdk.config import (
    DiscoveryResult,
    ExploitationResult,
    ProtocolType,
    VettingDecision,
    VettingResult,
    VettingVerdict,
)
from ifinder_sdk.tools import discover_itrue_candidates, exploit_candidate, vet_discovery_result


@dataclass(frozen=True)
class IFinderPaths:
    pattern_dir: Path = Path("pattern")
    procedure_dir: Path = Path("protocol/pfcp/procedure")
    message_schema_path: Path = Path("protocol/pfcp/generated/message_schemas.normalized.json")


class IFinderClient:
    def __init__(self, *, paths: IFinderPaths | None = None) -> None:
        self.paths = paths or IFinderPaths()

    def phase1_discover(
        self,
        *,
        pattern: str | Path | dict[str, Any],
        target_codebase: str | Path,
        scan_dirs: list[str],
        target_version: str = "unknown",
        include_uncertain: bool = True,
        max_candidates: int = 200,
        max_call_depth: int = 8,
    ) -> DiscoveryResult:
        pattern_payload = self._resolve_pattern_input(pattern)
        return discover_itrue_candidates(
            pattern=pattern_payload,
            target_codebase=target_codebase,
            scan_dirs=scan_dirs,
            target_version=target_version,
            include_uncertain=include_uncertain,
            max_candidates=max_candidates,
            max_call_depth=max_call_depth,
        )

    def phase2_vet(
        self,
        *,
        discovery: DiscoveryResult | dict[str, Any],
        target_codebase: str | Path,
        scan_dirs: list[str] | None = None,
        procedure_dir: str | Path | None = None,
        max_handler_hits_per_message: int = 2,
    ) -> VettingResult:
        return vet_discovery_result(
            discovery,
            procedure_dir=procedure_dir or self.paths.procedure_dir,
            target_codebase=target_codebase,
            scan_dirs=scan_dirs,
            max_handler_hits_per_message=max_handler_hits_per_message,
        )

    def phase3_exploit(
        self,
        *,
        discovery: DiscoveryResult | dict[str, Any],
        vetting: VettingResult | dict[str, Any],
        output_root: str | Path,
        protocol: ProtocolType = ProtocolType.PFCP,
        docker_container: str | None = None,
        target_ip: str | None = None,
        local_ip: str | None = None,
        seid: int | None = None,
        timeout: int | None = None,
        max_iterations: int = 5,
        message_schemas: str | Path | dict[str, Any] | None = None,
    ) -> list[ExploitationResult]:
        discovery_obj = (
            discovery if isinstance(discovery, DiscoveryResult) else DiscoveryResult.model_validate(discovery)
        )
        vetting_obj = vetting if isinstance(vetting, VettingResult) else VettingResult.model_validate(vetting)

        candidate_by_id = {cand.id: cand for cand in discovery_obj.candidates}
        feasible_decisions = [
            item for item in vetting_obj.results if item.verdict == VettingVerdict.FEASIBLE
        ]

        target_software = Path(discovery_obj.target_codebase).name
        results: list[ExploitationResult] = []
        schema_source = message_schemas or self.paths.message_schema_path
        for decision in feasible_decisions:
            candidate = candidate_by_id.get(decision.candidate_id)
            if candidate is None:
                continue

            prerequisite_messages = _collect_checked_messages(decision)
            stage3 = exploit_candidate(
                candidate,
                output_root=output_root,
                message_schemas=schema_source,
                prerequisite_messages=prerequisite_messages,
                protocol=protocol,
                docker_container=docker_container,
                target_ip=target_ip,
                local_ip=local_ip,
                seid=seid,
                timeout=timeout,
                max_iterations=max_iterations,
                expected_file=candidate.vulnerable_site.file,
                expected_function=candidate.vulnerable_site.function,
                pattern_id=discovery_obj.pattern_id,
                target_version=discovery_obj.target_version,
                target_software=target_software,
            )
            results.append(stage3["result"])
        return results

    def run_pipeline(
        self,
        *,
        pattern: str | Path | dict[str, Any],
        target_codebase: str | Path,
        scan_dirs: list[str],
        output_root: str | Path,
        target_version: str = "unknown",
        include_uncertain: bool = True,
        max_candidates: int = 200,
        max_call_depth: int = 8,
        max_handler_hits_per_message: int = 2,
        protocol: ProtocolType = ProtocolType.PFCP,
        docker_container: str | None = None,
        target_ip: str | None = None,
        local_ip: str | None = None,
        seid: int | None = None,
        timeout: int | None = None,
        max_iterations: int = 5,
        persist_artifacts: bool = True,
    ) -> dict[str, Any]:
        discovery = self.phase1_discover(
            pattern=pattern,
            target_codebase=target_codebase,
            scan_dirs=scan_dirs,
            target_version=target_version,
            include_uncertain=include_uncertain,
            max_candidates=max_candidates,
            max_call_depth=max_call_depth,
        )
        vetting = self.phase2_vet(
            discovery=discovery,
            target_codebase=target_codebase,
            scan_dirs=scan_dirs,
            max_handler_hits_per_message=max_handler_hits_per_message,
        )
        exploitation = self.phase3_exploit(
            discovery=discovery,
            vetting=vetting,
            output_root=output_root,
            protocol=protocol,
            docker_container=docker_container,
            target_ip=target_ip,
            local_ip=local_ip,
            seid=seid,
            timeout=timeout,
            max_iterations=max_iterations,
        )

        artifact = {
            "discovery": discovery,
            "vetting": vetting,
            "exploitation": exploitation,
        }
        if persist_artifacts:
            self.persist_pipeline_artifacts(
                artifact=artifact,
                output_root=output_root,
            )
        return artifact

    def persist_pipeline_artifacts(
        self,
        *,
        artifact: dict[str, Any],
        output_root: str | Path,
    ) -> None:
        base = Path(output_root)
        discovery_dir = base / "discovery_results"
        vetting_dir = base / "vetting_results"
        exploitation_dir = base / "exploitation_results"
        discovery_dir.mkdir(parents=True, exist_ok=True)
        vetting_dir.mkdir(parents=True, exist_ok=True)
        exploitation_dir.mkdir(parents=True, exist_ok=True)

        discovery_obj: DiscoveryResult = artifact["discovery"]
        vetting_obj: VettingResult = artifact["vetting"]
        exploitation_objs: list[ExploitationResult] = artifact["exploitation"]

        (discovery_dir / f"{discovery_obj.pattern_id}.json").write_text(
            json.dumps(discovery_obj.model_dump(mode="json"), indent=2) + "\n",
            encoding="utf-8",
        )
        (vetting_dir / f"{vetting_obj.pattern_id}.json").write_text(
            json.dumps(vetting_obj.model_dump(mode="json"), indent=2) + "\n",
            encoding="utf-8",
        )
        for result in exploitation_objs:
            (exploitation_dir / f"{result.candidate_id}.json").write_text(
                json.dumps(result.model_dump(mode="json"), indent=2) + "\n",
                encoding="utf-8",
            )

    def _resolve_pattern_input(self, pattern: str | Path | dict[str, Any]) -> dict[str, Any] | str | Path:
        if isinstance(pattern, dict):
            return pattern
        path = Path(pattern)
        if path.exists():
            return path

        candidate = self.paths.pattern_dir / pattern
        if candidate.exists():
            return candidate
        raise FileNotFoundError(f"Pattern not found: {pattern}")


def _collect_checked_messages(decision: VettingDecision) -> list[str]:
    ordered: list[str] = []
    for item in decision.prerequisite_handlers_checked:
        message = item.message.strip()
        if message and message not in ordered:
            ordered.append(message)
    return ordered
