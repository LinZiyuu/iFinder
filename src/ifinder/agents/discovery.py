from __future__ import annotations

import copy
import logging
from datetime import datetime, timezone
from typing import Any

from claude_agent_sdk import create_sdk_mcp_server, tool
from pydantic import ValidationError

from ifinder import client, config, prompts
from ifinder.models import CoverageReport, DiscoveryResult, Pattern, ScopeTarget, iTrueCandidate

logger = logging.getLogger("ifinder.discovery")

# JSON Schema (inlined — no $ref, so the model/API accept it cleanly) mirroring models.iTrueCandidate.
_CANDIDATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "id": {"type": "string"},
        "vulnerable_site": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "function": {"type": "string"},
                "dangerous_operation": {"type": "string"},
            },
            "required": ["file", "line", "function", "dangerous_operation"],
        },
        "trigger_message": {"type": "string"},
        "trigger_ie": {"type": "string"},
        "ie_field": {"type": "string"},
        "call_chain": {"type": "array", "items": {"type": "string"}},
        "data_flow": {"type": "string"},
        "missing_validation": {"type": "string"},
        "network_function": {"type": "string", "enum": ["UPF", "SMF"]},
    },
    "required": ["id", "vulnerable_site", "trigger_message", "trigger_ie", "ie_field"],
}

_COVERAGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "total_messages": {"type": "integer"},
        "audited_messages": {"type": "integer"},
        "total_ies": {"type": "integer"},
        "audited_ies": {"type": "integer"},
        "skipped_messages": {"type": "array", "items": {"type": "string"}},
        "missing_ie_paths": {"type": "array", "items": {"type": "string"}},
    },
    "required": [],
}


def _build_report_server(
    candidates: list[iTrueCandidate], coverage: dict[str, Any], rejects: list[str], nfs: list[str]
):
    """In-process SDK MCP server whose tools validate every report against the models contracts.

    The closures append to the caller-owned ``candidates`` / ``coverage`` so the DA reads them after the
    turn drains. Server key MUST be ``ifinder_report`` to match ``client.REPORT_TOOLS`` namespacing.

    ``nfs`` are the protocol-specific valid network_function values (PFCP: UPF/SMF, GTP-C: SGW-C/MME/PGW-C).
    """
    candidate_schema = copy.deepcopy(_CANDIDATE_SCHEMA)
    candidate_schema["properties"]["network_function"]["enum"] = list(nfs)

    @tool("report_candidate", "Report ONE iTrue candidate. Call once per finding.", candidate_schema)
    async def report_candidate(args: dict[str, Any]) -> dict[str, Any]:
        try:
            candidates.append(iTrueCandidate.model_validate(args))
            return {"content": [{"type": "text", "text": f"accepted {args.get('id', '?')}"}]}
        except ValidationError as exc:  # reject -> agent sees the error and re-calls with fixed fields
            rejects.append(str(exc))
            return {
                "content": [{"type": "text", "text": f"REJECTED — fix these fields and call again:\n{exc}"}],
                "is_error": True,
            }

    @tool("report_coverage", "Report coverage once, after the whole map is audited.", _COVERAGE_SCHEMA)
    async def report_coverage(args: dict[str, Any]) -> dict[str, Any]:
        coverage.clear()
        coverage.update(args)
        return {"content": [{"type": "text", "text": "coverage recorded"}]}

    return create_sdk_mcp_server("ifinder_report", tools=[report_candidate, report_coverage])


class DiscoveryAgent:
    def __init__(self, *, model: str = config.DEFAULT_MODEL, paths: config.Paths = config.DEFAULT_PATHS) -> None:
        self.model = model
        self.paths = paths

    async def run(
        self,
        *,
        pattern: Pattern,
        target: ScopeTarget,
        coverage_map: dict[str, Any],
    ) -> DiscoveryResult:
        cwd = self.paths.target_path(target.target_codebase)
        candidates: list[iTrueCandidate] = []
        coverage: dict[str, Any] = {}
        rejects: list[str] = []
        server = _build_report_server(candidates, coverage, rejects, prompts.protocol_nfs(target.protocol))
        cfg = client.SessionConfig(
            system_prompt=prompts.system_discovery(target.protocol),
            allowed_tools=client.DISCOVERY_TOOLS,
            cwd=cwd,
            model=self.model,
            mcp_servers={"ifinder_report": server},
        )
        prompt = prompts.build_discovery_prompt(pattern=pattern, target=target, coverage_map=coverage_map)
        logger.info("DA run: pattern=%s target=%s cwd=%s", pattern.pattern_id, target.name, cwd)
        text = await client.run_single_turn(prompt, cfg)
        self._persist_raw(target, pattern, text)
        if rejects:
            logger.warning(
                "DA %s/%s: %d report(s) rejected by schema (agent should have re-called; see raw)",
                pattern.pattern_id, target.name, len(rejects),
            )
        cov = CoverageReport.model_validate(coverage) if coverage else CoverageReport()
        return DiscoveryResult(
            pattern_id=pattern.pattern_id,
            target_codebase=target.target_codebase,
            target_version=target.version or "unknown",
            timestamp=datetime.now(timezone.utc),
            candidates=candidates,
            coverage_report=cov,
        )

    def _persist_raw(self, target: ScopeTarget, pattern: Pattern, text: str) -> None:
        """Always keep the agent's final text alongside the artifact, so nothing is ever lost."""
        try:
            p = self.paths.discovery_out(target.name, pattern.pattern_id).with_suffix(".raw.txt")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text or "", encoding="utf-8")
        except Exception as exc:  # never let persistence break a run
            logger.debug("DA raw persist failed: %s", exc)
