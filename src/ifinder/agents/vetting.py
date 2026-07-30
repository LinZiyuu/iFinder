from __future__ import annotations

import logging
from datetime import datetime, timezone

from ifinder import client, config, prompts
from ifinder.models import (
    DiscoveryResult,
    Procedure,
    ScopeTarget,
    VettingDecision,
    VettingResult,
    VettingStatistics,
    VettingVerdict,
    iTrueCandidate,
)
from ifinder.util import extract_json

logger = logging.getLogger("ifinder.vetting")


class VettingAgent:
    def __init__(self, *, model: str = config.DEFAULT_MODEL, paths: config.Paths = config.DEFAULT_PATHS) -> None:
        self.model = model
        self.paths = paths

    async def run(
        self,
        *,
        discovery: DiscoveryResult,
        target: ScopeTarget,
        procedures: dict[str, Procedure],
    ) -> VettingResult:
        results: list[VettingDecision] = []
        for candidate in discovery.candidates:
            results.append(await self._vet_candidate(candidate=candidate, target=target, procedures=procedures))
        stats = VettingStatistics(
            feasible=sum(d.verdict is VettingVerdict.FEASIBLE for d in results),
            infeasible=sum(d.verdict is VettingVerdict.INFEASIBLE for d in results),
        )
        return VettingResult(
            pattern_id=discovery.pattern_id,
            target_codebase=discovery.target_codebase,
            target_version=discovery.target_version,
            timestamp=datetime.now(timezone.utc),
            statistics=stats,
            results=results,
        )

    async def _vet_candidate(
        self,
        *,
        candidate: iTrueCandidate,
        target: ScopeTarget,
        procedures: dict[str, Procedure],
    ) -> VettingDecision:
        prereq, procedure_name = self._prerequisite_messages(candidate, procedures)
        cfg = client.SessionConfig(
            system_prompt=prompts.SYSTEM_VETTING,
            allowed_tools=client.READONLY_TOOLS,
            cwd=self.paths.target_path(target.target_codebase),
            model=self.model,
        )
        prompt = prompts.build_vetting_prompt(
            candidate=candidate,
            procedure_name=procedure_name,
            prerequisite_messages=prereq,
            target=target,
        )
        text = await client.run_single_turn(prompt, cfg)
        try:
            data = extract_json(text)
            data = {k: v for k, v in data.items() if v is not None}  # null field -> use model default
            data.setdefault("candidate_id", candidate.id)
            return VettingDecision.model_validate(data)
        except Exception as exc:
            # Recall-oriented: never silently drop on a parse error — pass through to EA to runtime-verify.
            logger.warning("VA %s: unparseable decision (%s); defaulting FEASIBLE", candidate.id, exc)
            return VettingDecision(
                candidate_id=candidate.id,
                verdict=VettingVerdict.FEASIBLE,
                procedure=procedure_name,
                evidence="VA reply could not be parsed; passed through for runtime verification.",
                prerequisite_messages=prereq,
            )

    @staticmethod
    def _prerequisite_messages(
        candidate: iTrueCandidate, procedures: dict[str, Procedure]
    ) -> tuple[list[str], str]:
        """Enumerate prerequisite messages (in-procedure earlier ∪ closure), root-first.

        Returns ``(messages, procedure_id)``. ``procedure_id`` is "" if the trigger maps to no procedure.
        """
        trigger = candidate.trigger_message
        home: Procedure | None = None
        trigger_seq: int | None = None
        for proc in procedures.values():
            for step in proc.message_flow:
                if step.message == trigger:
                    home, trigger_seq = proc, step.seq
                    break
            if home is not None:
                break
        if home is None:
            return [], ""

        messages: list[str] = []
        # prerequisite procedures (dependency_procedures is the transitive closure, authored root-first)
        for dep_id in home.dependency_procedures:
            dep = procedures.get(dep_id)
            if dep is None:
                continue
            for step in sorted(dep.message_flow, key=lambda s: s.seq):
                if step.message not in messages:
                    messages.append(step.message)
        # earlier messages within the candidate's own procedure
        for step in sorted(home.message_flow, key=lambda s: s.seq):
            if trigger_seq is not None and step.seq < trigger_seq and step.message not in messages:
                messages.append(step.message)
        return messages, home.procedure_id
