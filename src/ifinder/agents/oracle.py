from __future__ import annotations

import logging
from typing import Optional

from pydantic import BaseModel

from ifinder import client, config, prompts
from ifinder.models import iTrueCandidate
from ifinder.util import extract_json

logger = logging.getLogger("ifinder.oracle")


class OracleVerdict(BaseModel):
    confirmed: bool = False
    signal_type: str = "none"   # "audit" | "behavior" | "state" | "none"
    evidence: str = ""          # quoted log line supporting the verdict (required when confirmed)
    reasoning: str = ""         # one short sentence


class LogJudge:
    """Single-turn LLM oracle for non-crash signals in runtime logs."""

    def __init__(
        self,
        *,
        model: str = config.DEFAULT_MODEL,
        log_tail_lines: int = 200,
        paths: config.Paths = config.DEFAULT_PATHS,
    ) -> None:
        self.model = model
        self.log_tail_lines = log_tail_lines
        self.paths = paths

    async def judge(self, *, candidate: iTrueCandidate, logs: str) -> OracleVerdict:
        tail = "\n".join(logs.splitlines()[-self.log_tail_lines:])
        cfg = client.SessionConfig(
            system_prompt=prompts.SYSTEM_ORACLE,
            allowed_tools=[],   # tool-less: the judge reads ONLY the logs in the prompt
            cwd=self.paths.outputs_dir,
            model=self.model,
            max_turns=1,
        )
        reply = await client.run_single_turn(
            prompts.build_oracle_prompt(candidate=candidate, logs=tail), cfg,
        )
        return self._parse(reply)

    @staticmethod
    def _parse(reply: str) -> OracleVerdict:
        try:
            data = extract_json(reply) or {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        verdict = OracleVerdict(
            confirmed=bool(data.get("confirmed", False)),
            signal_type=str(data.get("signal_type", "none")),
            evidence=str(data.get("evidence", "")),
            reasoning=str(data.get("reasoning", "")),
        )
        # Safety net: refuse to confirm without a quoted evidence line, even if the LLM tried to.
        if verdict.confirmed and not verdict.evidence.strip():
            logger.warning("oracle returned confirmed=True without evidence — downgrading to false")
            verdict.confirmed = False
            verdict.signal_type = "none"
        return verdict
