"""Pydantic models for iFinder SDK contracts.

These models type the structured artifacts defined in `skill/SKILL_iFinder.md`:
- Discovery output (`discovery_results/*.json`)
- Vetting output (`vetting_results/*.json`)
- Attack vector artifact (`attack_vector.json`)
- Exploitation output (`exploitation_results/*.json`)
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ProtocolType(str, Enum):
    """Supported control-plane protocols."""

    PFCP = "PFCP"
    GTPC = "GTP-C"


class VettingVerdict(str, Enum):
    """Feasibility verdict returned by Vetting Agent."""

    FEASIBLE = "FEASIBLE"
    INFEASIBLE = "INFEASIBLE"


class ExploitationVerdict(str, Enum):
    """Validation result returned by Exploitation Agent."""

    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    TRIGGERED_DIFFERENT = "TRIGGERED_DIFFERENT"


class VulnerableSite(BaseModel):
    """Code location for a discovered risky operation."""

    file: str
    line: int
    function: str
    dangerous_operation: str


class iTrueCandidate(BaseModel):
    """One candidate returned by Discovery Agent."""

    id: str
    vulnerable_site: VulnerableSite
    trigger_message: str
    trigger_ie: str
    ie_field: str
    data_flow: str
    call_chain: list[str]


class DiscoveryResult(BaseModel):
    """Discovery Agent output schema (`discovery_results/*.json`)."""

    pattern_id: str
    target_codebase: str
    target_version: str
    discovery_timestamp: datetime
    candidates: list[iTrueCandidate]


class PriorMessageHandlerMapping(BaseModel):
    """Code mapping result for one prior message in the same procedure."""

    message: str
    handler: str
    file: str
    validation_found: bool
    validation_detail: str


# Backward-compatible alias
PrerequisiteHandlerCheck = PriorMessageHandlerMapping


class FeasibilityEvidence(BaseModel):
    """Evidence payload used for vetting decisions.

    The primary signal for current VA logic is whether security checks are
    observed in the expanded code context. Legacy fields are kept for
    compatibility with older result consumers.
    """

    security_check_found: bool | None = None
    security_check_detail: str | None = None

    input_controllability: str | None = None
    code_reachability: str | None = None
    defense_absence: str | None = None
    state_reachability: str | None = None
    impact: str | None = None


class VettingDecision(BaseModel):
    """Per-candidate vetting decision from Stage 2."""

    candidate_id: str
    verdict: VettingVerdict
    procedure: str
    prerequisite_handlers_checked: list[PriorMessageHandlerMapping] = Field(default_factory=list)
    feasibility_evidence: FeasibilityEvidence
    rejection_reason: str | None = None
    expanded_context: dict[str, Any] | None = None


class VettingStatistics(BaseModel):
    """Summary statistics for Stage 2 results."""

    total_candidates: int
    feasible: int
    infeasible: int


class VettingResult(BaseModel):
    """Stage 2 output schema (`vetting_results/*.json`)."""

    pattern_id: str
    target_codebase: str
    target_version: str = "unknown"
    vetting_timestamp: datetime
    statistics: VettingStatistics
    results: list[VettingDecision]


class AttackManipulation(BaseModel):
    """IE manipulation for one crafted protocol step."""

    ie: str
    field: str
    malicious_value: Any
    expected_buffer_size: int | None = None
    raw_hex: str | None = None
    raw_hex_kind: str | None = None  # "ie" or "message"


class AttackSequenceStep(BaseModel):
    """One step in the attack sequence."""

    step: int
    message: str
    manipulation: AttackManipulation
    triggers_vulnerability: bool = False
    action: str = "send"  # "send" or "respond"


class ExpectedOutcome(BaseModel):
    """Expected runtime effect for an attack vector."""

    type: str
    location: str
    impact: str


class AttackVector(BaseModel):
    """Attack strategy derived from vetted candidate evidence."""

    target_entity: str
    target_interface: str
    attacker_role: str
    attack_sequence: list[AttackSequenceStep]
    expected_outcome: ExpectedOutcome


class ProtocolMessageSpec(BaseModel):
    """Protocol message payload to reproduce the attack."""

    header: dict[str, Any]
    ies: dict[str, Any]
    raw_hex: str | None = None
    raw_hex_kind: str | None = None


class AttackVectorDocument(BaseModel):
    """Artifact schema for `attack_vector.json`."""

    candidate_id: str
    attack_vector: AttackVector
    protocol_messages: dict[str, ProtocolMessageSpec]


class CrashLocation(BaseModel):
    """Observed crash location."""

    file: str
    line: int
    function: str


class CrashEvidence(BaseModel):
    """Crash proof bundle used for CONFIRMED results."""

    type: str
    location: CrashLocation
    log_snippet: list[str] = Field(default_factory=list)


class ExploitationResult(BaseModel):
    """Stage 3 output schema (`exploitation_results/*.json`)."""

    candidate_id: str
    validation_result: ExploitationVerdict
    timestamp: datetime
    attempts: int
    crash_evidence: CrashEvidence | None = None
    poc_path: str | None = None
    failure_analysis: str | None = None
    refinements_attempted: list[str] | None = None
