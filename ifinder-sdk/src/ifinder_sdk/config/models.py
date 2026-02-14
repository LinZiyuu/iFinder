from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ProtocolType(str, Enum):
    PFCP = "PFCP"
    GTPC = "GTP-C"


class VettingVerdict(str, Enum):
    FEASIBLE = "FEASIBLE"
    INFEASIBLE = "INFEASIBLE"


class ExploitationVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    TRIGGERED_DIFFERENT = "TRIGGERED_DIFFERENT"


class VulnerableSite(BaseModel):
    file: str
    line: int
    function: str
    dangerous_operation: str


class iTrueCandidate(BaseModel):
    id: str
    vulnerable_site: VulnerableSite
    trigger_message: str
    trigger_ie: str
    ie_field: str
    data_flow: str
    call_chain: list[str]


class DiscoveryResult(BaseModel):
    pattern_id: str
    target_codebase: str
    target_version: str
    discovery_timestamp: datetime
    candidates: list[iTrueCandidate]


class PriorMessageHandlerMapping(BaseModel):
    message: str
    handler: str
    file: str
    validation_found: bool
    validation_detail: str


PrerequisiteHandlerCheck = PriorMessageHandlerMapping


class FeasibilityEvidence(BaseModel):
    security_check_found: bool | None = None
    security_check_detail: str | None = None

    input_controllability: str | None = None
    code_reachability: str | None = None
    defense_absence: str | None = None
    state_reachability: str | None = None
    impact: str | None = None


class VettingDecision(BaseModel):
    candidate_id: str
    verdict: VettingVerdict
    procedure: str
    prerequisite_handlers_checked: list[PriorMessageHandlerMapping] = Field(default_factory=list)
    feasibility_evidence: FeasibilityEvidence
    rejection_reason: str | None = None
    expanded_context: dict[str, Any] | None = None


class VettingStatistics(BaseModel):
    total_candidates: int
    feasible: int
    infeasible: int


class VettingResult(BaseModel):
    pattern_id: str
    target_codebase: str
    target_version: str = "unknown"
    vetting_timestamp: datetime
    statistics: VettingStatistics
    results: list[VettingDecision]


class AttackManipulation(BaseModel):
    ie: str
    field: str
    malicious_value: Any
    expected_buffer_size: int | None = None
    raw_hex: str | None = None
    raw_hex_kind: str | None = None


class AttackSequenceStep(BaseModel):
    step: int
    message: str
    manipulation: AttackManipulation
    triggers_vulnerability: bool = False
    action: str = "send"


class ExpectedOutcome(BaseModel):
    type: str
    location: str
    impact: str


class AttackVector(BaseModel):
    target_entity: str
    target_interface: str
    attacker_role: str
    attack_sequence: list[AttackSequenceStep]
    expected_outcome: ExpectedOutcome


class ProtocolMessageSpec(BaseModel):
    header: dict[str, Any]
    ies: dict[str, Any]
    raw_hex: str | None = None
    raw_hex_kind: str | None = None


class AttackVectorDocument(BaseModel):
    candidate_id: str
    attack_vector: AttackVector
    protocol_messages: dict[str, ProtocolMessageSpec]


class TriggerLocation(BaseModel):
    file: str
    line: int
    function: str


class TriggerEvidence(BaseModel):
    type: str
    location: TriggerLocation
    log_snippet: list[str] = Field(default_factory=list)


class ExploitationResult(BaseModel):
    candidate_id: str
    validation_result: ExploitationVerdict
    timestamp: datetime
    attempts: int
    trigger_evidence: TriggerEvidence | None = None
    poc_path: str | None = None
    failure_analysis: str | None = None
    refinements_attempted: list[str] | None = None
