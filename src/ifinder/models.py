"""Pydantic contracts for iFinder (PFCP + GTP-C).

These models are the *interfaces* between stages and the on-disk artifact formats. They are defined in
full (the skeleton's contracts); the logic that produces them lives in ``agents/``.

Grouping:
- Preprocessing inputs : ``Pattern`` (../pattern), ``Procedure`` (../procedure), ``Scope`` (../scope)
- Discovery (DA → VA)  : ``iTrueCandidate`` / ``DiscoveryResult``
- Vetting   (VA → EA)  : ``VettingDecision`` / ``VettingResult``
- Exploitation         : ``ExploitationResult``
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ValidationClass(str, Enum):
    SYNTACTIC = "syntactic"
    SEMANTIC = "semantic"
    RESOURCE = "resource"


class NetworkFunction(str, Enum):
    # PFCP network functions
    UPF = "UPF"
    SMF = "SMF"
    # GTP-C network functions (4G EPC control plane)
    SGW_C = "SGW-C"
    MME = "MME"
    PGW_C = "PGW-C"


class VettingVerdict(str, Enum):
    FEASIBLE = "FEASIBLE"
    INFEASIBLE = "INFEASIBLE"


class ExploitationVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED" 



class Pattern(BaseModel):
    """One iTrue detection pattern (../pattern/<PID>.json). Fed to DA as prose + explicit triple."""

    pattern_id: str
    pattern_name: str
    validation_class: ValidationClass
    element: str
    dangerous_operation: str
    missing_validation: str
    security_impact: str
    pattern_description: str


class MessageFlowStep(BaseModel):
    """One message in a procedure's flow (../procedure/*.json -> message_flow[])."""

    model_config = ConfigDict(populate_by_name=True)

    seq: int
    from_: str = Field(alias="from")
    to: str
    message: str
    mandatory_ies: list[str] = Field(default_factory=list)


class Procedure(BaseModel):
    """A PFCP procedure (../procedure/*.json).

    ``dependency_procedures`` is the **transitive closure** (downward-closed): one read yields every
    prerequisite procedure, so VA does not traverse the graph.
    """

    procedure_id: str
    direction: str
    dependency_procedures: list[str] = Field(default_factory=list)
    message_flow: list[MessageFlowStep] = Field(default_factory=list)


class ScopeTarget(BaseModel):
    """One target entry inside a scope file (../scope/scope_*.json -> targets[])."""

    name: str
    target_codebase: str
    version: Optional[str] = None
    # Selects the protocol knowledge base (schema/<protocol>/ + procedure/<protocol>/) for this target.
    protocol: str = "pfcp"
    scan_dirs: list[str] = Field(default_factory=list)


class Scope(BaseModel):
    scope_name: str
    targets: list[ScopeTarget] = Field(default_factory=list)


class VulnerableSite(BaseModel):
    file: str
    line: int
    function: str
    dangerous_operation: str


class iTrueCandidate(BaseModel):
    id: str  # e.g. "DA-PA1-001"
    vulnerable_site: VulnerableSite
    trigger_message: str
    trigger_ie: str
    ie_field: str
    call_chain: list[str] = Field(default_factory=list)
    data_flow: str = ""
    missing_validation: str = ""  # prose note of the absent check
    network_function: Optional[NetworkFunction] = None  # reasoning hint for VA (not a hard filter)


class CoverageReport(BaseModel):
    """Proof the coverage_map + stop condition were satisfied."""

    total_messages: int = 0
    audited_messages: int = 0
    total_ies: int = 0
    audited_ies: int = 0
    skipped_messages: list[str] = Field(default_factory=list)
    missing_ie_paths: list[str] = Field(default_factory=list)


class DiscoveryResult(BaseModel):
    """One DA run = one pattern × one target -> outputs/discovery_results/<target>/<pattern_id>.json."""

    pattern_id: str
    target_codebase: str
    target_version: str = "unknown"
    timestamp: datetime
    candidates: list[iTrueCandidate] = Field(default_factory=list)
    coverage_report: CoverageReport = Field(default_factory=CoverageReport)



class PrerequisiteHandlerCheck(BaseModel):
    message: str
    handler: str
    file: str
    validation_found: bool
    detail: str = ""


class VettingDecision(BaseModel):
    candidate_id: str
    verdict: VettingVerdict
    procedure: str = ""
    prerequisite_handlers_checked: list[PrerequisiteHandlerCheck] = Field(default_factory=list)
    evidence: str = ""  # rationale for the verdict
    rejection_reason: Optional[str] = None  # set when INFEASIBLE
    # Ordered setup messages EA must send first to reach the vulnerable state (e.g. Establishment
    # before Modification). Carried only for FEASIBLE decisions.
    prerequisite_messages: list[str] = Field(default_factory=list)


class VettingStatistics(BaseModel):
    feasible: int = 0
    infeasible: int = 0


class VettingResult(BaseModel):
    """One VA run = one DiscoveryResult -> outputs/vetting_results/<target>/<pattern_id>.json."""

    pattern_id: str
    target_codebase: str
    target_version: str = "unknown"
    timestamp: datetime
    statistics: VettingStatistics = Field(default_factory=VettingStatistics)
    results: list[VettingDecision] = Field(default_factory=list)



class TriggerLocation(BaseModel):
    file: str = ""
    line: int = 0
    function: str = ""


class TriggerEvidence(BaseModel):
    type: str = ""  # e.g. "segfault" / "assertion" / "panic"
    location: Optional[TriggerLocation] = None  # recorded if known; not used to decide the verdict
    log_snippet: list[str] = Field(default_factory=list)


class ExploitationResult(BaseModel):
    """One EA run = one FEASIBLE candidate -> outputs/exploitation_results/<target>/<candidate_id>.json."""

    candidate_id: str
    validation_result: ExploitationVerdict
    timestamp: datetime
    attempts: int = 0  # refinement iterations used (budget: MAX_REFINE_ITERATIONS)
    trigger_evidence: Optional[TriggerEvidence] = None
    poc_path: Optional[str] = None  # path to the generated Go PoC
    failure_analysis: Optional[str] = None
    refinements_attempted: list[str] = Field(default_factory=list)
