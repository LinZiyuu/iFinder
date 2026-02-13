"""Tests for pydantic config models."""

from datetime import datetime, timezone

from ifinder_sdk.config import (
    DiscoveryResult,
    ExploitationResult,
    ExploitationVerdict,
    FeasibilityEvidence,
    VettingDecision,
    VettingResult,
    VettingStatistics,
    VettingVerdict,
    VulnerableSite,
    iTrueCandidate,
)


def _candidate() -> iTrueCandidate:
    return iTrueCandidate(
        id="DA-PA1-001",
        vulnerable_site=VulnerableSite(
            file="src/s11-handler.c",
            line=608,
            function="handle_modify_bearer_request",
            dangerous_operation="ogs_assert_if_reached()",
        ),
        trigger_message="PFCP_Session_Modification_Request",
        trigger_ie="PAA",
        ie_field="paa.len",
        data_flow="handler -> parser -> sink",
        call_chain=["handle_modify_bearer_request", "decode_paa", "sink"],
    )


def test_discovery_result_model_roundtrip() -> None:
    result = DiscoveryResult(
        pattern_id="PB1",
        target_codebase="/tmp/open5gs",
        target_version="v2.7.6",
        discovery_timestamp=datetime.now(timezone.utc),
        candidates=[_candidate()],
    )
    as_dict = result.model_dump(mode="json")
    loaded = DiscoveryResult.model_validate(as_dict)
    assert loaded.pattern_id == "PB1"
    assert loaded.target_version == "v2.7.6"
    assert loaded.candidates[0].trigger_ie == "PAA"


def test_vetting_and_exploitation_models() -> None:
    decision = VettingDecision(
        candidate_id="DA-PA1-001",
        verdict=VettingVerdict.FEASIBLE,
        procedure="PFCP_Session_Modification",
        prerequisite_handlers_checked=[],
        feasibility_evidence=FeasibilityEvidence(
            security_check_found=False,
            security_check_detail="No blocking checks found.",
        ),
        rejection_reason=None,
    )
    vet = VettingResult(
        pattern_id="PB1",
        target_codebase="/tmp/open5gs",
        target_version="v2.7.6",
        vetting_timestamp=datetime.now(timezone.utc),
        statistics=VettingStatistics(total_candidates=1, feasible=1, infeasible=0),
        results=[decision],
    )
    assert vet.target_version == "v2.7.6"
    assert vet.results[0].feasibility_evidence.security_check_found is False

    exp = ExploitationResult(
        candidate_id="DA-PA1-001",
        validation_result=ExploitationVerdict.UNCONFIRMED,
        timestamp=datetime.now(timezone.utc),
        attempts=1,
        failure_analysis="No crash observed",
    )
    assert exp.validation_result == ExploitationVerdict.UNCONFIRMED
