from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ifinder_sdk import IFinderClient, IFinderPaths
from ifinder_sdk.config import DiscoveryResult, VulnerableSite, iTrueCandidate
from ifinder_sdk.tools import (
    build_expanded_context_for_candidate,
    collect_code_for_messages,
    derive_attack_vector_and_messages,
    load_message_schemas,
    vet_discovery_result,
)


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _prepare_procedure_dir(base: Path) -> Path:
    proc = base / "procedure"
    proc.mkdir(parents=True)
    _write_json(
        proc / "association_setup.json",
        {
            "procedure_id": "PFCP_Association_Setup",
            "dependency_procedure": None,
            "message_flow": [
                {"seq": 1, "message": "PFCP_Association_Setup_Request"},
                {"seq": 2, "message": "PFCP_Association_Setup_Response"},
            ],
        },
    )
    _write_json(
        proc / "session_establishment.json",
        {
            "procedure_id": "PFCP_Session_Establishment",
            "dependency_procedure": "PFCP_Association_Setup",
            "message_flow": [
                {"seq": 1, "message": "PFCP_Session_Establishment_Request"},
                {"seq": 2, "message": "PFCP_Session_Establishment_Response"},
            ],
        },
    )
    _write_json(
        proc / "session_modification.json",
        {
            "procedure_id": "PFCP_Session_Modification",
            "dependency_procedure": "PFCP_Session_Establishment",
            "message_flow": [
                {"seq": 1, "message": "PFCP_Session_Modification_Request"},
                {"seq": 2, "message": "PFCP_Session_Modification_Response"},
            ],
        },
    )
    return proc


def _prepare_mock_codebase(base: Path) -> Path:
    codebase = base / "open5gs"
    code_dir = codebase / "src"
    code_dir.mkdir(parents=True)
    (code_dir / "handlers.c").write_text(
        """
// PFCP_Session_Establishment_Request
int sgwc_s5c_handle_create_session_response(int paa_len) {
    const char *msg = "PFCP_Session_Establishment_Request";
    if (paa_len > 21) {
        return -1;
    }
    return 0;
}

// PFCP_Association_Setup_Request
int pfcp_handle_association_setup_request(void) {
    return 0;
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return codebase


def _candidate() -> iTrueCandidate:
    return iTrueCandidate(
        id="DA-PA1-001",
        vulnerable_site=VulnerableSite(
            file="src/s11-handler.c",
            line=608,
            function="handle_modify_bearer_request",
            dangerous_operation="memcpy(sess->paa, paa->data, paa->len)",
        ),
        trigger_message="PFCP_Session_Modification_Request",
        trigger_ie="PAA",
        ie_field="paa_len",
        data_flow="handler -> parser -> memcpy(paa_len)",
        call_chain=["handle_modify_bearer_request", "decode_paa", "memcpy_sink"],
    )


def test_build_expanded_context_recursive_dependencies(tmp_path: Path) -> None:
    proc = _prepare_procedure_dir(tmp_path)
    expanded = build_expanded_context_for_candidate(
        "PFCP_Session_Modification_Request",
        proc,
    )
    assert expanded["matched_procedure"] == "PFCP_Session_Modification"
    assert expanded["same_procedure_prior_messages"] == []
    assert expanded["dependency_chain"] == [
        "PFCP_Session_Establishment",
        "PFCP_Association_Setup",
    ]


def test_collect_code_for_messages_finds_snippets(tmp_path: Path) -> None:
    codebase = _prepare_mock_codebase(tmp_path)
    snippets = collect_code_for_messages(
        ["PFCP_Session_Establishment_Request"],
        target_codebase=codebase,
        scan_dirs=["src"],
    )
    assert snippets
    assert any("PFCP_Session_Establishment_Request" in s["code"] for s in snippets)


def test_load_message_schemas_and_derive_attack_vector(tmp_path: Path) -> None:
    schema_file = tmp_path / "schemas.json"
    _write_json(
        schema_file,
        {
            "messages": {
                "PFCP_Session_Modification_Request": {
                    "mandatory_ies": ["NodeID", "FSEID"],
                    "ies": {"NodeID": {}, "FSEID": {}},
                }
            }
        },
    )
    loaded = load_message_schemas(schema_file)
    assert "PFCP_Session_Modification_Request" in loaded

    doc = derive_attack_vector_and_messages(
        _candidate(),
        message_schemas=loaded,
        prerequisite_messages=["PFCP_Association_Setup_Request"],
    )
    assert doc.candidate_id == "DA-PA1-001"
    assert "PFCP_Session_Modification_Request" in doc.protocol_messages


def test_client_phase1_phase2_integration(tmp_path: Path) -> None:
    pattern_dir = tmp_path / "pattern"
    pattern_dir.mkdir(parents=True)
    _write_json(
        pattern_dir / "PA1.json",
        {
            "pattern_id": "PA1",
            "dangerous_operations": {"c": ["memcpy"]},
            "required_validations": ["semantic"],
        },
    )

    proc = _prepare_procedure_dir(tmp_path)
    codebase = _prepare_mock_codebase(tmp_path)
    schema_file = tmp_path / "message_schemas.normalized.json"
    _write_json(schema_file, {"messages": {}})

    client = IFinderClient(
        paths=IFinderPaths(
            pattern_dir=pattern_dir,
            procedure_dir=proc,
            message_schema_path=schema_file,
        )
    )
    discovery = client.phase1_discover(
        pattern="PA1.json",
        target_codebase=codebase,
        scan_dirs=["src"],
        target_version="v2.7.6",
        max_candidates=20,
    )
    assert discovery.target_version == "v2.7.6"

    vetting = client.phase2_vet(
        discovery=discovery,
        target_codebase=codebase,
        scan_dirs=["src"],
    )
    assert vetting.pattern_id == discovery.pattern_id
