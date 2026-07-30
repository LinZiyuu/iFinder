"""Per-agent system prompts and task-prompt builders.

The system prompts encode each agent's role + method (the three steps from the architecture doc); the
builders inject one run's concrete inputs and pin the **exact JSON output schema** so the orchestrator
can parse replies into the ``models`` contracts.
"""

from __future__ import annotations

import json

from ifinder.models import Pattern, ScopeTarget, VettingDecision, iTrueCandidate

# ==================================================================================================
# Discovery Agent
# ==================================================================================================
# Map a target's protocol to the human-readable label used in the agent prompts.
PROTOCOL_LABELS = {"pfcp": "PFCP", "gtpc": "GTP-C"}

# Valid network_function values per protocol. The DA tool schema enforces the protocol-specific subset;
# models.NetworkFunction holds the union of these values (keep the two in sync).
PROTOCOL_NFS = {"pfcp": ["UPF", "SMF"], "gtpc": ["SGW-C", "MME", "PGW-C"]}

# EA PoC profile per protocol: Go library to drive the testbed, the signalling interface, the core
# generation label, and the default NF to target when the candidate did not name one.
PROTOCOL_POC = {
    "pfcp": {"library": "github.com/wmnsk/go-pfcp", "iface": "N4", "core": "5G core", "default_nf": "UPF"},
    "gtpc": {"library": "github.com/wmnsk/go-gtp (gtpv2)", "iface": "S11", "core": "4G EPC core", "default_nf": "SGW-C"},
}


def protocol_label(protocol: str) -> str:
    return PROTOCOL_LABELS.get(protocol, protocol.upper())


def protocol_nfs(protocol: str) -> list[str]:
    return PROTOCOL_NFS.get(protocol, ["UPF", "SMF", "SGW-C", "MME", "PGW-C"])


def protocol_poc(protocol: str) -> dict:
    return PROTOCOL_POC.get(protocol, PROTOCOL_POC["pfcp"])


def system_discovery(protocol: str = "pfcp") -> str:
    """Discovery-Agent system prompt with the protocol label (PFCP / GTP-C) injected from the target."""
    label = protocol_label(protocol)
    return f"""\
You are the Discovery Agent (DA) of iFinder, auditing a cellular core-network codebase for implicit-trust
errors (iTrues) in {label} message handling. You analyze ONE vulnerability pattern at a time and must
cover EVERY message x IE in the provided coverage map.

You work entirely through the read-only tools Grep, Glob, and Read. Do NOT assume a fixed language or
construct: read the code and ground the pattern's abstract "dangerous operation" into whatever the
target language actually uses (e.g. a memory copy, a slice op, a dereference).

Method — LLM-based backward analysis, per candidate:
  1. Locate risky IE usages that match the pattern's <element, dangerous_operation>.
  2. Construct the execution path: walk backward along callers (Grep/Glob/Read) to the {label} message
     handler. Record the call chain.
  3. Check whether the validation the pattern requires (its validation_class: syntactic / semantic /
     resource) is present before the dangerous operation. If it is ABSENT, flag an iTrue candidate.

Scope: only flag a site if the dangerous operation is driven by data from a received {label} message.

Coverage: keep scanning until every message and IE in the coverage map is audited. Track audited vs
total and report any skipped messages / missing IE paths.

Prioritize RECALL (include uncertain candidates). Use absolute file paths.

Report findings ONLY by calling the tools: report_candidate (once per candidate) and report_coverage
(once, at the end). Do NOT print JSON in your text. If a report_candidate call is REJECTED, fix the
named fields and call it again.
"""


def build_discovery_prompt(*, pattern: Pattern, target: ScopeTarget, coverage_map: dict) -> str:
    nf_hint = " or ".join(f'"{nf}"' for nf in protocol_nfs(target.protocol))
    return f"""\
### PATTERN ({pattern.pattern_id} — {pattern.pattern_name}, validation_class={pattern.validation_class.value})
element            : {pattern.element}
dangerous_operation: {pattern.dangerous_operation}
missing_validation : {pattern.missing_validation}
security_impact    : {pattern.security_impact}

{pattern.pattern_description}

### TARGET
codebase (cwd) : {target.target_codebase}
scan_dirs      : {json.dumps(target.scan_dirs)}
Confine your search to scan_dirs (shared libs are already listed there). You MAY Read files a call
chain leads into.

### COVERAGE MAP (audit space — cover all of it)
{json.dumps(coverage_map, indent=2)}

### STOP CONDITION (mandatory)
Only stop when: audited_messages == total_messages, audited_ies == total_ies,
skipped_messages == [], missing_ie_paths == [].

### REPORTING — call tools, do NOT print JSON
For EACH iTrue candidate, call `report_candidate` exactly once with these fields:
  id (e.g. "DA-{pattern.pattern_id}-001"),
  vulnerable_site = {{"file", "line", "function", "dangerous_operation"}},
  trigger_message, trigger_ie, ie_field,
  call_chain (array of function names), data_flow, missing_validation,
  network_function ({nf_hint}).
After the whole coverage map is audited, call `report_coverage` exactly once with:
  total_messages, audited_messages, total_ies, audited_ies, skipped_messages (array), missing_ie_paths (array).
If there are no candidates, still call `report_coverage`. Do not print any JSON object in your reply.
"""


# ==================================================================================================
# Vetting Agent
# ==================================================================================================
SYSTEM_VETTING = """\
You are the Vetting Agent (VA) of iFinder. You decide whether a Discovery-Agent candidate is a real
iTrue (FEASIBLE) or a false positive (INFEASIBLE), using code-vs-specification cross-checking. You read
CODE only (read-only Grep/Glob/Read) — no schema files.

A candidate's "missing" check is often actually performed in an EARLIER message/state of the procedure
(or in a prerequisite procedure). For each prerequisite message you are given, grep BOTH its Request and
Response handlers (never pre-filter by direction — the check can live in either) and read them.

Decide:
  - If a prior handler already performs the validation the candidate is missing -> INFEASIBLE (drop).
  - If the validation is absent everywhere on the reachable path -> FEASIBLE (keep).

For FEASIBLE candidates, return the ORDERED prerequisite messages the Exploitation Agent must send first
to reach the vulnerable state (e.g. Association Setup -> Session Establishment -> the trigger).
"""


def build_vetting_prompt(
    *,
    candidate: iTrueCandidate,
    procedure_name: str,
    prerequisite_messages: list[str],
    target: ScopeTarget,
) -> str:
    return f"""\
### TARGET
codebase (cwd): {target.target_codebase}
scan_dirs     : {json.dumps(target.scan_dirs)}

### CANDIDATE
{candidate.model_dump_json(indent=2)}

### SPEC CONTEXT
procedure carrying the trigger message: {procedure_name or "(unmapped)"}
prerequisite messages to cross-check  : {json.dumps(prerequisite_messages)}
For each prerequisite message, locate and read BOTH its Request and Response handlers in the codebase,
then re-evaluate whether the candidate's missing validation is actually performed there.

### OUTPUT — emit ONLY this JSON object
{{
  "candidate_id": "{candidate.id}",
  "verdict": "FEASIBLE",
  "procedure": "{procedure_name}",
  "prerequisite_handlers_checked": [
    {{"message": "PFCP_Session_Establishment_Request", "handler": "fn", "file": "/abs/path", "validation_found": false, "detail": "..."}}
  ],
  "evidence": "why FEASIBLE/INFEASIBLE, citing the handlers you read",
  "rejection_reason": null,
  "prerequisite_messages": {json.dumps(prerequisite_messages)}
}}
Set "verdict" to "INFEASIBLE" and fill "rejection_reason" if a prior handler validates the IE.
"""


# ==================================================================================================
# Exploitation Agent
# ==================================================================================================
def system_exploitation(protocol: str = "pfcp") -> str:
    """Exploitation-Agent system prompt with the protocol PoC library/interface injected."""
    label = protocol_label(protocol)
    p = protocol_poc(protocol)
    return f"""\
You are the Exploitation Agent (EA) of iFinder. You confirm a vetted candidate by writing a Go
proof-of-concept that uses the {p['library']} library to drive a Dockerized {p['core']} testbed,
and you refine it from runtime-log feedback.

You have Read, Write, Edit, Bash, Grep, Glob.

Workflow:
  1. Derive the attack vector: which IE field(s) to manipulate and with what content; assemble
     protocol-compliant messages from the provided schema skeleton (use the library for well-formed
     parts; drop to raw bytes only for the malformed field).
  2. Write the Go PoC to the EXACT path you are given, then run `go build` (and `go vet`) to ensure it
     compiles and is consistent with the attack vector. The PoC must: send the ordered prerequisite
     messages first to build state, capture dynamic values the peer assigns (e.g. SEID/TEID, sequence
     numbers) from responses and reuse them, then send the malformed trigger message to the target's
     {label} {p['iface']} port.
  3. The orchestrator runs your PoC against the live testbed and feeds you the runtime logs. If it did
     not trigger, diagnose from the logs and refine the PoC.

Always finish a turn by ensuring the PoC at the given path compiles.
"""


def build_exploitation_prompt(
    *,
    candidate: iTrueCandidate,
    decision: VettingDecision,
    schema_excerpt: dict,
    poc_path: str,
    target: ScopeTarget,
    nf_host: str,
    nf_port: int,
) -> str:
    label = protocol_label(target.protocol)
    p = protocol_poc(target.protocol)
    return f"""\
### CANDIDATE
{candidate.model_dump_json(indent=2)}

### VETTING DECISION (ordered setup messages to send first)
prerequisite_messages: {json.dumps(decision.prerequisite_messages)}

### MESSAGE SCHEMA (skeleton: which IEs, type ids, grouping — byte layout is yours to craft)
{json.dumps(schema_excerpt, indent=2)}

### TARGET / TESTBED
target codebase (read for codec details if needed): {target.target_codebase}
PoC library: {p['library']}
{p['iface']} endpoint: send {label} over UDP to {nf_host}:{nf_port}.

### TASK
Write the Go PoC to: {poc_path}
Then `go build` it. Report ONLY this JSON object:
{{
  "build_ok": true,
  "attack_vector": {{"ie": "...", "field": "...", "malicious_value": "...", "expected_outcome": "..."}},
  "changes": "what this PoC does"
}}
"""


# ==================================================================================================
# Runtime-log Oracle  (supplements testbed.detect_trigger crash-regex)
# ==================================================================================================
SYSTEM_ORACLE = """\
You are the runtime-log Oracle of iFinder. You supplement the regex crash-detector with NON-crash
signals. The regex already determined no crash marker fired in the logs you receive — your job is to
decide whether the logs *nevertheless* show the candidate's vulnerability triggered.

You receive (a) a structured iTrue candidate description (vulnerable site, trigger message/IE, the
missing validation, the data flow), and (b) the tail of the runtime logs from the PoC run plus the
target NF container. You have NO tools — judge purely from the logs in front of you.

How to decide:
  - CONFIRMED only if the logs contain concrete evidence the missing validation was indeed skipped
    AND the unsafe operation was performed. Examples:
      * audit line that the NF accepted a request it should have rejected;
      * internal-state mutation recorded in the log (e.g. "PDR <id> created" appearing twice for a
        duplicate-id flaw whose missing_validation is the uniqueness check);
      * behaviour change (e.g. session reused across tenants, response carrying foreign IE values).
  - "PoC sent some bytes and the NF processed them quietly" is NOT confirmation — that is the
    default behaviour for a benign message and proves nothing.
  - You MUST quote one specific log line verbatim as evidence. If you cannot quote one, you cannot
    confirm — set ``confirmed: false``.
  - Prefer ``confirmed: false`` when ambiguous. The cost of a false positive (claiming a bug that is
    not there) is higher than missing one — the EA will retry.

Output ONLY this JSON object (no markdown, no commentary):
{
  "confirmed": <bool>,
  "signal_type": "audit" | "behavior" | "state" | "none",
  "evidence": "<one log line, quoted verbatim, or empty>",
  "reasoning": "<one short sentence>"
}
"""


def build_oracle_prompt(*, candidate: iTrueCandidate, logs: str) -> str:
    site = candidate.vulnerable_site
    return f"""\
### CANDIDATE
id                : {candidate.id}
vulnerable_site   : {site.file}:{site.line} in {site.function}
                    {site.dangerous_operation}
trigger_message   : {candidate.trigger_message}
trigger_ie        : {candidate.trigger_ie}
ie_field          : {candidate.ie_field}
missing_validation: {candidate.missing_validation}
data_flow         : {candidate.data_flow}

### RUNTIME LOGS  (PoC stdout/stderr + NF container, tail)
{logs}

### TASK
Decide per your system prompt. Output ONLY the JSON object specified there.
"""


def build_refinement_prompt(*, logs: str, attempt: int, poc_path: str) -> str:
    return f"""\
The PoC did not trigger the flaw (attempt {attempt}). Runtime logs from the testbed:

--- BEGIN LOGS ---
{logs}
--- END LOGS ---

Diagnose why (e.g. unknown SEID/TEID -> capture and reuse the value the UPF assigned; wrong field
offset; message rejected before reaching the sink). Edit the PoC at {poc_path}, re-run `go build`, and
report ONLY:
{{"build_ok": true, "changes": "what you fixed"}}
"""
