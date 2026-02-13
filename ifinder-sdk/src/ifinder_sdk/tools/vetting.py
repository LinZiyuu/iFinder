"""Stage 2 Vetting helpers for code-specification cross-checking.

Workflow implemented in this module:
1) locate trigger message in procedure definitions;
2) collect prior messages in the same procedure;
3) recursively expand dependency procedures;
4) collect code snippets from the target codebase that reference each prior message;
5) pass all collected code to LLM to judge whether any validation / sanitization
   exists that would prevent the dangerous operation from being triggered.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ifinder_sdk.config import (
    DiscoveryResult,
    FeasibilityEvidence,
    PriorMessageHandlerMapping,
    VettingDecision,
    VettingResult,
    VettingStatistics,
    VettingVerdict,
    iTrueCandidate,
)

logger = logging.getLogger(__name__)

ProcedureData = dict[str, Any]
ProcedureIndex = dict[str, ProcedureData]
MessageFlowItem = dict[str, Any]

_SOURCE_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".go"}
_CONTEXT_LINES = 60  # lines before/after a match to include as context


# ---------------------------------------------------------------------------
# Steps 1-3: procedure / message expansion (unchanged)
# ---------------------------------------------------------------------------

def load_procedure_index(procedure_dir: str | Path) -> ProcedureIndex:
    """Load procedure JSON files into an index keyed by `procedure_id`."""
    base = Path(procedure_dir)
    if not base.exists():
        raise FileNotFoundError(f"Procedure directory not found: {base}")

    procedures: ProcedureIndex = {}
    for path in sorted(base.glob("*.json")):
        with open(path, encoding="utf-8") as fp:
            data = json.load(fp)
        procedure_id = data.get("procedure_id")
        if not procedure_id:
            raise ValueError(f"Missing procedure_id in file: {path}")
        procedures[procedure_id] = data

    return procedures


def find_procedures_containing_message(
    trigger_message: str,
    procedure_index: ProcedureIndex,
) -> list[str]:
    """Return procedure IDs whose message_flow contains `trigger_message`."""
    matches: list[str] = []
    for procedure_id, procedure in procedure_index.items():
        flow = procedure.get("message_flow", [])
        if any(item.get("message") == trigger_message for item in flow):
            matches.append(procedure_id)
    return matches


def _sort_flow_items(items: list[MessageFlowItem]) -> list[MessageFlowItem]:
    """Sort flow items by sequence number."""
    return sorted(items, key=lambda x: x.get("seq", 0))


def get_same_procedure_prior_messages(
    procedure: ProcedureData,
    trigger_message: str,
) -> list[MessageFlowItem]:
    """Get messages with lower `seq` than the trigger in the same procedure."""
    flow: list[MessageFlowItem] = _sort_flow_items(procedure.get("message_flow", []))
    trigger_items = [item for item in flow if item.get("message") == trigger_message]
    if not trigger_items:
        raise ValueError(
            f"Trigger message {trigger_message} not found in procedure "
            f"{procedure.get('procedure_id')}"
        )

    trigger_seq = trigger_items[0].get("seq", 0)
    return [item for item in flow if item.get("seq", 0) < trigger_seq]


def get_dependency_chain(
    procedure_id: str,
    procedure_index: ProcedureIndex,
) -> list[str]:
    """Return recursive dependency chain from nearest to farthest ancestor."""
    chain: list[str] = []
    visited: set[str] = set()
    current = procedure_id

    while True:
        if current not in procedure_index:
            raise ValueError(f"Unknown procedure_id in dependency traversal: {current}")
        dep = procedure_index[current].get("dependency_procedure")
        if dep is None:
            break
        if dep in visited:
            raise ValueError(f"Dependency cycle detected at procedure: {dep}")
        if dep not in procedure_index:
            raise ValueError(f"Unknown dependency_procedure: {dep}")

        chain.append(dep)
        visited.add(dep)
        current = dep

    return chain


def build_expanded_context_for_candidate(
    trigger_message: str,
    procedure_dir: str | Path,
) -> dict[str, Any]:
    """Build expanded vetting context for a trigger message."""
    procedure_index = load_procedure_index(procedure_dir)
    matches = find_procedures_containing_message(trigger_message, procedure_index)
    if not matches:
        raise ValueError(f"No procedure contains trigger message: {trigger_message}")
    if len(matches) > 1:
        raise ValueError(
            "Trigger message is ambiguous across procedures; "
            f"matches={matches}, trigger={trigger_message}"
        )

    matched_procedure = matches[0]
    same_procedure_prior = get_same_procedure_prior_messages(
        procedure_index[matched_procedure], trigger_message
    )
    dependency_chain = get_dependency_chain(matched_procedure, procedure_index)
    dependency_messages = [
        {
            "procedure_id": dep_id,
            "messages": _sort_flow_items(procedure_index[dep_id].get("message_flow", [])),
        }
        for dep_id in dependency_chain
    ]

    return {
        "trigger_message": trigger_message,
        "matched_procedure": matched_procedure,
        "same_procedure_prior_messages": same_procedure_prior,
        "dependency_chain": dependency_chain,
        "dependency_messages": dependency_messages,
    }


def collect_expanded_messages(expanded_context: dict[str, Any]) -> list[str]:
    """Collect unique message names from same-procedure + dependency expansion."""
    ordered: list[str] = []

    def _add(msg: str) -> None:
        if msg and msg not in ordered:
            ordered.append(msg)

    for item in expanded_context.get("same_procedure_prior_messages", []):
        _add(str(item.get("message", "")))

    for dep in expanded_context.get("dependency_messages", []):
        for item in dep.get("messages", []):
            _add(str(item.get("message", "")))

    return ordered


# ---------------------------------------------------------------------------
# Step 4: collect code snippets for prior messages
# ---------------------------------------------------------------------------

def collect_code_for_messages(
    messages: list[str],
    target_codebase: str | Path,
    scan_dirs: list[str] | None = None,
    *,
    context_lines: int = _CONTEXT_LINES,
) -> list[dict[str, Any]]:
    """For each message, search source files and collect surrounding code context.

    Returns a list of ``{message, file, start_line, code}`` dicts.
    """
    roots = _resolve_scan_roots(target_codebase, scan_dirs)
    source_files = _iter_source_files(roots)

    snippets: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()  # (message, file, start_line)

    for message in messages:
        keywords = _message_search_keywords(message)
        if not keywords:
            continue

        for path in source_files:
            lines = _safe_read_lines(path)
            for line_idx, line in enumerate(lines):
                if not _line_matches_any_keyword(line, keywords):
                    continue

                start = max(0, line_idx - context_lines)
                end = min(len(lines), line_idx + context_lines + 1)
                key = (message, str(path), start)
                if key in seen:
                    continue
                seen.add(key)

                snippet_text = "".join(lines[start:end])
                snippets.append({
                    "message": message,
                    "file": str(path),
                    "start_line": start + 1,
                    "match_line": line_idx + 1,
                    "code": snippet_text,
                })

    return snippets


# ---------------------------------------------------------------------------
# Steps 4+5 combined: evaluate candidate
# ---------------------------------------------------------------------------

def evaluate_candidate_with_expanded_context(
    candidate: iTrueCandidate | dict[str, Any],
    *,
    procedure_dir: str | Path,
    target_codebase: str | Path,
    scan_dirs: list[str] | None = None,
    max_handler_hits_per_message: int = 2,
) -> VettingDecision:
    """Run VA code-specification cross-checking for one iTrue candidate."""
    cand = _normalize_candidate(candidate)
    expanded = build_expanded_context_for_candidate(cand.trigger_message, procedure_dir)
    context_messages = collect_expanded_messages(expanded)

    # Collect code snippets for all prior messages.
    snippets = collect_code_for_messages(
        context_messages,
        target_codebase,
        scan_dirs,
    )

    # Build per-message mapping entries (for result reporting).
    mappings: list[PriorMessageHandlerMapping] = []
    messages_with_code: set[str] = set()
    for snip in snippets:
        messages_with_code.add(snip["message"])
        mappings.append(
            PriorMessageHandlerMapping(
                message=snip["message"],
                handler=f"{Path(snip['file']).name}:{snip['match_line']}",
                file=snip["file"],
                validation_found=False,  # will be updated by LLM
                validation_detail="Pending LLM analysis.",
            )
        )
    for msg in context_messages:
        if msg not in messages_with_code:
            mappings.append(
                PriorMessageHandlerMapping(
                    message=msg,
                    handler="code_not_found",
                    file="",
                    validation_found=False,
                    validation_detail="No matching code found in target codebase.",
                )
            )

    # Ask LLM to judge all collected code at once.
    if snippets:
        blocked, reason = _run_llm_vetting(cand, snippets)
    else:
        blocked = False
        reason = "No prior-message code found in codebase to analyse."

    # Update mappings with LLM result.
    for mapping in mappings:
        if mapping.file:
            mapping.validation_found = blocked
            mapping.validation_detail = reason

    if blocked:
        verdict = VettingVerdict.INFEASIBLE
        rejection_reason = reason
        defense_absence = "Security checks observed."
    else:
        verdict = VettingVerdict.FEASIBLE
        rejection_reason = None
        defense_absence = reason

    evidence = FeasibilityEvidence(
        security_check_found=blocked,
        security_check_detail=reason,
        defense_absence=defense_absence,
    )

    return VettingDecision(
        candidate_id=cand.id,
        verdict=verdict,
        procedure=str(expanded["matched_procedure"]),
        prerequisite_handlers_checked=mappings,
        feasibility_evidence=evidence,
        rejection_reason=rejection_reason,
        expanded_context={
            "same_procedure_prior_messages": expanded["same_procedure_prior_messages"],
            "dependency_chain": expanded["dependency_chain"],
        },
    )


def vet_discovery_result(
    discovery: DiscoveryResult | dict[str, Any],
    *,
    procedure_dir: str | Path,
    target_codebase: str | Path,
    scan_dirs: list[str] | None = None,
    max_handler_hits_per_message: int = 2,
) -> VettingResult:
    """Run stage-2 vetting for all candidates in a discovery result."""
    disc = _normalize_discovery_result(discovery)
    decisions: list[VettingDecision] = []

    for candidate in disc.candidates:
        decision = evaluate_candidate_with_expanded_context(
            candidate,
            procedure_dir=procedure_dir,
            target_codebase=target_codebase,
            scan_dirs=scan_dirs,
            max_handler_hits_per_message=max_handler_hits_per_message,
        )
        decisions.append(decision)

    feasible = sum(1 for item in decisions if item.verdict == VettingVerdict.FEASIBLE)
    stats = VettingStatistics(
        total_candidates=len(decisions),
        feasible=feasible,
        infeasible=len(decisions) - feasible,
    )

    return VettingResult(
        pattern_id=disc.pattern_id,
        target_codebase=disc.target_codebase,
        target_version=disc.target_version,
        vetting_timestamp=datetime.now(timezone.utc),
        statistics=stats,
        results=decisions,
    )


# ---------------------------------------------------------------------------
# Step 5: LLM-based security check
# ---------------------------------------------------------------------------

def _run_llm_vetting(
    candidate: iTrueCandidate,
    snippets: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Synchronous wrapper around the async LLM vetting call."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    try:
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, _llm_security_check(candidate, snippets))
                return future.result(timeout=120)
        else:
            return asyncio.run(_llm_security_check(candidate, snippets))
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM vetting failed for candidate %s: %s", candidate.id, exc)
        return False, f"LLM vetting error: {exc}"


async def _llm_security_check(
    candidate: iTrueCandidate,
    snippets: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Ask LLM whether the collected code contains validation that blocks the vulnerability."""
    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, TextBlock, query

    # Build code section — truncate to fit context window.
    code_parts: list[str] = []
    budget = 24000  # characters
    for snip in snippets:
        header = f"--- {snip['file']}  (message: {snip['message']}, match at line {snip['match_line']}) ---"
        section = f"{header}\n{snip['code']}\n"
        if len("\n".join(code_parts)) + len(section) > budget:
            break
        code_parts.append(section)

    code_block = "\n".join(code_parts)

    prompt = f"""You are a security code auditor performing vulnerability feasibility analysis
on a telecom protocol stack implementation (e.g. 5G Core / EPC).

Below is a candidate vulnerability and all code snippets from the target codebase
that handle **prior protocol messages** — i.e. messages that the implementation
processes BEFORE the trigger message arrives.

Your task: determine whether ANY of these code snippets contain **validation,
sanitization, bounds checking, or other defensive logic** that would **prevent
the dangerous operation from being triggered** when the trigger message carrying
the malicious IE field is later processed.

Specifically look for:
- Input validation or sanitization on the IE field (or its parent IE / structure)
  performed during an earlier message handler
- Length / bounds / range checks that reject or clamp the field value before it
  can reach the dangerous operation (buffer copy, memory allocation, pointer
  arithmetic, etc.)
- Mandatory-IE presence checks that cause early rejection / error response
  before the protocol state advances to the trigger step
- State-machine guards that would prevent the trigger message from being
  accepted if prerequisite validation failed
- Any conditional guard (if / switch / assert) whose failure path returns an
  error, sends a reject response, or aborts processing

Do NOT count as blocking:
- Logging, tracing, or debug-only statements
- Checks on completely unrelated IEs or fields
- Validation that happens AFTER the dangerous operation has already executed
- Comments describing intended checks that are not actually implemented in code

=== Candidate vulnerability ===
- Trigger message : {candidate.trigger_message}
- Trigger IE      : {candidate.trigger_ie}
- IE field        : {candidate.ie_field}
- Data flow       : {candidate.data_flow}
- Call chain      : {' -> '.join(candidate.call_chain)}

=== Prior-message code snippets ===
{code_block}

Respond with EXACTLY this format (no other text):
VERDICT: BLOCKED or VERDICT: NOT_BLOCKED
REASON: <one-sentence explanation of what validation exists or why it is absent>
"""

    options = ClaudeAgentOptions(
        model="claude-haiku-4-5-20251001",
        allowed_tools=[],
    )

    response_text = ""
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    response_text += block.text

    return _parse_llm_verdict(response_text)


def _parse_llm_verdict(response: str) -> tuple[bool, str]:
    """Parse LLM response into (blocked: bool, reason: str)."""
    lines = response.strip().splitlines()

    verdict_line = ""
    reason_line = ""
    for line in lines:
        stripped = line.strip()
        if stripped.upper().startswith("VERDICT:"):
            verdict_line = stripped
        elif stripped.upper().startswith("REASON:"):
            reason_line = stripped

    blocked = "BLOCKED" in verdict_line.upper() and "NOT_BLOCKED" not in verdict_line.upper()
    reason = reason_line.split(":", 1)[1].strip() if ":" in reason_line else response[:200]

    return blocked, reason


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalize_candidate(candidate: iTrueCandidate | dict[str, Any]) -> iTrueCandidate:
    if isinstance(candidate, iTrueCandidate):
        return candidate
    return iTrueCandidate.model_validate(candidate)


def _normalize_discovery_result(discovery: DiscoveryResult | dict[str, Any]) -> DiscoveryResult:
    if isinstance(discovery, DiscoveryResult):
        return discovery
    return DiscoveryResult.model_validate(discovery)


def _resolve_scan_roots(target_codebase: str | Path, scan_dirs: list[str] | None) -> list[Path]:
    base = Path(target_codebase)
    if not base.exists():
        raise FileNotFoundError(f"Target codebase not found: {base}")

    if not scan_dirs:
        return [base]

    roots: list[Path] = []
    for rel in scan_dirs:
        root = base / rel
        if root.exists():
            roots.append(root)
    return roots or [base]


def _iter_source_files(roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in _SOURCE_EXTENSIONS:
                files.append(path)
    return sorted(set(files))


def _safe_read_lines(path: Path) -> list[str]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fp:
            return fp.readlines()
    except OSError:
        return []


def _message_search_keywords(message: str) -> list[str]:
    """Generate search keyword variants for a protocol message name."""
    raw = message.strip()
    if not raw:
        return []
    no_pfcp = raw[5:] if raw.startswith("PFCP_") else raw
    tokens = [tok for tok in no_pfcp.split("_") if tok]
    camel = "".join(token.title() for token in tokens)
    spaced = " ".join(tokens)
    aliases = [
        raw,
        no_pfcp,
        camel,
        spaced,
        no_pfcp.replace("_", ""),
        no_pfcp.lower(),
    ]
    unique: list[str] = []
    for item in aliases:
        if item and item not in unique:
            unique.append(item)
    return unique


def _line_matches_any_keyword(line: str, keywords: list[str]) -> bool:
    """Return True if line contains any of the keywords (case-insensitive)."""
    lowered = line.lower()
    return any(kw.lower() in lowered for kw in keywords)
