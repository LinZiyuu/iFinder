from __future__ import annotations

import asyncio
import json
import logging
import os
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
_CONTEXT_LINES = 60
_LLM_HANDLER_SEARCH_TIMEOUT_S = int(os.getenv("IFINDER_VA_HANDLER_TIMEOUT_S", "180"))
_LLM_VETTING_TIMEOUT_S = int(os.getenv("IFINDER_VA_VETTING_TIMEOUT_S", "180"))
_LLM_MODEL = os.getenv("IFINDER_VA_MODEL", "claude-sonnet-4-5-20250929")

# Cache handler-search results because many candidates map to the same procedure
# and thus the same "prior messages" set.
_HANDLER_SEARCH_CACHE: dict[tuple[str, tuple[str, ...], tuple[str, ...]], list[dict[str, Any]]] = {}


def _handler_search_cache_key(
    messages: list[str],
    target_codebase: str | Path,
    scan_dirs: list[str] | None,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    base = str(Path(target_codebase).resolve())
    norm_dirs = tuple(str(d).rstrip("/") for d in (scan_dirs or []))
    norm_msgs = tuple(str(m).strip() for m in messages)
    return base, norm_dirs, norm_msgs


def _normalize_trigger_name(
    trigger_message: str,
    procedure_index: ProcedureIndex,
) -> str:
    """Map a discovery trigger name to the procedure message name.

    If the trigger already exists in some procedure, return it unchanged.
    Otherwise try to build the canonical ``PFCP_Camel_Case`` form and fall
    back to a substring search across all procedure messages.
    """
    # Fast path: exact match
    for proc in procedure_index.values():
        for item in proc.get("message_flow", []):
            if item.get("message") == trigger_message:
                return trigger_message

    # Build canonical form: "SessionEstablishmentRequest" -> "PFCP_Session_Establishment_Request"
    import re

    parts = re.findall(r"[A-Z][a-z]*", trigger_message)
    if parts:
        canonical = "PFCP_" + "_".join(parts)
        for proc in procedure_index.values():
            for item in proc.get("message_flow", []):
                if item.get("message") == canonical:
                    return canonical

    # Substring fallback: find any procedure message containing the trigger as substring
    trigger_lower = trigger_message.lower().replace(" ", "").replace("_", "")
    for proc in procedure_index.values():
        for item in proc.get("message_flow", []):
            msg = item.get("message", "")
            msg_lower = msg.lower().replace("_", "")
            if trigger_lower in msg_lower or msg_lower in trigger_lower:
                return msg

    return trigger_message


def load_procedure_index(procedure_dir: str | Path) -> ProcedureIndex:
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
    matches: list[str] = []
    for procedure_id, procedure in procedure_index.items():
        flow = procedure.get("message_flow", [])
        if any(item.get("message") == trigger_message for item in flow):
            matches.append(procedure_id)
    return matches


def _sort_flow_items(items: list[MessageFlowItem]) -> list[MessageFlowItem]:
    return sorted(items, key=lambda x: x.get("seq", 0))


def get_same_procedure_prior_messages(
    procedure: ProcedureData,
    trigger_message: str,
) -> list[MessageFlowItem]:
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
    procedure_index = load_procedure_index(procedure_dir)
    normalized = _normalize_trigger_name(trigger_message, procedure_index)
    if normalized != trigger_message:
        logger.info("Mapped trigger name: %s -> %s", trigger_message, normalized)
    matches = find_procedures_containing_message(normalized, procedure_index)
    if not matches:
        raise ValueError(f"No procedure contains trigger message: {trigger_message} (normalized: {normalized})")
    if len(matches) > 1:
        raise ValueError(
            "Trigger message is ambiguous across procedures; "
            f"matches={matches}, trigger={trigger_message}"
        )

    matched_procedure = matches[0]
    same_procedure_prior = get_same_procedure_prior_messages(
        procedure_index[matched_procedure], normalized
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
        "trigger_message": normalized,
        "matched_procedure": matched_procedure,
        "same_procedure_prior_messages": same_procedure_prior,
        "dependency_chain": dependency_chain,
        "dependency_messages": dependency_messages,
    }


def collect_expanded_messages(expanded_context: dict[str, Any]) -> list[str]:
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


def collect_code_for_messages(
    messages: list[str],
    target_codebase: str | Path,
    scan_dirs: list[str] | None = None,
    *,
    context_lines: int = _CONTEXT_LINES,
) -> list[dict[str, Any]]:
    roots = _resolve_scan_roots(target_codebase, scan_dirs)
    source_files = _iter_source_files(roots)

    snippets: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()

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


def evaluate_candidate_with_expanded_context(
    candidate: iTrueCandidate | dict[str, Any],
    *,
    procedure_dir: str | Path,
    target_codebase: str | Path,
    scan_dirs: list[str] | None = None,
    max_handler_hits_per_message: int = 2,
) -> VettingDecision:
    cand = _normalize_candidate(candidate)
    expanded = build_expanded_context_for_candidate(cand.trigger_message, procedure_dir)
    context_messages = collect_expanded_messages(expanded)

    handler_results = _run_llm_handler_search(
        context_messages,
        target_codebase,
        scan_dirs,
    )
    if max_handler_hits_per_message > 0 and handler_results:
        counts: dict[str, int] = {}
        trimmed: list[dict[str, Any]] = []
        for item in handler_results:
            msg = str(item.get("message", "")).strip()
            if not msg:
                continue
            counts[msg] = counts.get(msg, 0) + 1
            if counts[msg] <= max_handler_hits_per_message:
                trimmed.append(item)
        if len(trimmed) != len(handler_results):
            logger.info(
                "Trimmed handler hits per message: %d -> %d (limit=%d)",
                len(handler_results),
                len(trimmed),
                max_handler_hits_per_message,
            )
        handler_results = trimmed

    snippets: list[dict[str, Any]] = []
    mappings: list[PriorMessageHandlerMapping] = []
    messages_with_code: set[str] = set()
    for hr in handler_results:
        messages_with_code.add(hr["message"])
        snippets.append(hr)
        mappings.append(
            PriorMessageHandlerMapping(
                message=hr["message"],
                handler=hr.get("handler", f"{Path(hr['file']).name}:{hr.get('match_line', 0)}"),
                file=hr["file"],
                validation_found=False,
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

    if snippets:
        blocked, reason = _run_llm_vetting(cand, snippets)
    else:
        blocked = False
        reason = "No prior-message code found in codebase to analyse."

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
    disc = _normalize_discovery_result(discovery)
    decisions: list[VettingDecision] = []

    total = len(disc.candidates)
    logger.info(
        "Vetting %d candidates (procedure_dir=%s, target_codebase=%s, scan_dirs=%s)",
        total,
        procedure_dir,
        target_codebase,
        scan_dirs,
    )

    for idx, candidate in enumerate(disc.candidates, start=1):
        logger.info(
            "Vetting candidate %d/%d: id=%s trigger_message=%s",
            idx,
            total,
            getattr(candidate, "id", "<unknown>"),
            getattr(candidate, "trigger_message", "<unknown>"),
        )
        try:
            decision = evaluate_candidate_with_expanded_context(
                candidate,
                procedure_dir=procedure_dir,
                target_codebase=target_codebase,
                scan_dirs=scan_dirs,
                max_handler_hits_per_message=max_handler_hits_per_message,
            )
        except ValueError as exc:
            logger.warning("Skipping candidate %s: %s", candidate.id, exc)
            continue
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


def _run_llm_handler_search(
    messages: list[str],
    target_codebase: str | Path,
    scan_dirs: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Synchronous wrapper for _llm_search_handlers."""
    if not messages:
        return []

    key = _handler_search_cache_key(messages, target_codebase, scan_dirs)
    cached = _HANDLER_SEARCH_CACHE.get(key)
    if cached is not None:
        logger.info("Handler search cache hit (messages=%d)", len(messages))
        return cached

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    try:
        if loop and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    asyncio.run,
                    _llm_search_handlers(messages, target_codebase, scan_dirs),
                )
                results = future.result(timeout=_LLM_HANDLER_SEARCH_TIMEOUT_S)
        else:
            results = asyncio.run(
                asyncio.wait_for(
                    _llm_search_handlers(messages, target_codebase, scan_dirs),
                    timeout=_LLM_HANDLER_SEARCH_TIMEOUT_S,
                )
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM handler search failed: %s", exc)
        return []

    _HANDLER_SEARCH_CACHE[key] = results
    logger.info("Handler search cached (messages=%d, results=%d)", len(messages), len(results))
    return results


async def _llm_search_handlers(
    messages: list[str],
    target_codebase: str | Path,
    scan_dirs: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Use Claude with code-search tools to locate handlers for prior messages."""
    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, TextBlock, query

    base = Path(target_codebase)
    if scan_dirs:
        scan_paths = ", ".join(str(base / d) for d in scan_dirs)
    else:
        scan_paths = str(base)

    messages_list = "\n".join(f"  - {m}" for m in messages)

    prompt = f"""You are a telecom protocol stack code analyst (5G Core / EPC).

Your task: locate the **handler functions** for each of the following protocol messages
in the target codebase. A handler is a function that is called when the protocol message
is received and that processes / decodes / dispatches it.

=== Protocol messages to locate ===
{messages_list}

=== Target codebase ===
Scan paths: {scan_paths}
Source file extensions: .c, .h, .cc, .cpp, .cxx, .go

=== Instructions ===
For each message:
1. Use Grep to search for the message name and common variants (e.g. for
   "PFCP_Session_Establishment_Request", also try "SessionEstablishmentRequest",
   "session_establishment_request", "SESSION_ESTABLISHMENT", etc.)
2. Use Read to examine promising matches — verify the code is an actual handler
   (function definition that processes the message), not just a log line, comment,
   enum constant, or unrelated reference
3. If you find a handler, use Read to capture ~60 lines of context around the
   handler entry point
4. If initial search yields no results, try broader keyword substrings or check
   dispatch tables / switch-case blocks that route messages to handlers

For each handler you find, record:
- Which message it handles
- The file path and line number
- The handler function name
- A code snippet (~60 lines of context)

=== Output format ===
Respond with EXACTLY a JSON array (no other text). Each element:
{{
  "message": "<protocol message name>",
  "file": "<absolute file path>",
  "match_line": <line number of handler entry>,
  "handler": "<function_name>",
  "code": "<code snippet with ~60 lines of context>"
}}

If no handler is found for a message, omit it from the array.
Return [] if nothing is found at all."""

    options = ClaudeAgentOptions(
        model=_LLM_MODEL,
        allowed_tools=["Grep", "Glob", "Read"],
    )

    response_text = ""
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    response_text += block.text

    return _parse_handler_search_results(response_text)


def _parse_handler_search_results(response: str) -> list[dict[str, Any]]:
    """Parse the JSON array returned by the handler search LLM."""
    text = response.strip()

    # Extract JSON array from response (handle markdown code blocks)
    if "```" in text:
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1:
            text = text[start : end + 1]
    elif not text.startswith("["):
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1:
            text = text[start : end + 1]

    try:
        results = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("Failed to parse handler search results as JSON")
        return []

    if not isinstance(results, list):
        return []

    validated: list[dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        if "message" in item and "file" in item:
            validated.append({
                "message": str(item.get("message", "")),
                "file": str(item.get("file", "")),
                "match_line": int(item.get("match_line", 0)),
                "handler": str(item.get("handler", "")),
                "code": str(item.get("code", "")),
            })
    return validated


def _run_llm_vetting(
    candidate: iTrueCandidate,
    snippets: list[dict[str, Any]],
) -> tuple[bool, str]:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    try:
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, _llm_security_check(candidate, snippets))
                return future.result(timeout=_LLM_VETTING_TIMEOUT_S)
        else:
            return asyncio.run(
                asyncio.wait_for(
                    _llm_security_check(candidate, snippets),
                    timeout=_LLM_VETTING_TIMEOUT_S,
                )
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM vetting failed for candidate %s: %s", candidate.id, exc)
        return False, f"LLM vetting error: {exc}"


async def _llm_security_check(
    candidate: iTrueCandidate,
    snippets: list[dict[str, Any]],
) -> tuple[bool, str]:
    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, TextBlock, query

    code_parts: list[str] = []
    budget = 24000
    for snip in snippets:
        header = f"--- {snip['file']}  (message: {snip['message']}, match at line {snip['match_line']}) ---"
        section = f"{header}\n{snip['code']}\n"
        if len("\n".join(code_parts)) + len(section) > budget:
            break
        code_parts.append(section)

    code_block = "\n".join(code_parts)

    prompt = f"""You are a security code auditor performing vulnerability feasibility analysis
on a telecom protocol stack implementation (e.g. 5G Core / EPC).

Below is a candidate vulnerability and code snippets from the target codebase that
handle **prior protocol messages** — i.e. messages that the implementation processes
BEFORE the trigger message arrives.

Your task: determine whether the prior-message handlers contain **validation,
sanitization, bounds checking, or other defensive logic** that would **prevent
the dangerous operation from being triggered** when the trigger message carrying
the malicious IE field is later processed.

=== Tools available ===
You have Grep, Glob, and Read tools. Use them to:
- Follow function calls in the snippets to their implementations (e.g. if a snippet
  calls validate_ie(), use Grep to find that function and Read to examine it)
- Search for additional validation logic beyond the provided snippets (e.g. shared
  validation functions, common check macros, decoder-level constraints)
- Read more context around a snippet when 60 lines is not enough to determine
  whether a check exists
- Trace the call chain from the candidate vulnerability to verify the data flow

=== What counts as BLOCKING ===
- Input validation on the IE field (or its parent IE / structure)
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

=== What does NOT count as BLOCKING ===
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

=== Prior-message code snippets (starting point) ===
{code_block}

=== Instructions ===
1. First review the provided snippets for obvious validation logic
2. Use Grep/Read to follow any function calls that might contain validation
3. Search for the IE field name in the codebase to find additional checks
4. After your analysis, respond with EXACTLY this format as your final answer:

VERDICT: BLOCKED or VERDICT: NOT_BLOCKED
REASON: <one-sentence explanation of what validation exists or why it is absent>
"""

    options = ClaudeAgentOptions(
        model=_LLM_MODEL,
        allowed_tools=["Grep", "Glob", "Read"],
    )

    response_text = ""
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    response_text += block.text

    return _parse_llm_verdict(response_text)


def _parse_llm_verdict(response: str) -> tuple[bool, str]:
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
    lowered = line.lower()
    return any(kw.lower() in lowered for kw in keywords)
