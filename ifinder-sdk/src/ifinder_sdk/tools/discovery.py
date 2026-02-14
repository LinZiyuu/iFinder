from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ifinder_sdk.config import (
    DiscoveryResult,
    VulnerableSite,
    iTrueCandidate,
)

logger = logging.getLogger(__name__)

_DEFAULT_DA_MODEL = "claude-sonnet-4-5-20250929"


@dataclass(frozen=True)
class RiskyUsage:
    file_path: Path
    line_no: int
    snippet: str
    operation_keyword: str
    ie_field: str
    function_name: str
    trigger_message: str


_C_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx"}
_GO_EXTENSIONS = {".go"}
_DEFAULT_SCAN_EXTENSIONS = _C_EXTENSIONS | _GO_EXTENSIONS

_DANGEROUS_OPERATION_DEFAULTS = {
    "c": ["memcpy", "memmove", "realloc", "strcpy", "strncpy", "assert", "abort"],
    "go": ["copy(", "panic(", "log.Fatal", "append("],
}

_VALIDATION_KEYWORDS = {
    "syntactic": [
        "mandatory",
        "length",
        "len(",
        "null",
        "nil",
        "format",
        "parse",
    ],
    "semantic": [
        "range",
        "state",
        "valid",
        "check",
        "enum",
        "type",
        "consistency",
    ],
    "resource": [
        "capacity",
        "quota",
        "limit",
        "alloc",
        "pool",
        "permission",
        "access",
        "authorization",
    ],
}

_MESSAGE_PATTERN_PRIMARY = re.compile(r"\bPFCP_[A-Za-z0-9_]+_(?:Request|Response)\b")
_MESSAGE_PATTERN_FALLBACK = re.compile(r"\b[A-Za-z0-9_]+(?:Request|Response)\b")

_FUNCTION_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_C_DEFINITION_RE = re.compile(
    r"^\s*(?:[A-Za-z_][\w\s\*\(\),]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{?\s*$"
)
_GO_DEFINITION_RE = re.compile(
    r"^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*(?:\([^)]+\)\s*)?\{?\s*$"
)
_NON_FUNCTION_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof"}


def load_pattern(pattern_path: str | Path) -> dict[str, Any]:
    path = Path(pattern_path)
    if not path.exists():
        raise FileNotFoundError(f"Pattern file not found: {path}")
    with open(path, encoding="utf-8") as fp:
        return json.load(fp)


def discover_itrue_candidates(
    *,
    pattern: dict[str, Any] | str | Path,
    target_codebase: str | Path,
    scan_dirs: list[str],
    target_version: str = "unknown",
    include_uncertain: bool = True,
    max_candidates: int = 200,
    max_call_depth: int = 8,
    model: str | None = None,
) -> DiscoveryResult:
    pattern_data = load_pattern(pattern) if isinstance(pattern, (str, Path)) else pattern
    pattern_id = str(pattern_data.get("pattern_id", "UNKNOWN"))

    llm_candidates = _run_llm_discovery(
        pattern_data,
        target_codebase,
        scan_dirs,
        pattern_id,
        max_candidates,
        include_uncertain=include_uncertain,
        max_call_depth=max_call_depth,
        model=model,
    )

    return DiscoveryResult(
        pattern_id=pattern_id,
        target_codebase=str(target_codebase),
        target_version=target_version,
        discovery_timestamp=datetime.now(timezone.utc),
        candidates=llm_candidates[:max_candidates],
    )


def collect_source_files(
    target_codebase: str | Path,
    scan_dirs: list[str],
    extensions: set[str] | None = None,
) -> list[Path]:
    base = Path(target_codebase)
    if not base.exists():
        raise FileNotFoundError(f"Target codebase not found: {base}")

    wanted = extensions or _DEFAULT_SCAN_EXTENSIONS
    files: list[Path] = []

    for rel in scan_dirs:
        root = base / rel
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in wanted:
                files.append(path)

    return sorted(set(files))


def locate_risky_ie_usages(
    pattern_data: dict[str, Any],
    source_files: list[Path],
) -> list[RiskyUsage]:
    risky: list[RiskyUsage] = []
    operation_map = _ground_dangerous_operations(pattern_data)

    for path in source_files:
        lang_key = _language_key(path)
        operation_keywords = operation_map.get(lang_key, [])
        if not operation_keywords:
            continue

        lines = _safe_read_lines(path)
        for idx, line in enumerate(lines, start=1):
            op = _first_matching_keyword(line, operation_keywords)
            if not op:
                continue
            ie_field = _infer_ie_field_from_line(line)
            function_name = _infer_enclosing_function(lines, idx - 1, path.suffix.lower())
            trigger_message = _infer_trigger_message(lines, idx - 1)
            risky.append(
                RiskyUsage(
                    file_path=path,
                    line_no=idx,
                    snippet=line.rstrip(),
                    operation_keyword=op,
                    ie_field=ie_field,
                    function_name=function_name,
                    trigger_message=trigger_message,
                )
            )

    return risky


def construct_execution_path_context(
    *,
    sink_function: str,
    source_files: list[Path],
    max_depth: int = 8,
) -> list[str]:
    if not sink_function or sink_function == "unknown_function":
        return [sink_function]

    chain: list[str] = [sink_function]
    visited: set[str] = {sink_function}
    current = sink_function

    for _ in range(max_depth):
        callers = find_callers_of_function(current, source_files)
        callers = [c for c in callers if c not in visited and c != "unknown_function"]
        if not callers:
            break

        callers.sort(key=lambda name: _is_handler_like(name), reverse=True)
        chosen = callers[0]
        chain.insert(0, chosen)
        visited.add(chosen)

        if _is_handler_like(chosen):
            break
        current = chosen

    return chain


def check_required_validations(
    *,
    pattern_data: dict[str, Any],
    call_chain: list[str],
    source_files: list[Path],
) -> tuple[dict[str, bool], str]:
    required = _required_validation_types(pattern_data)
    chain_text = _collect_call_chain_context(call_chain, source_files).lower()

    syntactic_found = _has_any_keyword(chain_text, _VALIDATION_KEYWORDS["syntactic"])
    semantic_found = _has_any_keyword(chain_text, _VALIDATION_KEYWORDS["semantic"])
    resource_found = _has_any_keyword(chain_text, _VALIDATION_KEYWORDS["resource"])

    checked = {
        "syntactic": syntactic_found,
        "semantic": semantic_found,
        "resource": resource_found,
    }

    missing: list[str] = []
    if "syntactic" in required and not syntactic_found:
        missing.append("syntactic validation")
    if "semantic" in required and not semantic_found:
        missing.append("semantic validation")
    if "resource" in required and not resource_found:
        missing.append("resource validation")

    if not missing:
        return checked, ""
    return checked, "Missing " + ", ".join(missing) + " along discovered call path."


def find_callers_of_function(function_name: str, source_files: list[Path]) -> list[str]:
    needle = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    callers: set[str] = set()

    for path in source_files:
        lines = _safe_read_lines(path)
        ext = path.suffix.lower()
        for idx, line in enumerate(lines):
            if not needle.search(line):
                continue
            defined = _match_function_definition(line, ext)
            if defined == function_name:
                continue
            caller = _infer_enclosing_function(lines, idx, ext)
            if caller and caller != function_name:
                callers.add(caller)

    return sorted(callers)


def _run_llm_discovery(
    pattern_data: dict[str, Any],
    target_codebase: str | Path,
    scan_dirs: list[str],
    pattern_id: str,
    max_candidates: int,
    *,
    include_uncertain: bool,
    max_call_depth: int,
    model: str | None,
) -> list[iTrueCandidate]:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                asyncio.run,
                _llm_discovery(
                    pattern_data,
                    target_codebase,
                    scan_dirs,
                    pattern_id,
                    max_candidates,
                    include_uncertain=include_uncertain,
                    max_call_depth=max_call_depth,
                    model=model,
                ),
            )
            return future.result(timeout=600)
    else:
        return asyncio.run(
            _llm_discovery(
                pattern_data,
                target_codebase,
                scan_dirs,
                pattern_id,
                max_candidates,
                include_uncertain=include_uncertain,
                max_call_depth=max_call_depth,
                model=model,
            )
        )


async def _llm_discovery(
    pattern_data: dict[str, Any],
    target_codebase: str | Path,
    scan_dirs: list[str],
    pattern_id: str,
    max_candidates: int,
    *,
    include_uncertain: bool,
    max_call_depth: int,
    model: str | None,
) -> list[iTrueCandidate]:
    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, TextBlock, query

    scan_paths = [str(Path(target_codebase) / d) for d in scan_dirs]

    prompt = f"""You are the Discovery Agent (DA) in the iFinder vulnerability discovery framework.
Your goal is to discover iTrue (implicit-trust violation) candidates in a telecom
protocol stack codebase by performing **semantic backward analysis** against a
known vulnerability pattern.

=== Vulnerability Pattern ===
{json.dumps(pattern_data, indent=2)}

=== Target Codebase ===
Root: {target_codebase}
Directories to scan: {json.dumps(scan_paths)}

=== Methodology: Semantic Backward Analysis (three steps) ===

You have full access to Grep, Glob, and Read tools. Use them freely in each step.

**Step 1 — Locating risky IE usages**
Read the pattern description. The pattern uses language-agnostic terms (e.g.
"memory operations"). Ground these abstract operations into concrete,
language-specific constructs in the target codebase. Then search the scan
directories to find code locations where a protocol-controlled Information Element
(IE) is used in one of these dangerous operations. For each detected site,
determine which IE field is passed as the argument to the dangerous operation.

**Step 2 — Constructing execution path context**
For each risky usage found in Step 1, reconstruct the call-path context via
iterative backward expansion. Starting from the function containing the dangerous
operation, search for its callers, locate relevant source files, and inspect each
caller's code. Repeat this backward traversal until you reach the protocol message
handler entry point. The resulting call chain should span from the message handler,
through intermediate parsing/processing functions, down to the function containing
the pattern-matched dangerous operation.

**Step 3 — Checking the existence of validation**
With the execution path constructed, check whether the necessary validations for
the target IE are enforced along the path. Depending on the pattern, look for
three kinds of validation:
  (1) Protocol-syntax validation — presence of mandatory-field checks, basic
      format/length constraints before accessing IE fields
  (2) Protocol-semantics validation — range checks, state-dependent invariants on
      IE values
  (3) Resource-availability validation — capacity checks, access-control checks
      before allocating requested resources
Scan each function along the call path for these checks. If the required
validation is absent on any feasible path to the dangerous operation, flag the
site as an iTrue candidate.

Return at most {max_candidates} candidates.
Limit call-chain expansion depth to at most {max_call_depth}.
Include uncertain candidates: {include_uncertain}.

=== Required Output Format ===
When you have finished your analysis, output ONLY a JSON array. Each element must
have exactly these fields:

[
  {{
    "id": "DA-{pattern_id}-001",
    "vulnerable_site": {{
      "file": "/absolute/path/to/file.c",
      "line": 123,
      "function": "function_name",
      "dangerous_operation": "the code snippet"
    }},
    "trigger_message": "PFCP_Session_Establishment_Request",
    "trigger_ie": "IE_Name",
    "ie_field": "ie_field_name",
    "data_flow": "handler -> ... -> dangerous_op(field)",
    "call_chain": ["handler", "intermediate", "sink_function"]
  }}
]

If you find no candidates, return an empty array: []"""

    options = ClaudeAgentOptions(
        model=model or _DEFAULT_DA_MODEL,
        allowed_tools=["Grep", "Glob", "Read"],
    )

    response_text = ""
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    response_text += block.text

    return _parse_llm_candidates(response_text, pattern_id)


def _parse_llm_candidates(response: str, pattern_id: str) -> list[iTrueCandidate]:
    json_match = re.search(r"\[[\s\S]*\]", response)
    if not json_match:
        logger.warning("No JSON array found in LLM discovery response for pattern %s", pattern_id)
        return []

    try:
        raw_list = json.loads(json_match.group(0))
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse LLM discovery JSON for pattern %s: %s", pattern_id, exc)
        return []

    if not isinstance(raw_list, list):
        return []

    candidates: list[iTrueCandidate] = []
    for idx, item in enumerate(raw_list):
        try:
            site = item.get("vulnerable_site", {})
            candidates.append(iTrueCandidate(
                id=item.get("id", f"DA-{pattern_id}-{idx + 1:03d}"),
                vulnerable_site=VulnerableSite(
                    file=str(site.get("file", "")),
                    line=int(site.get("line", 0)),
                    function=str(site.get("function", "unknown")),
                    dangerous_operation=str(site.get("dangerous_operation", "")),
                ),
                trigger_message=str(item.get("trigger_message", "UnknownMessage")),
                trigger_ie=str(item.get("trigger_ie", "UnknownIE")),
                ie_field=str(item.get("ie_field", "unknown_field")),
                data_flow=str(item.get("data_flow", "")),
                call_chain=list(item.get("call_chain", [])),
            ))
        except (TypeError, ValueError, KeyError) as exc:
            logger.warning("Skipping malformed candidate %d for pattern %s: %s", idx, pattern_id, exc)
            continue

    return candidates


def _ground_dangerous_operations(pattern_data: dict[str, Any]) -> dict[str, list[str]]:
    grounded = {
        "c": list(_DANGEROUS_OPERATION_DEFAULTS["c"]),
        "go": list(_DANGEROUS_OPERATION_DEFAULTS["go"]),
    }

    for field in ("dangerous_operations", "operation_keywords", "keywords"):
        raw = pattern_data.get(field)
        if isinstance(raw, list):
            for op in raw:
                if not isinstance(op, str):
                    continue
                grounded["c"].append(op)
                grounded["go"].append(op)
        elif isinstance(raw, dict):
            for lang_key in ("c", "go"):
                for op in raw.get(lang_key, []):
                    if isinstance(op, str):
                        grounded[lang_key].append(op)

    desc = str(pattern_data.get("pattern_description", "")).lower()
    if "memory operation" in desc:
        grounded["c"].extend(["memcpy", "memmove", "realloc"])
        grounded["go"].extend(["copy(", "append("])
    if "assert" in desc:
        grounded["c"].append("assert")
        grounded["go"].append("panic(")

    grounded["c"] = sorted(set(grounded["c"]))
    grounded["go"] = sorted(set(grounded["go"]))
    return grounded


def _required_validation_types(pattern_data: dict[str, Any]) -> set[str]:
    raw = pattern_data.get("required_validations")
    if isinstance(raw, list):
        parsed = {str(x).lower() for x in raw}
    elif isinstance(raw, dict):
        parsed = {str(k).lower() for k, v in raw.items() if v}
    else:
        parsed = {"syntactic", "semantic", "resource"}

    normalized: set[str] = set()
    for item in parsed:
        if "syntax" in item:
            normalized.add("syntactic")
        elif "semantic" in item:
            normalized.add("semantic")
        elif "resource" in item or "capacity" in item or "access" in item:
            normalized.add("resource")
    return normalized or {"syntactic", "semantic", "resource"}


def _collect_call_chain_context(call_chain: list[str], source_files: list[Path]) -> str:
    chunks: list[str] = []
    for func in call_chain:
        if func == "unknown_function":
            continue
        chunks.append(_extract_function_context(func, source_files))
    return "\n".join(chunks)


def _extract_function_context(function_name: str, source_files: list[Path], window: int = 120) -> str:
    contexts: list[str] = []
    for path in source_files:
        lines = _safe_read_lines(path)
        ext = path.suffix.lower()
        for idx, line in enumerate(lines):
            if _match_function_definition(line, ext) != function_name:
                continue
            start = max(0, idx)
            end = min(len(lines), idx + window)
            contexts.append("".join(lines[start:end]))
    return "\n".join(contexts)


def _build_data_flow(call_chain: list[str], usage: RiskyUsage) -> str:
    chain = [x for x in call_chain if x and x != "unknown_function"]
    if not chain:
        chain = ["unknown_handler"]
    return " -> ".join(chain + [f"{usage.operation_keyword}({usage.ie_field})"])


def _guess_trigger_ie(ie_field: str) -> str:
    token = ie_field.replace("->", ".").split(".")[0].split("[")[0]
    token = token.strip()
    return token or "UnknownIE"


def _has_any_keyword(text: str, keywords: list[str]) -> bool:
    return any(keyword.lower() in text for keyword in keywords)


def _language_key(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in _GO_EXTENSIONS:
        return "go"
    return "c"


def _first_matching_keyword(line: str, keywords: list[str]) -> str | None:
    lowered = line.lower()
    for kw in keywords:
        if kw.lower() in lowered:
            return kw
    return None


def _infer_ie_field_from_line(line: str) -> str:
    arg_like = re.findall(r"[A-Za-z_][A-Za-z0-9_\.\->\[\]]*", line)
    preferred = [
        tok
        for tok in arg_like
        if any(key in tok.lower() for key in ("ie", "len", "length", "size", "count", "field"))
    ]
    if preferred:
        return preferred[0]
    return arg_like[0] if arg_like else "unknown_ie_field"


def _infer_trigger_message(lines: list[str], line_idx: int, window: int = 80) -> str:
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + 1)
    region = "".join(lines[start:end])

    matches = list(_MESSAGE_PATTERN_PRIMARY.finditer(region))
    if matches:
        return matches[-1].group(0)

    fallback = list(_MESSAGE_PATTERN_FALLBACK.finditer(region))
    if fallback:
        return fallback[-1].group(0)

    return "UnknownMessage"


def _match_function_definition(line: str, ext: str) -> str | None:
    if ext in _GO_EXTENSIONS:
        match = _GO_DEFINITION_RE.match(line)
        return match.group(1) if match else None

    if ext in _C_EXTENSIONS:
        match = _C_DEFINITION_RE.match(line)
        if not match:
            return None
        name = match.group(1)
        if name in _NON_FUNCTION_KEYWORDS:
            return None
        return name

    return None


def _infer_enclosing_function(lines: list[str], line_idx: int, ext: str) -> str:
    for i in range(line_idx, -1, -1):
        fn = _match_function_definition(lines[i], ext)
        if fn:
            return fn
    return "unknown_function"


def _is_handler_like(function_name: str) -> bool:
    lowered = function_name.lower()
    if "handler" in lowered:
        return True
    if "handle" in lowered and ("request" in lowered or "response" in lowered):
        return True
    return False


def _safe_read_lines(path: Path) -> list[str]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fp:
            return fp.readlines()
    except OSError:
        return []
