"""Stage 1 Discovery helpers for semantic backward analysis.

This module implements the Discovery Agent workflow in three steps:
1) locate pattern-matched dangerous operations;
2) walk backward along caller chains to reconstruct execution context;
3) check required validations along the recovered path.
"""

from __future__ import annotations

import json
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


@dataclass(frozen=True)
class RiskyUsage:
    """A raw risky operation usage hit before candidate materialization."""

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
    """Load a pattern file as JSON."""
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
) -> DiscoveryResult:
    """Run stage-1 discovery using semantic backward analysis.

    Args:
        pattern: Pattern dict or path to pattern JSON.
        target_codebase: Root of the target codebase.
        scan_dirs: Relative directories under target_codebase to scan.
        target_version: Target release version (e.g., "v2.7.6").
        include_uncertain: Keep hits with no obvious missing validation.
        max_candidates: Upper bound for returned candidates.
        max_call_depth: Maximum backward caller expansion depth.
    """
    pattern_data = load_pattern(pattern) if isinstance(pattern, (str, Path)) else pattern
    pattern_id = str(pattern_data.get("pattern_id", "UNKNOWN"))

    source_files = collect_source_files(target_codebase, scan_dirs)
    risky_usages = locate_risky_ie_usages(pattern_data, source_files)

    candidates: list[iTrueCandidate] = []
    for idx, usage in enumerate(risky_usages, start=1):
        call_chain = construct_execution_path_context(
            sink_function=usage.function_name,
            source_files=source_files,
            max_depth=max_call_depth,
        )
        _, missing_summary = check_required_validations(
            pattern_data=pattern_data,
            call_chain=call_chain,
            source_files=source_files,
        )

        if not missing_summary and not include_uncertain:
            continue

        candidate = iTrueCandidate(
            id=f"DA-{pattern_id}-{idx:03d}",
            vulnerable_site=VulnerableSite(
                file=str(usage.file_path),
                line=usage.line_no,
                function=usage.function_name,
                dangerous_operation=usage.snippet.strip(),
            ),
            trigger_message=usage.trigger_message,
            trigger_ie=_guess_trigger_ie(usage.ie_field),
            ie_field=usage.ie_field,
            data_flow=_build_data_flow(call_chain, usage),
            call_chain=call_chain,
        )
        candidates.append(candidate)
        if len(candidates) >= max_candidates:
            break

    return DiscoveryResult(
        pattern_id=pattern_id,
        target_codebase=str(target_codebase),
        target_version=target_version,
        discovery_timestamp=datetime.now(timezone.utc),
        candidates=candidates,
    )


def collect_source_files(
    target_codebase: str | Path,
    scan_dirs: list[str],
    extensions: set[str] | None = None,
) -> list[Path]:
    """Collect source files for discovery scanning."""
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
    """Step 1: locate risky IE usages matching grounded dangerous operations."""
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
    """Step 2: reconstruct an execution path via backward caller expansion.

    This uses a grep-style heuristic:
    - find caller functions that reference the current function;
    - iteratively walk to higher callers;
    - prioritize likely handler names when multiple callers exist.
    """
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

        # Heuristic: prefer handler-like callers to reach message entry points quickly.
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
    """Step 3: check validation existence along the reconstructed call path."""
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
    """Find candidate caller functions that invoke `function_name(...)`."""
    needle = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    callers: set[str] = set()

    for path in source_files:
        lines = _safe_read_lines(path)
        ext = path.suffix.lower()
        for idx, line in enumerate(lines):
            if not needle.search(line):
                continue
            # Skip definitions of the same function.
            defined = _match_function_definition(line, ext)
            if defined == function_name:
                continue
            caller = _infer_enclosing_function(lines, idx, ext)
            if caller and caller != function_name:
                callers.add(caller)

    return sorted(callers)


def _ground_dangerous_operations(pattern_data: dict[str, Any]) -> dict[str, list[str]]:
    """Ground abstract pattern operations into language-specific keywords."""
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
    """Parse required validation categories from pattern configuration."""
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
    """Collect textual context for each function in call_chain."""
    chunks: list[str] = []
    for func in call_chain:
        if func == "unknown_function":
            continue
        chunks.append(_extract_function_context(func, source_files))
    return "\n".join(chunks)


def _extract_function_context(function_name: str, source_files: list[Path], window: int = 120) -> str:
    """Extract a window of text around function definition occurrences."""
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
    # Prefer argument-like tokens often used as IE value/length/count carriers.
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
