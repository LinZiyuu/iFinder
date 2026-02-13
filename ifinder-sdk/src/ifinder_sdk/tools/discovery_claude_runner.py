from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from ifinder_sdk.claude_client import IFinderClaudeClient


def _resolve_pattern_path(pattern: str, pattern_dir: str) -> Path:
    path = Path(pattern)
    if path.exists():
        return path
    base = Path(pattern_dir)
    candidate = base / pattern
    if candidate.exists():
        return candidate
    if not pattern.endswith(".json"):
        candidate = base / f"{pattern}.json"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"Pattern not found: {pattern}")


def _resolve_scope_path(scope: str, scope_dir: str) -> Path:
    path = Path(scope)
    if path.exists():
        return path
    base = Path(scope_dir)
    candidate = base / scope
    if candidate.exists():
        return candidate
    if not scope.endswith(".json"):
        candidate = base / f"{scope}.json"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"Scope file not found: {scope}")


async def _run(args: argparse.Namespace) -> dict[str, str]:
    pattern_path = _resolve_pattern_path(args.pattern, args.pattern_dir)
    scope_path = _resolve_scope_path(args.scope, args.scope_dir)
    coverage_path: Path | None = None
    if args.coverage_map:
        coverage_path = Path(args.coverage_map)

    output_path: Path | None = None
    if args.output_path or args.output_dir:
        pattern_data = json.loads(pattern_path.read_text(encoding="utf-8"))
        pattern_id = pattern_data.get("pattern_id", "UNKNOWN")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        if args.output_path:
            output_path = Path(args.output_path)
        else:
            target_slug = args.target or "target"
            output_path = Path(args.output_dir) / f"{pattern_id}-{target_slug}-{timestamp}.json"

    async with IFinderClaudeClient(
        model=args.model,
        setting_sources=args.setting_source,
    ) as client:
        result = await client.phase1_discover(
            pattern_path=pattern_path,
            scope_path=scope_path,
            coverage_map=coverage_path,
            target_name=args.target,
            target_version=args.target_version,
            output_path=output_path,
        )

    return {
        "pattern_id": result["pattern_id"],
        "output_path": result["output_path"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Discovery Agent via Claude Agent SDK.")
    parser.add_argument("--pattern", required=True, help="Pattern ID or path (e.g., PA1 or PA1.json).")
    parser.add_argument("--scope", required=True, help="Scope file name or path (e.g., scope_open5gs.json).")
    parser.add_argument("--target", help="Target name from scope file (defaults to first).")
    parser.add_argument("--target-version", default="unknown", help="Target version label.")
    parser.add_argument("--pattern-dir", default="pattern", help="Base directory for patterns.")
    parser.add_argument("--scope-dir", default="scope", help="Base directory for scope files.")
    parser.add_argument("--output-dir", default=None, help="Output directory for DiscoveryResult JSON.")
    parser.add_argument("--output-path", default=None, help="Full output file path.")
    parser.add_argument(
        "--coverage-map",
        default=None,
        help="Coverage map JSON file path (messages and IEs).",
    )
    parser.add_argument("--model", default="claude-sonnet-4-20250514", help="Claude model name.")
    parser.add_argument(
        "--setting-source",
        action="append",
        default=None,
        help="Claude settings source (can be repeated).",
    )

    args = parser.parse_args()
    result = asyncio.run(_run(args))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
