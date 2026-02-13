from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ifinder_sdk.config import DiscoveryResult
from ifinder_sdk.tools.discovery import discover_itrue_candidates, load_pattern


def load_scope(scope_path: str | Path) -> dict[str, Any]:
    path = Path(scope_path)
    if not path.exists():
        raise FileNotFoundError(f"Scope file not found: {path}")
    with open(path, encoding="utf-8") as fp:
        return json.load(fp)


def _resolve_target(scope: dict[str, Any], target_name: str | None) -> dict[str, Any]:
    targets = scope.get("targets", [])
    if not targets:
        raise ValueError("Scope file has no targets")
    if target_name is None:
        return targets[0]
    for target in targets:
        if target.get("name") == target_name:
            return target
    raise ValueError(f"Target not found in scope: {target_name}")


def run_discovery(
    *,
    pattern_path: str | Path,
    scope_path: str | Path,
    target_name: str | None = None,
    output_dir: str | Path = "outputs",
    include_uncertain: bool = True,
    max_candidates: int = 200,
    max_call_depth: int = 8,
) -> DiscoveryResult:
    pattern = load_pattern(pattern_path)
    scope = load_scope(scope_path)
    target = _resolve_target(scope, target_name)

    target_codebase = target.get("target_codebase")
    scan_dirs = target.get("scan_dirs") or []
    if not target_codebase:
        raise ValueError("target_codebase missing in scope target")

    result = discover_itrue_candidates(
        pattern=pattern,
        target_codebase=target_codebase,
        scan_dirs=scan_dirs,
        target_version=str(scope.get("scope_name", "unknown")),
        include_uncertain=include_uncertain,
        max_candidates=max_candidates,
        max_call_depth=max_call_depth,
    )

    out_dir = Path(output_dir) / "discovery_results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{result.pattern_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.json"
    out_path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run Discovery Agent.")
    parser.add_argument("--pattern", required=True, help="Path to pattern JSON")
    parser.add_argument("--scope", required=True, help="Path to scope JSON")
    parser.add_argument("--target", default=None, help="Target name in scope")
    parser.add_argument("--output", default="outputs", help="Output directory")
    parser.add_argument("--max-candidates", type=int, default=200)
    parser.add_argument("--max-call-depth", type=int, default=8)
    parser.add_argument("--include-uncertain", action="store_true", default=True)
    args = parser.parse_args()

    run_discovery(
        pattern_path=args.pattern,
        scope_path=args.scope,
        target_name=args.target,
        output_dir=args.output,
        include_uncertain=args.include_uncertain,
        max_candidates=args.max_candidates,
        max_call_depth=args.max_call_depth,
    )
