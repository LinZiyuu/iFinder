"""Claude Agent SDK client for iFinder Discovery Agent."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    AssistantMessage,
    TextBlock,
)


class IFinderClaudeClient:
    """High-level client for running the Discovery Agent with Claude Code."""

    def __init__(
        self,
        *,
        model: str = "claude-sonnet-4-20250514",
        additional_tools: list[str] | None = None,
        setting_sources: list[str] | None = None,
    ) -> None:
        self.model = model
        self.additional_tools = additional_tools or []
        self.setting_sources = setting_sources

        self._client: ClaudeSDKClient | None = None

    def _build_options(self, allowed_tools: list[str] | None = None) -> ClaudeAgentOptions:
        tools = list(set((allowed_tools or []) + self.additional_tools))
        tools.extend(["Read", "Write", "Edit", "Glob", "Grep", "Bash"])

        options_kwargs: dict[str, Any] = {
            "allowed_tools": list(set(tools)),
            "model": self.model,
        }
        if self.setting_sources:
            options_kwargs["setting_sources"] = self.setting_sources
        return ClaudeAgentOptions(**options_kwargs)

    async def __aenter__(self) -> "IFinderClaudeClient":
        self._client = ClaudeSDKClient(options=self._build_options())
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.__aexit__(exc_type, exc_val, exc_tb)
            self._client = None

    async def query(self, prompt: str) -> AsyncIterator[Any]:
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context manager.")
        await self._client.query(prompt)
        async for message in self._client.receive_response():
            yield message

    async def phase1_discover(
        self,
        *,
        pattern_path: str | Path,
        scope_path: str | Path,
        coverage_map: dict[str, Any] | str | Path | None = None,
        target_name: str | None = None,
        target_version: str = "unknown",
        output_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Run Discovery Agent scanning via Claude Agent SDK."""
        pattern_path = Path(pattern_path)
        scope_path = Path(scope_path)
        pattern = json.loads(pattern_path.read_text(encoding="utf-8"))
        scope = json.loads(scope_path.read_text(encoding="utf-8"))

        coverage_payload: dict[str, Any] | None = None
        if coverage_map is not None:
            if isinstance(coverage_map, (str, Path)):
                coverage_path = Path(coverage_map)
                if not coverage_path.exists():
                    raise FileNotFoundError(f"Coverage map not found: {coverage_path}")
                coverage_payload = json.loads(coverage_path.read_text(encoding="utf-8"))
            else:
                coverage_payload = coverage_map

        targets = scope.get("targets", [])
        if not targets:
            raise ValueError(f"No targets found in scope file: {scope_path}")

        selected = None
        if target_name:
            for target in targets:
                if target.get("name") == target_name:
                    selected = target
                    break
            if not selected:
                raise ValueError(f"Target '{target_name}' not found in scope file.")
        else:
            selected = targets[0]

        pattern_id = str(pattern.get("pattern_id", "UNKNOWN"))
        output_path = Path(output_path) if output_path else Path("outputs/discovery_results") / (
            f"{pattern_id}-{selected.get('name', 'target')}-"
            f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)

        prompt = f"""You are a security researcher for PFCP vulnerability discovery.

### MISSION
Find ALL potential vulnerabilities matching the pattern.
Prioritize RECALL - include uncertain cases.

### PATTERN
**ID**: {pattern.get('pattern_id')}
**Name**: {pattern.get('pattern_name')}
**Description**:
{pattern.get('pattern_description')}

### TARGET
**Codebase**: {selected.get('target_codebase')}
**Scan Directories (MUST scan these explicitly)**: {json.dumps(selected.get('scan_dirs', []))}

### SCOPE
{json.dumps(scope, indent=2)}

### PROTOCOL KB (Messages and IEs to scan)
{json.dumps(coverage_payload or {}, indent=2)}

### Scanning codebase
Read the PATTERN description above - it tells you exactly what dangerous operations to find.

**Key principle**: Do NOT only look at parsing code. Trace to where values are actually USED.

### Verifying Coverage
After scanning, verify all messages and IEs are covered:

1. Check `audited_messages == total_messages`
2. Check `audited_ies == total_ies`
3. Check `skipped_messages == []`
4. Check `missing_ie_paths == []`

If coverage is incomplete, continue scanning until 100% coverage.

### STOP CONDITION (MANDATORY)
Only stop when:
1) skipped_messages == []
2) missing_ie_paths == []
3) audited_messages == total_messages
4) audited_ies == total_ies

### OUTPUT
Write JSON to: {str(output_path)}

Required fields (DiscoveryResult schema):
- pattern_id
- target_codebase
- target_version
- discovery_timestamp (ISO 8601)
- candidates: list of iTrue candidates

Candidate fields:
- id
- vulnerable_site (file, line, function, dangerous_operation)
- trigger_message
- trigger_ie
- ie_field
- data_flow
- call_chain

Do NOT include fields named "missing_validation" or "validation_checked".
Do NOT include any coverage_report or coverage fields in the output.
Use absolute paths in vulnerable_site.file.
"""

        responses: list[str] = []
        async for message in self.query(prompt):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        responses.append(block.text)

        return {
            "pattern_id": pattern_id,
            "target": selected,
            "output_path": str(output_path),
            "messages": responses,
        }
