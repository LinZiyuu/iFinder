"""Uniform ``ClaudeSDKClient`` wrapper used by all three agents.

All agents use the same client class (``ClaudeSDKClient``, a superset of ``query()``):
- **DA / VA** call :func:`run_single_turn` — one ``query()`` + ``receive_response()``, then close.
- **EA** uses :class:`MultiTurnSession` — a persistent session so the orchestrator can re-inject
  testbed logs each refinement round.
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    TextBlock,
    ToolUseBlock,
)

from ifinder import config

logger = logging.getLogger("ifinder.client")

# Least-privilege tool sets.
READONLY_TOOLS: list[str] = ["Grep", "Glob", "Read"]
EXPLOIT_TOOLS: list[str] = ["Read", "Write", "Edit", "Bash", "Grep", "Glob"]

# DA structured-output report tools, served by an in-process SDK MCP server keyed "ifinder_report".
# The DA reports findings by CALLING these (schema-enforced) instead of printing free-text JSON.
REPORT_TOOLS: list[str] = [
    "mcp__ifinder_report__report_candidate",
    "mcp__ifinder_report__report_coverage",
]
# Bash is included intentionally (orientation: pwd/ls/find); analysis stays read-only otherwise.
DISCOVERY_TOOLS: list[str] = READONLY_TOOLS + ["Bash"] + REPORT_TOOLS


@dataclass
class SessionConfig:
    """Maps onto ``claude_agent_sdk.ClaudeAgentOptions``."""

    system_prompt: str
    allowed_tools: list[str]
    cwd: Path
    model: str = config.DEFAULT_MODEL
    max_turns: int = config.DEFAULT_MAX_TURNS
    permission_mode: Optional[str] = None  # None -> SDK default; EA uses "acceptEdits"
    add_dirs: list[Path] = field(default_factory=list)  # extra readable roots (e.g. target codebase)
    mcp_servers: Optional[dict] = None  # in-process SDK MCP servers (e.g. DA's report tools)


def _build_options(cfg: SessionConfig) -> ClaudeAgentOptions:
    kwargs: dict = {
        "system_prompt": cfg.system_prompt,
        "allowed_tools": list(cfg.allowed_tools),
        "model": cfg.model,
        "cwd": str(cfg.cwd),
        "max_turns": cfg.max_turns,
        # setting_sources left unset -> do not load user/project CLAUDE.md (isolated & reproducible).
    }
    if cfg.permission_mode is not None:
        kwargs["permission_mode"] = cfg.permission_mode
    if cfg.add_dirs:
        kwargs["add_dirs"] = [str(p) for p in cfg.add_dirs]
    if cfg.mcp_servers:
        kwargs["mcp_servers"] = cfg.mcp_servers
    cli = os.environ.get("IFINDER_CLAUDE_CLI") or shutil.which("claude")
    if cli:
        kwargs["cli_path"] = cli
    return ClaudeAgentOptions(**kwargs)


def _text_of(message: object) -> str:
    """Concatenate the TextBlock content of an AssistantMessage (and log tool calls)."""
    if not isinstance(message, AssistantMessage):
        return ""
    parts: list[str] = []
    for block in message.content:
        if isinstance(block, TextBlock):
            parts.append(block.text)
        elif isinstance(block, ToolUseBlock):
            logger.debug("tool %s input=%s", block.name, block.input)
    return "".join(parts)


async def run_single_turn(prompt: str, cfg: SessionConfig) -> str:
    """Run one autonomous tool-loop turn and return the assistant's final text (used by DA and VA)."""
    text: list[str] = []
    async with ClaudeSDKClient(options=_build_options(cfg)) as client:
        await client.query(prompt)
        async for message in client.receive_response():
            text.append(_text_of(message))
    return "".join(text)


class MultiTurnSession:
    """Persistent ``ClaudeSDKClient`` session for EA's execute→analyze→refine loop."""

    def __init__(self, cfg: SessionConfig) -> None:
        self.cfg = cfg
        self._client: Optional[ClaudeSDKClient] = None

    async def __aenter__(self) -> "MultiTurnSession":
        self._client = ClaudeSDKClient(options=_build_options(self.cfg))
        await self._client.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.disconnect()
            self._client = None

    async def send(self, prompt: str) -> str:
        """Send a turn into the persistent session and return the assistant's text."""
        if self._client is None:
            raise RuntimeError("MultiTurnSession not entered (use 'async with').")
        await self._client.query(prompt)
        text: list[str] = []
        async for message in self._client.receive_response():
            text.append(_text_of(message))
        return "".join(text)
