from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ifinder_sdk.tools.discovery import discover_itrue_candidates
from ifinder_sdk.tools.exploitation import exploit_candidate
from ifinder_sdk.tools.vetting import vet_discovery_result


ToolCallable = Callable[..., Any]


TOOL_REGISTRY: dict[str, ToolCallable] = {
    "discovery.discover_itrue_candidates": discover_itrue_candidates,
    "vetting.vet_discovery_result": vet_discovery_result,
    "exploitation.exploit_candidate": exploit_candidate,
}


def list_registered_tools() -> list[str]:
    return sorted(TOOL_REGISTRY.keys())


def get_tool(tool_id: str) -> ToolCallable:
    try:
        return TOOL_REGISTRY[tool_id]
    except KeyError as exc:
        raise KeyError(f"Unknown tool id: {tool_id}") from exc


def invoke_tool(tool_id: str, **kwargs: Any) -> Any:
    tool = get_tool(tool_id)
    return tool(**kwargs)
