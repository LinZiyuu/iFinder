"""Hook configuration profiles for iFinder SDK."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HookPolicy:
    """Execution guardrail policy consumed by SDK client/tools."""

    allowed_roots: tuple[str, ...]
    blocked_command_tokens: tuple[str, ...]
    allowed_container_prefixes: tuple[str, ...]
    require_poc_under_output_root: bool = True


def default_hook_policy(project_root: str | Path) -> HookPolicy:
    """Balanced defaults suitable for local development."""
    root = str(Path(project_root).resolve())
    return HookPolicy(
        allowed_roots=(root,),
        blocked_command_tokens=(
            "rm -rf /",
            "mkfs",
            "shutdown",
            "reboot",
            "kill -9 1",
        ),
        allowed_container_prefixes=("ifinder-", "open5gs-", "testbed-"),
        require_poc_under_output_root=True,
    )


def strict_hook_policy(project_root: str | Path) -> HookPolicy:
    """Stricter profile for CI/shared environments."""
    root = str(Path(project_root).resolve())
    return HookPolicy(
        allowed_roots=(root,),
        blocked_command_tokens=(
            "rm -rf",
            "mkfs",
            "dd if=",
            "shutdown",
            "reboot",
            "kill -9",
            "chmod -R 777 /",
        ),
        allowed_container_prefixes=("ifinder-",),
        require_poc_under_output_root=True,
    )


def permissive_hook_policy(project_root: str | Path) -> HookPolicy:
    """Permissive profile for trusted local experiments."""
    root = str(Path(project_root).resolve())
    return HookPolicy(
        allowed_roots=(root,),
        blocked_command_tokens=("rm -rf /", "mkfs"),
        allowed_container_prefixes=("",),
        require_poc_under_output_root=False,
    )

