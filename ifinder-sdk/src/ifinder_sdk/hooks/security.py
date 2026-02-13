from __future__ import annotations

import shlex
from pathlib import Path
from typing import Iterable


def validate_path_within_roots(path: str | Path, allowed_roots: Iterable[str | Path]) -> tuple[bool, str]:
    target = Path(path).resolve()
    roots = [Path(root).resolve() for root in allowed_roots]
    for root in roots:
        if target == root or root in target.parents:
            return True, ""
    return False, f"Path is outside allowed roots: {target}"


def validate_command(command: str, blocked_tokens: Iterable[str]) -> tuple[bool, str]:
    lowered = command.lower()
    for token in blocked_tokens:
        if token.lower() in lowered:
            return False, f"Blocked command token detected: {token}"
    return True, ""


def validate_container_name(container: str, allowed_prefixes: Iterable[str]) -> tuple[bool, str]:
    if not container:
        return False, "Container name cannot be empty."
    for prefix in allowed_prefixes:
        if container.startswith(prefix):
            return True, ""
    return False, f"Container `{container}` does not match allowed prefixes."


def is_safe_shell_command(command: str) -> bool:
    blocked_tokens = (
        "rm -rf /",
        "mkfs",
        "dd if=",
        "shutdown",
        "reboot",
        ":(){",
        "kill -9 1",
    )
    ok, _ = validate_command(command, blocked_tokens)
    if not ok:
        return False
    try:
        shlex.split(command)
    except ValueError:
        return False
    return True

