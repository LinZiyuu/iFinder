"""Tests for hook policies and security validators."""

from pathlib import Path

from ifinder_sdk.hooks import (
    default_hook_policy,
    is_safe_shell_command,
    validate_command,
    validate_container_name,
    validate_path_within_roots,
)


def test_validate_path_within_roots(tmp_path: Path) -> None:
    ok_file = tmp_path / "ok.txt"
    ok_file.write_text("x", encoding="utf-8")

    ok, reason = validate_path_within_roots(ok_file, [tmp_path])
    assert ok
    assert reason == ""

    outside, reason2 = validate_path_within_roots("/etc/passwd", [tmp_path])
    assert not outside
    assert "outside allowed roots" in reason2.lower()


def test_validate_command_and_safe_shell_detection() -> None:
    ok, _ = validate_command("go build ./...", ["rm -rf /"])
    assert ok

    blocked, reason = validate_command("rm -rf /tmp/demo", ["rm -rf"])
    assert not blocked
    assert "blocked command token" in reason.lower()

    assert is_safe_shell_command("echo hello")
    assert not is_safe_shell_command("rm -rf /")


def test_validate_container_name_with_default_policy(tmp_path: Path) -> None:
    policy = default_hook_policy(tmp_path)
    ok, _ = validate_container_name("ifinder-open5gs", policy.allowed_container_prefixes)
    assert ok

    bad, reason = validate_container_name("prod-open5gs", policy.allowed_container_prefixes)
    assert not bad
    assert "does not match" in reason.lower()
