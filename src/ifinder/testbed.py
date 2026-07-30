"""Testbed driver for the Exploitation Agent.

Wraps the user-provided **Docker Compose full-5GC** stack: lifecycle (up/down/reset), running a
generated Go PoC against it (``go run``), and capturing target-NF runtime logs for trigger detection.
The EA orchestrator uses this to drive the deterministic ≤5 refinement loop and to re-inject logs.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger("ifinder.testbed")


def _nf_labels(name: str, protocol: str) -> list[str]:
    """Docker service name -> the NF label(s) it serves for ``protocol`` (DA's network_function values)."""
    low = name.lower()
    if protocol == "gtpc":
        labels: list[str] = []
        # OAI SPGW-C is the combined SGW-C + PGW-C; open5gs splits sgwc / smf(=PGW-C) / mme.
        if "sgwc" in low or "spgwc" in low or low == "sgw-c":
            labels.append("SGW-C")
        if "pgwc" in low or "spgwc" in low or low == "pgw-c" or low == "smf" or low.endswith("-smf"):
            labels.append("PGW-C")
        if "mme" in low:
            labels.append("MME")
        return labels
    # pfcp (default): 5G *-upf/*-smf (open5gs, free5gc, OAI-CN5G); 4G EPC SPGW CUPS spgwu/spgwc
    # (same TS 29.244 PFCP) — SPGW-U maps to UPF, SPGW-C to SMF, matching the NF labels the DA assigns.
    if low == "upf" or low.endswith("-upf") or "spgwu" in low:
        return ["UPF"]
    if low == "smf" or low.endswith("-smf") or "spgwc" in low:
        return ["SMF"]
    return []


def discover_nf_endpoints(compose_file: Path, protocol: str = "pfcp") -> dict[str, dict[str, str]]:
    """Parse the docker-compose YAML and return per-NF routing info for ``protocol``.

    Returns ``{<NF>: {"service": <docker service>, "host": <ipv4>}}``. PFCP NFs are UPF/SMF; GTP-C NFs
    are SGW-C/PGW-C/MME (OAI combined SPGW-C serves both SGW-C and PGW-C). Pins an ``ipv4_address``
    under any of a service's networks. Missing NFs are simply omitted; callers fall back.
    """
    with Path(compose_file).open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    services = doc.get("services") or {} if isinstance(doc, dict) else {}
    out: dict[str, dict[str, str]] = {}
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        labels = _nf_labels(name, protocol)
        if not labels:
            continue
        nets = svc.get("networks") or {}
        if not isinstance(nets, dict):
            continue
        host = None
        for net_cfg in nets.values():
            if isinstance(net_cfg, dict) and net_cfg.get("ipv4_address"):
                host = str(net_cfg["ipv4_address"])
                break
        if host is None:
            continue
        for nf in labels:
            out.setdefault(nf, {"service": name, "host": host})
    return out

# Markers that indicate the target NF crashed / hit the flaw (used by detect_trigger).
_CRASH_MARKERS = [
    r"SIGSEGV",
    r"segmentation fault",
    r"signal SIGABRT",
    r"SIGABRT",
    r"\bpanic:",
    r"runtime error:",
    r"fatal error:",
    r"assertion\b",
    r"Assert(ion)? failed",
    r"ogs_assert",
    r"core dumped",
    r"\bAborted\b",
]
_CRASH_RE = re.compile("|".join(_CRASH_MARKERS), re.IGNORECASE)

# Container exit codes from a fatal signal (128 + signo): SIGILL(4)->132, SIGABRT(6)->134,
# SIGBUS(7)->135, SIGFPE(8)->136, SIGSEGV(11)->139. Used to catch a crash that only surfaces when the
# NF is *stopped* — a state desync planted by a PoC that aborts on teardown (e.g. ogs_assert in cleanup),
# which run_poc's ``logs --since`` window never sees. Deliberately excludes 143 (clean SIGTERM) and 137
# (SIGKILL/OOM, ambiguous) so a normally-terminating NF is never mistaken for a crash.
_CRASH_EXIT_CODES = frozenset({132, 134, 135, 136, 139})


@dataclass
class ExecutionResult:
    logs: str = ""
    crashed: bool = False
    detail: str = ""  # the matched crash marker, or why no trigger
    exit_code: Optional[int] = None  # container exit code, when a crash is detected via container state


async def _run(cmd: list[str], *, cwd: Optional[Path] = None, timeout: int = 60) -> tuple[int, str, str]:
    """Run a subprocess, capturing stdout/stderr; kill on timeout."""
    logger.debug("exec: %s (cwd=%s)", " ".join(cmd), cwd)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd) if cwd else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        out, err = await proc.communicate()
        return -1, out.decode(errors="ignore"), "TIMEOUT\n" + err.decode(errors="ignore")
    return proc.returncode or 0, out.decode(errors="ignore"), err.decode(errors="ignore")


class TestbedDriver:
    """Handle to one target's Dockerized 5GC testbed."""

    def __init__(
        self,
        *,
        target: str,
        compose_file: Path,
        log_service: str = "upf",
        readiness_wait: int = 20,
        log_tail: int = 400,
        env_file: Optional[Path] = None,
        manage: bool = True,
    ) -> None:
        self.target = target
        self.compose_file = Path(compose_file)
        self.log_service = log_service  # which container's logs to watch for crashes
        self.readiness_wait = readiness_wait
        self.log_tail = log_tail
        self.env_file = Path(env_file) if env_file else None  # docker compose --env-file (optional)
        self.manage = manage  # False -> reuse an already-running stack (skip up/down)

    def _compose(self, *args: str) -> list[str]:
        # Pin --project-directory to the compose file's dir so relative paths (configs/build contexts/
        # volumes) and the derived project name match how the stack was launched; add --env-file if set.
        base = [
            "docker", "compose",
            "-f", str(self.compose_file),
            "--project-directory", str(self.compose_file.parent),
        ]
        if self.env_file is not None:
            base += ["--env-file", str(self.env_file)]
        return [*base, *args]

    async def up(self) -> None:
        """`docker compose up -d` the 5GC stack, then wait for readiness (coarse)."""
        if not self.manage:
            logger.info("testbed: manage=False -> reusing already-running stack (skip 'up -d')")
            return
        rc, out, err = await _run(self._compose("up", "-d"), timeout=300)
        if rc != 0:
            raise RuntimeError(f"testbed up failed: {err or out}")
        # Coarse readiness: a fixed settle window (tunable via readiness_wait) rather than a per-service
        # health probe — the NFs expose no uniform healthcheck, and the EA re-verifies liveness (and
        # restarts the NF) before each PoC attempt, so a precise probe here buys little.
        await asyncio.sleep(self.readiness_wait)

    async def down(self) -> None:
        """`docker compose down` and clean up (skipped when reusing an externally-managed stack)."""
        if not self.manage:
            logger.info("testbed: manage=False -> leaving stack running (skip 'down -v')")
            return
        await _run(self._compose("down", "-v"), timeout=120)

    async def reset(self, *, service: Optional[str] = None) -> Optional[ExecutionResult]:
        """Restore a clean state before/between PoC attempts (restart the NF being tested).

        Implemented as stop -> (read exit code) -> start instead of a single ``restart`` so we can see
        *how the NF terminated*. A state-desync bug planted by the previous attempt's PoC often does not
        crash during live processing but aborts on teardown (e.g. ogs_assert in sess_remove on SIGTERM);
        that abort never reaches :meth:`run_poc`'s ``logs --since`` window. We read the stop-phase exit
        code and, on a fatal-signal code, return an :class:`ExecutionResult` so the caller can attribute
        the crash to the *previous* PoC. Clean exits (0 / 143 SIGTERM) return ``None``, so a non-crashing
        NF behaves exactly as the old ``restart`` did (only crash detection is added, nothing removed).

        ``service`` overrides the default watched NF so an SMF-side candidate restarts the SMF (not the
        UPF), matching where its PoC sends and where its crash would surface.
        """
        svc = service or self.log_service
        await _run(self._compose("stop", svc), timeout=120)
        exit_code = await self._service_exit_code(svc)
        result: Optional[ExecutionResult] = None
        if exit_code in _CRASH_EXIT_CODES:
            _, logs_out, logs_err = await _run(
                self._compose("logs", "--no-color", "--tail", str(self.log_tail), svc),
                timeout=30,
            )
            result = ExecutionResult(
                logs=f"[{svc} aborted on teardown — container exit {exit_code}]\n{logs_out}\n{logs_err}",
                crashed=True,
                detail=f"crash on teardown (container exit {exit_code})",
                exit_code=exit_code,
            )
        await _run(self._compose("start", svc), timeout=120)
        await asyncio.sleep(max(2, self.readiness_wait // 4))
        return result

    async def _service_exit_code(self, service: str) -> Optional[int]:
        """Exit code of the (now-stopped) container backing ``service``, or None if it can't be read."""
        _, ids_out, _ = await _run(self._compose("ps", "-a", "-q", service), timeout=20)
        cid = next((ln.strip() for ln in ids_out.splitlines() if ln.strip()), "")
        if not cid:
            return None
        _, code_out, _ = await _run(["docker", "inspect", "-f", "{{.State.ExitCode}}", cid], timeout=20)
        try:
            return int(code_out.strip())
        except ValueError:
            return None

    async def run_poc(self, poc_path: Path, *, timeout: int = 60, service: Optional[str] = None) -> ExecutionResult:
        """`go run` the PoC, then collect ONLY the target-NF logs produced SINCE the PoC started.

        Time-scoping (``logs --since``) ensures a crash left by a *previous* candidate's PoC can never be
        mis-attributed to this one (the EA also restarts the NF before each attempt). We back off a couple
        of seconds to absorb host/daemon clock skew. ``service`` overrides which NF's logs are watched
        (SMF-side candidates watch the SMF, not the UPF).
        """
        poc_path = Path(poc_path)
        svc = service or self.log_service
        since = (datetime.now(timezone.utc) - timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        _, poc_out, poc_err = await _run(["go", "run", str(poc_path)], cwd=poc_path.parent, timeout=timeout)
        _, logs_out, logs_err = await _run(
            self._compose("logs", "--no-color", "--since", since, svc),
            timeout=30,
        )
        combined = (
            f"[poc stdout]\n{poc_out}\n[poc stderr]\n{poc_err}\n"
            f"[{svc} logs since {since}]\n{logs_out}\n{logs_err}"
        )
        return self.detect_trigger(combined)

    def detect_trigger(self, logs: str) -> ExecutionResult:
        """Crash-only regex over the runtime logs (precise / fast). Non-crash signals (audit, state,
        behaviour) are NOT detected here — the EA layers :class:`ifinder.agents.oracle.LogJudge` on
        top of this result to widen the oracle without sacrificing the regex's hard precision."""
        m = _CRASH_RE.search(logs)
        if m:
            return ExecutionResult(logs=logs, crashed=True, detail=f"crash marker: {m.group(0)!r}")
        return ExecutionResult(logs=logs, crashed=False, detail="no crash marker found")
