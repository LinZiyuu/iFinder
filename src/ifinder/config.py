"""Paths, constants, and KB loaders for iFinder."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ifinder.models import Pattern, Procedure, Scope


DEFAULT_MODEL: str = "claude-opus-4-5-20251101"

# DA/VA agentic-loop bound (one ClaudeSDKClient turn may issue many tool calls).
DEFAULT_MAX_TURNS: int = 200


MAX_REFINE_ITERATIONS: int = 5

# UDP port the EA sends the trigger message to. PFCP N4 = 8805; GTPv2-C (S11/S5/S8) = 2123. The host is
# NOT defined here — the EA derives the per-NF host (and the docker service to restart / scrape logs
# from) by parsing the testbed compose file at runtime; see :func:`ifinder.testbed.discover_nf_endpoints`.
PFCP_PORT: int = 8805
GTPC_PORT: int = 2123


def protocol_port(protocol: str) -> int:
    """Trigger UDP port for a protocol: PFCP N4 = 8805, GTP-C S11/S5 = 2123 (default PFCP)."""
    return {"pfcp": PFCP_PORT, "gtpc": GTPC_PORT}.get(protocol, PFCP_PORT)



ROOT: Path = Path(__file__).resolve().parents[2]  # .../iFinder_artifact-v4


@dataclass(frozen=True)
class Paths:
    root: Path = ROOT
    # Protocol knowledge bases are split per protocol: schema/<protocol>/ and procedure/<protocol>/.
    # "pfcp" (default) keeps every existing call site working; "gtpc" selects the GTP-C tree.
    protocol: str = "pfcp"
    pattern_dir: Path = ROOT / "pattern"
    target_dir: Path = ROOT / "target"
    outputs_dir: Path = ROOT / "outputs"

    @property
    def procedure_dir(self) -> Path:
        return self.root / "procedure" / self.protocol

    @property
    def schema_dir(self) -> Path:
        return self.root / "schema" / self.protocol / "generated"

    @property
    def scope_dir(self) -> Path:
        return self.root / "scope" / self.protocol

    @property
    def message_schemas(self) -> Path:
        return self.schema_dir / "message_schemas.normalized.json"

    @property
    def ie_catalog(self) -> Path:
        return self.schema_dir / "ie_catalog.normalized.json"

    def for_protocol(self, protocol: str) -> "Paths":
        """Return a sibling ``Paths`` bound to another protocol ('pfcp' | 'gtpc')."""
        return replace(self, protocol=protocol)

    def target_path(self, target_codebase: str) -> Path:
        """Resolve a scope ``target_codebase`` (e.g. 'target/open5gs_code/open5gs_275') to an absolute path."""
        p = Path(target_codebase)
        return p if p.is_absolute() else self.root / p

    def discovery_out(self, target: str, pattern_id: str) -> Path:
        return self.outputs_dir / "discovery_results" / target / f"{pattern_id}.json"

    def vetting_out(self, target: str, pattern_id: str) -> Path:
        return self.outputs_dir / "vetting_results" / target / f"{pattern_id}.json"

    def exploitation_out(self, target: str, candidate_id: str) -> Path:
        return self.outputs_dir / "exploitation_results" / target / f"{candidate_id}.json"


DEFAULT_PATHS = Paths()


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------------
# KB loaders
# --------------------------------------------------------------------------------------------------
def load_pattern(pattern_id: str, paths: Paths = DEFAULT_PATHS) -> Pattern:
    """Load ../pattern/<pattern_id>.json into a ``Pattern``."""
    return Pattern.model_validate(_read_json(paths.pattern_dir / f"{pattern_id}.json"))


def load_procedures(paths: Paths = DEFAULT_PATHS) -> dict[str, Procedure]:
    """Load all ../procedure/<protocol>/*.json, keyed by ``procedure_id``."""
    out: dict[str, Procedure] = {}
    for fp in sorted(paths.procedure_dir.glob("*.json")):
        proc = Procedure.model_validate(_read_json(fp))
        out[proc.procedure_id] = proc
    return out


def load_scope(scope_file: str | Path, paths: Paths = DEFAULT_PATHS) -> Scope:
    """Load a scope file. Accepts an absolute path, a path relative to cwd, or a bare name found
    anywhere under ``scope/`` (e.g. ``scope/pfcp/`` or ``scope/gtpc/``). Each target carries its own
    ``protocol``; the pipeline selects the matching schema/procedure KB per target."""
    p = Path(scope_file)
    if not p.exists():
        # bare name: search the whole scope/ tree so pfcp/ and gtpc/ scopes both resolve.
        matches = sorted((paths.root / "scope").rglob(p.name))
        if not matches:
            raise FileNotFoundError(f"scope file not found: {scope_file}")
        p = matches[0]
    return Scope.model_validate(_read_json(p))


def load_message_schemas(paths: Paths = DEFAULT_PATHS) -> dict:
    """Load schema/<protocol>/generated/message_schemas.normalized.json (raw dict; EA skeleton)."""
    return _read_json(paths.message_schemas)


def load_ie_catalog(paths: Paths = DEFAULT_PATHS) -> dict:
    """Load schema/<protocol>/generated/ie_catalog.normalized.json (raw dict; EA skeleton)."""
    return _read_json(paths.ie_catalog)


def load_schema(paths: Paths = DEFAULT_PATHS) -> dict:
    """Convenience: both schema files combined as {'message_schemas':..., 'ie_catalog':...}."""
    return {
        "message_schemas": load_message_schemas(paths),
        "ie_catalog": load_ie_catalog(paths),
    }
