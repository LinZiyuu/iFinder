"""Agent definitions for the iFinder SDK pipeline."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentDefinition:
    """Static agent metadata used by the SDK orchestrator."""

    name: str
    model: str
    system_prompt: str
    allowed_tools: tuple[str, ...]


DISCOVERY_AGENT = AgentDefinition(
    name="DiscoveryAgent",
    model="gpt-5",
    system_prompt=(
        "You are the Discovery Agent. Locate risky IE usages, reconstruct call paths, "
        "and identify missing validations according to the pattern."
    ),
    allowed_tools=(
        "discover_itrue_candidates",
        "locate_risky_ie_usages",
        "collect_source_files",
    ),
)


VETTING_AGENT = AgentDefinition(
    name="VettingAgent",
    model="gpt-5",
    system_prompt=(
        "You are the Vetting Agent. Expand candidate context using 3GPP procedure mappings "
        "and determine whether prior handlers contain blocking security checks."
    ),
    allowed_tools=(
        "build_expanded_context_for_candidate",
        "collect_code_for_messages",
        "evaluate_candidate_with_expanded_context",
        "vet_discovery_result",
    ),
)


EXPLOITATION_AGENT = AgentDefinition(
    name="ExploitationAgent",
    model="gpt-5",
    system_prompt=(
        "You are the Exploitation Agent. Derive attack vectors, generate PoCs, run checks, "
        "and iteratively refine execution using runtime feedback."
    ),
    allowed_tools=(
        "derive_attack_vector_and_messages",
        "generate_poc_from_attack_vector",
        "run_pre_execution_checks",
        "feedback_aware_refinement_loop",
        "exploit_candidate",
    ),
)


_AGENTS_BY_NAME = {
    DISCOVERY_AGENT.name: DISCOVERY_AGENT,
    VETTING_AGENT.name: VETTING_AGENT,
    EXPLOITATION_AGENT.name: EXPLOITATION_AGENT,
}


def get_agent_definition(name: str) -> AgentDefinition:
    """Return an agent definition by name."""
    try:
        return _AGENTS_BY_NAME[name]
    except KeyError as exc:
        raise KeyError(f"Unknown agent name: {name}") from exc


def list_agent_definitions() -> list[AgentDefinition]:
    """Return all predefined agent definitions."""
    return [DISCOVERY_AGENT, VETTING_AGENT, EXPLOITATION_AGENT]

