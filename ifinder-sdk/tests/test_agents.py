"""Tests for agent definitions."""

from ifinder_sdk.agents import (
    DISCOVERY_AGENT,
    EXPLOITATION_AGENT,
    VETTING_AGENT,
    get_agent_definition,
    list_agent_definitions,
)


def test_list_agent_definitions_contains_three_stages() -> None:
    agents = list_agent_definitions()
    names = [agent.name for agent in agents]
    assert names == [
        "DiscoveryAgent",
        "VettingAgent",
        "ExploitationAgent",
    ]


def test_get_agent_definition_by_name() -> None:
    assert get_agent_definition("DiscoveryAgent") == DISCOVERY_AGENT
    assert get_agent_definition("VettingAgent") == VETTING_AGENT
    assert get_agent_definition("ExploitationAgent") == EXPLOITATION_AGENT
