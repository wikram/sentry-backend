import json
from unittest.mock import patch, MagicMock
from orchestrator.state import make_initial_state
from agents.jira_ticket import create_jira_tickets

SAMPLE_CLASSIFIED = [
    {"timestamp": "", "severity": "CRITICAL", "category": "OOM", "source": "kernel", "raw_line": "", "summary": "OOM kill"},
    {"timestamp": "", "severity": "HIGH", "category": "timeout", "source": "sqlalchemy", "raw_line": "", "summary": "DB pool exhausted"},
    {"timestamp": "", "severity": "LOW", "category": "config", "source": "app", "raw_line": "", "summary": "Deprecated config key"},
]

SAMPLE_REMEDIATIONS = [
    {
        "issue_summary": "OOM Kill on api-server",
        "root_cause": "Memory limit too low",
        "fix_steps": ["Increase memory limit to 4Gi"],
        "rationale": "Process exceeded 2Gi limit",
        "confidence": 0.9,
        "linked_log_entries": [0],
    },
    {
        "issue_summary": "DB connection pool exhaustion",
        "root_cause": "Pool size too small",
        "fix_steps": ["Increase pool_size to 40"],
        "rationale": "All connections in use",
        "confidence": 0.85,
        "linked_log_entries": [1],
    },
    {
        "issue_summary": "Deprecated config warning",
        "root_cause": "Old config key still in use",
        "fix_steps": ["Update config key name"],
        "rationale": "Non-breaking but should be fixed",
        "confidence": 0.95,
        "linked_log_entries": [2],
    },
]

MOCK_LLM_RESPONSE = json.dumps([
    {
        "title": "CRITICAL: OOM Kill on api-server",
        "description": "Container exceeded memory limit (2Gi). Increase to 4Gi.",
        "priority": "Critical",
        "assignee": "oncall-team",
        "labels": ["incident", "OOM", "critical"],
    },
    {
        "title": "HIGH: DB connection pool exhaustion",
        "description": "Pool size of 20 insufficient. Increase to 40.",
        "priority": "High",
        "assignee": "oncall-team",
        "labels": ["incident", "database", "high"],
    },
])


@patch("agents.jira_ticket.get_llm")
def test_create_jira_tickets_filters_critical_high(mock_chat_class):
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content=MOCK_LLM_RESPONSE)
    mock_chat_class.return_value = mock_llm

    state = make_initial_state("")
    state["classified_entries"] = SAMPLE_CLASSIFIED
    state["remediations"] = SAMPLE_REMEDIATIONS
    result = create_jira_tickets(state)

    assert len(result["jira_tickets"]) == 2
    assert result["jira_tickets"][0]["priority"] == "Critical"


@patch("agents.jira_ticket.get_llm")
def test_create_jira_tickets_adds_trace(mock_chat_class):
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content=MOCK_LLM_RESPONSE)
    mock_chat_class.return_value = mock_llm

    state = make_initial_state("")
    state["classified_entries"] = SAMPLE_CLASSIFIED
    state["remediations"] = SAMPLE_REMEDIATIONS
    result = create_jira_tickets(state)

    trace = [t for t in result["agent_trace"] if t["agent_name"] == "jira_ticket"]
    assert len(trace) == 1
    assert trace[0]["status"] == "completed"
