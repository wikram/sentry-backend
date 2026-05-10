import json
from unittest.mock import patch, MagicMock
from orchestrator.graph import build_graph
from orchestrator.state import make_initial_state

MOCK_CLASSIFIED = [
    {
        "timestamp": "2024-01-15T03:42:18Z",
        "severity": "CRITICAL",
        "category": "OOM",
        "source": "kernel",
        "raw_line": "kernel: OOM killed process",
        "summary": "OOM kill",
    },
]

MOCK_REMEDIATIONS = [
    {
        "issue_summary": "OOM Kill",
        "root_cause": "Memory limit too low",
        "fix_steps": ["Increase memory limit"],
        "rationale": "Process exceeded limit",
        "confidence": 0.9,
        "linked_log_entries": [0],
    },
]

MOCK_COOKBOOK = "# Runbook\n- [ ] Increase memory limit"

MOCK_TICKETS = [
    {
        "title": "CRITICAL: OOM Kill",
        "description": "Increase memory",
        "priority": "Critical",
        "assignee": "oncall-team",
        "labels": ["incident"],
    },
]


@patch("agents.jira_ticket.get_llm")
@patch("agents.slack_notifier.WebClient")
@patch("agents.cookbook.get_llm")
@patch("agents.remediation.get_llm")
@patch("agents.classifier.get_llm")
def test_graph_runs_all_agents_for_critical(
    mock_classifier_llm,
    mock_remediation_llm,
    mock_cookbook_llm,
    mock_slack_client,
    mock_jira_llm,
):
    # Setup classifier mock
    mock_cls = MagicMock()
    mock_cls.invoke.return_value = MagicMock(content=json.dumps(MOCK_CLASSIFIED))
    mock_classifier_llm.return_value = mock_cls

    # Setup remediation mock
    mock_rem = MagicMock()
    mock_rem.invoke.return_value = MagicMock(content=json.dumps(MOCK_REMEDIATIONS))
    mock_remediation_llm.return_value = mock_rem

    # Setup cookbook mock
    mock_cb = MagicMock()
    mock_cb.invoke.return_value = MagicMock(content=MOCK_COOKBOOK)
    mock_cookbook_llm.return_value = mock_cb

    # Setup slack mock
    mock_sc = MagicMock()
    mock_sc.chat_postMessage.return_value = {"ok": True}
    mock_slack_client.return_value = mock_sc

    # Setup jira mock
    mock_jr = MagicMock()
    mock_jr.invoke.return_value = MagicMock(content=json.dumps(MOCK_TICKETS))
    mock_jira_llm.return_value = mock_jr

    graph = build_graph()
    initial_state = make_initial_state("2024-01-15 03:42:18 ERROR kernel: OOM killed process")

    with patch.dict("os.environ", {"SLACK_BOT_TOKEN": "xoxb-test", "SLACK_CHANNEL": "#test"}):
        result = graph.invoke(initial_state)

    assert len(result["classified_entries"]) == 1
    assert len(result["remediations"]) == 1
    assert "Runbook" in result["cookbook"]
    assert len(result["jira_tickets"]) == 1
    assert len(result["slack_notifications"]) == 1
    assert len(result["agent_trace"]) >= 5


def test_build_graph_returns_compiled_graph():
    graph = build_graph()
    assert graph is not None


@patch("agents.jira_ticket.get_llm")
@patch("agents.slack_notifier.WebClient")
@patch("agents.cookbook.get_llm")
@patch("agents.remediation.get_llm")
@patch("agents.classifier.get_llm")
def test_graph_with_low_severity_skips_jira_and_slack(
    mock_classifier_llm,
    mock_remediation_llm,
    mock_cookbook_llm,
    mock_slack_client,
    mock_jira_llm,
):
    low_classified = [
        {
            "timestamp": "2024-01-15T03:43:25Z",
            "severity": "LOW",
            "category": "config",
            "source": "config.loader",
            "raw_line": "Deprecated config key used",
            "summary": "Deprecated config key",
        },
    ]
    low_remediations = [
        {
            "issue_summary": "Deprecated config",
            "root_cause": "Old config key",
            "fix_steps": ["Update config key"],
            "rationale": "Non-breaking",
            "confidence": 0.95,
            "linked_log_entries": [0],
        },
    ]

    mock_cls = MagicMock()
    mock_cls.invoke.return_value = MagicMock(content=json.dumps(low_classified))
    mock_classifier_llm.return_value = mock_cls

    mock_rem = MagicMock()
    mock_rem.invoke.return_value = MagicMock(content=json.dumps(low_remediations))
    mock_remediation_llm.return_value = mock_rem

    mock_cb = MagicMock()
    mock_cb.invoke.return_value = MagicMock(content="# Low priority runbook")
    mock_cookbook_llm.return_value = mock_cb

    graph = build_graph()
    initial_state = make_initial_state("2024-01-15 WARN Deprecated config key used")

    with patch.dict("os.environ", {"SLACK_BOT_TOKEN": "xoxb-test", "SLACK_CHANNEL": "#test"}):
        result = graph.invoke(initial_state)

    assert len(result["classified_entries"]) == 1
    assert len(result["remediations"]) == 1
    assert "runbook" in result["cookbook"].lower()
    # LOW severity -> no JIRA, no Slack
    assert result["jira_tickets"] == []
    assert result["slack_notifications"] == []
