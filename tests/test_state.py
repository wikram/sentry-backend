from orchestrator.state import (
    LogEntry,
    Remediation,
    JIRATicket,
    SlackMessage,
    TraceEntry,
    IncidentState,
    make_initial_state,
)


def test_log_entry_has_required_fields():
    entry: LogEntry = {
        "timestamp": "2024-01-15T03:42:18Z",
        "severity": "CRITICAL",
        "category": "OOM",
        "source": "kernel",
        "raw_line": "kernel: Out of memory: Killed process 1842",
        "summary": "OOM kill on api-server container",
    }
    assert entry["severity"] == "CRITICAL"
    assert entry["category"] == "OOM"


def test_remediation_has_required_fields():
    rem: Remediation = {
        "issue_summary": "OOM Kill on api-server",
        "root_cause": "Memory limit too low for workload",
        "fix_steps": ["Increase memory limit to 4Gi", "Add memory monitoring"],
        "rationale": "Container exceeded 2Gi limit during peak traffic",
        "confidence": 0.85,
        "linked_log_entries": [0, 1],
    }
    assert rem["confidence"] == 0.85
    assert len(rem["fix_steps"]) == 2


def test_jira_ticket_has_required_fields():
    ticket: JIRATicket = {
        "title": "CRITICAL: OOM Kill on api-server",
        "description": "Container exceeded memory limit",
        "priority": "Critical",
        "assignee": "oncall-team",
        "labels": ["incident", "OOM"],
    }
    assert ticket["priority"] == "Critical"


def test_slack_message_has_required_fields():
    msg: SlackMessage = {
        "channel": "#incident-alerts",
        "text": "OOM Kill detected",
        "blocks": {"type": "section", "text": {"type": "mrkdwn", "text": "test"}},
        "status": "sent",
    }
    assert msg["status"] == "sent"


def test_trace_entry_has_required_fields():
    trace: TraceEntry = {
        "agent_name": "classifier",
        "start_time": 1000.0,
        "end_time": 1002.1,
        "input_summary": "Raw logs: 27 lines",
        "output_summary": "Classified 27 entries",
        "status": "completed",
    }
    assert trace["status"] == "completed"
    assert trace["end_time"] - trace["start_time"] == pytest.approx(2.1)


def test_make_initial_state():
    state = make_initial_state("some raw logs here")
    assert state["raw_logs"] == "some raw logs here"
    assert state["classified_entries"] == []
    assert state["remediations"] == []
    assert state["cookbook"] == ""
    assert state["jira_tickets"] == []
    assert state["slack_notifications"] == []
    assert state["agent_trace"] == []


import pytest
