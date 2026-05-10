from orchestrator.router import get_highest_severity, route_after_remediation
from orchestrator.state import make_initial_state


def test_highest_severity_critical():
    state = make_initial_state("")
    state["classified_entries"] = [
        {"timestamp": "", "severity": "LOW", "category": "", "source": "", "raw_line": "", "summary": ""},
        {"timestamp": "", "severity": "CRITICAL", "category": "", "source": "", "raw_line": "", "summary": ""},
        {"timestamp": "", "severity": "MEDIUM", "category": "", "source": "", "raw_line": "", "summary": ""},
    ]
    assert get_highest_severity(state) == "CRITICAL"


def test_highest_severity_medium_only():
    state = make_initial_state("")
    state["classified_entries"] = [
        {"timestamp": "", "severity": "MEDIUM", "category": "", "source": "", "raw_line": "", "summary": ""},
        {"timestamp": "", "severity": "LOW", "category": "", "source": "", "raw_line": "", "summary": ""},
    ]
    assert get_highest_severity(state) == "MEDIUM"


def test_highest_severity_all_low():
    state = make_initial_state("")
    state["classified_entries"] = [
        {"timestamp": "", "severity": "LOW", "category": "", "source": "", "raw_line": "", "summary": ""},
    ]
    assert get_highest_severity(state) == "LOW"


def test_highest_severity_high():
    state = make_initial_state("")
    state["classified_entries"] = [
        {"timestamp": "", "severity": "HIGH", "category": "", "source": "", "raw_line": "", "summary": ""},
        {"timestamp": "", "severity": "MEDIUM", "category": "", "source": "", "raw_line": "", "summary": ""},
    ]
    assert get_highest_severity(state) == "HIGH"


def test_route_critical_returns_all_agents():
    state = make_initial_state("")
    state["classified_entries"] = [
        {"timestamp": "", "severity": "CRITICAL", "category": "", "source": "", "raw_line": "", "summary": ""},
    ]
    state["remediations"] = [
        {"issue_summary": "x", "root_cause": "y", "fix_steps": [], "rationale": "", "confidence": 0.9, "linked_log_entries": [0]},
    ]
    result = route_after_remediation(state)
    assert set(result) == {"slack_notifier", "jira_ticket", "cookbook"}


def test_route_medium_returns_slack_and_cookbook():
    state = make_initial_state("")
    state["classified_entries"] = [
        {"timestamp": "", "severity": "MEDIUM", "category": "", "source": "", "raw_line": "", "summary": ""},
    ]
    state["remediations"] = [
        {"issue_summary": "x", "root_cause": "y", "fix_steps": [], "rationale": "", "confidence": 0.9, "linked_log_entries": [0]},
    ]
    result = route_after_remediation(state)
    assert set(result) == {"slack_notifier", "cookbook"}


def test_route_low_returns_cookbook_only():
    state = make_initial_state("")
    state["classified_entries"] = [
        {"timestamp": "", "severity": "LOW", "category": "", "source": "", "raw_line": "", "summary": ""},
    ]
    state["remediations"] = [
        {"issue_summary": "x", "root_cause": "y", "fix_steps": [], "rationale": "", "confidence": 0.9, "linked_log_entries": [0]},
    ]
    result = route_after_remediation(state)
    assert result == ["cookbook"]
