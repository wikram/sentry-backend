from orchestrator.state import IncidentState
from config import SEVERITY_ORDER


def get_highest_severity(state: IncidentState) -> str:
    """Return the highest severity level present in classified log entries.

    Args:
        state: Current incident state containing classified_entries.

    Returns:
        Severity string ("CRITICAL", "HIGH", "MEDIUM", or "LOW"),
        defaulting to "LOW" when no entries are present.
    """
    entries = state["classified_entries"]
    if not entries:
        return "LOW"
    return max(entries, key=lambda e: SEVERITY_ORDER.get(e["severity"], 0))["severity"]


def route_after_remediation(state: IncidentState) -> list[str]:
    """Determine which downstream agents to run based on highest severity.

    Routes CRITICAL/HIGH incidents to Slack, JIRA, and cookbook; MEDIUM to
    Slack and cookbook; and LOW incidents to cookbook only.

    Args:
        state: Current incident state containing classified_entries.

    Returns:
        List of node names to activate in the fan-out step.
    """
    highest = get_highest_severity(state)
    severity_rank = SEVERITY_ORDER.get(highest, 0)

    if severity_rank >= 3:  # CRITICAL or HIGH
        return ["slack_notifier", "jira_ticket", "cookbook"]
    elif severity_rank == 2:  # MEDIUM
        return ["slack_notifier", "cookbook"]
    else:  # LOW
        return ["cookbook"]