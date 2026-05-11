import operator
from typing import Annotated, TypedDict


class LogEntry(TypedDict):
    timestamp: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # OOM, timeout, auth_failure, disk, network, etc.
    source: str
    raw_line: str
    summary: str


class Remediation(TypedDict):
    issue_summary: str
    root_cause: str
    fix_steps: list[str]
    rationale: str
    confidence: float
    linked_log_entries: list[int]


class JIRATicket(TypedDict):
    title: str
    description: str
    priority: str
    assignee: str
    labels: list[str]


class SlackMessage(TypedDict):
    channel: str
    text: str
    blocks: dict
    status: str  # sent, failed


class TraceEntry(TypedDict):
    agent_name: str
    start_time: float
    end_time: float
    input_summary: str
    output_summary: str
    status: str  # running, completed, skipped, failed


class IncidentState(TypedDict):
    raw_logs: str
    classified_entries: list[LogEntry]
    remediations: list[Remediation]
    llm: dict  # LLM configuration passed to agents
    cookbook: str
    jira_tickets: list[JIRATicket]
    slack_notifications: list[SlackMessage]
    agent_trace: Annotated[list[TraceEntry], operator.add]


def make_initial_state(raw_logs: str) -> IncidentState:
    """Create a blank IncidentState seeded with raw log text.

    Args:
        raw_logs: Raw multi-line log content uploaded by the user.

    Returns:
        IncidentState with all list and string fields initialized to empty values.
    """
    return {
        "raw_logs": raw_logs,
        "classified_entries": [],
        "remediations": [],
        "cookbook": "",
        "jira_tickets": [],
        "slack_notifications": [],
        "agent_trace": [],
    }