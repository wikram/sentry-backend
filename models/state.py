from typing import TypedDict


class AgentState(TypedDict):
    jenkins: dict
    llm: dict
    raw_logs: str
    parsed_logs: dict
    remediation: dict
    cookbook: str
    jira_ticket: str
