import logging
from langgraph.graph import StateGraph, END
from orchestrator.state import IncidentState
from orchestrator.router import route_after_remediation
from agents.classifier import classify_logs
from agents.remediation import generate_remediations
from agents.cookbook import synthesize_cookbook
from agents.slack_notifier import send_slack_notifications
from agents.jira_ticket import create_jira_tickets

logger = logging.getLogger(__name__)


def _classifier_node(state: IncidentState) -> dict:
    logger.info("Graph node: classifier started")
    result = classify_logs(state)
    logger.info("Graph node: classifier completed")
    return result


def _remediation_node(state: IncidentState) -> dict:
    logger.info("Graph node: remediation started")
    result = generate_remediations(state)
    logger.info("Graph node: remediation completed")
    return result


def _cookbook_node(state: IncidentState) -> dict:
    logger.info("Graph node: cookbook started")
    result = synthesize_cookbook(state)
    logger.info("Graph node: cookbook completed")
    return result


def _slack_node(state: IncidentState) -> dict:
    logger.info("Graph node: slack_notifier started")
    result = send_slack_notifications(state)
    logger.info("Graph node: slack_notifier completed")
    return result


def _jira_node(state: IncidentState) -> dict:
    logger.info("Graph node: jira_ticket started")
    result = create_jira_tickets(state)
    logger.info("Graph node: jira_ticket completed")
    return result


def _route_after_remediation(state: IncidentState) -> list[str]:
    return route_after_remediation(state)


def build_graph():
    """Build and compile the LangGraph incident analysis workflow.

    Constructs a directed graph with a linear classifier → remediation path
    followed by a conditional fan-out to cookbook, Slack, and JIRA nodes
    based on the highest detected severity.

    Returns:
        A compiled LangGraph runnable ready to invoke with an IncidentState.
    """
    graph = StateGraph(IncidentState)

    # Add nodes
    graph.add_node("classifier", _classifier_node)
    graph.add_node("remediation", _remediation_node)
    graph.add_node("cookbook", _cookbook_node)
    graph.add_node("slack_notifier", _slack_node)
    graph.add_node("jira_ticket", _jira_node)

    # Linear: start -> classifier -> remediation
    graph.set_entry_point("classifier")
    graph.add_edge("classifier", "remediation")

    # Conditional fan-out after remediation
    graph.add_conditional_edges(
        "remediation",
        _route_after_remediation,
        {
            "cookbook": "cookbook",
            "slack_notifier": "slack_notifier",
            "jira_ticket": "jira_ticket",
        },
    )

    # Fan-out agents all go to END
    graph.add_edge("cookbook", END)
    graph.add_edge("slack_notifier", END)
    graph.add_edge("jira_ticket", END)

    return graph.compile()