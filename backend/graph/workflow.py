from langgraph.graph import StateGraph, END

from models.state import AgentState

from agents.jenkins_fetcher import jenkins_fetcher
from agents.log_reader import parse_logs
from agents.remediation_agent import remediation_agent
from agents.cookbook_agent import cookbook_agent
from agents.jira_agent import jira_agent
from agents.notification_agent import notification_agent



def build_workflow():

    workflow = StateGraph(AgentState)

    workflow.add_node(
        'fetch_logs',
        jenkins_fetcher
    )

    workflow.add_node(
        'log_reader',
        parse_logs
    )

    workflow.add_node(
        'remediation',
        remediation_agent
    )

    workflow.add_node(
        'cookbook',
        cookbook_agent
    )

    workflow.add_node(
        'jira',
        jira_agent
    )

    workflow.add_node(
        'notification',
        notification_agent
    )

    workflow.set_entry_point(
        'fetch_logs'
    )

    workflow.add_edge(
        'fetch_logs',
        'log_reader'
    )

    workflow.add_edge(
        'log_reader',
        'remediation'
    )

    workflow.add_edge(
        'remediation',
        'cookbook'
    )

    workflow.add_edge(
        'cookbook',
        'jira'
    )

    workflow.add_edge(
        'jira',
        'notification'
    )

    workflow.add_edge(
        'notification',
        END
    )

    return workflow.compile()
