from integrations.jira_client import create_ticket


CRITICAL_SEVERITIES = [
    'critical',
    'high'
]



def jira_agent(state):

    remediation = state['remediation']

    severity = remediation.get(
        'severity',
        ''
    ).lower()

    if severity in CRITICAL_SEVERITIES:

        ticket = create_ticket(
            summary=(
                'Jenkins Pipeline Failure - '
                f"{state['parsed_logs']['issue_type']}"
            ),
            description=str(remediation)
        )

        state['jira_ticket'] = ticket

    else:
        state['jira_ticket'] = 'not_created'

    return state
