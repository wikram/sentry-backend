from integrations.slack_client import send_slack_message



def notification_agent(state):

    remediation = state['remediation']

    message = f"""
Jenkins Failure Detected

Stage:
{state['parsed_logs']['failed_stage']}

Issue:
{state['parsed_logs']['issue_type']}

Root Cause:
{remediation.get('root_cause')}

Fix:
{remediation.get('immediate_fix')}

Severity:
{remediation.get('severity')}

JIRA:
{state['jira_ticket']}
"""

    send_slack_message(message)

    return state
