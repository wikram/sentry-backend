import os

from jira import JIRA
from dotenv import load_dotenv


load_dotenv()


jira = JIRA(
    server=os.getenv('JIRA_URL'),
    basic_auth=(
        os.getenv('JIRA_USER'),
        os.getenv('JIRA_API_TOKEN')
    )
)



def create_ticket(summary, description):

    issue = jira.create_issue(
        project=os.getenv('JIRA_PROJECT'),
        summary=summary,
        description=description,
        issuetype={
            'name': 'Task'
        }
    )

    return issue.key
