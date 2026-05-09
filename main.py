from fastapi import FastAPI
from pydantic import BaseModel

from graph.workflow import build_workflow


app = FastAPI()
workflow = build_workflow()


class AnalyzeRequest(BaseModel):
    jenkins: dict
    llm: dict


@app.post('/analyze')
async def analyze(request: AnalyzeRequest):

    result = workflow.invoke({
        'jenkins': request.jenkins,
        'llm': request.llm
    })

    return {
        'parsed_logs': result['parsed_logs'],
        'remediation': result['remediation'],
        'cookbook': result['cookbook'],
        'jira_ticket': result['jira_ticket']
    }
