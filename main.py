import os

from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel

from graph.workflow import build_workflow


load_dotenv()


app = FastAPI()
workflow = build_workflow()


class AnalyzeRequest(BaseModel):
    jenkins: dict
    llm: dict


class LLMConfigRequest(BaseModel):
    model: str


@app.get('/api/v1/health')
async def health():

    return {
        'status': 'healthy'
    }


@app.post('/api/v1/config/llm')
async def configure_llm(request: LLMConfigRequest):

    env_path = '.env'

    lines = []

    if os.path.exists(env_path):

        with open(env_path, 'r') as file:
            lines = file.readlines()

    updated = False

    for index, line in enumerate(lines):

        if line.startswith('LLM_MODEL='):
            lines[index] = f'LLM_MODEL={request.model}\n'
            updated = True
            break

    if not updated:
        lines.append(f'LLM_MODEL={request.model}\n')

    with open(env_path, 'w') as file:
        file.writelines(lines)

    os.environ['LLM_MODEL'] = request.model

    return {
        'message': 'LLM model updated successfully',
        'model': request.model
    }


@app.post('/api/v1/analyze')
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
