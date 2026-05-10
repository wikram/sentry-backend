import os

from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from graph.workflow import build_workflow


BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR.joinpath('.env').resolve()


load_dotenv(dotenv_path=ENV_PATH, override=True)


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


workflow = build_workflow()


LAST_ANALYSIS_RESPONSE = {}


CONFIGURED_AGENTS = [
    {
        'name': 'jenkins_fetcher',
        'description': 'Fetches Jenkins console logs'
    },
    {
        'name': 'log_reader',
        'description': 'Parses and classifies logs'
    },
    {
        'name': 'remediation_agent',
        'description': 'Generates remediation suggestions'
    },
    {
        'name': 'cookbook_agent',
        'description': 'Creates recovery checklists'
    },
    {
        'name': 'jira_agent',
        'description': 'Creates Jira tickets for critical issues'
    },
    {
        'name': 'notification_agent',
        'description': 'Sends Slack notifications'
    }
]


class AnalyzeRequest(BaseModel):
    error: str


class LLMConfigRequest(BaseModel):
    model: str


@app.get('/api/v1/health')
async def health():

    return {
        'status': 'healthy'
    }


@app.get('/api/v1/agents')
async def list_agents():

    return {
        'count': len(CONFIGURED_AGENTS),
        'agents': CONFIGURED_AGENTS
    }


@app.get('/api/v1/getresponse')
async def get_response():

    return {
        'response': LAST_ANALYSIS_RESPONSE
    }


@app.post('/api/v1/config/llm')
async def configure_llm(request: LLMConfigRequest):

    env_lines = []

    if ENV_PATH.exists():

        with open(ENV_PATH, 'r', encoding='utf-8') as file:
            env_lines = file.readlines()

    llm_model_found = False

    updated_lines = []

    for line in env_lines:

        if line.strip().startswith('LLM_MODEL='):
            updated_lines.append(
                f'LLM_MODEL={request.model}\n'
            )
            llm_model_found = True
        else:
            updated_lines.append(line)

    if not llm_model_found:
        updated_lines.append(
            f'LLM_MODEL={request.model}\n'
        )

    with open(ENV_PATH, 'w', encoding='utf-8') as file:
        file.writelines(updated_lines)
        file.flush()

    os.environ['LLM_MODEL'] = request.model

    load_dotenv(
        dotenv_path=ENV_PATH,
        override=True
    )

    return {
        'message': 'LLM model updated successfully',
        'model': request.model,
        'env_path': str(ENV_PATH)
    }


@app.post('/api/v1/analyze')
async def analyze(request: AnalyzeRequest):

    global LAST_ANALYSIS_RESPONSE

    result = workflow.invoke({
        'raw_logs': request.error,
        'llm': {}
    })

    LAST_ANALYSIS_RESPONSE = {
        'parsed_logs': result['parsed_logs'],
        'remediation': result['remediation'],
        'cookbook': result['cookbook'],
        'jira_ticket': result['jira_ticket']
    }

    return LAST_ANALYSIS_RESPONSE
