import json

from services.llm_service import LLMService
from services.prompt_loader import load_prompt


PROMPT = load_prompt('remediation.md')



def remediation_agent(state):

    llm = LLMService(state['llm'])

    parsed = state['parsed_logs']

    prompt = PROMPT.format(
        failed_stage=parsed['failed_stage'],
        issue_type=parsed['issue_type'],
        error_context=parsed['error_context']
    )

    response = llm.invoke(prompt)

    try:
        state['remediation'] = json.loads(response)

    except Exception:

        state['remediation'] = {
            'raw_response': response
        }

    return state
