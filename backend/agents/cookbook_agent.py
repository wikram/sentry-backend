from services.llm_service import LLMService
from services.prompt_loader import load_prompt


PROMPT = load_prompt('cookbook.md')



def cookbook_agent(state):

    llm = LLMService(state['llm'])

    prompt = PROMPT.format(
        incident=state['remediation']
    )

    response = llm.invoke(prompt)

    state['cookbook'] = response

    return state
