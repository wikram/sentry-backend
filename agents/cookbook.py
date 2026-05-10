import json
import logging
import time
from langchain_core.messages import SystemMessage, HumanMessage
from orchestrator.state import IncidentState
from utils.llm import get_llm
from services.llm_service import LLMService
from services.prompt_loader import load_prompt

logger = logging.getLogger(__name__)

COOKBOOK_SYSTEM_PROMPT = load_prompt('cookbook.md')


def synthesize_cookbook(state: IncidentState) -> dict:
    """Synthesize a prioritized incident response runbook from remediations.

    Produces a markdown checklist grouped by severity that an on-call engineer
    can follow step-by-step, including verification steps after each fix.

    Args:
        state: Current incident state containing remediations.

    Returns:
        Dict with cookbook (markdown string) and agent_trace updates.
    """
    start_time = time.time()

    remediations = state.get("remediations", [])
    if not remediations:
        logger.warning("synthesize_cookbook called with empty remediations — skipping LLM call")
        end_time = time.time()
        return {
            "cookbook": "",
            "agent_trace": [{
                "agent_name": "cookbook",
                "start_time": start_time,
                "end_time": end_time,
                "input_summary": "Remediations: 0 items",
                "output_summary": "Skipped — no remediations",
                "status": "skipped",
            }],
        }

    logger.info("Synthesizing cookbook from %d remediations", len(remediations))

    llm = get_llm()
    remediations_json = json.dumps(remediations, indent=2)
    messages = [
        SystemMessage(content=COOKBOOK_SYSTEM_PROMPT),
        HumanMessage(content=f"Create a runbook from these remediations:\n\n{remediations_json}"),
    ]
    response = llm.invoke(messages)
    end_time = time.time()

    logger.info("Cookbook synthesized in %.1fs", end_time - start_time)

    trace_entry = {
        "agent_name": "cookbook",
        "start_time": start_time,
        "end_time": end_time,
        "input_summary": f"Remediations: {len(remediations)} items",
        "output_summary": "Generated incident response runbook",
        "status": "completed",
    }

    return {
        "cookbook": response.content.strip(),
        "agent_trace": [trace_entry],
    }