import json
import logging
import time
from langchain_core.messages import SystemMessage, HumanMessage
from orchestrator.state import IncidentState
from utils.llm import get_llm
from services.prompt_loader import load_prompt

logger = logging.getLogger(__name__)

REMEDIATION_SYSTEM_PROMPT = load_prompt('remediation.md')


def generate_remediations(state: IncidentState) -> dict:
    """Generate actionable remediations from classified log entries using LLM.

    Groups related log entries by underlying issue and produces structured
    remediations with root cause analysis, fix steps, and confidence scores.

    Args:
        state: Current incident state containing classified_entries.

    Returns:
        Dict with remediations and agent_trace updates.
    """
    start_time = time.time()

    classified_entries = state.get("classified_entries", [])
    if not classified_entries:
        logger.warning("generate_remediations called with empty classified_entries — skipping LLM call")
        end_time = time.time()
        return {
            "remediations": [],
            "agent_trace": [{
                "agent_name": "remediation",
                "start_time": start_time,
                "end_time": end_time,
                "input_summary": "Classified entries: 0 issues",
                "output_summary": "Skipped — no classified entries",
                "status": "skipped",
            }],
        }

    logger.info("Generating remediations for %d classified entries", len(classified_entries))

    llm = get_llm()
    entries_json = json.dumps(classified_entries, indent=2)
    messages = [
        SystemMessage(content=REMEDIATION_SYSTEM_PROMPT),
        HumanMessage(content=f"Generate remediations for these classified entries:\n\n{entries_json}"),
    ]
    response = llm.invoke(messages)

    raw_content = response.content.strip()
    if raw_content.startswith("```"):
        raw_content = raw_content.split("\n", 1)[1].rsplit("```", 1)[0].strip()

    try:
        remediations = json.loads(raw_content)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse remediation JSON response: %s\nRaw content: %s", e, raw_content)
        raise

    end_time = time.time()
    logger.info("Generated %d remediations in %.1fs", len(remediations), end_time - start_time)

    trace_entry = {
        "agent_name": "remediation",
        "start_time": start_time,
        "end_time": end_time,
        "input_summary": f"Classified entries: {len(classified_entries)} issues",
        "output_summary": f"Generated {len(remediations)} remediations",
        "status": "completed",
    }

    return {
        "remediations": remediations,
        "agent_trace": [trace_entry],
    }