import json
import logging
import time

from langchain_core.messages import HumanMessage
from langchain_core.messages import SystemMessage

from orchestrator.state import IncidentState
from utils.llm import get_llm


logger = logging.getLogger(__name__)


CLASSIFIER_SYSTEM_PROMPT = """You are a DevOps log analysis expert. Parse the provided ops logs and classify each log entry.

For each log entry, extract:
- timestamp: ISO 8601 format (best effort)
- severity: one of CRITICAL, HIGH, MEDIUM, LOW
- category: e.g. OOM, timeout, auth_failure, disk, network, crash, config_error
- source: the system/service that produced the log
- raw_line: the original log line
- summary: one-sentence description of the issue

Severity guidelines:
- CRITICAL: system down, data loss, OOM kills, crash loops
- HIGH: degraded service, connection pool exhaustion, repeated failures
- MEDIUM: auth failures, intermittent errors, elevated latency
- LOW: warnings, deprecation notices, minor config issues

Return a JSON array of objects. No markdown, no explanation, just the JSON array.

Example input:
2024-01-10 12:00:00 ERROR disk: /dev/sda1 is 95% full

Example output:
[{"timestamp": "2024-01-10T12:00:00Z", "severity": "HIGH", "category": "disk", "source": "disk", "raw_line": "disk: /dev/sda1 is 95% full", "summary": "Root disk nearly full at 95% capacity"}]"""



def classify_logs(state: IncidentState) -> dict:
    """Classify raw log entries by severity and category using LLM.

    Parses unstructured logs of any format and produces structured
    LogEntry objects with severity, category, and summary fields.

    Args:
        state: Current incident state containing raw_logs.

    Returns:
        Dict with classified_entries and agent_trace updates.
    """

    start_time = time.time()

    raw_logs = state.get("raw_logs", "")

    if not raw_logs or not raw_logs.strip():

        logger.warning(
            "classify_logs called with empty raw_logs — skipping LLM call"
        )

        end_time = time.time()

        return {
            "classified_entries": [],
            "agent_trace": [{
                "agent_name": "classifier",
                "start_time": start_time,
                "end_time": end_time,
                "input_summary": "Raw logs: 0 lines",
                "output_summary": "Skipped — empty input",
                "status": "skipped",
            }],
        }

    log_line_count = len(raw_logs.splitlines())

    logger.info(
        "Classifying %d lines of logs",
        log_line_count
    )

    llm = get_llm()

    messages = [
        SystemMessage(
            content=CLASSIFIER_SYSTEM_PROMPT
        ),
        HumanMessage(
            content=f"Classify these logs:\n\n{raw_logs}"
        ),
    ]

    response = llm.invoke(messages)

    raw_content = response.content.strip()

    if raw_content.startswith("```"):
        raw_content = raw_content.split(
            "\n",
            1
        )[1].rsplit(
            "```",
            1
        )[0].strip()

    try:
        classified = json.loads(raw_content)

    except json.JSONDecodeError as error:

        logger.error(
            "Failed to parse classifier JSON response: %s\nRaw content: %s",
            error,
            raw_content
        )

        raise

    end_time = time.time()

    logger.info(
        "Classified %d entries in %.1fs",
        len(classified),
        end_time - start_time
    )

    trace_entry = {
        "agent_name": "classifier",
        "start_time": start_time,
        "end_time": end_time,
        "input_summary": f"Raw logs: {log_line_count} lines",
        "output_summary": f"Classified {len(classified)} entries",
        "status": "completed",
    }

    return {
        "classified_entries": classified,
        "agent_trace": [trace_entry],
    }
