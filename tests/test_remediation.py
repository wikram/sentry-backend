import json
from unittest.mock import patch, MagicMock
from orchestrator.state import make_initial_state
from agents.remediation import generate_remediations

SAMPLE_CLASSIFIED = [
    {
        "timestamp": "2024-01-15T03:42:18Z",
        "severity": "CRITICAL",
        "category": "OOM",
        "source": "kernel",
        "raw_line": "kernel: Out of memory: Killed process 1842",
        "summary": "OOM kill on node process",
    },
    {
        "timestamp": "2024-01-15T03:42:20Z",
        "severity": "HIGH",
        "category": "timeout",
        "source": "sqlalchemy",
        "raw_line": "sqlalchemy.exc.TimeoutError: QueuePool limit reached",
        "summary": "Database connection pool exhausted",
    },
]

MOCK_LLM_RESPONSE = json.dumps([
    {
        "issue_summary": "OOM Kill on node process",
        "root_cause": "Container memory limit (2Gi) insufficient for workload",
        "fix_steps": ["Increase memory limit to 4Gi in deployment spec", "Add memory usage alerting at 80% threshold"],
        "rationale": "Process was killed by kernel OOM killer, indicating the configured limit is too low for the actual workload",
        "confidence": 0.9,
        "linked_log_entries": [0],
    },
    {
        "issue_summary": "Database connection pool exhaustion",
        "root_cause": "Pool size of 20 with overflow 10 cannot handle concurrent request volume",
        "fix_steps": ["Increase pool_size to 40 and max_overflow to 20", "Add connection pool monitoring"],
        "rationale": "TimeoutError indicates all 30 connections (20 + 10 overflow) were in use simultaneously",
        "confidence": 0.85,
        "linked_log_entries": [1],
    },
])


@patch("agents.remediation.get_llm")
def test_generate_remediations_parses_response(mock_chat_class):
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content=MOCK_LLM_RESPONSE)
    mock_chat_class.return_value = mock_llm

    state = make_initial_state("")
    state["classified_entries"] = SAMPLE_CLASSIFIED
    result = generate_remediations(state)

    assert len(result["remediations"]) == 2
    assert result["remediations"][0]["confidence"] == 0.9
    assert "memory limit" in result["remediations"][0]["fix_steps"][0].lower()


@patch("agents.remediation.get_llm")
def test_generate_remediations_adds_trace(mock_chat_class):
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content=MOCK_LLM_RESPONSE)
    mock_chat_class.return_value = mock_llm

    state = make_initial_state("")
    state["classified_entries"] = SAMPLE_CLASSIFIED
    result = generate_remediations(state)

    trace = [t for t in result["agent_trace"] if t["agent_name"] == "remediation"]
    assert len(trace) == 1
    assert trace[0]["status"] == "completed"
