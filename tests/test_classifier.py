import json
from unittest.mock import patch, MagicMock
from orchestrator.state import make_initial_state
from agents.classifier import classify_logs

SAMPLE_LOGS = """2024-01-15 03:42:18 ERROR kernel: Out of memory: Killed process 1842 (node) total-vm:2451832kB
2024-01-15 03:42:20 WARN sqlalchemy.exc.TimeoutError: QueuePool limit of 20 overflow 10 reached
2024-01-15 03:43:01 ERROR auth.middleware: JWT validation failed: token expired"""

MOCK_LLM_RESPONSE = json.dumps([
    {
        "timestamp": "2024-01-15T03:42:18Z",
        "severity": "CRITICAL",
        "category": "OOM",
        "source": "kernel",
        "raw_line": "kernel: Out of memory: Killed process 1842 (node) total-vm:2451832kB",
        "summary": "OOM kill on node process, VM size 2.4GB",
    },
    {
        "timestamp": "2024-01-15T03:42:20Z",
        "severity": "HIGH",
        "category": "timeout",
        "source": "sqlalchemy",
        "raw_line": "sqlalchemy.exc.TimeoutError: QueuePool limit of 20 overflow 10 reached",
        "summary": "Database connection pool exhausted",
    },
    {
        "timestamp": "2024-01-15T03:43:01Z",
        "severity": "MEDIUM",
        "category": "auth_failure",
        "source": "auth.middleware",
        "raw_line": "auth.middleware: JWT validation failed: token expired",
        "summary": "JWT token expired causing auth failure",
    },
])


@patch("agents.classifier.get_llm")
def test_classify_logs_parses_response(mock_chat_class):
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content=MOCK_LLM_RESPONSE)
    mock_chat_class.return_value = mock_llm

    state = make_initial_state(SAMPLE_LOGS)
    result = classify_logs(state)

    assert len(result["classified_entries"]) == 3
    assert result["classified_entries"][0]["severity"] == "CRITICAL"
    assert result["classified_entries"][1]["category"] == "timeout"
    assert result["classified_entries"][2]["source"] == "auth.middleware"


@patch("agents.classifier.get_llm")
def test_classify_logs_adds_trace_entry(mock_chat_class):
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content=MOCK_LLM_RESPONSE)
    mock_chat_class.return_value = mock_llm

    state = make_initial_state(SAMPLE_LOGS)
    result = classify_logs(state)

    assert len(result["agent_trace"]) == 1
    trace = result["agent_trace"][0]
    assert trace["agent_name"] == "classifier"
    assert trace["status"] == "completed"
    assert trace["end_time"] >= trace["start_time"]
