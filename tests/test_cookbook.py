from unittest.mock import patch, MagicMock
from orchestrator.state import make_initial_state
from agents.cookbook import synthesize_cookbook

SAMPLE_REMEDIATIONS = [
    {
        "issue_summary": "OOM Kill on api-server",
        "root_cause": "Memory limit too low",
        "fix_steps": ["Increase memory limit to 4Gi"],
        "rationale": "Process exceeded 2Gi limit",
        "confidence": 0.9,
        "linked_log_entries": [0],
    },
    {
        "issue_summary": "DB connection pool exhaustion",
        "root_cause": "Pool size too small",
        "fix_steps": ["Increase pool_size to 40"],
        "rationale": "All connections in use",
        "confidence": 0.85,
        "linked_log_entries": [1],
    },
]

MOCK_COOKBOOK = """# Incident Response Runbook

## Priority 1: Critical Issues

### OOM Kill on api-server
- [ ] Increase memory limit to 4Gi in deployment spec
- [ ] Verify pod restarts cleanly with new limit

## Priority 2: High Issues

### DB connection pool exhaustion
- [ ] Increase pool_size to 40 in database config
- [ ] Monitor connection count after change"""


@patch("agents.cookbook.get_llm")
def test_synthesize_cookbook_returns_markdown(mock_chat_class):
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content=MOCK_COOKBOOK)
    mock_chat_class.return_value = mock_llm

    state = make_initial_state("")
    state["remediations"] = SAMPLE_REMEDIATIONS
    result = synthesize_cookbook(state)

    assert "# Incident Response Runbook" in result["cookbook"]
    assert "OOM Kill" in result["cookbook"]
    assert "- [ ]" in result["cookbook"]


@patch("agents.cookbook.get_llm")
def test_synthesize_cookbook_adds_trace(mock_chat_class):
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content=MOCK_COOKBOOK)
    mock_chat_class.return_value = mock_llm

    state = make_initial_state("")
    state["remediations"] = SAMPLE_REMEDIATIONS
    result = synthesize_cookbook(state)

    trace = [t for t in result["agent_trace"] if t["agent_name"] == "cookbook"]
    assert len(trace) == 1
    assert trace[0]["status"] == "completed"
