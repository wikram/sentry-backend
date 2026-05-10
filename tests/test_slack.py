import os
from unittest.mock import patch, MagicMock
from orchestrator.state import make_initial_state
from agents.slack_notifier import send_slack_notifications

SAMPLE_REMEDIATIONS = [
    {
        "issue_summary": "OOM Kill on api-server",
        "root_cause": "Memory limit too low",
        "fix_steps": ["Increase memory limit to 4Gi"],
        "rationale": "Process exceeded 2Gi limit",
        "confidence": 0.9,
        "linked_log_entries": [0],
    },
]


@patch.dict(os.environ, {"SLACK_BOT_TOKEN": "xoxb-test", "SLACK_CHANNEL": "#test"})
@patch("agents.slack_notifier.WebClient")
def test_send_slack_notifications_posts_message(mock_webclient_class):
    mock_client = MagicMock()
    mock_client.chat_postMessage.return_value = {"ok": True}
    mock_webclient_class.return_value = mock_client

    state = make_initial_state("")
    state["remediations"] = SAMPLE_REMEDIATIONS
    result = send_slack_notifications(state)

    assert len(result["slack_notifications"]) == 1
    assert result["slack_notifications"][0]["status"] == "sent"
    mock_client.chat_postMessage.assert_called_once()


@patch.dict(os.environ, {"SLACK_BOT_TOKEN": "xoxb-test", "SLACK_CHANNEL": "#test"})
@patch("agents.slack_notifier.WebClient")
def test_send_slack_handles_failure(mock_webclient_class):
    mock_client = MagicMock()
    mock_client.chat_postMessage.side_effect = Exception("channel_not_found")
    mock_webclient_class.return_value = mock_client

    state = make_initial_state("")
    state["remediations"] = SAMPLE_REMEDIATIONS
    result = send_slack_notifications(state)

    assert len(result["slack_notifications"]) == 1
    assert result["slack_notifications"][0]["status"] == "failed"


@patch.dict(os.environ, {"SLACK_BOT_TOKEN": "xoxb-test", "SLACK_CHANNEL": "#test"})
@patch("agents.slack_notifier.WebClient")
def test_send_slack_adds_trace(mock_webclient_class):
    mock_client = MagicMock()
    mock_client.chat_postMessage.return_value = {"ok": True}
    mock_webclient_class.return_value = mock_client

    state = make_initial_state("")
    state["remediations"] = SAMPLE_REMEDIATIONS
    result = send_slack_notifications(state)

    trace = [t for t in result["agent_trace"] if t["agent_name"] == "slack_notifier"]
    assert len(trace) == 1
    assert trace[0]["status"] == "completed"
