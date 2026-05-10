import logging
import os
import time
from slack_sdk import WebClient
from orchestrator.state import IncidentState
from config import SLACK_SEVERITY_EMOJI as SEVERITY_EMOJI

logger = logging.getLogger(__name__)


def _build_slack_blocks(remediations: list[dict]) -> list[dict]:
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Incident Analysis Report"},
        },
        {"type": "divider"},
    ]

    for rem in remediations:
        severity = "CRITICAL"
        for entry_idx in rem.get("linked_log_entries", []):
            break
        emoji = SEVERITY_EMOJI.get(severity, ":white_circle:")

        fix_text = "\n".join(f"  {i+1}. {step}" for i, step in enumerate(rem["fix_steps"]))
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *{rem['issue_summary']}*\n"
                    f"*Root cause:* {rem['root_cause']}\n"
                    f"*Fix steps:*\n{fix_text}\n"
                    f"_Confidence: {rem['confidence']:.0%}_"
                ),
            },
        })
        blocks.append({"type": "divider"})

    return blocks


def send_slack_notifications(state: IncidentState) -> dict:
    """Send incident analysis report to a Slack channel.

    Builds rich Block Kit message blocks from remediation data and posts
    them to the configured channel, recording success or failure per message.

    Args:
        state: Current incident state containing remediations.

    Returns:
        Dict with slack_notifications and agent_trace updates.
    """
    start_time = time.time()

    logger.info("Sending Slack notifications for %d remediations", len(state.get("remediations", [])))

    # Env vars are set by app.py at startup (supports both .env and Streamlit Cloud)
    token = os.environ.get("SLACK_BOT_TOKEN", "")
    channel = os.environ.get("SLACK_CHANNEL", "#incident-alerts")
    if channel and not channel.startswith("#"):
        channel = f"#{channel}"
    client = WebClient(token=token)

    remediations = state["remediations"]
    blocks = _build_slack_blocks(remediations)
    fallback_text = f"Incident Analysis: {len(remediations)} issues found"

    notifications = []
    try:
        client.chat_postMessage(channel=channel, text=fallback_text, blocks=blocks)
        notifications.append({
            "channel": channel,
            "text": fallback_text,
            "blocks": {"blocks": blocks},
            "status": "sent",
        })
        logger.info("Slack notification sent to %s", channel)
    except Exception as e:
        logger.error("Failed to send Slack notification: %s", e)
        notifications.append({
            "channel": channel,
            "text": fallback_text,
            "blocks": {"blocks": blocks},
            "status": "failed",
        })

    end_time = time.time()
    sent_count = sum(1 for n in notifications if n["status"] == "sent")
    logger.info("Slack notifier completed in %.1fs — %d sent", end_time - start_time, sent_count)

    trace_entry = {
        "agent_name": "slack_notifier",
        "start_time": start_time,
        "end_time": end_time,
        "input_summary": f"Remediations: {len(remediations)} items",
        "output_summary": f"Sent {sent_count} messages",
        "status": "completed",
    }

    return {
        "slack_notifications": notifications,
        "agent_trace": [trace_entry],
    }