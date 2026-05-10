import os
from slack_sdk import WebClient


def get_slack_client() -> WebClient:
    token = os.environ.get("SLACK_BOT_TOKEN", "")
    return WebClient(token=token)


def get_slack_channel() -> str:
    return os.environ.get("SLACK_CHANNEL", "#incident-alerts")
