"""Centralized configuration and constants for the DevOps Incident Analyzer."""

# Severity levels and their sort order
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Severity display colors (hex, css_class)
SEVERITY_COLORS = {
    "CRITICAL": ("#f85149", "critical"),
    "HIGH": ("#d29922", "high"),
    "MEDIUM": ("#58a6ff", "medium"),
    "LOW": ("#8b949e", "low"),
}

# Severity emoji for UI display
SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",
    "HIGH": "\U0001f7e0",
    "MEDIUM": "\U0001f535",
    "LOW": "\u26aa",
}

# Slack severity emoji (mrkdwn format)
SLACK_SEVERITY_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH": ":large_orange_circle:",
    "MEDIUM": ":large_blue_circle:",
    "LOW": ":white_circle:",
}
