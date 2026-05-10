import os

import requests

from dotenv import load_dotenv


load_dotenv(override=True)


SLACK_WEBHOOK_URL = os.getenv(
    'SLACK_WEBHOOK_URL'
)



def send_slack_message(message):

    if not SLACK_WEBHOOK_URL:
        raise ValueError(
            'SLACK_WEBHOOK_URL is not configured'
        )

    payload = {
        'text': message
    }

    response = requests.post(
        SLACK_WEBHOOK_URL,
        json=payload,
        timeout=30
    )

    response.raise_for_status()

    return response.text
