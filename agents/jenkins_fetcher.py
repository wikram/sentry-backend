import requests


def jenkins_fetcher(state):

    jenkins = state['jenkins']

    url = (
        f"{jenkins['base_url']}"
        f"/job/{jenkins['job_name']}"
        f"/{jenkins['build_number']}"
        f"/consoleText"
    )

    response = requests.get(
        url,
        auth=(
            jenkins['username'],
            jenkins['api_token']
        ),
        timeout=30
    )

    response.raise_for_status()

    state['raw_logs'] = response.text

    return state
