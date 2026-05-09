import re


ERROR_PATTERNS = {
    'KUBERNETES': [
        r'CrashLoopBackOff',
        r'ImagePullBackOff',
        r'OOMKilled'
    ],
    'MAVEN': [
        r'BUILD FAILURE',
        r'Failed to execute goal'
    ],
    'NPM': [
        r'npm ERR!'
    ],
    'DOCKER': [
        r'docker: Error response from daemon'
    ],
    'TERRAFORM': [
        r'terraform.*Error:'
    ]
}


def extract_failed_stage(logs):

    pattern = r'Stage \"(.*?)\"'

    matches = re.findall(pattern, logs)

    return matches[-1] if matches else 'unknown'



def detect_issue(logs):

    for category, patterns in ERROR_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, logs, re.IGNORECASE):
                return category

    return 'UNKNOWN'



def extract_error_context(logs):

    lines = logs.splitlines()

    error_lines = []

    for line in lines:

        if (
            'ERROR' in line
            or 'FAIL' in line
            or 'Exception' in line
            or 'fatal' in line.lower()
        ):
            error_lines.append(line)

    return '\n'.join(error_lines[-50:])



def parse_logs(state):

    logs = state['raw_logs']

    state['parsed_logs'] = {
        'failed_stage': extract_failed_stage(logs),
        'issue_type': detect_issue(logs),
        'error_context': extract_error_context(logs)
    }

    return state
