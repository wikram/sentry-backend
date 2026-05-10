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



def detect_issue(logs):

    for category, patterns in ERROR_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, logs, re.IGNORECASE):
                return category

    return 'UNKNOWN'



def parse_logs(state):

    logs = state['raw_logs']

    state['parsed_logs'] = {
        'failed_stage': 'direct_error_input',
        'issue_type': detect_issue(logs),
        'error_context': logs
    }

    return state
