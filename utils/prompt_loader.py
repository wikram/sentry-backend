from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
PROMPT_DIR = BASE_DIR / 'prompts'


def load_prompt(filename: str):

    path = PROMPT_DIR / filename

    with open(path, 'r', encoding='utf-8') as file:
        return file.read()