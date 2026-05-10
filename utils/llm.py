import os
from langchain_openai import ChatOpenAI


def get_llm() -> ChatOpenAI:
    """Instantiate the shared ChatOpenAI client with project defaults.

    Reads LLM_MODEL from the environment (defaults to "openai/gpt-4o") and
    returns a zero-temperature client suitable for deterministic JSON outputs.

    Returns:
        Configured ChatOpenAI instance.
    """
    return ChatOpenAI(
        model=os.environ.get("LLM_MODEL", "openai/gpt-4o"),
        temperature=0,
    )
