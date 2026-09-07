import os

from dotenv import load_dotenv
from openai import OpenAI
from langchain_core.messages import BaseMessage


load_dotenv(override=True)


class LLMResponse:
    """Simple wrapper for LLM response to provide .content attribute."""
    def __init__(self, content):
        self.content = content


class LLMService:

    def __init__(self, llm_config=None):
        llm_config = llm_config or {}

        self.client = OpenAI(
            base_url=os.getenv('OPENROUTER_API_BASE', 'https://openrouter.ai/api/v1'),
            api_key=os.getenv('OPENROUTER_API_KEY') or os.getenv('OPENAI_API_KEY', 'dummy-key')
        )

        model = llm_config.get('model')
        temperature = llm_config.get('temperature')

        if not model or temperature is None:
            try:
                from utils.helpers import get_llm_config
                cfg = get_llm_config()
                if not model:
                    model = cfg.get('model')
                if temperature is None:
                    temperature = cfg.get('temperature', 0)
            except Exception:
                pass

        self.model = model or os.getenv('LLM_MODEL') or 'openai/gpt-4o'
        self.temperature = float(temperature) if temperature is not None else 0

    def invoke(self, messages):
        """Invoke the LLM with messages.
        
        Args:
            messages: Either a list of langchain Message objects or a string prompt
            
        Returns:
            LLMResponse object with .content attribute containing the response text
        """
        # Convert langchain messages to OpenAI format
        if isinstance(messages, list):
            formatted_messages = []
            for msg in messages:
                if isinstance(msg, BaseMessage):
                    formatted_messages.append({
                        'role': self._get_role(msg),
                        'content': msg.content
                    })
                else:
                    formatted_messages.append({
                        'role': 'user',
                        'content': str(msg)
                    })
        else:
            # If it's a string, treat it as a user message
            formatted_messages = [
                {
                    'role': 'system',
                    'content': 'You are a senior DevOps and SRE engineer.'
                },
                {
                    'role': 'user',
                    'content': str(messages)
                }
            ]

        response = self.client.chat.completions.create(
            model=self.model,
            messages=formatted_messages,
            temperature=self.temperature
        )

        return LLMResponse(response.choices[0].message.content)
    
    def _get_role(self, message: BaseMessage) -> str:
        """Get the OpenAI role from a langchain message."""
        msg_type = type(message).__name__
        if msg_type == 'SystemMessage':
            return 'system'
        elif msg_type == 'HumanMessage':
            return 'user'
        elif msg_type == 'AIMessage':
            return 'assistant'
        else:
            return 'user'  # Default to user role