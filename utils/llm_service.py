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

        self.client = OpenAI(
            base_url='https://openrouter.ai/api/v1',
            api_key=os.getenv('OPENROUTER_API_KEY')
        )

        self.model = os.getenv('LLM_MODEL')

        if not self.model:
            raise ValueError(
                'LLM_MODEL is not configured in .env'
            )

        self.temperature = 0

        if llm_config:
            self.temperature = llm_config.get(
                'temperature',
                0
            )

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