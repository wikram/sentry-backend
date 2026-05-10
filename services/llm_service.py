import os

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv(override=True)


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

    def invoke(self, prompt):

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    'role': 'system',
                    'content': 'You are a senior DevOps and SRE engineer.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            temperature=self.temperature
        )

        return response.choices[0].message.content
