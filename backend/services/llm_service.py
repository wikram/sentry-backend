from openai import OpenAI


class LLMService:

    def __init__(self, llm_config):

        self.client = OpenAI(
            base_url='https://openrouter.ai/api/v1',
            api_key=llm_config['api_key']
        )

        self.model = llm_config['model']

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
