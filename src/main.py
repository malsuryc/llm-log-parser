import os

from dotenv import load_dotenv
from openai import OpenAI


def main():
    # Load environment variables from .env file
    load_dotenv()

    # Get the OpenAI API URL and key from environment variables
    api_url = os.getenv("OPENAI_API_URL")
    # Default to dummy key if not set
    api_key = os.getenv("OPENAI_API_KEY", "dummy-key")

    if not api_url:
        print("Error: OPENAI_API_URL not found in .env file")
        return

    print(f"Connecting to OpenAI API at: {api_url}")

    # Initialize OpenAI client with custom base URL
    client = OpenAI(base_url=api_url, api_key=api_key)

    try:
        # Test the API connection with a simple completion
        response = client.chat.completions.create(
            model="Qwen3-32B",  # Adjust model name as needed for your API
            messages=[
                {"role": "user", "content": "Hello! Can you tell me a brief joke?"}
            ],
            max_tokens=100,
        )

        print("API Response:")
        print(response.choices[0].message.content)

    except Exception as e:
        print(f"Error calling OpenAI API: {e}")


if __name__ == "__main__":
    main()
