import os
import subprocess
from datetime import datetime

from dotenv import load_dotenv
from openai import OpenAI


def get_log_content(log_file_path, lines=100):
    """Read the last N lines from a log file using tail command."""
    try:
        result = subprocess.run(
            ["tail", "-n", str(lines), log_file_path],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error reading log file: {e}")
        return None
    except FileNotFoundError:
        print("Error: 'tail' command not found")
        return None


def analyze_logs_with_ai(client, log_content):
    """Send log content to AI for anomaly detection."""
    prompt = """You are a system engineer analyzing server logs for anomalies. 
Please analyze the following log entries and identify any potential issues, errors, or anomalies.
Focus on:
1. Error messages or exceptions
2. Unusual patterns in timestamps or frequencies
3. Security-related events
4. Performance issues
5. System warnings

Please highlight any concerning entries and explain why they might be problematic.

Log entries:
```
{log_content}
```

Please provide your analysis in a clear, structured format."""

    try:
        response = client.chat.completions.create(
            model="Qwen3-32B",
            messages=[
                {"role": "user", "content": prompt.format(log_content=log_content)}
            ],
            max_tokens=1000,
            temperature=0.1,  # Lower temperature for more focused analysis
        )

        return response.choices[0].message.content
    except Exception as e:
        print(f"Error calling AI API: {e}")
        return None


def extract_response_content(ai_response):
    """Extract the actual response content, handling <think> tags."""
    if not ai_response:
        return None

    # Look for content after </think> tag if it exists
    if "</think>" in ai_response:
        parts = ai_response.split("</think>", 1)
        if len(parts) > 1:
            return parts[1].strip()

    return ai_response


def main():
    # Load environment variables from .env file
    load_dotenv()

    # Get configuration from environment variables
    api_url = os.getenv("OPENAI_API_URL")
    api_key = os.getenv("OPENAI_API_KEY", "dummy-key")
    log_file_path = os.getenv("LOG_FILE_PATH")

    # Validate configuration
    if not api_url:
        print("Error: OPENAI_API_URL not found in .env file")
        return

    if not log_file_path:
        print("Error: LOG_FILE_PATH not found in .env file")
        print("Please add LOG_FILE_PATH=/path/to/your/logfile to .env")
        return

    if not os.path.exists(log_file_path):
        print(f"Error: Log file does not exist: {log_file_path}")
        return

    print(f"Log Analyzer Starting...")
    print(f"API URL: {api_url}")
    print(f"Log file: {log_file_path}")
    print("-" * 50)

    # Initialize OpenAI client
    client = OpenAI(base_url=api_url, api_key=api_key)

    # Test API connection first
    try:
        print("Testing API connection...")
        test_response = client.chat.completions.create(
            model="Qwen3-32B",
            messages=[
                {"role": "user", "content": "Hello, are you ready to analyze logs?"}
            ],
            max_tokens=2048,
        )
        print("✓ API connection successful")
    except Exception as e:
        print(f"✗ API connection failed: {e}")
        return

    # Get log content
    print(f"\nReading last 100 lines from {log_file_path}...")
    log_content = get_log_content(log_file_path)

    if not log_content:
        print("Failed to read log content")
        return

    if not log_content.strip():
        print("Log file appears to be empty")
        return

    print(f"✓ Successfully read {len(log_content.splitlines())} lines")

    # Analyze logs with AI
    print("\n🤖 Analyzing logs for anomalies...")
    ai_response = analyze_logs_with_ai(client, log_content)

    if ai_response:
        # Extract content after <think> tags if present
        clean_response = extract_response_content(ai_response)

        print("\n" + "=" * 60)
        print("📊 LOG ANALYSIS RESULTS")
        print("=" * 60)
        print(f"Analysis completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        print(clean_response)
        print("=" * 60)
    else:
        print("Failed to get analysis from AI")


if __name__ == "__main__":
    main()
