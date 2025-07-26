# LLM Log Parser

A Python application that uses AI to analyze log files and detect anomalies.

## Setup

1. Activate your virtual environment:
   ```bash
   . .venv/bin/activate
   ```

2. Configure your `.env` file:
   ```
   OPENAI_API_URL=http://10.12.40.145:23334/v1
   OPENAI_API_KEY=your-api-key-here
   LOG_FILE_PATH=/path/to/your/logfile
   ```

3. Make sure the log file exists and is readable.

## Usage

Run the log analyzer:
```bash
python src/main.py
```

The program will:
1. Test the API connection
2. Read the last 100 lines from your log file using `tail -n 100`
3. Send the log content to the AI model for analysis
4. Display anomalies and potential issues found in the logs

## Features

- **Automatic log reading**: Uses `tail` command to read recent log entries
- **AI-powered analysis**: Leverages the Qwen3-32B model for intelligent log analysis
- **Anomaly detection**: Identifies errors, unusual patterns, security events, and performance issues
- **Clean output**: Handles the model's `<think>` tags and provides clean analysis results

## Configuration

### Environment Variables

- `OPENAI_API_URL`: Your OpenAI-compatible API endpoint
- `OPENAI_API_KEY`: API key (can be dummy for local models)  
- `LOG_FILE_PATH`: Path to the log file you want to analyze

### Example log files to analyze

- `/var/log/syslog` - System logs
- `/var/log/auth.log` - Authentication logs
- `/var/log/nginx/access.log` - Web server logs
- `/var/log/apache2/error.log` - Apache error logs

## Sample Output

The analyzer will provide structured analysis including:
- Error messages and exceptions
- Unusual timestamp patterns
- Security-related events
- Performance issues
- System warnings

Each analysis includes explanations of why certain entries might be problematic.
