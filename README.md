# LLM Log Parser

A Python application that uses AI to analyze log files and detect anomalies using a sliding window approach for continuous analysis.

## Features

- **Sliding Window Analysis**: Continuously analyzes log files using overlapping windows
- **Deduplication**: Automatically merges and deduplicates similar issues across windows
- **Configurable Parameters**: Customizable window size, step size, and processing limits
- **Comprehensive Output**: Detailed analysis with window-by-window summaries and final deduplicated results

## Setup

1. Activate your virtual environment:
   ```bash
   . .venv/bin/activate
   ```

2. Configure your `.env` file:
   ```
   # API Configuration
   OPENAI_API_URL=http://10.12.40.145:23334/v1
   OPENAI_API_KEY=your-api-key-here
   LOG_FILE_PATH=/path/to/your/logfile
   
   # Sliding Window Configuration (Optional)
   WINDOW_SIZE=100          # Number of lines per window (default: 100)
   STEP_SIZE=90             # Step size between windows (default: 90, 10-line overlap)
   MAX_WINDOWS=             # Maximum windows to process (empty = no limit)
   DELAY_SECONDS=2          # Delay between API calls (default: 2 seconds)
   ```

3. Make sure the log file exists and is readable.

## Usage

Run the log analyzer:
```bash
python src/main.py
```

### How Sliding Window Analysis Works

The program processes your log file using a sliding window approach:

1. **Window 1**: Lines 1-100
2. **Window 2**: Lines 91-190 (10-line overlap with previous window)
3. **Window 3**: Lines 181-280 (10-line overlap with previous window)
4. And so on...

This approach provides:
- **Continuity**: Overlapping windows ensure no issues are missed at window boundaries
- **Context**: Each analysis includes sufficient context around potential issues
- **Efficiency**: Configurable parameters allow balancing thoroughness with API costs

The program will:
1. Test the API connection
2. Determine the total number of lines in your log file
3. Process the log file using sliding windows with the configured parameters
4. Send each window's content to the AI model for analysis
5. Merge and deduplicate results from all windows
6. Display comprehensive analysis results
7. Save detailed results to timestamped YAML files

## Output

The program generates two types of output files:

1. **Comprehensive Analysis** (`sliding_window_analysis_TIMESTAMP.yaml`):
   - Complete window-by-window results
   - Merged and deduplicated issues
   - Analysis metadata and configuration

2. **Summary** (`summary_TIMESTAMP.yaml`):
   - Analysis summary statistics
   - Final unique issues only

## Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `WINDOW_SIZE` | 100 | Number of lines in each analysis window |
| `STEP_SIZE` | 90 | Lines to advance between windows (smaller = more overlap) |
| `MAX_WINDOWS` | None | Maximum windows to process (useful for testing) |
| `DELAY_SECONDS` | 2 | Seconds to wait between API calls (rate limiting) |

### Example Configurations

**High Overlap (thorough analysis)**:
```
WINDOW_SIZE=100
STEP_SIZE=80    # 20-line overlap
```

**Low Overlap (faster processing)**:
```
WINDOW_SIZE=100
STEP_SIZE=95    # 5-line overlap
```

**Testing Configuration**:
```
WINDOW_SIZE=50
STEP_SIZE=40
MAX_WINDOWS=5   # Only process first 5 windows
```

## Features

- **Sliding Window Processing**: Continuous analysis with configurable overlap
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
