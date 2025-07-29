import os
import subprocess
import yaml
from datetime import datetime

from dotenv import load_dotenv
from openai import OpenAI


def get_log_content(log_file_path, lines=100):
    """Read the last N lines from a log file using tail command."""
    try:
        result = subprocess.run(
            ["bash", "-c", f"cat {log_file_path} | grep -v wwclient | tail -n {lines}"],
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
    """Send log content to AI for structured anomaly detection."""
    prompt = """You are a system engineer analyzing cluster logs aggregated from multiple nodes using 'journalctl -xef' via pdsh.

Please analyze the log entries and identify issues on each node. Provide a YAML response with ONLY the issues section:

```yaml
issues:
  - node_name: "node001"
    severity: "CRITICAL|HIGH|MEDIUM|LOW"
    category: "system|security|performance|network|storage|user"
    summary: "Brief description of the issue"
    log_entries: |
      Multi-line log entries relevant to this issue
      Include timestamps and full context
    analysis: "Detailed explanation of what this means and potential impact"
    recommended_action: "Specific steps to resolve or investigate further"
  
  - node_name: "node002"
    severity: "HIGH"
    category: "performance"
    summary: "Another issue description"
    log_entries: |
      Related log entries here
    analysis: "Analysis of this issue"
    recommended_action: "What to do about it"
```

Focus on:
1. Parse node names from log prefixes (typically in format like "node001:" or similar)
2. Group related errors by node
3. Identify severity levels (CRITICAL for system failures, HIGH for service issues, etc.)
4. Categorize issues (system, security, performance, network, storage, user)
5. Only include actual issues/errors/warnings - ignore normal operational logs

Log entries to analyze:
```
{log_content}
```

Respond ONLY with the YAML structure showing the issues array, no additional text."""

    try:
        response = client.chat.completions.create(
            model="Qwen3-32B",
            messages=[
                {"role": "user", "content": prompt.format(log_content=log_content)}
            ],
            max_tokens=4096,
            temperature=0.1,
        )

        return response.choices[0].message.content
    except Exception as e:
        print(f"Error calling AI API: {e}")
        return None


def extract_and_parse_yaml(ai_response):
    """Extract YAML content from AI response and parse it."""
    if not ai_response:
        return None

    # Remove <think> tags if present
    content = ai_response
    if "</think>" in content:
        parts = content.split("</think>", 1)
        if len(parts) > 1:
            content = parts[1].strip()

    # Extract YAML from code blocks if present
    if "```yaml" in content:
        yaml_start = content.find("```yaml") + 7
        yaml_end = content.find("```", yaml_start)
        if yaml_end != -1:
            content = content[yaml_start:yaml_end].strip()
    elif "```" in content:
        # Handle generic code blocks
        lines = content.split("\n")
        in_code_block = False
        yaml_lines = []

        for line in lines:
            if line.strip() == "```" and not in_code_block:
                in_code_block = True
                continue
            elif line.strip() == "```" and in_code_block:
                break
            elif in_code_block:
                yaml_lines.append(line)

        if yaml_lines:
            content = "\n".join(yaml_lines)

    try:
        parsed_yaml = yaml.safe_load(content)
        print(f"✓ Successfully parsed YAML structure")
        return parsed_yaml
    except yaml.YAMLError as e:
        print(f"✗ Error parsing YAML: {e}")
        print(f"Raw content that failed to parse:\n{content[:500]}...")
        return {"raw_response": content}


def group_similar_issues(parsed_yaml):
    """
    Groups similar issues across different nodes.
    Returns a new structure with deduplicated issues and lists of affected nodes.
    """
    if not parsed_yaml or "issues" not in parsed_yaml or not parsed_yaml["issues"]:
        return parsed_yaml
        
    grouped_issues = {}
    
    for issue in parsed_yaml["issues"]:
        # Create a key based on similarity criteria
        # Here we use category + summary as the grouping key
        key = f"{issue.get('category', 'unknown')}::{issue.get('summary', 'unknown')}"
        
        if key not in grouped_issues:
            # Create a new group with this issue as template
            grouped_issues[key] = {
                "severity": issue.get("severity", "N/A"),
                "category": issue.get("category", "N/A"),
                "summary": issue.get("summary", "N/A"),
                "analysis": issue.get("analysis", ""),
                "recommended_action": issue.get("recommended_action", ""),
                "affected_nodes": [],
                "sample_log_entries": issue.get("log_entries", "")
            }
            
        # Add this node to the affected nodes list
        node_name = issue.get("node_name", "Unknown")
        if node_name not in grouped_issues[key]["affected_nodes"]:
            grouped_issues[key]["affected_nodes"].append(node_name)
    
    # Convert back to list format
    result = {"grouped_issues": list(grouped_issues.values())}
    return result


def format_analysis_output(parsed_yaml):
    """Format the parsed YAML analysis into a readable output."""
    if not parsed_yaml:
        return "No analysis data available"

    if "raw_response" in parsed_yaml:
        return f"Raw AI Response (YAML parsing failed):\n{parsed_yaml['raw_response']}"

    output = []
    
    # Group similar issues first
    grouped_data = group_similar_issues(parsed_yaml)

    # Issues section (original format)
    if "issues" in parsed_yaml and parsed_yaml["issues"]:
        output.append("🚨 DETECTED ISSUES BY NODE (ORIGINAL FORMAT)")
        output.append("=" * 60)

        for i, issue in enumerate(parsed_yaml["issues"], 1):
            output.append(f"\n[{i}] Node: {issue.get('node_name', 'Unknown')}")
            # ...existing code...
            
    # Grouped issues section (new format)
    if "grouped_issues" in grouped_data and grouped_data["grouped_issues"]:
        output.append("\n\n🔍 DEDUPLICATED ISSUES")
        output.append("=" * 60)

        for i, issue in enumerate(grouped_data["grouped_issues"], 1):
            output.append(f"\n[{i}] {issue.get('summary', 'Unknown issue')}")
            output.append(f"    Severity: {issue.get('severity', 'N/A')}")
            output.append(f"    Category: {issue.get('category', 'N/A')}")
            output.append(f"    Affected Nodes ({len(issue.get('affected_nodes', []))}): {', '.join(issue.get('affected_nodes', ['Unknown']))}")
            
            if issue.get("sample_log_entries"):
                output.append("    Sample Log Entries:")
                for line in issue["sample_log_entries"].strip().split("\n")[:5]:  # Limit to 5 lines as sample
                    output.append(f"      {line}")
                if len(issue["sample_log_entries"].strip().split("\n")) > 5:
                    output.append("      ...")

            if issue.get("analysis"):
                output.append(f"    Analysis: {issue['analysis']}")

            if issue.get("recommended_action"):
                output.append(f"    Action: {issue['recommended_action']}")

            output.append("-" * 60)
    else:
        output.append("✅ No issues detected in the log entries")

    return "\n".join(output)


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
            max_tokens=50,
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
    print(log_content)
    print(f"✓ Successfully read {len(log_content.splitlines())} lines")

    # Analyze logs with AI
    print("\n🤖 Analyzing cluster logs for issues...")
    ai_response = analyze_logs_with_ai(client, log_content)

    if ai_response:
        # Parse the YAML response
        parsed_analysis = extract_and_parse_yaml(ai_response)

        # In main(), replace the existing output saving with:
        if parsed_analysis:
            # Format and display the structured analysis
            formatted_output = format_analysis_output(parsed_analysis)
            
            print("\n" + "=" * 70)
            print("📊 CLUSTER LOG ANALYSIS - ISSUES BY NODE")
            print("=" * 70)
            print(formatted_output)
            print("=" * 70)
            
            # Save to file with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"output/cluster_issues_{timestamp}.yaml"
            grouped_analysis = group_similar_issues(parsed_analysis)
            
            try:
                # Save both formats
                with open(output_file, "w") as f:
                    yaml.dump({
                        "original": parsed_analysis,
                        "grouped": grouped_analysis
                    }, f, default_flow_style=False, indent=2)
                print(f"\n💾 Issues analysis saved to: {output_file}")
            except Exception as e:
                print(f"Warning: Could not save analysis to file: {e}")
        else:
            print("Failed to parse structured analysis")
    else:
        print("Failed to get analysis from AI")


if __name__ == "__main__":
    main()
