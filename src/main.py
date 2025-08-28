import os
import subprocess
import yaml
import time
from datetime import datetime

from dotenv import load_dotenv
from openai import OpenAI


def get_total_log_lines(log_file_path):
    """Get the total number of lines in the log file."""
    try:
        result = subprocess.run(
            ["bash", "-c", f"cat {log_file_path} | grep -v wwclient | wc -l"],
            capture_output=True,
            text=True,
            check=True,
        )
        return int(result.stdout.strip())
    except (subprocess.CalledProcessError, ValueError) as e:
        print(f"Error getting total lines: {e}")
        return None


def get_log_window(log_file_path, start_line=1, window_size=100):
    """Read a specific window of lines from a log file."""
    try:
        # Use sed to extract lines from start_line to start_line+window_size-1
        end_line = start_line + window_size - 1
        result = subprocess.run(
            ["bash", "-c", f"cat {log_file_path} | grep -v wwclient | sed -n '{start_line},{end_line}p'"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error reading log window: {e}")
        return None
    except FileNotFoundError:
        print("Error: 'sed' command not found")
        return None


def get_log_content(log_file_path, lines=100):
    """Read the last N lines from a log file using tail command (legacy function)."""
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


def analyze_logs_with_ai(client, log_content, window_info=None):
    """Send log content to AI for structured anomaly detection."""
    window_text = f" (Window: {window_info})" if window_info else ""
    prompt = f"""You are a system engineer analyzing cluster logs aggregated from multiple nodes using 'journalctl -xef' via pdsh{window_text}.

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
{{log_content}}
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


def merge_window_results(all_results):
    """
    Merge issues from multiple windows, deduplicating similar issues.
    """
    if not all_results:
        return {"issues": []}
    
    all_issues = []
    seen_issues = set()
    
    for window_result in all_results:
        if window_result and "issues" in window_result:
            for issue in window_result["issues"]:
                # Create a deduplication key based on node, category, and summary
                dedup_key = (
                    issue.get("node_name", "unknown"),
                    issue.get("category", "unknown"),
                    issue.get("summary", "unknown")[:50]  # First 50 chars of summary
                )
                
                if dedup_key not in seen_issues:
                    seen_issues.add(dedup_key)
                    # Add window information to the issue
                    issue["first_detected_window"] = window_result.get("window_info", "unknown")
                    all_issues.append(issue)
    
    return {"issues": all_issues}


def sliding_window_analysis(client, log_file_path, window_size=100, step_size=90, max_windows=None, delay_seconds=2):
    """
    Perform sliding window analysis on log file.
    
    Args:
        client: OpenAI client
        log_file_path: Path to log file
        window_size: Size of each window (default 100 lines)
        step_size: Step size between windows (default 90 lines, 10 line overlap)
        max_windows: Maximum number of windows to process (None for all)
        delay_seconds: Delay between API calls to avoid rate limiting
    
    Returns:
        List of analysis results from each window
    """
    print(f"🔄 Starting sliding window analysis...")
    print(f"   Window size: {window_size} lines")
    print(f"   Step size: {step_size} lines (overlap: {window_size - step_size} lines)")
    print(f"   Delay between windows: {delay_seconds} seconds")
    
    # Get total number of lines in the log file
    total_lines = get_total_log_lines(log_file_path)
    if total_lines is None:
        print("❌ Failed to get total line count")
        return []
    
    print(f"   Total lines in log: {total_lines}")
    
    all_results = []
    current_start = 1
    window_count = 0
    
    while current_start <= total_lines:
        window_count += 1
        
        # Check if we've reached the maximum number of windows
        if max_windows and window_count > max_windows:
            print(f"🛑 Reached maximum window limit ({max_windows})")
            break
        
        # Calculate actual window end (don't go beyond total lines)
        actual_window_size = min(window_size, total_lines - current_start + 1)
        window_end = current_start + actual_window_size - 1
        
        window_info = f"lines {current_start}-{window_end}"
        print(f"\n📊 Processing window {window_count}: {window_info}")
        
        # Get log content for this window
        log_content = get_log_window(log_file_path, current_start, actual_window_size)
        
        if not log_content or not log_content.strip():
            print(f"⚠️  Window {window_count} is empty, skipping...")
            current_start += step_size
            continue
        
        print(f"   Read {len(log_content.splitlines())} lines from window")
        
        # Analyze this window with AI
        ai_response = analyze_logs_with_ai(client, log_content, window_info)
        
        if ai_response:
            # Parse the YAML response
            parsed_analysis = extract_and_parse_yaml(ai_response)
            if parsed_analysis:
                # Add window metadata
                parsed_analysis["window_info"] = window_info
                parsed_analysis["window_number"] = window_count
                parsed_analysis["timestamp"] = datetime.now().isoformat()
                all_results.append(parsed_analysis)
                
                # Show brief summary of this window's findings
                issue_count = len(parsed_analysis.get("issues", []))
                print(f"   ✅ Found {issue_count} issues in window {window_count}")
            else:
                print(f"   ❌ Failed to parse response for window {window_count}")
        else:
            print(f"   ❌ AI analysis failed for window {window_count}")
        
        # Move to next window
        current_start += step_size
        
        # Add delay to avoid rate limiting (except for the last window)
        if current_start <= total_lines and delay_seconds > 0:
            print(f"   ⏳ Waiting {delay_seconds} seconds before next window...")
            time.sleep(delay_seconds)
    
    print(f"\n🎯 Sliding window analysis complete!")
    print(f"   Processed {len(all_results)} windows successfully")
    
    return all_results


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


def format_sliding_window_output(all_results, merged_results):
    """Format the sliding window analysis results into a readable output."""
    if not all_results:
        return "No sliding window analysis results available"

    output = []
    
    # Summary section
    output.append("🔄 SLIDING WINDOW ANALYSIS SUMMARY")
    output.append("=" * 70)
    output.append(f"Total windows processed: {len(all_results)}")
    
    # Count total issues found across all windows
    total_issues = sum(len(result.get("issues", [])) for result in all_results)
    merged_issues_count = len(merged_results.get("issues", []))
    
    output.append(f"Total raw issues found: {total_issues}")
    output.append(f"Unique issues after deduplication: {merged_issues_count}")
    
    # Window-by-window summary
    output.append("\n📊 WINDOW-BY-WINDOW SUMMARY")
    output.append("-" * 70)
    
    for result in all_results:
        window_info = result.get("window_info", "Unknown")
        window_num = result.get("window_number", "?")
        issue_count = len(result.get("issues", []))
        timestamp = result.get("timestamp", "Unknown")
        
        output.append(f"Window {window_num} ({window_info}): {issue_count} issues found at {timestamp}")
        
        # Show brief issue summaries for this window
        for issue in result.get("issues", []):
            node = issue.get("node_name", "Unknown")
            severity = issue.get("severity", "N/A")
            summary = issue.get("summary", "No summary")[:50] + "..." if len(issue.get("summary", "")) > 50 else issue.get("summary", "No summary")
            output.append(f"  • [{severity}] {node}: {summary}")
    
    # Merged/deduplicated results
    if merged_results and merged_results.get("issues"):
        output.append(f"\n🎯 FINAL DEDUPLICATED ISSUES ({merged_issues_count} unique)")
        output.append("=" * 70)
        
        for i, issue in enumerate(merged_results["issues"], 1):
            output.append(f"\n[{i}] Node: {issue.get('node_name', 'Unknown')}")
            output.append(f"    Severity: {issue.get('severity', 'N/A')}")
            output.append(f"    Category: {issue.get('category', 'N/A')}")
            output.append(f"    Summary: {issue.get('summary', 'No summary')}")
            output.append(f"    First detected in: {issue.get('first_detected_window', 'Unknown window')}")
            
            if issue.get("log_entries"):
                output.append("    Sample Log Entries:")
                for line in issue["log_entries"].strip().split("\n")[:3]:  # Limit to 3 lines as sample
                    output.append(f"      {line}")
                if len(issue["log_entries"].strip().split("\n")) > 3:
                    output.append("      ...")

            if issue.get("analysis"):
                output.append(f"    Analysis: {issue['analysis']}")

            if issue.get("recommended_action"):
                output.append(f"    Recommended Action: {issue['recommended_action']}")

            output.append("-" * 60)
    else:
        output.append("\n✅ No issues detected across all windows")

    return "\n".join(output)


def main():
    # Load environment variables from .env file
    load_dotenv()

    # Get configuration from environment variables
    api_url = os.getenv("OPENAI_API_URL")
    api_key = os.getenv("OPENAI_API_KEY", "dummy-key")
    log_file_path = os.getenv("LOG_FILE_PATH")
    
    # Sliding window configuration (can be added to .env file)
    window_size = int(os.getenv("WINDOW_SIZE", "100"))  # lines per window
    step_size = int(os.getenv("STEP_SIZE", "90"))       # overlap = window_size - step_size
    max_windows = os.getenv("MAX_WINDOWS")              # None = process all
    delay_seconds = float(os.getenv("DELAY_SECONDS", "2"))  # delay between API calls
    
    if max_windows:
        max_windows = int(max_windows)

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

    print(f"🚀 Sliding Window Log Analyzer Starting...")
    print(f"API URL: {api_url}")
    print(f"Log file: {log_file_path}")
    print(f"Window configuration:")
    print(f"  - Window size: {window_size} lines")
    print(f"  - Step size: {step_size} lines (overlap: {window_size - step_size} lines)")
    print(f"  - Max windows: {max_windows if max_windows else 'No limit'}")
    print(f"  - Delay between calls: {delay_seconds} seconds")
    print("-" * 70)

    # Initialize OpenAI client
    client = OpenAI(base_url=api_url, api_key=api_key)

    # Test API connection first
    try:
        print("🔍 Testing API connection...")
        test_response = client.chat.completions.create(
            model="Qwen3-32B",
            messages=[
                {"role": "user", "content": "Hello, are you ready to analyze logs?"}
            ],
            max_tokens=50,
        )
        print("✅ API connection successful")
    except Exception as e:
        print(f"❌ API connection failed: {e}")
        return

    # Perform sliding window analysis
    print(f"\n🔄 Starting sliding window analysis on {log_file_path}...")
    all_results = sliding_window_analysis(
        client=client,
        log_file_path=log_file_path,
        window_size=window_size,
        step_size=step_size,
        max_windows=max_windows,
        delay_seconds=delay_seconds
    )

    if not all_results:
        print("❌ No results from sliding window analysis")
        return

    # Merge and deduplicate results from all windows
    print(f"\n🔧 Merging and deduplicating results from {len(all_results)} windows...")
    merged_results = merge_window_results(all_results)
    unique_issues_count = len(merged_results.get("issues", []))
    print(f"✅ Found {unique_issues_count} unique issues after deduplication")

    # Format and display the results
    formatted_output = format_sliding_window_output(all_results, merged_results)
    
    print("\n" + "=" * 80)
    print("📊 SLIDING WINDOW LOG ANALYSIS RESULTS")
    print("=" * 80)
    print(formatted_output)
    print("=" * 80)
    
    # Save results to file with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"output/sliding_window_analysis_{timestamp}.yaml"
    
    # Create output directory if it doesn't exist
    os.makedirs("output", exist_ok=True)
    
    try:
        # Save comprehensive results
        save_data = {
            "analysis_summary": {
                "timestamp": timestamp,
                "log_file": log_file_path,
                "total_windows": len(all_results),
                "window_size": window_size,
                "step_size": step_size,
                "total_raw_issues": sum(len(result.get("issues", [])) for result in all_results),
                "unique_issues_after_dedup": unique_issues_count
            },
            "window_results": all_results,
            "merged_results": merged_results,
            "grouped_results": group_similar_issues(merged_results)
        }
        
        with open(output_file, "w") as f:
            yaml.dump(save_data, f, default_flow_style=False, indent=2)
        print(f"\n💾 Comprehensive analysis saved to: {output_file}")
        
        # Also save a simplified summary file
        summary_file = f"output/summary_{timestamp}.yaml"
        with open(summary_file, "w") as f:
            yaml.dump({
                "summary": save_data["analysis_summary"],
                "unique_issues": merged_results.get("issues", [])
            }, f, default_flow_style=False, indent=2)
        print(f"💾 Summary saved to: {summary_file}")
        
    except Exception as e:
        print(f"⚠️  Warning: Could not save analysis to file: {e}")

    print(f"\n🎉 Sliding window analysis complete!")
    print(f"   Processed {len(all_results)} windows")
    print(f"   Found {unique_issues_count} unique issues")


if __name__ == "__main__":
    main()
