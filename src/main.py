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
            model="Qwen-32B",
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

    content = ai_response
    if "</think>" in content:
        parts = content.split("</think>", 1)
        if len(parts) > 1:
            content = parts[1].strip()

    if "```yaml" in content:
        yaml_start = content.find("```yaml") + 7
        yaml_end = content.find("```", yaml_start)
        if yaml_end != -1:
            content = content[yaml_start:yaml_end].strip()
    elif "```" in content:
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
        return yaml.safe_load(content)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return {"raw_response": content}


def merge_window_results(all_results):
    """Merge issues from multiple windows, deduplicating similar issues."""
    if not all_results:
        return {"issues": []}
    
    all_issues = []
    seen_issues = set()
    
    for window_result in all_results:
        if window_result and "issues" in window_result:
            for issue in window_result["issues"]:
                dedup_key = (
                    issue.get("node_name", "unknown"),
                    issue.get("category", "unknown"),
                    issue.get("summary", "unknown")[:50]
                )
                
                if dedup_key not in seen_issues:
                    seen_issues.add(dedup_key)
                    issue["first_detected_window"] = window_result.get("window_info", "unknown")
                    all_issues.append(issue)
    
    return {"issues": all_issues}


def create_issue_labels(issues):
    """Create concise labels for each issue to be used for AI grouping."""
    issue_labels = []
    for i, issue in enumerate(issues, 1):
        label = f"Issue {i}: [{issue.get('category', 'unknown')}] {issue.get('summary', 'unknown')[:100]}"
        issue_labels.append((i, label, issue))
    return issue_labels


def group_issues_with_ai(client, issue_labels):
    """Use AI to group similar issues based on their labels."""
    if not issue_labels:
        return {}
    
    labels_text = "\n".join([f"{idx}: {label}" for idx, label, _ in issue_labels])
    
    prompt = f"""You are a system log analyzer. Group similar issues based on semantic similarity:

{labels_text}

Respond with a YAML structure:
```yaml
groups:
  - name: "Network connectivity failures"
    issues: [1, 3, 5]
  - name: "Disk space warnings" 
    issues: [2, 4]
```

Respond ONLY with the YAML structure, no additional text."""

    try:
        response = client.chat.completions.create(
            model="Qwen-32B",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2048,
            temperature=0.1,
        )
        
        content = response.choices[0].message.content
        if "```yaml" in content:
            yaml_start = content.find("```yaml") + 7
            yaml_end = content.find("```", yaml_start)
            if yaml_end != -1:
                content = content[yaml_start:yaml_end].strip()
        elif "```" in content:
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
        
        parsed_yaml = yaml.safe_load(content)
        grouped_issues = {}
        
        if "groups" in parsed_yaml:
            for group in parsed_yaml["groups"]:
                group_name = group.get("name", "Unnamed Group")
                issue_indices = group.get("issues", [])
                grouped_issues[group_name] = issue_indices
            return grouped_issues
        else:
            print("Warning: AI response didn't contain expected 'groups' key")
            return {}
            
    except Exception as e:
        print(f"Error calling AI for grouping: {e}")
        return {}


def format_final_output(merged_results, ai_groups):
    """Format the final grouped analysis output."""
    if not merged_results or "issues" not in merged_results or not merged_results["issues"]:
        return "No issues found in the log analysis."
        
    if not ai_groups:
        return "No AI grouping results available."
    
    issues = merged_results.get("issues", [])
    
    output = []
    output.append("🧠 AI-GROUPED LOG ANALYSIS RESULTS")
    output.append("=" * 80)
    output.append(f"Total unique issues found: {len(issues)}")
    output.append(f"Issues grouped into {len(ai_groups)} categories")
    output.append("")
    
    for i, (group_name, issue_indices) in enumerate(ai_groups.items(), 1):
        output.append(f"[GROUP {i}] {group_name}")
        output.append(f"Issues: {', '.join(map(str, issue_indices))} | Total: {len(issue_indices)}")
        
        # List affected nodes
        all_nodes = set()
        for idx in issue_indices:
            array_idx = idx - 1
            if 0 <= array_idx < len(issues):
                issue = issues[array_idx]
                all_nodes.add(issue.get("node_name", "Unknown"))
        
        output.append(f"Affected Nodes ({len(all_nodes)}): {', '.join(sorted(all_nodes))}")
        
        # Show details for each issue in the group
        for idx in issue_indices:
            array_idx = idx - 1
            if 0 <= array_idx < len(issues):
                issue = issues[array_idx]
                output.append(f"")
                output.append(f"  Issue {idx}: {issue.get('node_name', 'Unknown')} | {issue.get('severity', 'N/A')} | {issue.get('category', 'N/A')}")
                output.append(f"  Summary: {issue.get('summary', 'No summary')}")
                output.append(f"  Analysis: {issue.get('analysis', 'No analysis')}")
                output.append(f"  Action: {issue.get('recommended_action', 'No action specified')}")
                output.append(f"  First seen: {issue.get('first_detected_window', 'Unknown')}")
                
                if issue.get("log_entries"):
                    output.append("  Sample logs:")
                    for line in issue["log_entries"].strip().split("\n")[:2]:
                        output.append(f"    {line}")
                    if len(issue["log_entries"].strip().split("\n")) > 2:
                        output.append("    ...")
        
        output.append("-" * 80)
    
    return "\n".join(output)

def sliding_window_analysis(client, log_file_path, window_size=100, step_size=90, max_windows=None, delay_seconds=2, start_line=1):
    """Perform sliding window analysis on log file."""
    print(f"🔄 Starting sliding window analysis...")
    print(f"   Window size: {window_size} lines")
    print(f"   Step size: {step_size} lines (overlap: {window_size - step_size} lines)")
    print(f"   Starting from line: {start_line}")
    
    total_lines = get_total_log_lines(log_file_path)
    if total_lines is None:
        print("❌ Failed to get total line count")
        return []
    
    print(f"   Total lines in log: {total_lines}")
    
    if start_line > total_lines:
        print(f"❌ START_LINE ({start_line}) is greater than total lines ({total_lines})")
        return []
    
    all_results = []
    current_start = start_line
    window_count = 0
    
    while current_start <= total_lines:
        window_count += 1
        
        if max_windows and window_count > max_windows:
            print(f"🛑 Reached maximum window limit ({max_windows})")
            break
        
        actual_window_size = min(window_size, total_lines - current_start + 1)
        window_end = current_start + actual_window_size - 1
        window_info = f"lines {current_start}-{window_end}"
        
        print(f"\n📊 Processing window {window_count}: {window_info}")
        
        log_content = get_log_window(log_file_path, current_start, actual_window_size)
        
        if not log_content or not log_content.strip():
            print(f"⚠️  Window {window_count} is empty, skipping...")
            current_start += step_size
            continue
        
        print(f"   Read {len(log_content.splitlines())} lines from window")
        
        ai_response = analyze_logs_with_ai(client, log_content, window_info)
        
        if ai_response:
            parsed_analysis = extract_and_parse_yaml(ai_response)
            if parsed_analysis:
                parsed_analysis["window_info"] = window_info
                parsed_analysis["window_number"] = window_count
                parsed_analysis["timestamp"] = datetime.now().isoformat()
                all_results.append(parsed_analysis)
                
                issue_count = len(parsed_analysis.get("issues", []))
                print(f"   ✅ Found {issue_count} issues in window {window_count}")
            else:
                print(f"   ❌ Failed to parse response for window {window_count}")
        else:
            print(f"   ❌ AI analysis failed for window {window_count}")
        
        current_start += step_size
        
        if current_start <= total_lines and delay_seconds > 0:
            print(f"   ⏳ Waiting {delay_seconds} seconds before next window...")
            time.sleep(delay_seconds)
    
    print(f"\n🎯 Sliding window analysis complete!")
    print(f"   Processed {len(all_results)} windows successfully")
    
    return all_results


def main():
    # Load environment variables from .env file
    load_dotenv()

    # Get configuration from environment variables
    api_url = os.getenv("OPENAI_API_URL")
    api_key = os.getenv("OPENAI_API_KEY", "dummy-key")
    log_file_path = os.getenv("LOG_FILE_PATH")
    
    # Sliding window configuration
    window_size = int(os.getenv("WINDOW_SIZE", "100"))
    step_size = int(os.getenv("STEP_SIZE", "90"))
    start_line = int(os.getenv("START_LINE", "1"))
    max_windows = os.getenv("MAX_WINDOWS")
    delay_seconds = float(os.getenv("DELAY_SECONDS", "2"))
    
    if max_windows:
        max_windows = int(max_windows)

    # Validate configuration
    if not api_url:
        print("Error: OPENAI_API_URL not found in .env file")
        return

    if not log_file_path:
        print("Error: LOG_FILE_PATH not found in .env file")
        return

    if not os.path.exists(log_file_path):
        print(f"Error: Log file does not exist: {log_file_path}")
        return

    print(f"🚀 Sliding Window Log Analyzer Starting...")
    print(f"API URL: {api_url}")
    print(f"Log file: {log_file_path}")
    print("-" * 70)

    # Initialize OpenAI client
    client = OpenAI(base_url=api_url, api_key=api_key)

    # Test API connection
    try:
        print("🔍 Testing API connection...")
        test_response = client.chat.completions.create(
            model="Qwen-32B",
            messages=[{"role": "user", "content": "Hello, are you ready to analyze logs?"}],
            max_tokens=50,
        )
        print("✅ API connection successful")
    except Exception as e:
        print(f"❌ API connection failed: {e}")
        return

    # STEP 1: Sliding window analysis
    print(f"\n🔄 Starting sliding window analysis on {log_file_path}...")
    all_results = sliding_window_analysis(
        client=client,
        log_file_path=log_file_path,
        window_size=window_size,
        step_size=step_size,
        max_windows=max_windows,
        delay_seconds=delay_seconds,
        start_line=start_line
    )

    if not all_results:
        print("❌ No results from sliding window analysis")
        return

    # STEP 2: Merge and deduplicate results
    print(f"\n🔧 Merging and deduplicating results from {len(all_results)} windows...")
    merged_results = merge_window_results(all_results)
    unique_issues_count = len(merged_results.get("issues", []))
    print(f"✅ Found {unique_issues_count} unique issues after deduplication")

    if unique_issues_count == 0:
        print("✅ No issues detected in the logs")
        return

    # STEP 3: Create issue labels for AI grouping
    print(f"\n🏷️  Creating issue labels for AI grouping...")
    issue_labels = create_issue_labels(merged_results.get("issues", []))
    print(f"✅ Created {len(issue_labels)} issue labels")

    # STEP 4: Group issues with AI
    print(f"🧠 Using AI to group similar issues...")
    ai_groups = group_issues_with_ai(client, issue_labels)
    print(f"✅ AI grouped issues into {len(ai_groups)} categories")

    # STEP 5: Format final output
    print(f"\n📋 Formatting final analysis output...")
    final_output = format_final_output(merged_results, ai_groups)

    # Display the results
    print("\n" + "=" * 80)
    print(final_output)
    print("=" * 80)
    
    # STEP 6: Save results to files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"output/log_analysis_{timestamp}.yaml"
    grouped_output_file = f"output/grouped_analysis_{timestamp}.log"
    
    os.makedirs("output", exist_ok=True)
    
    try:
        # Save comprehensive YAML analysis
        save_data = {
            "analysis_summary": {
                "timestamp": timestamp,
                "total_windows_processed": len(all_results),
                "unique_issues_found": unique_issues_count,
                "issue_groups": len(ai_groups),
                "log_file": log_file_path,
                "window_size": window_size,
                "step_size": step_size,
                "start_line": start_line
            },
            "grouped_results": {
                "groups": [
                    {"name": group_name, "issues": issue_indices}
                    for group_name, issue_indices in ai_groups.items()
                ]
            },
            "all_issues": merged_results.get("issues", []),
            "raw_window_results": all_results
        }
        
        with open(output_file, "w") as f:
            yaml.dump(save_data, f, default_flow_style=False, indent=2)
        print(f"\n💾 Complete analysis saved to: {output_file}")
        
        # Save grouped analysis as readable log file
        with open(grouped_output_file, "w") as f:
            f.write(final_output)
        print(f"💾 Grouped analysis saved to: {grouped_output_file}")
        
    except Exception as e:
        print(f"⚠️  Warning: Could not save analysis to file: {e}")

    print(f"\n🎉 Log analysis complete!")
    print(f"   Processed {len(all_results)} windows")
    print(f"   Found {unique_issues_count} unique issues")
    print(f"   Grouped into {len(ai_groups)} categories")


if __name__ == "__main__":
    main()
