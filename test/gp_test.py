import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

import yaml
from main import group_similar_issues

def test_group_similar_issues():
    """Test the grouping functionality with mock data"""
    # Sample data simulating parsed YAML from AI response
    mock_issues = {
        "issues": [
            {
                "node_name": "node001",
                "severity": "HIGH",
                "category": "system",
                "summary": "High CPU usage",
                "log_entries": "node001: Jul 29 10:15:32 kernel: CPU usage at 95%",
                "analysis": "System under heavy load",
                "recommended_action": "Check for runaway processes"
            },
            {
                "node_name": "node002",
                "severity": "HIGH", 
                "category": "system",
                "summary": "High CPU usage",
                "log_entries": "node002: Jul 29 10:16:12 kernel: CPU usage at 97%",
                "analysis": "System under heavy load",
                "recommended_action": "Check for runaway processes"
            },
            {
                "node_name": "node003",
                "severity": "MEDIUM",
                "category": "network",
                "summary": "Network connectivity issues",
                "log_entries": "node003: Jul 29 10:17:22 network[123]: Connection timeout",
                "analysis": "Network unreliable",
                "recommended_action": "Check network configuration"
            }
        ]
    }
    
    # Group the issues
    grouped_result = group_similar_issues(mock_issues)
    
    # Print the result
    print("\n=== Grouped Issues ===")
    print(yaml.dump(grouped_result, default_flow_style=False, indent=2))
    
    # Verify grouping worked correctly
    assert len(grouped_result["grouped_issues"]) == 2, "Should have 2 grouped issues"
    
    # Find the CPU usage issue group
    cpu_issue = None
    for issue in grouped_result["grouped_issues"]:
        if "CPU usage" in issue["summary"]:
            cpu_issue = issue
            break
    
    # Verify the CPU usage issue has 2 affected nodes
    assert cpu_issue is not None, "CPU usage issue not found"
    assert len(cpu_issue["affected_nodes"]) == 2, "CPU issue should affect 2 nodes"
    assert "node001" in cpu_issue["affected_nodes"], "node001 should be affected"
    assert "node002" in cpu_issue["affected_nodes"], "node002 should be affected"
    
    print("✅ All tests passed!")

if __name__ == "__main__":
    test_group_similar_issues()