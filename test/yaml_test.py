import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

import yaml
from main import extract_and_parse_yaml, group_similar_issues, format_analysis_output

def test_with_mock_data():
    """Test the full flow with mock data"""
    # Load mock YAML data
    mock_file = os.path.join(os.path.dirname(__file__), 'mock_data', 'sample.yaml')
    
    with open(mock_file, 'r') as f:
        mock_yaml = f.read()
    
    # Prepare the mock response as if it came from the AI
    mock_response = f"```yaml\n{mock_yaml}\n```"
    
    # Process the mock response
    print("Extracting and parsing YAML from mock response...")
    parsed_yaml = extract_and_parse_yaml(mock_response)
    
    # Group similar issues
    print("Grouping similar issues...")
    grouped_data = group_similar_issues(parsed_yaml)
    
    # Format the output
    print("Formatting analysis output...")
    formatted_output = format_analysis_output(parsed_yaml)
    
    # Print the results
    print("\n" + "=" * 70)
    print("📊 TEST RESULTS - FORMATTED OUTPUT")
    print("=" * 70)
    print(formatted_output)
    print("=" * 70)
    
    # Save the results
    output_dir = os.path.join(os.path.dirname(__file__), 'output')
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'test_output.yaml')
    
    with open(output_file, 'w') as f:
        yaml.dump({
            "original": parsed_yaml,
            "grouped": grouped_data
        }, f, default_flow_style=False, indent=2)
    
    print(f"\n💾 Test results saved to: {output_file}")

if __name__ == "__main__":
    test_with_mock_data()