"""
Quick start script to run an example incident analysis.
This is a convenience script for testing the system.
"""

import sys
import os

# Ensure we're in the right directory
if __name__ == "__main__":
    # Run the orchestrator with a sample finding
    sample_file = "data/sample_guardduty_1.json"
    
    if not os.path.exists(sample_file):
        print(f"Error: Sample file not found: {sample_file}")
        print("Please ensure you're running from the project root directory.")
        sys.exit(1)
    
    # Import and run orchestrator
    from orchestrator.orchestrator import main
    
    # Set up sys.argv for the orchestrator
    sys.argv = ["orchestrator.py", sample_file]
    
    print("="*60)
    print("IncidentResponder.AI - Example Run")
    print("="*60)
    print(f"Processing: {sample_file}")
    print("="*60)
    print()
    
    main()

