"""
Pipeline runner that integrates with the orchestrator.
"""

import sys
import os
from pathlib import Path
from typing import Dict, Any

# Add parent directory to path to import orchestrator
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from orchestrator.orchestrator import IncidentOrchestrator


def run_investigation(temp_json_path: str) -> Dict[str, Any]:
    """
    Calls the orchestrator and returns the structured output.
    
    Args:
        temp_json_path: Path to the temporary GuardDuty finding JSON file
        
    Returns:
        Dictionary containing:
        {
            "forensics": {...},
            "threat": {...},
            "mitre": {...},
            "remediation": {...},
            "final_report": {...}
        }
    """
    try:
        # Initialize orchestrator
        # Note: The orchestrator doesn't require OpenAI for basic operation
        orchestrator = IncidentOrchestrator(use_openai=False, openai_key=None)
        
        # Process the incident
        report = orchestrator.process_incident(temp_json_path)
        
        # Extract agent outputs from the analysis trace
        analysis_trace = report.get("analysis_trace", {})
        agents = analysis_trace.get("agents", [])
        
        # Extract individual agent outputs
        forensics_result = {}
        threat_result = {}
        mitre_result = {}
        remediation_result = {}
        
        for agent_data in agents:
            agent_name = agent_data.get("agent", "")
            agent_output = agent_data.get("output", {})
            
            if agent_name == "LogForensicsAgent":
                forensics_result = agent_output
            elif agent_name == "ThreatAttributionAgent":
                threat_result = agent_output
            elif agent_name == "KnowledgeRetrievalAgent":
                mitre_result = agent_output
            elif agent_name == "RemediationAgent":
                remediation_result = agent_output
        
        # Return structured output
        return {
            "forensics": forensics_result,
            "threat": threat_result,
            "mitre": mitre_result,
            "remediation": remediation_result,
            "final_report": report
        }
        
    except Exception as e:
        # Re-raise with context
        raise RuntimeError(f"Error running investigation: {str(e)}") from e

