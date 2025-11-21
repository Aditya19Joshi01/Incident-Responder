"""
Main Orchestrator - Coordinates multi-agent incident response workflow.
"""

import json
import sys
import os
import logging
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

# Add parent directory to path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from agents.log_forensics_agent import LogForensicsAgent
from agents.threat_attribution_agent import ThreatAttributionAgent
from agents.knowledge_retrieval_agent import KnowledgeRetrievalAgent
from agents.remediation_agent import RemediationAgent
from utils.db import IncidentDB
from utils.embedding import MITREEmbeddingStore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IncidentOrchestrator:
    """Orchestrates the multi-agent incident response workflow."""
    
    def __init__(self, use_openai: bool = False, openai_key: str = None):
        """
        Initialize the orchestrator.
        
        Args:
            use_openai: Whether to use OpenAI embeddings (requires API key)
            openai_key: OpenAI API key (optional, can use env var)
        """
        # Initialize embedding store
        self.embedding_store = MITREEmbeddingStore(use_openai=use_openai, api_key=openai_key)
        
        # Initialize agents
        self.forensics_agent = LogForensicsAgent()
        self.attribution_agent = ThreatAttributionAgent()
        self.knowledge_agent = KnowledgeRetrievalAgent(self.embedding_store)
        self.remediation_agent = RemediationAgent()
        
        # Initialize database (support custom path via env)
        db_path = os.getenv("INCIDENT_DB_PATH", "incident_reports.db")
        self.db = IncidentDB(db_path=db_path)

        # Create reports directory (customizable via env)
        self.reports_dir = os.getenv("REPORTS_DIR", "reports")
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def process_incident(self, guardduty_finding_path: str) -> Dict[str, Any]:
        """
        Process a GuardDuty finding through the complete workflow.
        
        Args:
            guardduty_finding_path: Path to GuardDuty JSON finding file
            
        Returns:
            Complete investigation report
        """
        logger.info(f"Processing incident from: {guardduty_finding_path}")
        
        # Load GuardDuty finding
        with open(guardduty_finding_path, 'r') as f:
            guardduty_finding = json.load(f)
        
        # Initialize trace
        trace = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "input_file": guardduty_finding_path,
            "agents": []
        }
        
        # Step 1: Log Forensics Agent
        logger.info("=== Step 1: Log Forensics Analysis ===")
        forensics_result = self.forensics_agent.analyze(guardduty_finding)
        trace["agents"].append({
            "agent": "LogForensicsAgent",
            "output": forensics_result
        })
        
        # Step 2: Threat Attribution Agent
        logger.info("=== Step 2: Threat Attribution ===")
        attribution_result = self.attribution_agent.analyze(forensics_result)
        trace["agents"].append({
            "agent": "ThreatAttributionAgent",
            "output": attribution_result
        })
        
        # Step 3: Knowledge Retrieval Agent
        logger.info("=== Step 3: MITRE Knowledge Retrieval ===")
        technique_guess = attribution_result.get("mitre_technique_guess", "")
        knowledge_result = self.knowledge_agent.retrieve(
            technique_guess,
            attribution_result
        )
        trace["agents"].append({
            "agent": "KnowledgeRetrievalAgent",
            "output": knowledge_result
        })
        
        # Step 4: Remediation Agent
        logger.info("=== Step 4: Remediation Planning ===")
        recommended_technique = knowledge_result.get("recommended_technique", {})
        remediation_result = self.remediation_agent.generate(
            attribution_result.get("threat_classification", {}),
            recommended_technique,
            forensics_result
        )
        trace["agents"].append({
            "agent": "RemediationAgent",
            "output": remediation_result
        })
        
        # Build final report
        report = self._build_report(
            guardduty_finding,
            forensics_result,
            attribution_result,
            knowledge_result,
            remediation_result,
            trace
        )
        
        # Save report
        self._save_report(report)
        
        logger.info("=== Incident Processing Complete ===")
        return report
    
    def _build_report(self, guardduty_finding: Dict[str, Any],
                     forensics: Dict[str, Any],
                     attribution: Dict[str, Any],
                     knowledge: Dict[str, Any],
                     remediation: Dict[str, Any],
                     trace: Dict[str, Any]) -> Dict[str, Any]:
        """Build the final investigation report."""
        recommended_technique = knowledge.get("recommended_technique", {})
        
        report = {
            "timestamp": trace["timestamp"],
            "alert": forensics.get("alert_type", "Unknown"),
            "severity": forensics.get("severity", 5.0),
            "parsed_details": {
                "resource": forensics.get("resource_details", {}),
                "metadata": forensics.get("metadata", {}),
                "key_indicators": forensics.get("key_indicators", [])
            },
            "threat_classification": attribution.get("threat_classification", {}),
            "mitre_mapping": {
                "primary_technique": recommended_technique.get("technique_id", "") if recommended_technique else "",
                "technique_name": recommended_technique.get("name", "") if recommended_technique else "",
                "technique_description": recommended_technique.get("description", "") if recommended_technique else "",
                "tactic": recommended_technique.get("tactic", "") if recommended_technique else "",
                "candidates": attribution.get("mitre_technique_candidates", [])
            },
            "reasoning_trace": attribution.get("reasoning", ""),
            "recommended_actions": remediation.get("remediation_steps", []),
            "remediation_priority": remediation.get("priority", "Medium"),
            "remediation_justification": remediation.get("justification", ""),
            "confidence": attribution.get("confidence", 0.5),
            "analysis_trace": trace,
            "raw_finding": guardduty_finding
        }
        
        return report
    
    def _save_report(self, report: Dict[str, Any]):
        """Save report to JSON file and database."""
        # Save to JSON file
        timestamp_str = report["timestamp"].replace(":", "-").replace(".", "-")
        filename = os.path.join(self.reports_dir, f"{timestamp_str}_report.json")

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to: {filename}")
        
        # Save to database
        report_id = self.db.save_report(report)
        logger.info(f"Report saved to database with ID: {report_id}")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py <path_to_guardduty_finding.json>")
        print("Example: python orchestrator.py data/sample_guardduty_1.json")
        sys.exit(1)
    
    finding_path = sys.argv[1]
    
    if not os.path.exists(finding_path):
        logger.error(f"File not found: {finding_path}")
        sys.exit(1)
    
    # Check for OpenAI key (optional)
    use_openai = os.getenv("OPENAI_API_KEY") is not None
    openai_key = os.getenv("OPENAI_API_KEY")
    
    if use_openai:
        logger.info("OpenAI API key detected. Using OpenAI embeddings.")
    else:
        logger.info("No OpenAI API key found. Using fallback embeddings.")
    
    # Initialize and run orchestrator
    orchestrator = IncidentOrchestrator(use_openai=use_openai, openai_key=openai_key)
    
    try:
        report = orchestrator.process_incident(finding_path)
        
        # Print summary
        print("\n" + "="*60)
        print("INCIDENT INVESTIGATION REPORT SUMMARY")
        print("="*60)
        print(f"Alert: {report['alert']}")
        print(f"Severity: {report['severity']}")
        print(f"MITRE Technique: {report['mitre_mapping']['primary_technique']} - {report['mitre_mapping']['technique_name']}")
        print(f"Threat Category: {report['threat_classification'].get('category', 'Unknown')}")
        print(f"Confidence: {report['confidence']:.2%}")
        print(f"Remediation Priority: {report['remediation_priority']}")
        print(f"Remediation Steps: {len(report['recommended_actions'])}")
        print("="*60)
        saved_path = os.path.join(
            orchestrator.reports_dir,
            f"{report['timestamp'].replace(':', '-').replace('.', '-')}_report.json",
        )
        print(f"\nFull report saved to: {saved_path}")
        
    except Exception as e:
        logger.error(f"Error processing incident: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

