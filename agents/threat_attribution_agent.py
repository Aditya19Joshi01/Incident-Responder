"""
Threat Attribution Agent - Maps suspicious activity to MITRE ATT&CK techniques.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ThreatAttributionAgent:
    """Agent responsible for identifying threat techniques and MITRE mapping."""
    
    def __init__(self):
        """Initialize the Threat Attribution Agent."""
        pass
    
    def analyze(self, forensics_summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze forensics data and attribute to MITRE techniques.
        
        Args:
            forensics_summary: Output from Log Forensics Agent
            
        Returns:
            Dictionary containing threat classification and MITRE mapping
        """
        logger.info("Starting threat attribution analysis...")
        
        alert_type = forensics_summary.get("alert_type", "Unknown")
        activity = forensics_summary.get("suspicious_activity", {})
        indicators = forensics_summary.get("key_indicators", [])
        
        # Analyze and classify threat
        classification = self._classify_threat(alert_type, activity, indicators)
        
        # Map to initial MITRE techniques
        mitre_techniques = self._map_to_mitre(alert_type, activity, indicators)
        
        # Generate reasoning
        reasoning = self._generate_reasoning(alert_type, classification, mitre_techniques, indicators)
        
        result = {
            "threat_classification": classification,
            "mitre_technique_guess": mitre_techniques[0] if mitre_techniques else None,
            "mitre_technique_candidates": mitre_techniques,
            "reasoning": reasoning,
            "confidence": self._calculate_confidence(indicators, mitre_techniques)
        }
        
        logger.info(f"Threat attribution complete. Primary technique: {result['mitre_technique_guess']}")
        return result
    
    def _classify_threat(self, alert_type: str, activity: Dict[str, Any], indicators: List[str]) -> Dict[str, Any]:
        """Classify the type of threat."""
        classification = {
            "category": "Unknown",
            "subcategory": "",
            "description": ""
        }
        
        alert_lower = alert_type.lower()
        
        # EC2-related threats
        if "ec2" in alert_lower or "instance" in alert_lower:
            if "port" in alert_lower or "scan" in alert_lower:
                classification = {
                    "category": "Reconnaissance",
                    "subcategory": "Network Scanning",
                    "description": "EC2 instance performing network scanning or port probing"
                }
            elif "outbound" in alert_lower or "traffic" in alert_lower:
                classification = {
                    "category": "Command and Control",
                    "subcategory": "C2 Communication",
                    "description": "Suspicious outbound network traffic from EC2 instance"
                }
            elif "crypto" in alert_lower or "mining" in alert_lower:
                classification = {
                    "category": "Impact",
                    "subcategory": "Resource Hijacking",
                    "description": "Cryptocurrency mining activity detected"
                }
        
        # IAM-related threats
        elif "iam" in alert_lower or "access" in alert_lower or "key" in alert_lower:
            if "anomalous" in alert_lower or "unusual" in alert_lower:
                classification = {
                    "category": "Credential Access",
                    "subcategory": "Compromised Credentials",
                    "description": "Anomalous IAM user activity detected"
                }
            elif "policy" in alert_lower:
                classification = {
                    "category": "Persistence",
                    "subcategory": "Modify Cloud Account",
                    "description": "Suspicious IAM policy modification"
                }
        
        # S3-related threats
        elif "s3" in alert_lower or "bucket" in alert_lower:
            classification = {
                "category": "Exfiltration",
                "subcategory": "Data Exfiltration",
                "description": "Suspicious S3 bucket access or data exfiltration"
            }
        
        # RDS-related threats
        elif "rds" in alert_lower or "database" in alert_lower:
            if "brute" in alert_lower or "force" in alert_lower:
                classification = {
                    "category": "Credential Access",
                    "subcategory": "Brute Force",
                    "description": "Brute force attack against RDS database"
                }
        
        return classification
    
    def _map_to_mitre(self, alert_type: str, activity: Dict[str, Any], indicators: List[str]) -> List[str]:
        """Map threat to MITRE ATT&CK technique IDs."""
        techniques = []
        alert_lower = alert_type.lower()
        indicators_str = " ".join(indicators).lower()
        
        # Network scanning
        if "scan" in alert_lower or "port" in alert_lower or "scanning" in indicators_str:
            techniques.append("T1595")  # Active Scanning
            techniques.append("T1046")  # Network Service Scanning
        
        # Outbound C2
        if "outbound" in alert_lower or "c2" in indicators_str or "command" in indicators_str:
            techniques.append("T1071")  # Application Layer Protocol
            techniques.append("T1105")  # Ingress Tool Transfer
        
        # Credential access
        if "iam" in alert_lower or "access" in alert_lower or "credential" in indicators_str:
            techniques.append("T1078")  # Valid Accounts
            techniques.append("T1081")  # Credentials in Files
        
        # Brute force
        if "brute" in alert_lower or "force" in alert_lower:
            techniques.append("T1110")  # Brute Force
        
        # Data exfiltration
        if "s3" in alert_lower or "exfiltrat" in indicators_str:
            techniques.append("T1537")  # Transfer Data to Cloud Account
            techniques.append("T1041")  # Exfiltration Over C2 Channel
        
        # Persistence
        if "policy" in alert_lower or "modify" in indicators_str:
            techniques.append("T1078.004")  # Cloud Accounts
            techniques.append("T1484")  # Domain Policy Modification
        
        # Resource hijacking
        if "crypto" in alert_lower or "mining" in alert_lower:
            techniques.append("T1496")  # Resource Hijacking
        
        # Default if nothing matches
        if not techniques:
            techniques.append("T1078")  # Valid Accounts (common fallback)
        
        return techniques[:5]  # Return top 5 candidates
    
    def _generate_reasoning(self, alert_type: str, classification: Dict[str, Any], 
                          techniques: List[str], indicators: List[str]) -> str:
        """Generate human-readable reasoning for the attribution."""
        reasoning_parts = [
            f"Alert Type: {alert_type}",
            f"Threat Category: {classification.get('category', 'Unknown')}",
            f"Subcategory: {classification.get('subcategory', 'Unknown')}"
        ]
        
        if techniques:
            reasoning_parts.append(f"Primary MITRE Technique: {techniques[0]}")
            if len(techniques) > 1:
                reasoning_parts.append(f"Additional candidates: {', '.join(techniques[1:])}")
        
        if indicators:
            reasoning_parts.append("Key Indicators:")
            for indicator in indicators[:3]:
                reasoning_parts.append(f"  - {indicator}")
        
        return "\n".join(reasoning_parts)
    
    def _calculate_confidence(self, indicators: List[str], techniques: List[str]) -> float:
        """Calculate confidence score (0.0 to 1.0)."""
        confidence = 0.5  # Base confidence
        
        # More indicators = higher confidence
        confidence += min(len(indicators) * 0.1, 0.3)
        
        # Multiple technique matches = higher confidence
        if len(techniques) > 1:
            confidence += 0.1
        
        # Cap at 1.0
        return min(confidence, 1.0)

