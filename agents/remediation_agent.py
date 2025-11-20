"""
Remediation Agent - Generates AWS remediation recommendations.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class RemediationAgent:
    """Agent responsible for generating remediation steps."""
    
    def __init__(self):
        """Initialize the Remediation Agent."""
        pass
    
    def generate(self, threat_classification: Dict[str, Any], 
                 mitre_technique: Dict[str, Any],
                 forensics_summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate remediation recommendations.
        
        Args:
            threat_classification: Output from Threat Attribution Agent
            mitre_technique: MITRE technique details from Knowledge Retrieval Agent
            forensics_summary: Original forensics summary
            
        Returns:
            Dictionary containing remediation steps and justification
        """
        logger.info("Generating remediation recommendations...")
        
        resource_type = forensics_summary.get("resource_details", {}).get("type", "Unknown")
        alert_type = forensics_summary.get("alert_type", "Unknown")
        technique_id = mitre_technique.get("technique_id", "") if mitre_technique else ""
        
        # Generate remediation steps
        steps = self._generate_steps(resource_type, alert_type, technique_id, forensics_summary)
        
        # Generate justification
        justification = self._generate_justification(steps, threat_classification, mitre_technique)
        
        result = {
            "remediation_steps": steps,
            "justification": justification,
            "priority": self._calculate_priority(threat_classification, forensics_summary),
            "estimated_time": self._estimate_time(steps)
        }
        
        logger.info(f"Generated {len(steps)} remediation steps")
        return result
    
    def _generate_steps(self, resource_type: str, alert_type: str, 
                       technique_id: str, forensics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate specific remediation steps."""
        steps = []
        
        # Immediate containment steps
        if resource_type == "EC2":
            steps.append({
                "step": 1,
                "action": "Isolate EC2 Instance",
                "description": "Place the affected EC2 instance in a security group that blocks all outbound traffic except to necessary services",
                "aws_command": "aws ec2 modify-instance-attribute --instance-id <instance-id> --groups <isolated-sg-id>",
                "category": "Containment"
            })
            
            steps.append({
                "step": 2,
                "action": "Create Snapshot for Forensics",
                "description": "Create an EBS snapshot of the instance for forensic analysis",
                "aws_command": "aws ec2 create-snapshot --volume-id <volume-id> --description 'Forensics snapshot'",
                "category": "Forensics"
            })
        
        elif resource_type == "IAM":
            steps.append({
                "step": 1,
                "action": "Revoke Compromised Access Keys",
                "description": "Immediately deactivate and delete the compromised IAM access keys",
                "aws_command": "aws iam update-access-key --access-key-id <key-id> --status Inactive && aws iam delete-access-key --access-key-id <key-id>",
                "category": "Containment"
            })
            
            steps.append({
                "step": 2,
                "action": "Review IAM User Permissions",
                "description": "Audit and reduce IAM user permissions to minimum required (principle of least privilege)",
                "aws_command": "aws iam list-user-policies --user-name <username>",
                "category": "Hardening"
            })
        
        elif resource_type == "S3":
            steps.append({
                "step": 1,
                "action": "Enable S3 Bucket Versioning and MFA Delete",
                "description": "Enable versioning and require MFA for delete operations",
                "aws_command": "aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled,MFADelete=Enabled",
                "category": "Hardening"
            })
            
            steps.append({
                "step": 2,
                "action": "Review and Restrict Bucket Policies",
                "description": "Audit S3 bucket policies and restrict public access",
                "aws_command": "aws s3api get-bucket-policy --bucket <bucket-name>",
                "category": "Hardening"
            })
        
        # Network security steps
        if "network" in alert_type.lower() or "scan" in alert_type.lower():
            steps.append({
                "step": len(steps) + 1,
                "action": "Review Security Group Rules",
                "description": "Audit security group rules and remove unnecessary open ports",
                "aws_command": "aws ec2 describe-security-groups --group-ids <sg-id>",
                "category": "Hardening"
            })
        
        # Credential security steps
        if "credential" in alert_type.lower() or "brute" in alert_type.lower():
            steps.append({
                "step": len(steps) + 1,
                "action": "Enable MFA for All IAM Users",
                "description": "Require multi-factor authentication for all IAM users",
                "aws_command": "aws iam enable-mfa-device --user-name <username> --serial-number <mfa-serial> --authentication-code-1 <code1> --authentication-code-2 <code2>",
                "category": "Hardening"
            })
            
            steps.append({
                "step": len(steps) + 1,
                "action": "Rotate All Access Keys",
                "description": "Rotate access keys for the affected IAM user",
                "aws_command": "aws iam create-access-key --user-name <username>",
                "category": "Remediation"
            })
        
        # Logging and monitoring steps
        steps.append({
            "step": len(steps) + 1,
            "action": "Enable Enhanced CloudTrail Logging",
            "description": "Ensure CloudTrail is enabled for all regions and log file validation is turned on",
            "aws_command": "aws cloudtrail create-trail --name <trail-name> --s3-bucket-name <bucket-name> --is-multi-region-trail",
            "category": "Monitoring"
        })
        
        steps.append({
            "step": len(steps) + 1,
            "action": "Enable VPC Flow Logs",
            "description": "Enable VPC Flow Logs for all VPCs to monitor network traffic",
            "aws_command": "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type s3 --log-destination <s3-arn>",
            "category": "Monitoring"
        })
        
        steps.append({
            "step": len(steps) + 1,
            "action": "Review GuardDuty Findings",
            "description": "Review all GuardDuty findings for related activity and patterns",
            "aws_command": "aws guardduty list-findings --detector-id <detector-id>",
            "category": "Investigation"
        })
        
        return steps
    
    def _generate_justification(self, steps: List[Dict[str, Any]], 
                               classification: Dict[str, Any],
                               mitre_technique: Dict[str, Any]) -> str:
        """Generate justification for remediation steps."""
        justification_parts = [
            f"Threat Category: {classification.get('category', 'Unknown')}",
            f"MITRE Technique: {mitre_technique.get('technique_id', 'Unknown') if mitre_technique else 'Unknown'}",
            "",
            "Remediation Strategy:",
            "1. Immediate containment to prevent further damage",
            "2. Forensic preservation for investigation",
            "3. Hardening to prevent similar attacks",
            "4. Enhanced monitoring for early detection",
            "",
            f"Total Steps: {len(steps)}"
        ]
        
        return "\n".join(justification_parts)
    
    def _calculate_priority(self, classification: Dict[str, Any], forensics: Dict[str, Any]) -> str:
        """Calculate remediation priority."""
        severity = forensics.get("severity", 5.0)
        category = classification.get("category", "")
        
        if severity >= 8.0 or category in ["Impact", "Exfiltration"]:
            return "Critical"
        elif severity >= 6.0 or category in ["Command and Control", "Credential Access"]:
            return "High"
        elif severity >= 4.0:
            return "Medium"
        else:
            return "Low"
    
    def _estimate_time(self, steps: List[Dict[str, Any]]) -> str:
        """Estimate time to complete remediation."""
        # Rough estimate: 15-30 minutes per step
        total_minutes = len(steps) * 20
        hours = total_minutes // 60
        minutes = total_minutes % 60
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"

