"""
Log Forensics Agent - Analyzes GuardDuty findings and simulated logs.
"""

import json
import os
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class LogForensicsAgent:
    """Agent responsible for parsing and analyzing security logs."""
    
    def __init__(self, logs_dir: str = "logs"):
        """
        Initialize the Log Forensics Agent.
        
        Args:
            logs_dir: Directory containing simulated CloudTrail/VPC logs
        """
        self.logs_dir = logs_dir
    
    def analyze(self, guardduty_finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a GuardDuty finding and correlate with available logs.
        
        Args:
            guardduty_finding: GuardDuty JSON finding
            
        Returns:
            Dictionary containing parsed forensics summary
        """
        logger.info("Starting log forensics analysis...")
        
        # Parse GuardDuty finding
        parsed = self._parse_guardduty(guardduty_finding)
        
        # Load and correlate with simulated logs
        correlated_logs = self._correlate_logs(parsed)
        
        summary = {
            "alert_type": parsed.get("type", "Unknown"),
            "severity": parsed.get("severity", "Medium"),
            "resource_details": parsed.get("resource", {}),
            "suspicious_activity": parsed.get("activity", {}),
            "metadata": {
                "region": parsed.get("region", "Unknown"),
                "account_id": parsed.get("account_id", "Unknown"),
                "timestamp": parsed.get("timestamp", ""),
                "finding_id": parsed.get("id", "")
            },
            "correlated_logs": correlated_logs,
            "key_indicators": self._extract_indicators(parsed, correlated_logs)
        }
        
        logger.info(f"Forensics analysis complete. Alert type: {summary['alert_type']}")
        return summary
    
    def _parse_guardduty(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GuardDuty finding structure."""
        # Handle different GuardDuty finding formats
        if "detail" in finding:
            detail = finding["detail"]
            finding_type = detail.get("type", "Unknown")
            
            # Extract common fields
            parsed = {
                "type": finding_type,
                "id": detail.get("id", ""),
                "account_id": detail.get("accountId", ""),
                "region": detail.get("region", ""),
                "timestamp": detail.get("updatedAt", detail.get("createdAt", "")),
                "severity": detail.get("severity", {}).get("score", 5.0),
                "resource": {},
                "activity": {}
            }
            
            # Extract resource information
            resource = detail.get("resource", {})
            if "instanceDetails" in resource:
                instance = resource["instanceDetails"]
                parsed["resource"] = {
                    "type": "EC2",
                    "instance_id": instance.get("instanceId", ""),
                    "instance_type": instance.get("instanceType", ""),
                    "launch_time": instance.get("launchTime", ""),
                    "image_id": instance.get("imageId", ""),
                    "ip_address": instance.get("privateIpAddresses", [{}])[0].get("privateIpAddress", "")
                }
            
            if "accessKeyDetails" in resource:
                key = resource["accessKeyDetails"]
                parsed["resource"] = {
                    "type": "IAM",
                    "user_name": key.get("userName", ""),
                    "access_key_id": key.get("accessKeyId", ""),
                    "principal_id": key.get("principalId", "")
                }
            
            if "s3BucketDetails" in resource:
                bucket = resource["s3BucketDetails"][0] if resource.get("s3BucketDetails") else {}
                parsed["resource"] = {
                    "type": "S3",
                    "bucket_name": bucket.get("name", ""),
                    "bucket_arn": bucket.get("arn", "")
                }
            
            # Extract activity/service-specific details
            service = detail.get("service", {})
            parsed["activity"] = {
                "action": service.get("action", {}).get("actionType", ""),
                "api_calls": service.get("action", {}).get("awsApiCallAction", {}),
                "network_connection": service.get("action", {}).get("networkConnectionAction", {}),
                "evidence": service.get("evidence", {})
            }
            
            return parsed
        
        # Fallback for simplified format
        return {
            "type": finding.get("type", "Unknown"),
            "id": finding.get("id", ""),
            "account_id": finding.get("accountId", ""),
            "region": finding.get("region", "us-east-1"),
            "timestamp": finding.get("timestamp", ""),
            "severity": finding.get("severity", 5.0),
            "resource": finding.get("resource", {}),
            "activity": finding.get("activity", {})
        }
    
    def _correlate_logs(self, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate finding with simulated CloudTrail/VPC logs."""
        correlated = []
        
        # Load CloudTrail logs if available
        cloudtrail_path = os.path.join(self.logs_dir, "simulated_cloudtrail.json")
        if os.path.exists(cloudtrail_path):
            try:
                with open(cloudtrail_path, 'r') as f:
                    cloudtrail_logs = json.load(f)
                    # Filter logs relevant to this finding
                    relevant = self._filter_relevant_logs(cloudtrail_logs, parsed)
                    correlated.extend(relevant)
            except Exception as e:
                logger.warning(f"Error loading CloudTrail logs: {e}")
        
        # Load VPC Flow logs if available
        flowlogs_path = os.path.join(self.logs_dir, "simulated_flowlogs.json")
        if os.path.exists(flowlogs_path):
            try:
                with open(flowlogs_path, 'r') as f:
                    flow_logs = json.load(f)
                    relevant = self._filter_relevant_logs(flow_logs, parsed)
                    correlated.extend(relevant)
            except Exception as e:
                logger.warning(f"Error loading Flow logs: {e}")
        
        return correlated
    
    def _filter_relevant_logs(self, logs: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Filter logs relevant to the finding."""
        relevant = []
        resource = parsed.get("resource", {})
        
        # Simple matching logic
        instance_id = resource.get("instance_id", "")
        ip_address = resource.get("ip_address", "")
        user_name = resource.get("user_name", "")
        
        for log in logs:
            # Match by instance ID
            if instance_id and instance_id in str(log):
                relevant.append(log)
            # Match by IP
            elif ip_address and ip_address in str(log):
                relevant.append(log)
            # Match by username
            elif user_name and user_name in str(log):
                relevant.append(log)
        
        return relevant[:10]  # Limit to 10 most relevant
    
    def _extract_indicators(self, parsed: Dict[str, Any], logs: List[Dict[str, Any]]) -> List[str]:
        """Extract key security indicators."""
        indicators = []
        
        activity = parsed.get("activity", {})
        resource = parsed.get("resource", {})
        
        # Network indicators
        if activity.get("network_connection"):
            conn = activity["network_connection"]
            if conn.get("remoteIpDetails", {}).get("ipAddressV4"):
                indicators.append(f"Suspicious outbound connection to {conn['remoteIpDetails']['ipAddressV4']}")
        
        # API call indicators
        if activity.get("api_calls"):
            api = activity["api_calls"]
            if api.get("api"):
                indicators.append(f"Unusual API call: {api['api']}")
        
        # Resource-based indicators
        if resource.get("type") == "EC2":
            indicators.append(f"EC2 instance {resource.get('instance_id', 'Unknown')} involved")
        
        if resource.get("type") == "IAM":
            indicators.append(f"IAM user {resource.get('user_name', 'Unknown')} activity")
        
        if resource.get("type") == "S3":
            indicators.append(f"S3 bucket {resource.get('bucket_name', 'Unknown')} accessed")
        
        return indicators

