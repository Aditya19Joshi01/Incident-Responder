"""
Components for displaying individual agent outputs.
"""

import streamlit as st
from typing import Dict, Any, List


def render_forensics_tab(forensics_data: Dict[str, Any]) -> None:
    """
    Render the log forensics agent output.
    
    Args:
        forensics_data: Output from LogForensicsAgent
    """
    st.markdown("### 🔎 Log Forensics Analysis")
    
    # Alert type and severity
    alert_type = forensics_data.get("alert_type", "Unknown")
    severity = forensics_data.get("severity", 5.0)
    
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**Alert Type:** {alert_type}")
    with col2:
        st.info(f"**Severity:** {severity}")
    
    st.markdown("---")
    
    # Key indicators
    key_indicators = forensics_data.get("key_indicators", [])
    if key_indicators:
        st.markdown("**🔍 Key Indicators:**")
        for indicator in key_indicators:
            st.markdown(f"- {indicator}")
    else:
        st.info("No key indicators extracted")
    
    st.markdown("---")
    
    # Resource details
    resource_details = forensics_data.get("resource_details", {})
    if resource_details:
        st.markdown("**📦 Resource Details:**")
        st.json(resource_details)
    
    st.markdown("---")
    
    # Metadata
    metadata = forensics_data.get("metadata", {})
    if metadata:
        st.markdown("**📋 Metadata:**")
        col1, col2, col3, col4 = st.columns(4)
        if "region" in metadata:
            col1.metric("Region", metadata.get("region", "N/A"))
        if "account_id" in metadata:
            col2.metric("Account ID", metadata.get("account_id", "N/A")[:12] + "..." if len(metadata.get("account_id", "")) > 12 else metadata.get("account_id", "N/A"))
        if "finding_id" in metadata:
            col3.metric("Finding ID", metadata.get("finding_id", "N/A")[:16] + "..." if len(metadata.get("finding_id", "")) > 16 else metadata.get("finding_id", "N/A"))
        if "timestamp" in metadata:
            col4.metric("Timestamp", metadata.get("timestamp", "N/A")[:10] if metadata.get("timestamp") else "N/A")
    
    st.markdown("---")
    
    # Suspicious activity
    suspicious_activity = forensics_data.get("suspicious_activity", {})
    if suspicious_activity:
        st.markdown("**⚠️ Suspicious Activity:**")
        st.json(suspicious_activity)
    
    # Correlated logs
    correlated_logs = forensics_data.get("correlated_logs", [])
    if correlated_logs:
        st.markdown("**📊 Correlated Logs:**")
        st.json(correlated_logs)
    
    # LLM Analysis
    llm_analysis = forensics_data.get("llm_analysis", "")
    if llm_analysis:
        st.markdown("**🤖 AI Analysis:**")
        st.info(llm_analysis)
    
    # Legacy fields (for backward compatibility)
    anomalies = forensics_data.get("anomalies", [])
    if anomalies:
        st.markdown("**⚠️ Anomalies Detected:**")
        for anomaly in anomalies:
            st.warning(f"⚠️ {anomaly}")
    
    iocs = forensics_data.get("iocs", [])
    if iocs:
        st.markdown("**🔴 Indicators of Compromise (IOCs):**")
        for ioc in iocs:
            st.code(ioc, language=None)
    
    suspicious_ips = forensics_data.get("suspicious_ips", [])
    if suspicious_ips:
        st.markdown("**🌐 Suspicious IP Addresses:**")
        for ip in suspicious_ips:
            st.code(ip, language=None)
    
    cloudtrail_events = forensics_data.get("cloudtrail_events", [])
    if cloudtrail_events:
        st.markdown("**📝 Relevant CloudTrail Events:**")
        st.json(cloudtrail_events)
    
    st.markdown("---")
    
    # Full output (collapsible)
    with st.expander("View Full Forensics Output"):
        st.json(forensics_data)


def render_threat_attribution_tab(threat_data: Dict[str, Any]) -> None:
    """
    Render the threat attribution agent output.
    
    Args:
        threat_data: Output from ThreatAttributionAgent
    """
    st.markdown("### ⚠️ Threat Attribution")
    
    threat_classification = threat_data.get("threat_classification", {})
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**Category:**")
        category = threat_classification.get("category", "Unknown")
        if category != "Unknown":
            st.success(category)
        else:
            st.info(category)
        
        st.markdown("**Subcategory:**")
        subcategory = threat_classification.get("subcategory", "")
        if subcategory:
            st.info(subcategory)
        else:
            st.caption("N/A")
    
    with col2:
        st.markdown("**Confidence Score:**")
        confidence = threat_data.get("confidence", 0.0)
        st.metric("Confidence", f"{confidence:.0%}", label_visibility="collapsed")
        
        # Confidence bar
        st.progress(confidence)
    
    with col3:
        st.markdown("**MITRE Technique Guess:**")
        mitre_guess = threat_data.get("mitre_technique_guess", "N/A")
        if mitre_guess and mitre_guess != "N/A":
            mitre_url = f"https://attack.mitre.org/techniques/{mitre_guess}/"
            st.markdown(f"[{mitre_guess}]({mitre_url})")
        else:
            st.caption("N/A")
    
    st.markdown("---")
    
    # Description
    description = threat_classification.get("description", "")
    if description:
        st.markdown("**Description:**")
        st.write(description)
    
    # Likely intent (if available)
    intent = threat_data.get("likely_intent", "")
    if intent:
        st.markdown("**Likely Intent:**")
        st.warning(intent)
    
    # Reasoning
    reasoning = threat_data.get("reasoning", "")
    if reasoning:
        st.markdown("**Reasoning:**")
        st.info(reasoning)
    
    # Attack phase (if available)
    attack_phase = threat_data.get("attack_phase", "")
    if attack_phase:
        st.markdown("**Attack Phase:**")
        st.warning(attack_phase)
    
    st.markdown("---")
    
    # MITRE candidates
    mitre_candidates = threat_data.get("mitre_technique_candidates", [])
    if mitre_candidates:
        st.markdown("**🧩 MITRE Technique Candidates:**")
        for candidate in mitre_candidates:
            candidate_url = f"https://attack.mitre.org/techniques/{candidate}/"
            st.markdown(f"- [{candidate}]({candidate_url})")
    
    st.markdown("---")
    
    # Full output (collapsible)
    with st.expander("View Full Threat Attribution Output"):
        st.json(threat_data)


def render_mitre_tab(mitre_data: Dict[str, Any], report: Dict[str, Any]) -> None:
    """
    Render the MITRE mapping output.
    
    Args:
        mitre_data: Output from KnowledgeRetrievalAgent
        report: Full report for MITRE mapping details
    """
    st.markdown("### 🧩 MITRE ATT&CK Mapping")
    
    # Get MITRE mapping from report
    mitre_mapping = report.get("mitre_mapping", {})
    primary_technique = mitre_mapping.get("primary_technique", "")
    technique_name = mitre_mapping.get("technique_name", "")
    technique_description = mitre_mapping.get("technique_description", "")
    tactic = mitre_mapping.get("tactic", "")
    
    if primary_technique:
        # Technique card
        st.markdown("**Primary Technique:**")
        
        col1, col2 = st.columns([1, 3])
        
        with col1:
            st.markdown(f"### {primary_technique}")
            mitre_url = f"https://attack.mitre.org/techniques/{primary_technique}/"
            st.markdown(f"[🔗 View on MITRE ATT&CK]({mitre_url})")
        
        with col2:
            st.markdown(f"**{technique_name}**")
            if tactic:
                st.caption(f"Tactic: {tactic}")
            if technique_description:
                st.write(technique_description)
        
        st.markdown("---")
        
        # Why it matched
        recommended_technique = mitre_data.get("recommended_technique", {})
        reasoning = recommended_technique.get("reasoning", "")
        if reasoning:
            st.markdown("**Why This Technique Matched:**")
            st.info(reasoning)
        
        # Candidates
        candidates = mitre_mapping.get("candidates", [])
        if candidates and len(candidates) > 1:
            st.markdown("**Other Candidate Techniques:**")
            for candidate in candidates:
                if candidate != primary_technique:
                    candidate_url = f"https://attack.mitre.org/techniques/{candidate}/"
                    st.markdown(f"- [{candidate}]({candidate_url})")
    else:
        st.warning("No MITRE technique mapped for this incident")
    
    # Full output (collapsible)
    with st.expander("View Full MITRE Mapping Output"):
        st.json(mitre_data)


def render_remediation_tab(remediation_data: Dict[str, Any], report: Dict[str, Any]) -> None:
    """
    Render the remediation agent output.
    
    Args:
        remediation_data: Output from RemediationAgent
        report: Full report for remediation details
    """
    st.markdown("### 🛡️ Remediation Steps")
    
    # Priority
    priority = report.get("remediation_priority", "Medium")
    priority_colors = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🟢"
    }
    priority_emoji = priority_colors.get(priority, "⚪")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**Priority:** {priority_emoji} **{priority}**")
    with col2:
        steps = report.get("recommended_actions", [])
        st.markdown(f"**Total Steps:** {len(steps)}")
    
    # Justification
    justification = report.get("remediation_justification", "")
    if justification:
        st.markdown("**Justification:**")
        st.info(justification)
    
    st.markdown("---")
    
    # Remediation steps
    steps = report.get("recommended_actions", [])
    if steps:
        st.markdown("**Recommended Actions:**")
        
        for step in steps:
            step_num = step.get("step", 0)
            action = step.get("action", "")
            description = step.get("description", "")
            category = step.get("category", "")
            aws_command = step.get("aws_command", "")
            
            with st.container():
                st.markdown(f"#### Step {step_num}: {action}")
                
                if category:
                    st.caption(f"Category: {category}")
                
                if description:
                    st.write(description)
                
                if aws_command:
                    st.code(aws_command, language="bash")
                
                st.markdown("---")
    else:
        st.info("No remediation steps generated")
    
    # Impact
    impact = remediation_data.get("impact", "")
    if impact:
        st.markdown("**Expected Impact:**")
        st.warning(impact)
    
    # Full output (collapsible)
    with st.expander("View Full Remediation Output"):
        st.json(remediation_data)

