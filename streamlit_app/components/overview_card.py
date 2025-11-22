"""
Overview card component for displaying incident summary.
"""

import streamlit as st
from typing import Dict, Any


def get_severity_color(severity: float) -> str:
    """
    Get color code based on severity score.
    
    Args:
        severity: Severity score (0-10)
        
    Returns:
        Color name for badge
    """
    if severity >= 8.0:
        return "🔴 Critical"
    elif severity >= 5.0:
        return "🟡 Medium"
    else:
        return "🟢 Low"


def get_severity_badge_color(severity: float) -> str:
    """
    Get Streamlit badge color based on severity.
    
    Args:
        severity: Severity score (0-10)
        
    Returns:
        Badge color string
    """
    if severity >= 8.0:
        return "error"
    elif severity >= 5.0:
        return "warning"
    else:
        return "success"


def render_overview_card(report: Dict[str, Any]) -> None:
    """
    Render the overview summary card.
    
    Args:
        report: The final investigation report
    """
    st.markdown("### 📊 Incident Summary")
    
    # Create columns for key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        alert_type = report.get("alert", "Unknown")
        st.metric("Alert Type", alert_type)
    
    with col2:
        severity_raw = report.get("severity", 5.0)
        # Handle both float and string severity values
        if isinstance(severity_raw, str):
            # Try to convert string to float, or use default
            try:
                severity = float(severity_raw)
            except (ValueError, TypeError):
                severity = 5.0
        else:
            severity = float(severity_raw) if severity_raw is not None else 5.0
        
        severity_label = get_severity_color(severity)
        st.metric("Severity", f"{severity:.1f}", delta=None)
        st.caption(severity_label)
    
    with col3:
        threat_cat = report.get("threat_classification", {}).get("category", "Unknown")
        st.metric("Threat Category", threat_cat)
    
    with col4:
        confidence = report.get("confidence", 0.0)
        st.metric("Confidence", f"{confidence:.0%}")
    
    # Main details section
    st.markdown("---")
    
    # MITRE Technique
    mitre_mapping = report.get("mitre_mapping", {})
    primary_technique = mitre_mapping.get("primary_technique", "N/A")
    technique_name = mitre_mapping.get("technique_name", "N/A")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**🧩 MITRE Technique**")
        if primary_technique != "N/A":
            mitre_url = f"https://attack.mitre.org/techniques/{primary_technique}/"
            st.markdown(f"- **ID:** [{primary_technique}]({mitre_url})")
            st.markdown(f"- **Name:** {technique_name}")
        else:
            st.info("No MITRE technique mapped")
    
    with col2:
        st.markdown("**⚡ Recommended Priority**")
        priority = report.get("remediation_priority", "Medium")
        priority_colors = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢"
        }
        priority_emoji = priority_colors.get(priority, "⚪")
        st.markdown(f"{priority_emoji} **{priority}**")
    
    # Narrative summary
    st.markdown("---")
    st.markdown("**📝 Summary**")
    
    reasoning = report.get("reasoning_trace", "")
    if reasoning:
        st.info(reasoning)
    else:
        # Generate a basic summary from available data
        summary_parts = []
        if alert_type != "Unknown":
            summary_parts.append(f"Alert type: {alert_type}")
        if threat_cat != "Unknown":
            summary_parts.append(f"Threat category: {threat_cat}")
        if primary_technique != "N/A":
            summary_parts.append(f"MITRE technique: {primary_technique} - {technique_name}")
        
        summary = ". ".join(summary_parts) if summary_parts else "No summary available."
        st.info(summary)

