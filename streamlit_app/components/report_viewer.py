"""
Report viewer component for displaying the full JSON report.
"""

import json
import streamlit as st
from typing import Dict, Any


def render_json_report_tab(report: Dict[str, Any]) -> str:
    """
    Render the full JSON report and provide download functionality.
    
    Args:
        report: The complete investigation report
        
    Returns:
        JSON string of the report for download
    """
    st.markdown("### 📄 Complete Investigation Report")
    
    # Display the JSON
    st.json(report)
    
    # Generate JSON string for download
    json_string = json.dumps(report, indent=2)
    
    # Download button
    st.download_button(
        label="📥 Download JSON Report",
        data=json_string,
        file_name=f"incident_report_{report.get('timestamp', 'unknown').replace(':', '-').replace('.', '-')}.json",
        mime="application/json",
        use_container_width=True
    )
    
    return json_string

