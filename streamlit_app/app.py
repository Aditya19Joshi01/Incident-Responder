"""
IncidentResponder.AI - Streamlit Dashboard
Main entry point for the Streamlit frontend.
"""

import streamlit as st
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from utils.config import load_ai_config
from streamlit_app.utils.run_pipeline import run_investigation
from streamlit_app.utils.file_utils import save_uploaded_file, cleanup_temp_file
from streamlit_app.components.overview_card import render_overview_card
from streamlit_app.components.agent_output import (
    render_forensics_tab,
    render_threat_attribution_tab,
    render_mitre_tab,
    render_remediation_tab
)
from streamlit_app.components.report_viewer import render_json_report_tab

# Page configuration
st.set_page_config(
    page_title="IncidentResponder.AI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme enhancements
st.markdown("""
<style>
    .main {
        background-color: #0e1117;
    }
    .stMetric {
        background-color: #1e1e1e;
        padding: 10px;
        border-radius: 5px;
    }
    h1, h2, h3 {
        color: #ffffff;
    }
    .stMarkdown {
        color: #ffffff;
    }
</style>
""", unsafe_allow_html=True)


def get_ai_status() -> dict:
    """
    Get AI provider status from configuration.
    
    Returns:
        Dictionary with provider info and status
    """
    try:
        config = load_ai_config()
        provider = config.get("ai_provider", "dummy")
        model_name = config.get("model_name", "N/A")
        
        # Determine if AI is enabled (not dummy)
        is_enabled = provider.lower() != "dummy"
        
        return {
            "provider": provider.upper(),
            "model": model_name,
            "enabled": is_enabled,
            "mode": "AI Enabled" if is_enabled else "Fallback Mode"
        }
    except Exception:
        return {
            "provider": "Unknown",
            "model": "N/A",
            "enabled": False,
            "mode": "Fallback Mode"
        }


def render_sidebar():
    """Render the sidebar with app info."""
    with st.sidebar:
        st.title("🛡️ IncidentResponder.AI")
        st.markdown("---")
        
        st.markdown("### About")
        st.markdown("""
        Multi-Agent Cloud Security Investigation Platform
        
        This dashboard allows you to upload GuardDuty findings and run
        a complete investigation using multiple specialized agents.
        """)
        
        st.markdown("---")
        
        st.markdown("### AI Status")
        ai_status = get_ai_status()
        st.info(f"**Provider:** {ai_status['provider']}")
        st.info(f"**Model:** {ai_status['model']}")
        
        mode_color = "🟢" if ai_status['enabled'] else "🟡"
        st.info(f"**Mode:** {mode_color} {ai_status['mode']}")
        
        st.markdown("---")
        
        st.markdown("### Links")
        st.markdown("""
        - [GitHub Repository](https://github.com)
        - [Documentation](https://github.com)
        """)
        
        st.markdown("---")
        
        st.markdown("### Instructions")
        st.markdown("""
        1. Upload a GuardDuty finding (JSON format)
        2. Click "Run Analysis"
        3. Review results in the tabs below
        4. Download the complete report
        """)


def main():
    """Main application function."""
    # Render sidebar
    render_sidebar()
    
    # Main header
    st.title("🛡️ IncidentResponder.AI Dashboard")
    st.markdown("### Multi-Agent Cloud Security Investigation Platform")
    
    # AI Status badges
    ai_status = get_ai_status()
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.info(f"**AI Provider:** {ai_status['provider']}")
    
    with col2:
        st.info(f"**Model:** {ai_status['model']}")
    
    with col3:
        mode_badge = "🟢 AI Enabled" if ai_status['enabled'] else "🟡 Fallback Mode"
        st.info(f"**Status:** {mode_badge}")
    
    st.markdown("---")
    
    # File upload section
    st.markdown("### 📤 Upload GuardDuty Finding")
    uploaded_file = st.file_uploader(
        "Upload a GuardDuty Finding (JSON Format)",
        type=['json'],
        help="Upload a JSON file containing a GuardDuty finding. The system uses simulated logs for analysis."
    )
    
    # Initialize session state
    if 'investigation_results' not in st.session_state:
        st.session_state.investigation_results = None
    if 'uploaded_file_path' not in st.session_state:
        st.session_state.uploaded_file_path = None
    
    # Run analysis button
    if uploaded_file is not None:
        # Save uploaded file
        if st.session_state.uploaded_file_path is None:
            temp_path = save_uploaded_file(uploaded_file)
            st.session_state.uploaded_file_path = temp_path
            st.success(f"✅ File uploaded: {uploaded_file.name}")
        
        st.markdown("---")
        
        col1, col2 = st.columns([1, 4])
        with col1:
            run_button = st.button("🚀 Run Analysis", type="primary", use_container_width=True)
        
        if run_button:
            with st.spinner("🔄 Running investigation... This may take a moment."):
                try:
                    # Run the investigation
                    results = run_investigation(st.session_state.uploaded_file_path)
                    st.session_state.investigation_results = results
                    st.success("✅ Analysis complete!")
                    st.balloons()
                except Exception as e:
                    st.error(f"❌ Error running investigation: {str(e)}")
                    st.exception(e)
                    st.session_state.investigation_results = None
    
    # Display results if available
    if st.session_state.investigation_results is not None:
        results = st.session_state.investigation_results
        report = results.get("final_report", {})
        
        st.markdown("---")
        st.markdown("## 📊 Investigation Results")
        
        # Create tabs
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
            "📊 Summary",
            "🔎 Log Forensics",
            "⚠️ Threat Attribution",
            "🧩 MITRE Mapping",
            "🛡️ Remediation",
            "📄 JSON Report"
        ])
        
        with tab1:
            render_overview_card(report)
        
        with tab2:
            forensics_data = results.get("forensics", {})
            render_forensics_tab(forensics_data)
        
        with tab3:
            threat_data = results.get("threat", {})
            render_threat_attribution_tab(threat_data)
        
        with tab4:
            mitre_data = results.get("mitre", {})
            render_mitre_tab(mitre_data, report)
        
        with tab5:
            remediation_data = results.get("remediation", {})
            render_remediation_tab(remediation_data, report)
        
        with tab6:
            render_json_report_tab(report)
    
    # Cleanup on app close (optional)
    # Note: Streamlit doesn't have a reliable cleanup hook, so we'll let the OS handle temp files


if __name__ == "__main__":
    main()

