"""
UI Sidebar Module - CLEAN VERSION
Completely redesigned sidebar without duplicates or confusion.
"""

import streamlit as st
import json
import os
import logging
from datetime import datetime
from typing import Dict, Any, List
from config import PRODUCTION_THRESHOLDS

# Set up logging
logger = logging.getLogger(__name__)


def render_dynamic_sidebar(detector):
    """
    Clean, simple sidebar with essential controls only.
    No more confusion or duplicates!
    """
    
    st.sidebar.title("🛡️ Anomaly Detection System")
    
    # Quick Status Overview (always visible)
    render_quick_status(detector)
    
    st.sidebar.markdown("---")
    
    # Main Navigation
    tabs = ["🏠 Main", "🔍 Analysis", "⚙️ Settings"]
    selected = st.sidebar.radio("Navigation", tabs, horizontal=False)
    
    st.sidebar.markdown("---")
    
    if selected == "🏠 Main":
        render_main_controls(detector)
    elif selected == "🔍 Analysis":
        render_analysis_tools(detector)
    elif selected == "⚙️ Settings":
        render_system_settings()

def render_quick_status(detector):
    """Essential status at the top - always visible."""
    
    # Processing status
    status_icon = "🟢" if st.session_state.get('processing_active', True) else "🟡"
    status_text = "Active" if st.session_state.get('processing_active', True) else "Paused"
    st.sidebar.info(f"{status_icon} Processing: {status_text}")
    
    # Model status - compact
    try:
        # Get orchestrator from session state (it's stored as 'orchestrator')
        orchestrator = st.session_state.get('orchestrator')
        if orchestrator and hasattr(orchestrator, 'get_model_status') and hasattr(orchestrator, 'get_dns_model_status'):
            model_status = orchestrator.get_model_status()
            dns_status = orchestrator.get_dns_model_status()
            
            # Count only actual ML models (not preprocessors)
            conn_models = sum([
                model_status.get('isolation_forest', False),
                model_status.get('autoencoder', False)
            ])
            
            dns_components = dns_status.get('components', {})
            dns_models = sum([
                dns_components.get('dns_isolation_forest', False),
                dns_components.get('dns_autoencoder', False)
                # Removed dns_scaler - it's just preprocessing, not a model
            ])
            
            total_models = conn_models + dns_models
            
            if total_models >= 4:
                st.sidebar.success("🤖 All Models Ready")
            elif total_models >= 3:
                st.sidebar.warning(f"🤖 {total_models}/4 Models Ready")
            elif total_models > 0:
                st.sidebar.warning(f"🤖 {total_models}/4 Models Ready")
            else:
                st.sidebar.error("🤖 No Models Ready")
        else:
            st.sidebar.error("🤖 Orchestrator not available")
            
    except Exception as e:
        st.sidebar.error(f"🤖 Model info error: {str(e)}")

def render_main_controls(detector):
    """Main dashboard controls - unified system control."""
    
    st.sidebar.subheader("🎮 System Control")
    
    # Watchdog system status display
    orchestrator = st.session_state.get('orchestrator')
    
    if orchestrator:
        # Use the monitoring_active attribute directly from orchestrator
        monitoring_active = getattr(orchestrator, 'monitoring_active', False)
        
        # System status overview
        if monitoring_active:
            st.sidebar.success("🟢 Monitoring Active")
            st.sidebar.caption("🔴 Auto-processing logs in real-time")
        else:
            st.sidebar.warning("🟡 Manual Mode")
            st.sidebar.caption("⚠️ Use 'Process Queue Now' to analyze logs")
        
        st.sidebar.markdown("---")
        
        # === MONITORING CONTROL ===
        st.sidebar.markdown("**🤖 Monitoring Control**")
        
        # ✅ FIX: Remove duplicate monitoring controls - now handled in main app
        if monitoring_active:
            st.sidebar.success("🔄 Background Monitoring: ACTIVE")
            if hasattr(orchestrator, 'monitoring_thread') and orchestrator.monitoring_thread:
                st.sidebar.caption(f"Thread: {orchestrator.monitoring_thread.name}")
            st.sidebar.info("💡 Use main app controls to start/stop monitoring")
        else:
            st.sidebar.info("⏸️ Background Monitoring: INACTIVE")
            st.sidebar.info("💡 Use main app controls to start monitoring")
        
        # Manual processing button (keep this for manual queue processing)
        if st.sidebar.button("📥 Process Queue Now", use_container_width=True, type="secondary", key="sidebar_process_queue"):
            st.session_state.manual_redis_requested = True
            st.rerun()
        
        # Quick stats
        render_processing_stats()
        
        # Compact Redis stats (always visible, no expander)
        if monitoring_active:
            system_status = orchestrator.get_system_status()
            st.sidebar.markdown("---")
            st.sidebar.caption(f"📊 Alerts: {system_status.get('active_alerts', 0)} | 📋 Findings: {system_status.get('processed_findings', 0)}")
            st.sidebar.caption(f"🕒 Updated: {system_status.get('last_update', 'N/A')[:19]}")
    
    # Findings filter (only if findings exist)
    findings_count = len(getattr(st.session_state, 'findings', {}))
    if findings_count > 0:
        st.sidebar.markdown("### 🔍 Filter Results")
        render_simple_filter()

def render_analysis_tools(detector):
    """Analysis and investigation tools."""
    
    st.sidebar.subheader("🔍 IP Investigation")
    
    # IP input
    target_ip = st.sidebar.text_input(
        "Target IP:",
        placeholder="192.168.1.100",
        key="analysis_ip_input"
    )
    
    if target_ip and st.sidebar.button("🔍 Investigate", use_container_width=True, key="sidebar_investigate_ip"):
        st.session_state.investigated_ip = target_ip
        st.rerun()
    
    # Current investigation
    if st.session_state.get('investigated_ip'):
        st.sidebar.info(f"📋 Investigating: {st.session_state.investigated_ip}")
        if st.sidebar.button("❌ Clear", use_container_width=True, key="sidebar_clear_investigation"):
            st.session_state.investigated_ip = None
            st.rerun()
    


def render_system_settings():
    """System settings and configuration."""
    
    # Model details - get detector from session state
    st.sidebar.markdown("### 🤖 Model Information")
    try:
        # Get orchestrator from session state (it's stored as 'orchestrator')
        orchestrator = st.session_state.get('orchestrator')
        if orchestrator and hasattr(orchestrator, 'get_model_status') and hasattr(orchestrator, 'get_dns_model_status'):
            model_status = orchestrator.get_model_status()
            
            # CONN.LOG Anomaly Detection (2 models)
            if model_status.get('isolation_forest') and model_status.get('autoencoder'):
                st.sidebar.success("🛡️ Anomaly CONN.LOG: Ready")
                # Get actual thresholds from backend
                actual_iso_threshold = getattr(orchestrator.detection_engine.ml_handler, 'iso_threshold', None)
                actual_ae_threshold = getattr(orchestrator.detection_engine.ml_handler, 'ae_threshold', None)
                
                if actual_iso_threshold is not None and actual_ae_threshold is not None:
                    st.sidebar.caption(f"🌲 IF: {actual_iso_threshold:.3f} | 🧠 AE: {actual_ae_threshold:.3f}")
                else:
                    st.sidebar.caption("🌲 Isolation Forest + 🧠 Autoencoder")
            
            # DNS.LOG Anomaly Detection (2 models)
            dns_status = orchestrator.get_dns_model_status()
            dns_components = dns_status.get('components', {})
            
            if dns_components.get('dns_isolation_forest') and dns_components.get('dns_autoencoder'):
                st.sidebar.success("🛡️ Anomaly DNS.LOG: Ready")
                # Get actual thresholds from backend
                actual_dns_iso_threshold = getattr(orchestrator.detection_engine.ml_handler, 'dns_iso_threshold', None)
                actual_dns_ae_threshold = getattr(orchestrator.detection_engine.ml_handler, 'dns_ae_threshold', None)
                
                if actual_dns_iso_threshold is not None and actual_dns_ae_threshold is not None:
                    st.sidebar.caption(f"🌲 IF: {actual_dns_iso_threshold:.3f} | 🧠 AE: {actual_dns_ae_threshold:.3f}")
                else:
                    st.sidebar.caption("🌲 Isolation Forest + 🧠 Autoencoder")
            
                        # Preprocessor status (if available)
            if model_status.get('preprocessor'):
                st.sidebar.info("📐 CONN.LOG: 21 features")
            
            # DNS preprocessor status (if available)
            dns_components = dns_status.get('components', {})
            if dns_components.get('dns_scaler'):
                st.sidebar.info("📐 DNS.LOG: 18 features")
            else:
                st.sidebar.error("🤖 Orchestrator not available")
        
    except Exception as e:
        st.sidebar.error(f"🤖 Model info error: {str(e)}")
    
    # Performance stats
    render_performance_section()

def render_processing_stats():
    """Show processing statistics."""
    
    # Get orchestrator from session state for Redis-based stats
    orchestrator = st.session_state.get('orchestrator')
    if orchestrator:
        try:
            processing_stats = getattr(orchestrator, 'processing_stats', {})
            
            lines_processed = processing_stats.get('lines_processed', 0)
            alerts_generated = processing_stats.get('alerts_generated', 0)
            
            if lines_processed > 0:
                st.sidebar.caption(f"📋 Processed: {lines_processed:,} logs | 🚨 {alerts_generated:,} alerts")
            else:
                st.sidebar.caption("📋 No data processed yet")
        except Exception as e:
            st.sidebar.caption("📋 Stats unavailable")
    else:
        st.sidebar.caption("📋 Orchestrator not available")

def render_simple_filter():
    """Simple findings filter."""
    
    # IP filter
    ip_filter = st.sidebar.text_input(
        "Filter by IP:",
        placeholder="192.168.1.100",
        key="simple_ip_filter"
    )
    
    # Risk level filter
    risk_filter = st.sidebar.selectbox(
        "Min Risk Level:",
        ["All", "Low (40+)", "Medium (60+)", "High (80+)"],
        key="simple_risk_filter"
    )
    
    # Apply filters to session state
    st.session_state.filter_ip = ip_filter
    st.session_state.filter_risk = risk_filter
    
    # ✅ FIX: Safe session state access with error handling
    try:
        findings_dict = st.session_state.get('findings', {})
        all_findings = list(findings_dict.values())
        filtered_count = len(apply_simple_filter(all_findings))
        st.sidebar.caption(f"Showing: {filtered_count}/{len(all_findings)} findings")
    except Exception as e:
        logger.error(f"Error accessing findings in sidebar: {e}")
        st.sidebar.caption("Showing: 0/0 findings")

def render_performance_section():
    """Performance monitoring section."""
    
    with st.sidebar.expander("⚡ Performance", expanded=False):
        
        # Cache stats
        cache_size = len(getattr(st.session_state, 'findings_cache', {}))
        st.metric("Cache Size", cache_size)
        
        # ✅ FIX: Safe session state access with error handling
        try:
            findings_dict = st.session_state.get('findings', {})
            total_findings = len(findings_dict)
            current_page = st.session_state.get('findings_page', 0)
            st.metric("Total Findings", total_findings)
            st.metric("Current Page", current_page + 1)
        except Exception as e:
            logger.error(f"Error accessing findings stats: {e}")
            st.metric("Total Findings", 0)
            st.metric("Current Page", 1)
        
        # Performance tips
        st.caption("💡 Tips:")
        st.caption("• Large datasets use pagination")
        st.caption("• Cache improves performance")

def apply_simple_filter(findings_list):
    """Apply simple filters to findings list."""
    
    filtered = findings_list
    
    # IP filter
    ip_filter = getattr(st.session_state, 'filter_ip', '')
    if ip_filter:
        filtered = [f for f in filtered if ip_filter in f.get('ip', '')]
    
    # Risk filter
    risk_filter = getattr(st.session_state, 'filter_risk', 'All')
    if risk_filter != 'All':
        risk_threshold = {
            'Low (40+)': 40,
            'Medium (60+)': 60, 
            'High (80+)': 80
        }.get(risk_filter, 0)
        
        filtered = [f for f in filtered if f.get('risk_score', 0) >= risk_threshold]
    
    return filtered

# Helper functions for compatibility
def render_findings_filter_sidebar():
    """Compatibility function - use simple filter instead."""
    render_simple_filter()

def render_ip_investigation_panel(detector):
    """Compatibility function."""
    st.sidebar.caption("🔍 Use Analysis tab for IP investigation")

def render_ip_investigation_report(detector):
    """Compatibility function."""  
    st.sidebar.caption("🔍 IP investigation active")

def render_performance_stats():
    """Compatibility function."""
    render_performance_section() 