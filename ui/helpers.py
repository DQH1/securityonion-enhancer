"""
UI Helper Functions Module
Contains utility functions for UI components and data processing.
"""

import streamlit as st
import pandas as pd
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

# Set up logging
logger = logging.getLogger(__name__)


def apply_findings_filters(findings: List[Dict]) -> List[Dict]:
    """
    Apply filters to the findings list based on session state filter settings.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Filtered list of findings
    """
    filtered_findings = findings.copy()
    
    def get_risk_level(score):
        """Convert numeric risk score to risk level string."""
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Info"
    
    # Apply source filter
    if st.session_state.findings_filter_source != "All Sources":
        source_map = {
            "Anomaly Engine": "anomaly_engine",
            "Suricata": "suricata"
        }
        target_source = source_map.get(st.session_state.findings_filter_source)
        if target_source:
            filtered_findings = [f for f in filtered_findings 
                               if any(e.get('source') == target_source for e in f.get('evidence', []))]
    
    # Apply risk level filter
    if st.session_state.findings_filter_risk != "All Risk Levels":
        filtered_findings = [f for f in filtered_findings 
                           if get_risk_level(f.get('risk_score', 0)) == st.session_state.findings_filter_risk]
    
    # Apply IP filter
    if st.session_state.findings_filter_ip.strip():
        ip_filter = st.session_state.findings_filter_ip.strip()
        filtered_findings = [f for f in filtered_findings if ip_filter in f.get('ip', '')]
    
    return filtered_findings


def render_export_alerts_button():
    """
    Render the export alerts button and handle the export functionality.
    """
    if st.button("📤 Export All Findings", help="Export all findings to JSON file"):
        try:
            # Collect all findings data
            export_data = collect_all_findings_for_export()
            
            if export_data['findings']:
                # Create JSON string
                json_str = json.dumps(export_data, indent=2, default=str, ensure_ascii=False)
                
                # Create download button
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"network_anomaly_findings_{timestamp}.json"
                
                st.download_button(
                    label="💾 Download JSON File",
                    data=json_str,
                    file_name=filename,
                    mime="application/json",
                    help=f"Download {len(export_data['findings'])} findings as JSON"
                )
                
                st.session_state.export_status = f"✅ Ready to download {len(export_data['findings'])} findings"
            else:
                st.session_state.export_status = "⚠️ No findings available to export"
                
        except Exception as e:
            st.session_state.export_status = f"❌ Export failed: {str(e)}"
    
    # Display export status
    if st.session_state.export_status:
        if "✅" in st.session_state.export_status:
            st.success(st.session_state.export_status)
        elif "⚠️" in st.session_state.export_status:
            st.warning(st.session_state.export_status)
        else:
            st.error(st.session_state.export_status)


def collect_all_findings_for_export() -> Dict[str, Any]:
    """
    Collect all findings and related data for export.
    
    Returns:
        Dictionary containing all export data
    """
    # ✅ FIX: Safe session state access with error handling
    try:
        findings_dict = st.session_state.get('findings', {})
        raw_events = st.session_state.get('all_raw_detection_events', [])
        
        export_data = {
            "export_metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(findings_dict),
                "total_raw_events": len(raw_events),
                "application_version": "Network Anomaly Detection v2.0"
            },
            "findings": findings_dict,
            "raw_detection_events": raw_events,
            "session_statistics": {
                "last_refresh": str(st.session_state.get('last_refresh', 'Never')),
                "processing_status": st.session_state.get('processing_status', 'Unknown'),
                "threat_intel_status": st.session_state.get('threat_intel_status', {}),
                "active_filters": {
                    "source": st.session_state.get('findings_filter_source', 'All Sources'),
                    "risk": st.session_state.get('findings_filter_risk', 'All Risk Levels'),
                    "ip": st.session_state.get('findings_filter_ip', '')
                }
            }
        }
    except Exception as e:
        logger.error(f"Error collecting findings for export: {e}")
        export_data = {
            "export_metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_findings": 0,
                "total_raw_events": 0,
                "application_version": "Network Anomaly Detection v2.0",
                "error": str(e)
            },
            "findings": {},
            "raw_detection_events": [],
            "session_statistics": {
                "last_refresh": "Error",
                "processing_status": "Error",
                "threat_intel_status": {},
                "active_filters": {
                    "source": "All Sources",
                    "risk": "All Risk Levels",
                    "ip": ""
                }
            }
        }
    
    return export_data


def convert_shap_explanation(shap_explanation_list):
    """
    Convert SHAP explanation list to DataFrame for display.
    
    Args:
        shap_explanation_list: List of SHAP explanation dictionaries
        
    Returns:
        pandas.DataFrame: Formatted DataFrame for display
    """
    if not shap_explanation_list:
        return pd.DataFrame()
    
    try:
        df = pd.DataFrame(shap_explanation_list)
        
        # Format the DataFrame for better display
        if 'feature' in df.columns:
            df = df.rename(columns={
                'feature': 'Feature',
                'value': 'SHAP Value',
                'abs_value': 'Importance',
                'direction': 'Direction'
            })
        
        # Round numerical values
        if 'SHAP Value' in df.columns:
            df['SHAP Value'] = df['SHAP Value'].round(4)
        if 'Importance' in df.columns:
            df['Importance'] = df['Importance'].round(4)
        
        return df
        
    except Exception as e:
        st.error(f"Error converting SHAP explanation: {str(e)}")
        return pd.DataFrame()


def convert_ae_explanation(ae_explanation_list):
    """
    Convert Autoencoder explanation list to DataFrame for display.
    
    Args:
        ae_explanation_list: List of AE explanation dictionaries
        
    Returns:
        pandas.DataFrame: Formatted DataFrame for display
    """
    if not ae_explanation_list:
        return pd.DataFrame()
    
    try:
        df = pd.DataFrame(ae_explanation_list)
        
        # Format the DataFrame for better display
        if 'feature' in df.columns:
            df = df.rename(columns={
                'feature': 'Feature',
                'error': 'Reconstruction Error',
                'original_value': 'Original',
                'reconstructed_value': 'Reconstructed',
                'contribution_percent': 'Contribution %'
            })
        
        # Round numerical values
        numerical_cols = ['Reconstruction Error', 'Original', 'Reconstructed', 'Contribution %']
        for col in numerical_cols:
            if col in df.columns:
                df[col] = df[col].round(4)
        
        return df
        
    except Exception as e:
        st.error(f"Error converting AE explanation: {str(e)}")
        return pd.DataFrame()


 