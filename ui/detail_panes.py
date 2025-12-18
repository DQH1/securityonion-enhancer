"""
UI Detail Panes Module
Contains functions for rendering detailed investigation and analysis panes.
"""

import streamlit as st
from datetime import datetime
from typing import Dict, Any


def render_ip_investigation_panel(detector):
    """Render IP investigation panel in sidebar."""
    with st.sidebar.expander("🔍 IP Investigation", expanded=True):
        st.markdown("### Active IP Profiles")
        
        try:
            if hasattr(detector.detection_engine, 'ml_handler') and detector.detection_engine.ml_handler:
                if hasattr(detector.detection_engine.ml_handler, 'runtime_profiler') and detector.detection_engine.ml_handler.runtime_profiler:
                    ip_profiles = detector.detection_engine.ml_handler.runtime_profiler.ip_profiles
                else:
                    ip_profiles = {}
            else:
                ip_profiles = {}
        except:
            ip_profiles = {}
        
        profile_count = len(ip_profiles)
        
        if profile_count > 0:
            st.caption(f"Found {profile_count} active IP profiles")
        else:
            st.caption("No active IP profiles")
        
        if profile_count == 0:
            st.info("No active IP profiles yet.")
            return
        
        # Sort IPs by connection count (descending) for better prioritization
        sorted_ips = sorted(
            ip_profiles.items(),
            key=lambda x: x[1].get('connection_count', 0),
            reverse=True
        )
        
        # Display top 10 IPs with investigation buttons
        for ip, profile in sorted_ips[:10]:
            connection_count = profile.get('connection_count', 0)
            unique_destinations = len(profile.get('unique_destinations', set()))
            
            # Create a compact display with investigation button
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.text(f"🔍 {ip}")
                st.caption(f"Connections: {connection_count}, Destinations: {unique_destinations}")
            
            with col2:
                if st.button("📊", key=f"investigate_{ip}", help=f"Investigate {ip}"):
                    st.session_state.investigated_ip = ip
                    st.session_state.selected_finding_id = None
                    st.rerun()
        
        # Show total count if there are more than 10
        if len(ip_profiles) > 10:
            remaining = len(ip_profiles) - 10
            st.caption(f"+ {remaining} more IPs")


def render_ip_investigation_report(detector):
    """Render detailed IP investigation report in sidebar."""
    investigated_ip = st.session_state.get('investigated_ip')
    if not investigated_ip:
        return
    
    st.sidebar.markdown(f"### 🔍 IP Investigation: `{investigated_ip}`")
    
    # Back button
    if st.sidebar.button("⬅️ Back to Findings"):
        st.session_state.investigated_ip = None
        st.rerun()
    
    st.sidebar.markdown("---")
    
    # Find all findings related to this IP
    related_findings = []
    for finding in st.session_state.findings.values():
        if finding['ip'] == investigated_ip:
            related_findings.append(finding)
    
    # Sort by risk score (descending)
    related_findings.sort(key=lambda x: x['risk_score'], reverse=True)
    
    # Summary metrics
    st.sidebar.markdown("### 📊 Summary")
    st.sidebar.metric("Related Findings", len(related_findings))
    
    if related_findings:
        avg_risk = sum(f['risk_score'] for f in related_findings) / len(related_findings)
        max_risk = max(f['risk_score'] for f in related_findings)
        st.sidebar.metric("Average Risk", f"{avg_risk:.1f}")
        st.sidebar.metric("Max Risk", f"{max_risk}")
    
    # Finding type breakdown
    finding_types = {}
    for finding in related_findings:
        finding_type = finding['attack_type']
        finding_types[finding_type] = finding_types.get(finding_type, 0) + 1
    
    if finding_types:
        st.sidebar.markdown("**Finding Types:**")
        for finding_type, count in sorted(finding_types.items(), key=lambda x: x[1], reverse=True):
            st.sidebar.text(f"• {finding_type}: {count}")
    
    # Total evidence count
    total_evidence = sum(finding['evidence_count'] for finding in related_findings)
    st.sidebar.metric("Total Evidence", total_evidence)
    
    # Time information from findings
    start_times = [finding['start_time'] for finding in related_findings]
    last_updates = [finding['last_updated'] for finding in related_findings]
    
    if start_times and last_updates:
        earliest = min(start_times)
        latest = max(last_updates)
        st.sidebar.markdown("**Activity Window:**")
        st.sidebar.text(f"First: {earliest.strftime('%Y-%m-%d %H:%M:%S')}")
        st.sidebar.text(f"Last: {latest.strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        if hasattr(detector.detection_engine, 'ml_handler') and detector.detection_engine.ml_handler:
            if hasattr(detector.detection_engine.ml_handler, 'runtime_profiler') and detector.detection_engine.ml_handler.runtime_profiler:
                profile = detector.detection_engine.ml_handler.runtime_profiler.ip_profiles.get(investigated_ip, {})
            else:
                profile = {}
        else:
            profile = {}
    except:
        profile = {}

    if profile:
        st.sidebar.markdown("---")
        st.sidebar.markdown("### 📊 Network Profile")
        st.sidebar.metric("Active Connections", profile.get('connection_count', 0))
        st.sidebar.metric("Unique Destinations", len(profile.get('unique_destinations', set())))
        
        if profile.get('unique_dest_ports'):
            st.sidebar.metric("Unique Ports", len(profile['unique_dest_ports']))
        
        # Connection states
        state_counts = profile.get('state_counts', {})
        if state_counts:
            st.sidebar.markdown("**Connection States:**")
            for state, count in sorted(state_counts.items(), key=lambda x: x[1], reverse=True)[:3]:
                st.sidebar.text(f"• {state}: {count}")
    
    # Related Findings Section
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🔍 Related Findings")
    
    if not related_findings:
        st.sidebar.info("No findings associated with this IP.")
    else:
        # Show findings in a scrollable container
        with st.sidebar.container():
            for i, finding in enumerate(related_findings):
                with st.sidebar.expander(f"{finding['attack_type']} (Risk: {finding['risk_score']})", expanded=i == 0):
                    st.markdown(f"**Status:** {finding['status']}")
                    st.markdown(f"**Evidence Count:** {finding['evidence_count']}")
                    st.markdown(f"**Created:** {finding['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                    st.markdown(f"**Last Updated:** {finding['last_updated'].strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    # Show sample evidence
                    if finding['evidence']:
                        st.markdown("**Sample Evidence:**")
                        for j, evidence in enumerate(finding['evidence'][:3]):  # Show first 3 pieces of evidence
                            evidence_type = evidence.get('type', 'Unknown')
                            timestamp = evidence.get('timestamp', 'Unknown')
                            st.caption(f"• {evidence_type} at {timestamp}")
                        
                        if len(finding['evidence']) > 3:
                            st.caption(f"+ {len(finding['evidence']) - 3} more evidence items")
    
    # Risk Assessment Summary
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🎯 Risk Assessment Summary")
    
    # Provide human-readable risk explanation based on findings
    risk_factors = []
    
    # Check findings for specific risk indicators
    for finding in related_findings:
        finding_type = finding['attack_type']
        risk_score = finding['risk_score']
        
        if finding_type == 'Port Scan':
            risk_factors.append(f"Port scanning activity (Risk: {risk_score})")
        elif finding_type == 'Connection Flood':
            risk_factors.append(f"Connection flooding (Risk: {risk_score})")
        elif finding_type == 'Data Exfiltration':
            risk_factors.append(f"Data exfiltration activity (Risk: {risk_score})")
        elif finding_type == 'Threat Intelligence Match':
            risk_factors.append(f"Known threat actor (Risk: {risk_score})")
        elif finding_type == 'C2 Beaconing':
            risk_factors.append(f"Command & Control communication (Risk: {risk_score})")
        elif risk_score >= 70:
            risk_factors.append(f"{finding_type} (High Risk: {risk_score})")
    
    # Check network profile if available
    try:
        if hasattr(detector.detection_engine, 'ml_handler') and detector.detection_engine.ml_handler:
            if hasattr(detector.detection_engine.ml_handler, 'runtime_profiler') and detector.detection_engine.ml_handler.runtime_profiler:
                profile = detector.detection_engine.ml_handler.runtime_profiler.ip_profiles.get(investigated_ip, {})
            else:
                profile = {}
        else:
            profile = {}
    except:
        profile = {}
    
    if profile:
        
        rej_count = profile.get('state_counts', {}).get('REJ', 0)
        if rej_count > 20:
            risk_factors.append(f"High rejection rate ({rej_count} REJ connections)")
        
        unique_ports = len(profile.get('unique_dest_ports', []))
        if unique_ports > 20:
            risk_factors.append(f"Multiple target ports ({unique_ports} ports)")
        
        connection_count = profile.get('connection_count', 0)
        if connection_count > 100:
            risk_factors.append(f"High connection volume ({connection_count} connections)")
    
    if risk_factors:
        st.sidebar.markdown("**Risk Indicators:**")
        for factor in risk_factors:
            st.sidebar.text(f"⚠️ {factor}")
    else:
        st.sidebar.success("✅ No significant risk indicators found")
    
    # Future LLM Integration Note
    st.sidebar.markdown("---")
    st.sidebar.info("🤖 **Future Enhancement**: This investigation will be enhanced with LLM-powered analysis for deeper insights.")


