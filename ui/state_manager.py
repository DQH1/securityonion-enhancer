"""
UI State Manager Module
Manages Streamlit session state for the network anomaly detection application.
"""

import streamlit as st
from typing import Dict, Any, List
from datetime import datetime, timedelta
from collections import deque
import logging
import time

# Set up logging
logger = logging.getLogger(__name__)

# PERFORMANCE OPTIMIZATION: Cache settings
CACHE_DURATION_SECONDS = 30  # Cache results for 30 seconds
MAX_CACHE_SIZE = 100  # Maximum number of cached items

def initialize_alert_session_state():
    """Initialize session state variables for the alert monitoring system with performance optimizations."""
    
    # Initialize findings cache for performance
    if 'findings_cache' not in st.session_state:
        st.session_state.findings_cache = {}
        st.session_state.cache_timestamps = {}
    
    # Initialize pagination
    if 'findings_page' not in st.session_state:
        st.session_state.findings_page = 0
    
    # Performance monitoring
    if 'last_cache_cleanup' not in st.session_state:
        st.session_state.last_cache_cleanup = time.time()
    
    # Core alert storage
    if 'all_raw_detection_events' not in st.session_state:
        st.session_state.all_raw_detection_events = []
    
    if 'findings' not in st.session_state:
        st.session_state.findings = {}
    
    # UI state management
    if 'selected_finding' not in st.session_state:
        st.session_state.selected_finding = None
    
    if 'selected_finding_id' not in st.session_state:
        st.session_state.selected_finding_id = None
    
    if 'show_finding_detail' not in st.session_state:
        st.session_state.show_finding_detail = False
    
    # Filter states
    if 'findings_filter_source' not in st.session_state:
        st.session_state.findings_filter_source = "All Sources"
    
    if 'findings_filter_risk' not in st.session_state:
        st.session_state.findings_filter_risk = "All Risk Levels"
    
    if 'findings_filter_ip' not in st.session_state:
        st.session_state.findings_filter_ip = ""
    
    # Additional filter states for sidebar
    if 'filter_alert_types' not in st.session_state:
        st.session_state.filter_alert_types = ['ML Anomaly', 'Port Scan', 'Data Exfiltration', 'C2 Beaconing']
    
    if 'filter_severity' not in st.session_state:
        st.session_state.filter_severity = ['Critical', 'High', 'Medium', 'Low']
    
    if 'filter_ip_search' not in st.session_state:
        st.session_state.filter_ip_search = ''
    
    if 'filter_alert_status' not in st.session_state:
        st.session_state.filter_alert_status = 'All Findings'
    
    # Investigation states
    if 'investigation_ip' not in st.session_state:
        st.session_state.investigation_ip = ""
    
    if 'investigated_ip' not in st.session_state:
        st.session_state.investigated_ip = None
    
    if 'investigation_report' not in st.session_state:
        st.session_state.investigation_report = None
    

    
    # System status
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = None
    
    if 'processing_status' not in st.session_state:
        st.session_state.processing_status = "Ready"
    
    if 'processing_active' not in st.session_state:
        st.session_state.processing_active = True
    

    
    
    # Attack simulation states
    if 'attack_results' not in st.session_state:
        st.session_state.attack_results = {}
    
    # Human feedback states
    if 'feedback_results' not in st.session_state:
        st.session_state.feedback_results = {}
    
    # Export states
    if 'export_status' not in st.session_state:
        st.session_state.export_status = None


def reset_session_state():
    """
    Reset all session state variables to their default values.
    This is useful for clearing the application state.
    """
    # Clear core alert data
    st.session_state.all_raw_detection_events = []
    st.session_state.findings = {}
    
    # Reset UI states
    st.session_state.selected_finding = None
    st.session_state.selected_finding_id = None
    st.session_state.show_finding_detail = False
    
    # Reset filter states
    st.session_state.findings_filter_source = "All Sources"
    st.session_state.findings_filter_risk = "All Risk Levels"
    st.session_state.findings_filter_ip = ""
    
    # Reset additional filter states
    st.session_state.filter_alert_types = ['ML Anomaly', 'Port Scan', 'Data Exfiltration', 
                                          'C2 Beaconing']
    st.session_state.filter_severity = ['Critical', 'High', 'Medium', 'Low']
    st.session_state.filter_ip_search = ''
    st.session_state.filter_alert_status = 'All Findings'
    
    # Reset investigation states
    st.session_state.investigation_ip = ""
    st.session_state.investigated_ip = None
    st.session_state.investigation_report = None
    

    # Reset system status
    st.session_state.last_refresh = None
    st.session_state.processing_status = "Ready"
    st.session_state.processing_active = True
    

    
    # Reset attack simulation states
    st.session_state.attack_results = {}
    
    # Reset feedback states
    st.session_state.feedback_results = {}
    
    # Reset export states
    st.session_state.export_status = None
    
    st.success("🔄 Session state has been reset!") 

# Add cache management functions

def get_cached_finding(finding_id: str) -> Dict[str, Any]:
    """Get cached finding with timestamp validation."""
    try:
        # ✅ FIX: Safe cache access with error handling
        cache = st.session_state.get('findings_cache', {})
        timestamps = st.session_state.get('cache_timestamps', {})
        
        if finding_id in cache:
            cache_time = timestamps.get(finding_id, 0)
            if time.time() - cache_time < CACHE_DURATION_SECONDS:
                return cache[finding_id]
        return None
    except Exception as e:
        logger.error(f"Error accessing cached finding {finding_id}: {e}")
        return None

def cache_finding(finding_id: str, finding_data: Dict[str, Any]) -> None:
    """Cache finding data with timestamp."""
    try:
        # ✅ FIX: Safe cache access with error handling
        current_time = time.time()
        
        # Initialize cache if not exists
        if 'findings_cache' not in st.session_state:
            st.session_state.findings_cache = {}
        if 'cache_timestamps' not in st.session_state:
            st.session_state.cache_timestamps = {}
        if 'last_cache_cleanup' not in st.session_state:
            st.session_state.last_cache_cleanup = current_time
        
        # Clean up old cache entries if needed
        if current_time - st.session_state.last_cache_cleanup > CACHE_DURATION_SECONDS:
            cleanup_cache()
            st.session_state.last_cache_cleanup = current_time
        
        # Add to cache
        st.session_state.findings_cache[finding_id] = finding_data
        st.session_state.cache_timestamps[finding_id] = current_time
        
        # Prevent cache from growing too large
        if len(st.session_state.findings_cache) > MAX_CACHE_SIZE:
            # Remove oldest entries
            sorted_items = sorted(st.session_state.cache_timestamps.items(), key=lambda x: x[1])
            for old_id, _ in sorted_items[:10]:  # Remove 10 oldest
                st.session_state.findings_cache.pop(old_id, None)
                st.session_state.cache_timestamps.pop(old_id, None)
    except Exception as e:
        logger.error(f"Error caching finding {finding_id}: {e}")

def cleanup_cache() -> None:
    """Remove expired cache entries."""
    try:
        # ✅ FIX: Safe cache cleanup with error handling
        current_time = time.time()
        expired_keys = []
        
        cache = st.session_state.get('findings_cache', {})
        timestamps = st.session_state.get('cache_timestamps', {})
        
        for finding_id, cache_time in timestamps.items():
            if current_time - cache_time > CACHE_DURATION_SECONDS:
                expired_keys.append(finding_id)
        
        for key in expired_keys:
            cache.pop(key, None)
            timestamps.pop(key, None)
        
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    except Exception as e:
        logger.error(f"Error during cache cleanup: {e}")

def get_cache_stats() -> Dict[str, Any]:
    """Get cache performance statistics."""
    try:
        # ✅ FIX: Safe cache stats access with error handling
        cache = st.session_state.get('findings_cache', {})
        timestamps = st.session_state.get('cache_timestamps', {})
        last_cleanup = st.session_state.get('last_cache_cleanup', 0)
        
        cache_size = len(cache)
        cache_age_avg = sum(time.time() - t for t in timestamps.values()) / max(1, len(timestamps)) if timestamps else 0
        
        return {
            'cache_size': cache_size,
            'cache_age_avg': cache_age_avg,
            'last_cleanup': last_cleanup
        }
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return {
            'cache_size': 0,
            'cache_age_avg': 0,
            'last_cleanup': 0
        } 