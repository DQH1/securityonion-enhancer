"""
Main Streamlit Application Entry Point
Network Anomaly Detection Dashboard with modular architecture.
Run with: E:/conda/python.exe -m streamlit run app.py
"""

import streamlit as st
import time
import logging
from datetime import datetime
import os
import json

# Set up logging for UI
logger = logging.getLogger(__name__)

try:
    from backend_orchestrator import BackendOrchestrator
except ImportError as e:
    st.error(f" Failed to import BackendOrchestrator: {e}")
    BackendOrchestrator = None

#  OPTIMIZED: Lazy load UI components
def get_ui_components():
    """ OPTIMIZED: Lazy load UI components to avoid import overhead."""
    try:
        from ui.state_manager import initialize_alert_session_state, reset_session_state
        from ui.sidebar import render_dynamic_sidebar
        from ui.dashboard import display_findings_board
        from ui.helpers import collect_all_findings_for_export
        return {
            'initialize_alert_session_state': initialize_alert_session_state,
            'reset_session_state': reset_session_state,
            'render_dynamic_sidebar': render_dynamic_sidebar,
            'display_findings_board': display_findings_board,
            'collect_all_findings_for_export': collect_all_findings_for_export
        }
    except ImportError as e:
        st.error(f" Failed to import UI components: {e}")
        return None

#  OPTIMIZED: Lazy load config
def get_config():
    """ OPTIMIZED: Lazy load config to avoid import overhead."""
    try:
        from config import (
            TENSORFLOW_AVAILABLE, SHAP_AVAILABLE, MODEL_DIRECTORY, 
            DNS_MODEL_DIRECTORY, PREPROCESSOR_FILE, ISOLATION_FOREST_FILE, 
            AUTOENCODER_FILE, DNS_ISOLATION_FOREST_FILE, DNS_AUTOENCODER_FILE
        )
        return {
            'TENSORFLOW_AVAILABLE': TENSORFLOW_AVAILABLE,
            'SHAP_AVAILABLE': SHAP_AVAILABLE,
            'MODEL_DIRECTORY': MODEL_DIRECTORY,
            'DNS_MODEL_DIRECTORY': DNS_MODEL_DIRECTORY,
            'PREPROCESSOR_FILE': PREPROCESSOR_FILE,
            'ISOLATION_FOREST_FILE': ISOLATION_FOREST_FILE,
            'AUTOENCODER_FILE': AUTOENCODER_FILE,
            'DNS_ISOLATION_FOREST_FILE': DNS_ISOLATION_FOREST_FILE,
            'DNS_AUTOENCODER_FILE': DNS_AUTOENCODER_FILE
        }
    except ImportError as e:
        st.error(f" Failed to import config: {e}")
        return None

#  OPTIMIZED: Lazy load utility functions
def get_utility_functions():
    """ OPTIMIZED: Lazy load utility functions to avoid import overhead."""
    try:
        from utils.helpers import generate_alert_id
        from core.correlation_engine import write_findings_to_jsonl
        return {
            'generate_alert_id': generate_alert_id,
            'write_findings_to_jsonl': write_findings_to_jsonl
        }
    except ImportError as e:
        st.error(f" Failed to import utility functions: {e}")
        return None


def _load_findings_from_file(filepath: str = 'output/alerts.jsonl'):
    """Read findings from JSONL file when backend runs in separate process."""
    try:
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return []
        findings = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except Exception:
                    continue
        return findings
    except Exception:
        return []

# Set up logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def render_export_alerts_button():
    """ OPTIMIZED: Render the export all findings to JSON functionality."""
    #  OPTIMIZED: Lazy load UI components
    ui_components = get_ui_components()
    if ui_components is None:
        st.error(" UI components not available")
        return
    
    # Collect all findings from session state
    all_findings_data = ui_components['collect_all_findings_for_export']()
    
    if all_findings_data:
        st.markdown("### 📥 Export Data")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            try:
                total_findings = len(all_findings_data.get('findings', {}))
            except Exception:
                total_findings = 0
            st.info(f"📊 Ready to export {total_findings} findings with complete evidence trails")
        
        with col2:
            # Convert to JSON string for download
            import json
            findings_json = json.dumps(all_findings_data, indent=2, default=str)
            
            st.download_button(
                label="💾 Download JSON",
                data=findings_json,
                file_name=f"network_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
    else:
        st.info("📋 No findings available for export yet.")


@st.cache_resource
def get_orchestrator():
    """ OPTIMIZED: Cached orchestrator to avoid re-initialization."""
    return BackendOrchestrator()

@st.cache_data(ttl=5)  # Short cache to reflect model load quickly
def get_model_status(_orchestrator):
    """ OPTIMIZED: Cached model status; lazily ensure models are loaded once."""
    try:
        # Ensure ML models are loaded at least once
        try:
            _orchestrator.detection_engine._ensure_ml_models_loaded()
        except Exception:
            pass
        mlh = _orchestrator.detection_engine.ml_handler
        return mlh.get_model_status() if mlh is not None else {
            'isolation_forest': False,
            'autoencoder': False,
            'dns_models': False,
            'preprocessor': False
        }
    except Exception:
        return {'isolation_forest': False, 'autoencoder': False, 'dns_models': False, 'preprocessor': False}

@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_dns_model_status(_orchestrator):
    """ OPTIMIZED: Cached DNS model status; lazily ensure models are loaded once."""
    try:
        try:
            _orchestrator.detection_engine._ensure_ml_models_loaded()
        except Exception:
            pass
        return _orchestrator.detection_engine.get_dns_model_status()
    except Exception:
        return {'dns_models_loaded': False}

@st.cache_data(ttl=10)  # Cache for 10 seconds
def get_system_status(_orchestrator):
    """ OPTIMIZED: Cached system status to avoid repeated Redis connections."""
    status = {}
    
    # Redis status
    try:
        redis_client = _orchestrator._create_redis_connection()
        redis_client.ping()
        status['redis'] = ("Connected", "OK")
    except Exception:
        status['redis'] = ("Disconnected", "ERROR")
    
    # Findings count
    try:
        total_findings = len(st.session_state.get('findings', {}))
        high_risk = len([f for f in st.session_state.get('findings', {}).values() if f.get('risk_score', 0) >= 75])
        status['findings'] = (total_findings, high_risk)
    except Exception:
        status['findings'] = (0, 0)
    
    return status

@st.cache_data(ttl=5)  # Cache for 5 seconds
def get_findings_display_data(_session_state):
    """ OPTIMIZED: Cached findings data to avoid repeated processing."""
    return {
        'findings': _session_state.get('findings', {}),
        'total_count': len(_session_state.get('findings', {})),
        'high_risk_count': len([f for f in _session_state.get('findings', {}).values() if f.get('risk_score', 0) >= 75])
    }

def main():
    """ OPTIMIZED: Main Streamlit application with performance improvements."""
    st.title("🛡️ Network Anomaly Detection Dashboard")
    st.markdown("Real-time network security monitoring with ML and behavioral analysis")
    
    #  OPTIMIZED: Use cached orchestrator
    if 'orchestrator' not in st.session_state:
        st.session_state.orchestrator = get_orchestrator()
        
        # Set up UI callbacks for the orchestrator
        ui_callbacks = {
            'show_warning': lambda msg: st.sidebar.warning(msg),
            'show_info': lambda msg: st.sidebar.info(msg),
            'show_success': lambda msg: st.sidebar.success(msg),
            'show_error': lambda msg: st.error(msg)
        }
        st.session_state.orchestrator.set_ui_callbacks(ui_callbacks)
    
    #  OPTIMIZED: Lazy load LLM client only when needed
    if 'llm_client' not in st.session_state:
        try:
            from openai import OpenAI
            st.session_state.llm_client = OpenAI(
                base_url="http://localhost:8080/v1", 
                api_key="not-needed"
            )
            st.session_state.orchestrator.llm_client = st.session_state.llm_client
        except Exception as e:
            st.session_state.llm_client = None
            st.session_state.orchestrator.llm_client = None
    
    
    orchestrator = st.session_state.orchestrator
    
    # Ensure orchestrator has access to LLM client
    if hasattr(st.session_state, 'llm_client') and st.session_state.llm_client:
        orchestrator.llm_client = st.session_state.llm_client
    
    # Initialize Redis-based processing system
    if 'redis_system_initialized' not in st.session_state:
        # Initializing Redis-based log processing system
        st.session_state.redis_system_initialized = True
    

    try:
        orchestrator.detection_engine._ensure_ml_models_loaded()
    except Exception:
        pass
    model_status = get_model_status(orchestrator)
    models_available = any([
        model_status.get('isolation_forest', False),
        model_status.get('autoencoder', False),
        model_status.get('dns_models', False),
        model_status.get('preprocessor', False)
    ])
    
    #  OPTIMIZED: Lazy load config
    config = get_config()
    if config is None:
        st.error(" Failed to load configuration")
        return
    
    if not models_available:
        st.error(" No ML models loaded. System will operate with behavioral detection only.")
        with st.expander("📋 Model Setup Instructions"):
            st.info("To enable ML detection, ensure these files are available:")
            st.info(f"   • {config['MODEL_DIRECTORY']}/{config['PREPROCESSOR_FILE']}")
            st.info(f"   • {config['MODEL_DIRECTORY']}/{config['ISOLATION_FOREST_FILE']}")
            st.info(f"   • {config['MODEL_DIRECTORY']}/{config['AUTOENCODER_FILE']}")
            st.info(f"   • {config['DNS_MODEL_DIRECTORY']}/{config['DNS_ISOLATION_FOREST_FILE']} (for DNS detection)")
            st.info(f"   • {config['DNS_MODEL_DIRECTORY']}/{config['DNS_AUTOENCODER_FILE']} (for DNS detection)")
            st.info("Run train_enhanced_models.py and sentinel_core_training.py to generate models.")
    else:
        #  OPTIMIZED: Compact model status display
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if model_status['isolation_forest'] and model_status['autoencoder']:
                st.success("🛡️ CONN.LOG: Ready")
            elif model_status['isolation_forest'] or model_status['autoencoder']:
                st.warning("⚠️ CONN.LOG: Partial")
            else:
                st.error(" CONN.LOG: None")
        
        with col2:
            dns_model_status = get_dns_model_status(orchestrator)
            if dns_model_status['dns_models_loaded']:
                st.success("🛡️ DNS.LOG: Ready")
            else:
                st.info("ℹ DNS.LOG: None")
        
        with col3:
            if not config['TENSORFLOW_AVAILABLE']:
                st.warning("⚠️ TensorFlow: Disabled")
            if not config['SHAP_AVAILABLE']:
                st.warning("⚠️ SHAP: Disabled")

    #  FIX: Single UI components loading to prevent race condition
    if 'session_initialized' not in st.session_state:
        ui_components = get_ui_components()
        if ui_components:
            ui_components['initialize_alert_session_state']()
        st.session_state.session_initialized = True
        #  FIX: Store UI components in session state to avoid reloading
        st.session_state.ui_components = ui_components
    
    #  FIX: Use cached UI components from session state
    ui_components = st.session_state.get('ui_components')
    if ui_components:
        ui_components['render_dynamic_sidebar'](orchestrator)
    else:
        #  FIX: Fallback if components not cached
        ui_components = get_ui_components()
        if ui_components:
            st.session_state.ui_components = ui_components
            ui_components['render_dynamic_sidebar'](orchestrator)
    
    
    #  OPTIMIZED: Manual Redis processing trigger with better UX
    if st.session_state.get('manual_redis_requested', False):
        try:
            findings_before = len(st.session_state.get('findings', {}))
        except Exception:
            findings_before = 0
        
        with st.spinner(" Processing Redis logs..."):
            try:
                #  OPTIMIZED: Use cached processing for better performance
                collection_result = orchestrator._collect_logs_from_redis_fifo(time_window_seconds=1)
                
                if collection_result['success'] and collection_result['total_collected'] > 0:
                    result = orchestrator._process_fifo_queues(max_logs_per_cycle=collection_result['total_collected'])
                    
                    if result['success'] and result.get('alerts_generated', 0) > 0:
                        # Force sync processed findings from backend
                        processed_findings = orchestrator.get_processed_findings()
                        if processed_findings:
                            logger.info(f"🔄 Force syncing {len(processed_findings)} findings after batch processing")
                            
                            # Convert backend findings to UI format (same as auto-sync logic)
                            new_findings_dict = {}
                            for finding in processed_findings:
                                #  FIX: Use backend finding_id directly to ensure sync
                                finding_id = finding.get('finding_id', '')
                                if not finding_id:
                                    # Fallback: Create ID using IP and timestamp if finding_id missing
                                    finding_ip = finding.get('ip', 'unknown') 
                                    finding_created = finding.get('created_at', '')
                                    finding_id = f"finding_{finding_ip}_{finding_created.replace(':', '').replace('-', '').replace('.', '')}"
                                
                                if 'last_updated' not in finding:
                                    finding['last_updated'] = finding.get('created_at', datetime.now().isoformat())
                                
                                new_findings_dict[finding_id] = finding
                            
                            st.session_state.findings = new_findings_dict.copy()  # Copy to ensure atomicity
                            logger.info(f" Immediate UI sync completed: {len(new_findings_dict)} findings")
                else:
                    result = {'success': True, 'lines_processed': 0, 'alerts_generated': 0, 'new_alerts': []}
                
                if result['success']:
                    alerts_generated = result.get('alerts_generated', 0)
                    lines_processed = result.get('lines_processed', 0)
                    
                    if lines_processed > 0:
                        st.success(f" Processed {lines_processed} Redis logs, generated {alerts_generated} alerts")
                        
                        #  FIX: Use consistent findings count from new_findings_dict
                        ui_findings_count = len(new_findings_dict) if 'new_findings_dict' in locals() else 0
                        if ui_findings_count > 0:
                            st.success(f"🎯 Dashboard now shows {ui_findings_count} total findings")
                        else:
                            st.warning("⚠️ No findings visible on dashboard yet - checking correlation...")
                    else:
                        st.info("ℹ No logs in Redis queue")
                else:
                    st.error(f" Redis processing failed: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                st.error(f" Error during Redis processing: {str(e)}")
        
        #  OPTIMIZED: Simplified results display
        try:
            findings_after = len(st.session_state.get('findings', {}))
            new_findings_detected = findings_after > findings_before
        except Exception:
            findings_after = findings_before
            new_findings_detected = False
        
        del st.session_state.manual_redis_requested
        
        if new_findings_detected:
            st.success(f"🎉 Manual processing complete: {findings_after - findings_before} new findings detected!")
        else:
            st.info("ℹ Manual processing complete: No new findings")
    
    # 🆕 FIX: Background Monitoring Controls
    st.subheader("🔄 Background Monitoring Controls")
    
    col_monitor1, col_monitor2, col_monitor3 = st.columns(3)
    
    with col_monitor1:
        if st.button("🚀 Start Background Monitoring", use_container_width=True, type="primary", key="main_start_monitoring"):
            try:
                if 'orchestrator' in st.session_state:
                    orchestrator = st.session_state.orchestrator
                    
                    #  FIX: Check if monitoring is already active
                    if st.session_state.get('monitoring_active', False):
                        st.warning("⚠️ Background monitoring is already active!")
                        return
                    
                    # Start background monitoring with default config
                    config = {
                        'collection_window_seconds': 0.5,
                        'processing_cycle_size': 500,
                        'enable_priority_processing': True,
                        'process_backlog_first': True,
                        'max_backlog_threshold': 2000
                    }
                    
                    result = orchestrator.start_dual_log_monitoring(config)
                    
                    if result.get('success'):
                        st.session_state.monitoring_active = True
                        st.session_state.monitoring_thread_info = {
                            'name': result.get('thread_name'),
                            'id': result.get('thread_id')
                        }
                        st.success(f" Background monitoring started!")
                        st.info(f"Thread: {result.get('thread_name')} (ID: {result.get('thread_id')})")
                        
                        #  FIX: Initialize auto-refresh timer
                        st.session_state.last_auto_refresh = time.time()
                        st.rerun()
                    else:
                        st.error(" Failed to start background monitoring")
                else:
                    st.error(" Orchestrator not available")
            except Exception as e:
                st.error(f" Error starting monitoring: {str(e)}")
                logger.error(f"Background monitoring start failed: {e}")
    
    with col_monitor2:
        if st.button("🛑 Stop Background Monitoring", use_container_width=True, type="secondary", key="main_stop_monitoring"):
            try:
                if 'orchestrator' in st.session_state:
                    orchestrator = st.session_state.orchestrator
                    
                    #  FIX: Check if monitoring is already stopped
                    if not st.session_state.get('monitoring_active', False):
                        st.warning("⚠️ Background monitoring is already stopped!")
                        return
                    
                    if hasattr(orchestrator, 'stop_monitoring'):
                        result = orchestrator.stop_monitoring()
                        if result:
                            # FIXED: Preserve findings before stopping monitoring
                            current_findings = st.session_state.get('findings', {})
                            if current_findings:
                                st.success(f" Background monitoring stopped! Preserving {len(current_findings)} findings.")
                            else:
                                st.success(" Background monitoring stopped!")
                            
                            st.session_state.monitoring_active = False
                            st.session_state.monitoring_thread_info = None
                            
                            #  FIX: Clear auto-refresh timer
                            if 'last_auto_refresh' in st.session_state:
                                del st.session_state.last_auto_refresh
                            

                        else:
                            st.error(" Failed to stop background monitoring")
                    else:
                        st.error(" Stop monitoring method not available")
                else:
                    st.error(" Orchestrator not available")
            except Exception as e:
                st.error(f" Error stopping monitoring: {str(e)}")
                logger.error(f"Background monitoring stop failed: {e}")
    
    with col_monitor3:
        # Show monitoring status
        if st.session_state.get('monitoring_active', False):
            thread_info = st.session_state.get('monitoring_thread_info', {})
            st.success("🔄 Background Monitoring: ACTIVE")
            if thread_info:
                st.caption(f"Thread: {thread_info.get('name', 'Unknown')}")
        else:
            st.info("⏸️ Background Monitoring: INACTIVE")
    
    # Show monitoring instructions
    if not st.session_state.get('monitoring_active', False):
        st.info("ℹ️ **Background Monitoring Instructions:**")
        st.info("1. Click 'Start Background Monitoring' to begin real-time log processing")
        st.info("2. The system will continuously collect logs from Redis in the background")
        st.info("3. UI will remain responsive while processing continues")
        st.info("4. Click 'Stop Background Monitoring' to halt processing")
        st.info("5. Findings will be automatically synced to the dashboard")
        
        current_findings = st.session_state.get('findings', {})
        if current_findings:
            st.success(f"📊 **Current Status:** {len(current_findings)} findings are preserved and displayed below")
        else:
            st.warning("⚠️ **Current Status:** No findings available. Start monitoring to detect anomalies.")
    
    try:
        if 'orchestrator' in st.session_state:
            orchestrator = st.session_state.orchestrator
            
            # Get processed findings from orchestrator
            processed_findings = orchestrator.get_processed_findings()
            
            # FIXED: Always preserve existing findings when monitoring stops
            current_findings = st.session_state.get('findings', {})
            
            if processed_findings:
                # Use backend findings if available
                new_findings_dict = {}
                for i, finding in enumerate(processed_findings):
                    finding_id = finding.get('finding_id', '')
                    if not finding_id:
                        finding_ip = finding.get('ip', 'unknown')
                        finding_created = finding.get('created_at', '')
                        finding_id = f"finding_{finding_ip}_{finding_created.replace(':', '').replace('-', '').replace('.', '')}"
                    
                    # Ensure last_updated is set
                    if 'last_updated' not in finding:
                        finding['last_updated'] = finding.get('created_at', datetime.now().isoformat())
                    
                    new_findings_dict[finding_id] = finding
                
                if new_findings_dict != current_findings:
                    st.session_state.findings = new_findings_dict.copy()
                    
                    backend_findings_count = len(processed_findings)
                    ui_findings_count = len(new_findings_dict)
                    
                    monitoring_status = "🔄" if st.session_state.get('monitoring_active', False) else "⏸️"
                    
                    if backend_findings_count != ui_findings_count:
                        st.success(f"{monitoring_status} Auto-synced findings: Backend({backend_findings_count}) → UI({ui_findings_count})")
                    else:
                        st.success(f"{monitoring_status} Auto-synced findings: {ui_findings_count} findings synchronized")
                    
                    if st.session_state.get('monitoring_active', False):
                        thread_info = st.session_state.get('monitoring_thread_info', {})
                        if thread_info:
                            st.info(f"🔄 Background monitoring active - Thread: {thread_info.get('name', 'Unknown')} (ID: {thread_info.get('id', 'Unknown')})")
                    
                    logger.info(f" UI findings synced: {ui_findings_count} total findings")
                    
                    if st.session_state.get('monitoring_active', False) and len(new_findings_dict) > len(current_findings):
                        st.rerun()  # Auto-refresh to show new findings immediately
            else:
                # FIXED: When no backend findings, preserve existing findings and try file reading
                if not current_findings:
                    # Only load from file if we have no findings at all
                    from ui.dashboard import get_optimized_findings
                    optimized_findings = get_optimized_findings(st.session_state, 'output/alerts.jsonl')
                    
                    if optimized_findings:
                        st.session_state.findings = optimized_findings.copy()
                        st.success(f"📊 Loaded {len(optimized_findings)} findings from file (optimized)")
                    else:
                        st.info("🔍 No findings available from backend or file")
                else:
                    # Preserve existing findings when monitoring stops
                    st.info(f"📊 Preserving {len(current_findings)} existing findings (monitoring stopped)")
                    
    except Exception as e:
        error_msg = f"Auto-sync failed: {str(e)}"
        logger.error(f" {error_msg}")
        
        # Show user-friendly error message
        if "orchestrator" in str(e).lower():
            st.warning("⚠️ Auto-sync temporarily unavailable - orchestrator not ready")
        elif "connection" in str(e).lower():
            st.warning("⚠️ Auto-sync failed - connection issue detected")
        else:
            st.warning(f"⚠️ Auto-sync failed: {type(e).__name__}")
        
        # Don't show technical error details to user in demo
        if st.session_state.get('debug_mode', False):
            st.error(f"Debug details: {error_msg}")
    
    st.header("🛡️ Security Alerts Dashboard")
    
    system_status = get_system_status(orchestrator)
    
    col_status1, col_status2, col_status3 = st.columns(3)
    
    with col_status1:
        st.metric("📡 Redis", system_status['redis'][0], delta=system_status['redis'][1])
    
    with col_status2:
        st.metric(" Total Findings", system_status['findings'][0])
        if system_status['findings'][0] == 0:
            st.caption("⚠️ No findings loaded")
        else:
            st.caption(f" {system_status['findings'][0]} findings ready")
    
    with col_status3:
        st.metric("🔴 High Risk", system_status['findings'][1])
    
    # Export functionality
    render_export_alerts_button()
    
    if st.session_state.get('monitoring_active', False):
        # Auto-refresh every 10 seconds when background monitoring is active (reduced from 5s for better performance)
        current_time = time.time()
        last_refresh = st.session_state.get('last_auto_refresh', 0)
        
        if (current_time - last_refresh > 10 and  # 10 second interval (increased for performance)
            'last_auto_refresh' not in st.session_state or  # First time
            current_time - last_refresh > 15):  # Max 15 second gap for safety
            
            st.session_state.last_auto_refresh = current_time
            logger.info(f"🔄 Auto-refreshing UI for background monitoring (interval: {current_time - last_refresh:.1f}s)")
            st.rerun()
    
    with st.expander(" Debug Controls", expanded=False):
        col_debug1, col_debug2, col_debug3 = st.columns(3)
        
        with col_debug1:
            if st.button(" Test Finding", use_container_width=True, key="debug_test_finding"):
                test_finding = {
                    'title': 'Test Finding - Nmap Scanning',
                    'ip': '192.168.1.100',
                    'risk_score': 85,
                    'severity': 'high',
                    'finding_type': 'port_scanning',
                    'evidence_count': 1,
                    'last_updated': '2025-01-12T12:00:00',
                    'description': 'Test finding for debugging dashboard display'
                }
                
                try:
                    if 'test_finding_counter' not in st.session_state:
                        st.session_state.test_finding_counter = 0
                    
                    st.session_state.test_finding_counter += 1
                    new_id = f"test_finding_{st.session_state.test_finding_counter}"
                    
                    current_findings = st.session_state.get('findings', {}).copy()
                    current_findings[new_id] = test_finding
                    st.session_state.findings = current_findings
                    
                    st.success(f" Test finding added: {new_id}")
                    st.rerun()
                except Exception as e:
                    st.error(f" Failed to add test finding: {str(e)}")
                    logger.error(f"Test finding creation failed: {e}")
            
            if st.button(" 🔄 Trigger Correlation", use_container_width=True, key="debug_trigger_correlation"):
                try:
                    if 'orchestrator' in st.session_state:
                        orchestrator = st.session_state.orchestrator
                        findings = orchestrator.correlate_alerts(time_window_minutes=3)
                        if findings:
                            st.success(f" Correlation completed: {len(findings)} findings generated")
                            st.rerun()
                        else:
                            st.warning("⚠️ No findings generated from correlation")
                    else:
                        st.error(" Orchestrator not available")
                except Exception as e:
                    st.error(f" Correlation failed: {str(e)}")
        
        with col_debug2:
            if st.button(" Clear All", use_container_width=True, key="debug_clear_all"):
                st.session_state.findings = {}
                st.success(" All findings cleared")
                st.rerun()
        
        with col_debug3:
            if st.button(" Force Sync", use_container_width=True, key="debug_force_sync"):
                try:
                    if 'orchestrator' in st.session_state:
                        orchestrator = st.session_state.orchestrator
                        processed_findings = orchestrator.get_processed_findings()
                        
                        if processed_findings:
                            # Load findings từ orchestrator memory
                            new_findings_dict = {}
                            for i, finding in enumerate(processed_findings):
                                finding_id = finding.get('finding_id', '')
                                if not finding_id:
                                    finding_ip = finding.get('ip', 'unknown')
                                    finding_created = finding.get('created_at', '')
                                    finding_id = f"finding_{finding_ip}_{finding_created.replace(':', '').replace('-', '').replace('.', '')}"
                                
                                if 'last_updated' not in finding:
                                    finding['last_updated'] = finding.get('created_at', datetime.now().isoformat())
                                
                                new_findings_dict[finding_id] = finding
                            
                            st.session_state.findings = new_findings_dict.copy()
                            st.success(f" Force synced {len(processed_findings)} findings from orchestrator")
                            time.sleep(0.1)  
                            st.rerun()
                        else:
                            st.info("🔄 No findings in orchestrator, trying to load from file...")
                            
                            # Method 1: Try optimized loading first
                            from ui.dashboard import get_optimized_findings
                            file_findings = get_optimized_findings(st.session_state, 'output/alerts.jsonl')
                            
                            if file_findings:
                                st.session_state.findings = file_findings.copy()
                                st.success(f"📊 Force synced {len(file_findings)} findings from file (optimized)")
                                time.sleep(0.1)
                                st.rerun()
                            else:
                                # Method 2: Try direct file reading as fallback
                                st.info("🔄 Trying direct file reading...")
                                
                                try:
                                    import json
                                    findings = []
                                    with open('output/alerts.jsonl', 'r', encoding='utf-8', errors='ignore') as f:
                                        for line in f:
                                            line = line.strip()
                                            if line:
                                                try:
                                                    finding = json.loads(line)
                                                    findings.append(finding)
                                                except json.JSONDecodeError:
                                                    continue
                                    
                                    if findings:
                                        # Convert to findings dict
                                        findings_dict = {}
                                        for finding in findings:
                                            finding_id = finding.get('finding_id', '')
                                            if not finding_id:
                                                finding_ip = finding.get('ip', 'unknown')
                                                finding_created = finding.get('created_at', '')
                                                finding_id = f"finding_{finding_ip}_{finding_created.replace(':', '').replace('-', '').replace('.', '')}"
                                            
                                            if 'last_updated' not in finding:
                                                finding['last_updated'] = finding.get('created_at', datetime.now().isoformat())
                                            
                                            findings_dict[finding_id] = finding
                                        
                                        st.session_state.findings = findings_dict.copy()
                                        st.success(f"📊 Force synced {len(findings_dict)} findings from file (direct read)")
                                        time.sleep(0.1)
                                        st.rerun()
                                    else:
                                        st.warning("⚠️ No findings available from orchestrator or file")
                                        
                                except Exception as file_error:
                                    st.error(f"📁 File reading failed: {str(file_error)}")
                                    st.warning("⚠️ No findings available from orchestrator or file")
                    else:
                        st.error(" No orchestrator available")
                except Exception as e:
                    st.error(f" Force sync failed: {str(e)}")
    
    st.markdown("---")
    
    # Get cached findings data
    findings_data = get_findings_display_data(st.session_state)
    
    ui_components = get_ui_components()
    if ui_components:
        ui_components['display_findings_board'](st.session_state)
    else:
        st.error(" Failed to load findings display component")
    
    if 'last_refresh' not in st.session_state or st.session_state.last_refresh is None:
        st.session_state.last_refresh = time.time()
    
    current_time = time.time()
    last_refresh = st.session_state.last_refresh or 0.0
    

    try:
        has_findings = findings_data.get('total_count', 0) > 0
        elapsed = current_time - float(last_refresh)
    except Exception:
        has_findings = False
        elapsed = 31  # force refresh on error

    should_refresh = False
    if elapsed > 5:  # Base refresh every 5 seconds
        if has_findings and elapsed > 2:  # Faster refresh when findings exist
            should_refresh = True
        elif elapsed > 10:  # Force refresh every 10 seconds max
            should_refresh = True
    
    if should_refresh:
        st.session_state.last_refresh = current_time
        time.sleep(0.05)
        st.rerun()


if __name__ == "__main__":
    main() 