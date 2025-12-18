"""
Detection Engine module for network anomaly detection system.
Contains the main analysis logic for processing network connections and generating alerts.
"""

import pandas as pd
import numpy as np
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import time
from collections import defaultdict

from config import (
    get_demo_rules, get_dns_rules, MODEL_DIRECTORY
)
from core.data_processor import ProductionDataProcessor, DNSProductionDataProcessor
from core.ml_handler import MLHandler
from core.ip_profiler import UnifiedIPProfiler

from components.xai import format_shap_explanation, format_ae_explanation, translate_shap_to_human_readable

# Set up logging
logger = logging.getLogger(__name__)

# Add debug logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger.setLevel(logging.INFO)

# Add file handler for debug logs
debug_handler = logging.FileHandler('debug_detection_engine.log')
debug_handler.setLevel(logging.DEBUG)
debug_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
debug_handler.setFormatter(debug_formatter)
logger.addHandler(debug_handler)

class DetectionEngine:
    """
    Main detection engine that orchestrates all analysis components.
    Handles connection analysis, ML predictions, behavioral analysis, and threat intelligence.
    """
    
    def __init__(self):
        """Initialize the detection engine with all components."""
        self.ml_handler = None

        try:            
            # Initialize UnifiedIPProfiler for IP Profiler features
            self.ip_profiler = UnifiedIPProfiler(time_window_seconds=300)
            logger.info(f"UnifiedIPProfiler initialized with 300s time window")
            
            self.conn_processor = ProductionDataProcessor(
                model_dir=MODEL_DIRECTORY,
                detection_engine=self
            )
            
            # Set IP Profiler in ProductionDataProcessor
            self.conn_processor.ip_profiler = self.ip_profiler
            logger.info(f"[SUCCESS] ProductionDataProcessor initialized with shared IP Profiler instance and model_dir: {MODEL_DIRECTORY}")
            logger.info("ProductionDataProcessor initialized in DetectionEngine")
        except Exception as e:
            logger.warning(f"⚠️ Failed to initialize ProductionDataProcessor in DetectionEngine: {str(e)}")
            logger.info(f"   This is normal for demo mode - continuing without ProductionDataProcessor")
            self.conn_processor = None
        
        self.dns_processor = None
        
        
        # Alert management structures
        self.ml_alert_history = defaultdict(lambda: defaultdict(list))  
        self.recent_alerts = {}  
        self.threat_cache = {}   
        self.alert_cooldowns = defaultdict(dict) 
        
        self.dedup_window = 300  
    

    
    
    def _ensure_ml_models_loaded(self):
        """⚡ OPTIMIZED: Lazy load ML models only when needed."""
        if self.ml_handler is None:
            logger.info("[RELOAD] Lazy loading ML models...")
            self.ml_handler = MLHandler(
                conn_processor=self.conn_processor,
                dns_processor=self.dns_processor 
            )
            self.ml_handler.load_models()
            logger.info("[SUCCESS] ML models loaded successfully")
    
    def _is_duplicate_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Check if an alert is a duplicate based on attack type and source IP.
        Groups alerts by attack type + IP to prevent spam (e.g., 1000 port scan alerts → 1 alert).
        
        Args:
            alert: Alert dictionary
            
        Returns:
            True if alert should be rate limited, False otherwise
        """
        # Get attack type and source IP for rate limiting
        matched_scenario = alert.get('matched_scenario', '')
        src_ip = alert.get('src_ip', alert.get('ip', ''))
        
        if not matched_scenario or not src_ip:
            logger.debug(f"Missing scenario or IP for rate limiting: scenario={matched_scenario}, ip={src_ip}")
            return False
        
        # Create a key that groups alerts by attack type and source IP (not by individual connection)
        # This prevents spam alerts for the same attack type from the same IP
        key = f"{matched_scenario}_{src_ip}"
        
        current_time = time.time()
        
        # Check if we've seen this alert recently
        if key in self.recent_alerts:
            last_time = self.recent_alerts[key]
            if current_time - last_time < self.dedup_window:
                logger.debug(f"Duplicate alert detected: {key}")
                return True
                
        # Not a duplicate, update last seen time
        self.recent_alerts[key] = current_time
        return False
    
    def analyze_connections_batch(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple connections in batch for better performance.
        Uses BATCH ML PREDICTION for much better performance.
        
        Args:
            log_lines: List of connection log lines
            
        Returns:
            List of detection events/alerts
        """
        logger.debug(f"Starting batch analysis for {len(log_lines)} connection logs")
        logger.debug(f"First log sample: {log_lines[0][:100] if log_lines else 'No logs'}...")
        
        try:
            # ⚡ OPTIMIZED: Lazy load ML models only when needed
            self._ensure_ml_models_loaded()
            
            if not log_lines:
                logger.debug("⚠️ No log lines provided for batch analysis")
                return []
            
            logger.info(f"Starting BATCH analysis of {len(log_lines)} logs")
            
            # Filter out empty logs
            logger.debug("🔍 Filtering out empty logs...")
            valid_logs = [log for log in log_lines if log.strip()]
            empty_logs = len(log_lines) - len(valid_logs)
            if empty_logs > 0:
                logger.debug(f"📊 Filtered out {empty_logs} empty logs")
            
            if not valid_logs:
                logger.debug("⚠️ No valid logs after filtering")
                return []
            
            logger.debug(f"📊 Valid logs for processing: {len(valid_logs)}")
            
            # STEP 1: BATCH ML prediction - MUCH FASTER than individual calls
            logger.debug("STEP 1: Starting batch ML prediction...")
            logger.debug(f"Calling ml_handler.predict_batch_logs with {len(valid_logs)} logs")
            
            batch_ml_results = self.ml_handler.predict_batch_logs(valid_logs)
            
            logger.debug(f"📊 Batch ML prediction completed: {len(batch_ml_results)} results returned")
            if batch_ml_results:
                logger.debug(f"Sample ML result: {batch_ml_results[0]}")
            
            # STEP 2: Process each result with rule engine
            logger.debug("�� STEP 2: Processing ML results with rule engine...")
            all_alerts = []
            processed_results = 0
            skipped_results = 0
            
            for i, ml_result in enumerate(batch_ml_results):
                if not ml_result:
                    skipped_results += 1
                    logger.debug(f"⚠️ Skipping empty ML result {i+1}")
                    continue
                
                try:
                    logger.debug(f"🔍 Processing ML result {i+1}/{len(batch_ml_results)}...")
                    
                    #  FIX: Safe extraction of all fields with fallbacks
                    connection_dict = ml_result.get('record', {})
                    if not connection_dict:
                        logger.warning(f"⚠️ Skipping ML result with no record data")
                        continue
                    
                    # === BỘ LỌC VETO CUỐI CÙNG (FINAL VETO FILTER) - BATCH ===
                    try:
                        src_ip_bt = str(connection_dict.get('id.orig_h', ''))
                        dst_ip_bt = str(connection_dict.get('id.resp_h', ''))
                        dst_port_bt = int(connection_dict.get('id.resp_p', 0) or 0)
                        proto_bt = connection_dict.get('proto', '')

                        # 1. Localhost (IPv4 & IPv6)
                        if src_ip_bt in ['127.0.0.1', '::1'] or dst_ip_bt in ['127.0.0.1', '::1']:
                            skipped_results += 1
                            continue

                        # 2. IPv6 Link-Local and Multicast
                        if (src_ip_bt.startswith('fe80::') or dst_ip_bt.startswith('fe80::') or
                            src_ip_bt.startswith('ff02::') or dst_ip_bt.startswith('ff02::')):
                            skipped_results += 1
                            continue

                        # 3. IPv4 Multicast (LLMNR/SSDP, etc.)
                        if dst_ip_bt.startswith('224.0.0.') or dst_ip_bt.startswith('239.255.255.'):
                            skipped_results += 1
                            continue

                        # 4. Core infra (DHCP, NTP)
                        if proto_bt == 'udp' and dst_port_bt in [67, 68, 123]:
                            skipped_results += 1
                            continue

                        # 5. Windows NetBIOS/SMB noise inside local RFC1918
                        if ((src_ip_bt.startswith('192.168.') and dst_ip_bt.startswith('192.168.')) or
                            (src_ip_bt.startswith('172.16.') and dst_ip_bt.startswith('172.16.')) or
                            (src_ip_bt.startswith('10.') and dst_ip_bt.startswith('10.'))):
                            if dst_port_bt in [137, 138, 139, 445]:
                                skipped_results += 1
                                continue

                        VICTIM_IP = "192.168.137.128"
                        if src_ip_bt == VICTIM_IP and dst_port_bt == 53:
                            skipped_results += 1
                            continue

                    except Exception as e:
                        logger.warning(f"Veto filter (batch) failed for result {i+1}, skipping. Error: {e}")
                        skipped_results += 1
                        continue
                    
                    # Extract ML scores with safe fallbacks
                    isof_score = ml_result.get('isof_score', 0.0)
                    isof_anomaly = ml_result.get('isof_anomaly', False)
                    ae_error = ml_result.get('ae_error', 0.0)
                    ae_anomaly = ml_result.get('ae_anomaly', False)
                    
                    #  FIX: Safe extraction of original_index with fallback
                    original_index = ml_result.get('original_index', 0)
                    if original_index is None:
                        original_index = 0
                        logger.debug(f"⚠️ original_index missing, using fallback value: 0")
                    
                    # Extract other fields with safe fallbacks
                    shap_values = ml_result.get('shap_values', None)
                    feature_names = ml_result.get('feature_names', [])
                    

                    logger.debug(f"📊 ML result {i+1} details:")
                    logger.debug(f"  - Original index: {original_index}")
                    logger.debug(f"  - ISO Forest anomaly: {isof_anomaly} (score: {isof_score:.4f})")
                    logger.debug(f"  - Autoencoder anomaly: {ae_anomaly} (error: {ae_error:.4f})")
                    logger.debug(f"  - Source IP: {connection_dict.get('id.orig_h', 'N/A')}")
                    
                    
                    # Get source IP for rate limiting
                    src_ip = connection_dict.get('id.orig_h', '')
                    
                    logger.debug(f"📊 Using vertical scan features from ML result: ports={ml_result.get('vertical_scan_unique_dst_port_count', 0)}, problematic_ratio={ml_result.get('vertical_scan_problematic_ratio', 0.0):.4f}")
                    
                    #  FIX: Add logging for horizontal_scan features
                    logger.debug(f"📊 Using horizontal scan features from ML result: dst_ips={ml_result.get('horizontal_scan_unique_dst_ip_count', 0)}, problematic_ratio={ml_result.get('horizontal_scan_problematic_ratio', 0.0):.4f}")
                    
                    # ==========================================
                    # SIMPLIFIED: Map ALL features from ml_result directly
                    # ==========================================
                    # Create enhanced connection details with ALL features (raw + z-score)
                    enhanced_connection_details = connection_dict.copy()
                    
                    # Map ALL features from ml_result (both raw and z-score + IP profile)
                    feature_mapping = [
                        'vertical_scan_unique_dst_port_count', 'vertical_scan_problematic_ratio',
                        'horizontal_scan_unique_dst_ip_count', 'horizontal_scan_problematic_ratio',
                        'beacon_group_count', 'beacon_group_cv',
                        'beacon_channel_timediff_std', 'beacon_channel_duration_std', 'beacon_channel_orig_bytes_std',
                        'ddos_group_unique_src_ip_count',
                        'z_horizontal_unique_dst_ip_count', 'z_horizontal_problematic_ratio',
                        'z_vertical_unique_dst_port_count', 'z_vertical_problematic_ratio',
                        'z_beacon_group_count', 'z_ddos_group_unique_src_ip_count',
                        'z_beacon_channel_timediff_std', 'z_beacon_channel_duration_std', 'z_beacon_channel_orig_bytes_std',
                        # IP PROFILE FEATURES (NEW!)
                        'concurrent_connections', 'ip_profile_uid_rate', 'ip_profile_id.resp_p_rate',
                        'ip_profile_id.resp_h_rate', 'ip_profile_conn_state_diversity',
                        'ip_profile_mean_duration', 'ip_profile_mean_orig_bytes'
                    ]
                    
                    for feature in feature_mapping:
                        if feature in ml_result:
                            enhanced_connection_details[feature] = ml_result[feature]
                    
                    logger.debug(f"📊 Enhanced connection details created with {len(enhanced_connection_details)} fields")

                    # try:
                    #     vert_ports_val = int(enhanced_connection_details.get('vertical_scan_unique_dst_port_count', 0) or 0)
                    #     horiz_ips_val = int(enhanced_connection_details.get('horizontal_scan_unique_dst_ip_count', 0) or 0)
                    #     p_rate_val = float(enhanced_connection_details.get('ip_profile_id.resp_p_rate', 0.0) or 0.0)
                    #     h_rate_val = float(enhanced_connection_details.get('ip_profile_id.resp_h_rate', 0.0) or 0.0)
                    #     scan_condition_met = (vert_ports_val > 10 or p_rate_val > 10 or horiz_ips_val > 10 or h_rate_val > 10)
                    #     logger.info(
                    #         "[TRACE] scan_cond=%s | vert_ports=%s p_rate=%s horiz_ips=%s h_rate=%s | ML(isof=%s, ae=%s)",
                    #         scan_condition_met, vert_ports_val, p_rate_val, horiz_ips_val, h_rate_val, isof_anomaly, ae_anomaly
                    #     )
                    #     if scan_condition_met and not (isof_anomaly or ae_anomaly):
                    #         logger.warning(
                    #             "[GATE_BLOCK] PortScan conditions met but ML gate false for src=%s (result %s)",
                    #             connection_dict.get('id.orig_h', ''), i+1
                    #         )
                    # except Exception:
                    #     pass
                    
                    # Apply ML-first classification if ML detected anomaly
                    if isof_anomaly or ae_anomaly:
                        logger.debug(f"🚨 ML anomaly detected in result {i+1}, starting classification...")
                        
                        
                        logger.debug("🔍 Loading demo rules for classification...")
                        demo_rules = get_demo_rules()
                        demo_rules = sorted(demo_rules, key=lambda x: x.get('priority', 4))
                        logger.debug(f"📊 Loaded {len(demo_rules)} demo rules")
                        
                        # Default classification
                        matched_rule = None
                        confidence = "Medium"
                        detector = "AI Classified: Generic ML Anomaly"
                        
                        # Try to classify the ML-detected anomaly
                        logger.debug("🔍 Applying classification rules...")
                        for rule_idx, rule in enumerate(demo_rules):
                            try:
                                logger.debug(f"🔍 Testing rule {rule_idx+1}: {rule.get('name', 'Unknown')}")
                                anom_flags = {
                                    'isof_anomaly': isof_anomaly,
                                    'ae_anomaly': ae_anomaly
                                }

                                z_scores = {
                                    'z_horizontal_unique_dst_ip_count': ml_result.get('z_horizontal_unique_dst_ip_count', 0.0),
                                    'z_horizontal_problematic_ratio': ml_result.get('z_horizontal_problematic_ratio', 0.0),
                                    'z_vertical_unique_dst_port_count': ml_result.get('z_vertical_unique_dst_port_count', 0.0),
                                    'z_vertical_problematic_ratio': ml_result.get('z_vertical_problematic_ratio', 0.0),
                                    'z_beacon_group_count': ml_result.get('z_beacon_group_count', 0.0),
                                    'z_ddos_group_unique_src_ip_count': ml_result.get('z_ddos_group_unique_src_ip_count', 0.0),
                                    'z_beacon_channel_timediff_std': ml_result.get('z_beacon_channel_timediff_std', 0.0),
                                    'z_beacon_channel_duration_std': ml_result.get('z_beacon_channel_duration_std', 0.0),
                                    'z_beacon_channel_orig_bytes_std': ml_result.get('z_beacon_channel_orig_bytes_std', 0.0)
                                }
                                
                                if rule['conditions'](enhanced_connection_details, anom_flags, z_scores):
                                    confidence, detector = rule['get_details'](anom_flags)
                                    matched_rule = rule
                                    logger.debug(f"[SUCCESS] Rule matched: {rule.get('name', 'Unknown')} -> {detector} ({confidence})")
                                    break
                                else:
                                    logger.debug(f"❌ Rule {rule_idx+1} conditions not met")
                            except Exception as e:
                                logger.warning(f"⚠️ Error applying classification rule {rule.get('name', 'Unknown')}: {e}")
                                logger.debug(f"Rule error details: {type(e).__name__}: {str(e)}")
                                continue
                        
                        if not matched_rule:
                            if isof_anomaly and ae_anomaly:
                                confidence = "High"
                                detector = "AI Classified: High-Confidence ML Anomaly"
                                matched_rule = {"name": "High-Confidence ML Anomaly", "description": "Both ML models detected anomaly"}
                            elif isof_anomaly:
                                confidence = "Medium"
                                detector = "AI Classified: IF Pattern Anomaly"
                                matched_rule = {"name": "Network Anomaly", "description": "Network pattern anomaly detected"}
                            elif ae_anomaly:
                                confidence = "Medium"
                                detector = "AI Classified: AE Pattern Anomaly"
                                matched_rule = {"name": "Behavioral Anomaly", "description": "Behavioral pattern anomaly detected"}
                        
                        alert = {
                            'type': 'ml_anomaly',  
                            'alert_type': 'ml_anomaly',  
                            'alert_id': f"batch_{original_index}_{int(time.time())}",  
                            'attack_name': matched_rule['name'],
                            'severity': confidence, 
                            'confidence': 0.9 if (isof_anomaly and ae_anomaly) else 0.7,  
                            'risk_score': self._calculate_ml_risk_score(confidence, isof_anomaly, ae_anomaly, isof_score, ae_error, matched_rule.get('priority', 4)),
                            'src_ip': src_ip,
                            'dst_ip': connection_dict.get('id.resp_h', ''),
                            'dst_port': connection_dict.get('id.resp_p', 0),
                            'proto': connection_dict.get('proto', ''),
                            'service': connection_dict.get('service', ''),
                            'description': matched_rule.get('description', 'ML-detected anomaly'),
                            'rule_priority': matched_rule.get('priority', 4),  
                            'is_anomaly': True,  
                            'timestamp': datetime.now().isoformat(),  
                            'matched_scenario': matched_rule.get('name', 'Unknown'),  
                            'source': 'connection_engine',  
                            'detector': detector,  
                            'ml_evidence': {  
                                'isolation_forest_score': isof_score,
                                'autoencoder_error': ae_error,
                                'isolation_forest_anomaly': isof_anomaly,
                                'autoencoder_anomaly': ae_anomaly,
                                'shap_explanation': format_shap_explanation(shap_values, ml_result.get('feature_names', []), top_n=5, log_type='conn') if (isof_anomaly or ae_anomaly) and shap_values is not None else None,
                                # IP Profile Evidence
                                'ip_profile_evidence': {
                                    'concurrent_connections': ml_result.get('concurrent_connections', 0.0),
                                    'ip_profile_uid_rate': ml_result.get('ip_profile_uid_rate', 0.0),
                                    'ip_profile_id.resp_p_rate': ml_result.get('ip_profile_id.resp_p_rate', 0.0),
                                    'ip_profile_id.resp_h_rate': ml_result.get('ip_profile_id.resp_h_rate', 0.0),
                                    'ip_profile_conn_state_diversity': ml_result.get('ip_profile_conn_state_diversity', 0.0),
                                    'ip_profile_mean_duration': ml_result.get('ip_profile_mean_duration', 0.0),
                                    'ip_profile_mean_orig_bytes': ml_result.get('ip_profile_mean_orig_bytes', 0.0)
                                },
                                # Scan Detection Evidence
                                'scan_detection_evidence': {
                                    'vertical_scan_unique_dst_port_count': ml_result.get('vertical_scan_unique_dst_port_count', 0),
                                    'vertical_scan_problematic_ratio': ml_result.get('vertical_scan_problematic_ratio', 0.0),
                                    'horizontal_scan_unique_dst_ip_count': ml_result.get('horizontal_scan_unique_dst_ip_count', 0),
                                    'horizontal_scan_problematic_ratio': ml_result.get('horizontal_scan_problematic_ratio', 0.0),
                                    'beacon_group_count': ml_result.get('beacon_group_count', 0),
                                    'beacon_group_cv': ml_result.get('beacon_group_cv', 0.0),
                                    'beacon_channel_timediff_std': ml_result.get('beacon_channel_timediff_std', 0.0),
                                    'beacon_channel_duration_std': ml_result.get('beacon_channel_duration_std', 0.0),
                                    'beacon_channel_orig_bytes_std': ml_result.get('beacon_channel_orig_bytes_std', 0.0),
                                    'ddos_group_unique_src_ip_count': ml_result.get('ddos_group_unique_src_ip_count', 0)
                                },
                                # Z-Score Evidence
                                'z_score_evidence': {
                                    'z_horizontal_unique_dst_ip_count': ml_result.get('z_horizontal_unique_dst_ip_count', 0.0),
                                    'z_horizontal_problematic_ratio': ml_result.get('z_horizontal_problematic_ratio', 0.0),
                                    'z_vertical_unique_dst_port_count': ml_result.get('z_vertical_unique_dst_port_count', 0.0),
                                    'z_vertical_problematic_ratio': ml_result.get('z_vertical_problematic_ratio', 0.0),
                                    'z_beacon_group_count': ml_result.get('z_beacon_group_count', 0.0),
                                    'z_ddos_group_unique_src_ip_count': ml_result.get('z_ddos_group_unique_src_ip_count', 0.0),
                                    'z_beacon_channel_timediff_std': ml_result.get('z_beacon_channel_timediff_std', 0.0),
                                    'z_beacon_channel_duration_std': ml_result.get('z_beacon_channel_duration_std', 0.0),
                                    'z_beacon_channel_orig_bytes_std': ml_result.get('z_beacon_channel_orig_bytes_std', 0.0)
                                }
                            },
                            'connection_details': enhanced_connection_details,  
                            'original_log_index': original_index,  
                        }
                        
                        # Deduplication check
                        if not self._is_duplicate_alert(alert):
                            all_alerts.append(alert)
                
                except Exception as e:
                    logger.warning(f"Error processing ML result: {e}")
                    continue
            
            logger.info(f"[SUCCESS] BATCH processing completed: {len(batch_ml_results)} ML results -> {len(all_alerts)} alerts")
            return all_alerts
            
        except Exception as e:
            logger.error(f"Error in batch analysis: {str(e)}")
            #  FIX: Safe fallback with loop prevention for demo stability
            logger.info("Attempting safe fallback to individual processing...")
            try:
                fallback_results = self._fallback_individual_processing(log_lines)
                if fallback_results:
                    logger.info(f" Fallback successful: {len(fallback_results)} alerts generated")
                    return fallback_results
                else:
                    logger.warning("Fallback processing returned no results")
                    return []
            except Exception as fallback_e:
                logger.error(f"Fallback processing also failed: {fallback_e}")
                logger.warning("Returning empty results to prevent infinite loop")
                return []
    
    def _fallback_individual_processing(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """ FIX: Safe fallback to individual processing with error handling for demo stability."""
        all_alerts = []
        processed_count = 0
        failed_count = 0
        
        for i, log_line in enumerate(log_lines):
            try:
                if not log_line or not log_line.strip():
                    logger.warning(f"Skipping empty log line {i} in fallback")
                    failed_count += 1
                    continue
                
                logger.debug(f"Log line {i} skipped in fallback (individual processing not implemented)")
                processed_count += 1
                    
            except Exception as e:
                logger.warning(f"Error processing individual log {i} in fallback: {e}")
                failed_count += 1
                continue
        
        logger.info(f" Fallback processing completed: {processed_count} processed, {failed_count} failed")
        return all_alerts
    
    def detect_events_from_logs(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """
        Process multiple log lines and return all detection events.
        
        Args:
            log_lines: List of raw log lines
            
        Returns:
            List of detection events
        """
        all_events = []
        
        if log_lines:
            return self.analyze_connections_batch(log_lines)
        return []
    
    
    def _extract_behavior_type(self, alert_details: str) -> str:
        """Extract behavior type from alert details string."""
        alert_lower = alert_details.lower()
        
        if 'port scan' in alert_lower:
            return 'port_scan'
        elif 'c2 beaconing' in alert_lower:
            return 'c2_beaconing'
        elif 'data exfiltration' in alert_lower:
            return 'data_exfiltration'
        else:
            return 'unknown'
    

    
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of all detection components."""
        # Guard against lazy-loading: ml_handler may be None until first use
        try:
            ml_status = self.ml_handler.get_model_status() if self.ml_handler is not None else {
                'isolation_forest': False,
                'autoencoder': False,
                'preprocessor': False,
                'shap_available': False,
                'tensorflow_available': False,
            }
        except Exception as e:
            logger.warning(f"ML status unavailable: {e}")
            ml_status = {
                'isolation_forest': False,
                'autoencoder': False,
                'preprocessor': False,
                'shap_available': False,
                'tensorflow_available': False,
            }

        return {
            'ml_handler': ml_status
        }
    

    def analyze_dns_batch(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple DNS log lines in batch using ML-first detection, then classify via DNS rules.
        Mirrors analyze_connections_batch but for dns.log with vectorized ML for performance.
        """
        detection_events: List[Dict[str, Any]] = []
        try:
            # ⚡ OPTIMIZED: Lazy load ML models only when needed
            self._ensure_ml_models_loaded()
            
            if not log_lines:
                return []

            # Filter out empty logs
            valid_logs = [log for log in log_lines if log.strip()]
            if not valid_logs:
                return []

            # Parse and process DNS records
            processed_dns_list: List[Dict[str, Any]] = []
            for log_line in valid_logs:
                try:
                    # Handle Redis JSON format
                    if log_line.strip().startswith('{'):
                        # Use ML handler's DNS processor if available
                        if self.ml_handler and self.ml_handler.dns_processor:
                            if hasattr(self.ml_handler.dns_processor, 'parse_redis_dns_log'):
                                parsed = self.ml_handler.dns_processor.parse_redis_dns_log(log_line)
                                if not parsed:
                                    continue
                                log_line = parsed
                            else:
                                # Fallback: try to extract log line from JSON
                                try:
                                    import json
                                    json_data = json.loads(log_line)
                                    log_line = json_data.get('log_line', log_line)
                                except:
                                    continue
                        else:
                            # Create temporary processor for Redis log parsing (fallback only)
                            temp_dns_processor = DNSProductionDataProcessor()
                            if hasattr(temp_dns_processor, 'parse_redis_dns_log'):
                                parsed = temp_dns_processor.parse_redis_dns_log(log_line)
                                if not parsed:
                                    continue
                                log_line = parsed
                            else:
                                # Fallback: try to extract log line from JSON
                                try:
                                    import json
                                    json_data = json.loads(log_line)
                                    log_line = json_data.get('log_line', log_line)
                                except:
                                    continue

                    # --- START: VECTOR FILTER DNS BATCH - LOẠI IP LINK-LOCAL & MULTICAST & WINDOWS HOSTNAMES RA KHỎI XỬ LÝ ---
                    # Parse the log line to extract IP addresses and query for filtering
                    fields = log_line.strip().split('\t')
                    if len(fields) >= 3:  # Ensure we have enough fields for IP addresses
                        src_ip = fields[2] if len(fields) > 2 else ''  # id.orig_h
                        dst_ip = fields[4] if len(fields) > 4 else ''  # id.resp_h
                        query = fields[8] if len(fields) > 8 else ''   # query field
                        
                        # IPv4 Multicast (IGMP, etc.) - Loại hoàn toàn
                        if dst_ip.startswith('224.0.0.'):
                            continue  # Skip this log, it's normal network noise.
                        
                        # IPv6 DHCP Agents Multicast - Loại hoàn toàn  
                        elif dst_ip == 'ff02::1:2':
                            continue # Skip this log, it's normal DHCPv6 traffic.
                        
                        # IPv6 Link-Local Addresses - Loại hoàn toàn
                        elif dst_ip.startswith('fe80:') or src_ip.startswith('fe80:'):
                            continue # Skip this log, it's normal IPv6 link-local traffic.
                        
                        # IPv6 Multicast - Loại hoàn toàn
                        elif dst_ip.startswith('ff02:') or src_ip.startswith('ff02:'):
                            continue # Skip this log, it's normal IPv6 multicast traffic.
                        
                        # Localhost - Loại hoàn toàn
                        elif dst_ip in ['127.0.0.1', '::1'] or src_ip in ['127.0.0.1', '::1']:
                            continue # Skip this log, it's localhost traffic.
                        
                        # Windows Hostname Patterns - Loại hoàn toàn (desktop-xxx, laptop-xxx, etc.)
                        import re
                        if query and re.search(r'^(desktop|laptop|pc|workstation|server)-[a-zA-Z0-9]+$', query.lower()):
                            continue # Skip this log, it's normal Windows hostname query.
                        
                        # mDNS/LLMNR Queries - Loại hoàn toàn (multicast destinations)
                        if dst_ip.startswith('224.') or dst_ip.startswith('ff02:'):
                            continue # Skip this log, it's normal mDNS/LLMNR traffic.
                        
                        # ANY Queries (*) - Loại hoàn toàn (discovery queries)
                        if query and query.strip() == '*':
                            continue # Skip this log, it's normal discovery query.
                    # --- END: VECTOR FILTER DNS BATCH ---

                    # Parse DNS record using ML handler's DNS processor
                    if self.ml_handler and self.ml_handler.dns_processor:
                        raw_dns = self.ml_handler.dns_processor.parse_dns_record(log_line)
                        processed_dns = self.ml_handler.dns_processor.process_complete_record(raw_dns)
                    elif self.dns_processor:
                        raw_dns = self.dns_processor.parse_dns_record(log_line)
                        processed_dns = self.dns_processor.process_complete_record(raw_dns)
                    else:
                        # Create temporary processor for parsing (fallback only)
                        from core.data_processor import DNSProductionDataProcessor
                        temp_dns_processor = DNSProductionDataProcessor()
                        raw_dns = temp_dns_processor.parse_dns_record(log_line)
                        processed_dns = temp_dns_processor.process_complete_record(raw_dns)
                    processed_dns_list.append(processed_dns)
                except Exception as e:
                    logger.warning(f"Failed to parse/process DNS log: {e}")
                    continue

            if not processed_dns_list:
                return []

            # Batch ML prediction via MLHandler
            batch_predictions = self.ml_handler.predict_batch_dns_queries(processed_dns_list)
            if not batch_predictions:
                return []

            # Apply rules to anomalies only
            dns_rules = get_dns_rules()
            dns_rules = sorted(dns_rules, key=lambda x: x.get('priority', 4))

            for i, prediction in enumerate(batch_predictions):
                try:
                    isof_anomaly = prediction.get('details', {}).get('isolation_forest', {}).get('is_anomaly', False)
                    ae_anomaly = prediction.get('details', {}).get('autoencoder', {}).get('is_anomaly', False)
                    if not (isof_anomaly or ae_anomaly):
                        continue

                    features = prediction.get('features', {})
                    processed_dns = processed_dns_list[i]

                    # Rule-based classification after ML anomaly
                    confidence = "Low"
                    detector = "AI Classified: Generic DNS Anomaly"
                    matched_scenario = "Unknown DNS Pattern"
                    rule_priority = 4
                    rule_matched = False

                    for rule in dns_rules:
                        try:
                            if rule["conditions"](processed_dns, features, isof_anomaly, ae_anomaly):
                                confidence, detector = rule["get_details"](isof_anomaly, ae_anomaly)
                                matched_scenario = rule["name"]
                                rule_priority = rule.get('priority', 4)
                                rule_matched = True
                                break
                        except Exception as e:
                            logger.warning(f"Error evaluating DNS classification rule '{rule.get('name', 'Unknown')}': {e}")
                            continue

                    if not rule_matched:
                        if isof_anomaly and ae_anomaly:
                            confidence = "High"
                            detector = "AI Classified: BOTH DNS Anomaly"
                            matched_scenario = "High-Confidence DNS Anomaly"
                            rule_priority = 2
                        elif isof_anomaly:
                            confidence = "Medium"
                            detector = "AI Classified: DNS IF Anomaly"
                            matched_scenario = "Suspicious DNS Behavior"
                            rule_priority = 3
                        elif ae_anomaly:
                            confidence = "Medium"
                            detector = "AI Classified: DNS AE Anomaly"
                            matched_scenario = "Unusual DNS Query Pattern"
                            rule_priority = 3

                    # Determine behavior type
                    if rule_matched:
                        if "DGA" in matched_scenario:
                            behavior_type = 'dns_dga'
                        elif "Tunneling" in matched_scenario:
                            behavior_type = 'dns_tunneling'
                        elif "Amplification" in matched_scenario:
                            behavior_type = 'dns_amplification'
                        else:
                            behavior_type = 'dns_anomaly'
                    else:
                        behavior_type = 'dns_tunneling'

                    # Risk score
                    risk_score = self._calculate_dns_risk_score(confidence, features, processed_dns)

                    # Build detection event
                    # Prepare ML details without AE reconstruction payload
                    dns_ml_details = prediction.get('details', {}) or {}
                    try:
                        ae_block = dns_ml_details.get('autoencoder') or {}
                        if isinstance(ae_block, dict) and 'reconstruction' in ae_block:
                            ae_block.pop('reconstruction', None)
                            dns_ml_details['autoencoder'] = ae_block
                    except Exception:
                        pass

                    detection_event = {
                        'type': 'behavior_anomaly',
                        'alert_type': 'behavior_anomaly',
                        'behavior_type': behavior_type,
                        'source': 'dns_engine',
                        'detector': detector,
                        'confidence': confidence,
                        'risk_score': risk_score,
                        'matched_scenario': matched_scenario,
                        'rule_priority': rule_priority,
                        'is_anomaly': True,
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': processed_dns.get('id.orig_h', ''),
                        'dst_ip': processed_dns.get('id.resp_h', ''),
                        'dst_port': processed_dns.get('id.resp_p', 53),
                        'proto': 'DNS',
                        'service': 'dns',
                        'dns_details': {
                            'query': processed_dns.get('query', ''),
                            'qtype': processed_dns.get('qtype_name', ''),
                            'rcode': processed_dns.get('rcode_name', ''),
                            'features': features,
                            'ml_details': dns_ml_details
                        },
                        'explanation': {
                            'primary_indicators': [],
                            'secondary_indicators': []
                        },
                        # For DNS alerts, do not include generic connection_details to avoid showing conn.log fields
                        'connection_details': {}
                    }

                    #  FIX: SHAP explanation cho DNS batch - VẪN dùng khi CÓ anomaly (IF HOẶC AE)
                    # SHAP explanation (IF HOẶC AE) - vì AE là context ML
                    if ((isof_anomaly or ae_anomaly) and 
                        prediction.get('shap_values') is not None and
                        prediction.get('feature_names') is not None):
                        try:
                            dns_shap_explanation = format_shap_explanation(
                                prediction['shap_values'],
                                prediction['feature_names'],
                                top_n=5,
                                log_type='dns'
                            )
                            # Keep only features that push toward anomaly/tunneling (like conn handling)
                            try:
                                filtered = []
                                for item in (dns_shap_explanation.get('top_features') or []):
                                    direction = str(item.get('direction', '')).lower()
                                    if direction in ['anomaly', 'tunneling']:
                                        filtered.append(item)
                                if filtered:
                                    dns_shap_explanation['top_features'] = filtered
                            except Exception:
                                pass
                            dns_human_readable = translate_shap_to_human_readable(
                                dns_shap_explanation,
                                processed_dns,
                                log_type='dns'
                            )
 
                            detection_event['explanation']['isolation_forest_shap'] = dns_shap_explanation
                            detection_event['explanation']['isolation_forest_human_readable'] = dns_human_readable
                        except Exception as e:
                            logger.warning(f"Could not add DNS SHAP explanation: {str(e)}")

                    # Add feature/context snippets
                    key_features = []
                    for feature_name, feature_value in features.items():
                        if feature_value and feature_value != 'N/A' and feature_value != 0:
                            key_features.append(f"{feature_name}: {feature_value}")
                    if key_features:
                        detection_event['explanation']['primary_indicators'] = [
                            f"ML models detected anomaly based on: {', '.join(key_features[:5])}"
                        ]
                    dns_context = []
                    if processed_dns.get('query'):
                        dns_context.append(f"Query: {processed_dns.get('query')}")
                    if processed_dns.get('qtype_name'):
                        dns_context.append(f"Type: {processed_dns.get('qtype_name')}")
                    if processed_dns.get('rcode_name'):
                        dns_context.append(f"Response: {processed_dns.get('rcode_name')}")
                    if dns_context:
                        detection_event['explanation']['secondary_indicators'] = dns_context

                    detection_events.append(detection_event)
                except Exception as e:
                    logger.warning(f"Error processing batch DNS prediction: {e}")
                    continue

            return detection_events

        except Exception as e:
            logger.error(f"Error in analyze_dns_batch: {str(e)}")
            return []

    def _calculate_ml_risk_score(self, confidence: str, isof_anomaly: bool, ae_anomaly: bool, 
                                isof_score: float, ae_error: float, rule_priority: int = 4) -> int:
        """
        Calculate risk score for ML anomaly detection (0-100).
        
        Args:
            confidence: Detection confidence level
            isof_anomaly: Whether Isolation Forest detected anomaly
            ae_anomaly: Whether Autoencoder detected anomaly
            isof_score: Isolation Forest anomaly score (not used for scoring)
            ae_error: Autoencoder reconstruction error (not used for scoring)
            rule_priority: Rule priority (1=Critical, 2=High, 3=Medium, 4=Low)
            
        Returns:
            Risk score (0-100)
        """
        try:
            #  SIMPLIFIED: Priority-based base score calculation
            priority_base_scores = {
                1: 80,  # Critical - base 80
                2: 65,  # High - base 65  
                3: 50,  # Medium - base 50
                4: 30   # Low - base 30
            }
            base_score = priority_base_scores.get(rule_priority, 30)
            
            #  SIMPLIFIED: Confidence adjustment
            confidence_bonus = 0
            if confidence == 'High':
                confidence_bonus = 10
            elif confidence == 'Medium':
                confidence_bonus = 6
            elif confidence == 'Low':
                confidence_bonus = 3
            
            consensus_bonus = 0
            if isof_anomaly and ae_anomaly:
                consensus_bonus = 15  # Both models agree - highest confidence
            elif isof_anomaly or ae_anomaly:
                consensus_bonus = 8   # Single model detection
            

            
            # Final risk score
            risk_score = base_score + confidence_bonus + consensus_bonus
            
            priority_caps = {
                1: 95,  # Critical - max 95
                2: 85,  # High - max 85
                3: 70,  # Medium - max 70
                4: 55   # Low - max 55
            }
            max_score = priority_caps.get(rule_priority, 55)
            risk_score = min(risk_score, max_score)
            
            return int(risk_score)
            
        except Exception as e:
            logger.error(f"Error calculating ML risk score: {str(e)}")
            return 30  # Default low risk
    


    def _calculate_dns_risk_score(self, confidence: str, features: Dict[str, Any], processed_dns: Dict[str, Any]) -> int:
        """
        Calculate risk score for DNS anomaly detection (0-100).
        
        Args:
            confidence: Detection confidence level
            features: DNS feature dictionary
            processed_dns: Processed DNS record
            
        Returns:
            Risk score (0-100)
        """
        try:
            # Base score from confidence level
            confidence_scores = {
                'High': 80,
                'Medium': 60,
                'Low': 40
            }
            base_score = confidence_scores.get(confidence, 40)
            
            # Bonus for suspicious DNS features
            feature_bonus = 0
            
            # Check for suspicious DNS patterns
            query = processed_dns.get('query', '').lower()
            qtype = processed_dns.get('qtype_name', '').lower()
            
            # High-risk DNS patterns
            if any(pattern in query for pattern in ['malware', 'c2', 'botnet', 'tunnel']):
                feature_bonus += 20
            elif len(query) > 100:  # Very long queries (potential tunneling)
                feature_bonus += 15
            elif query.count('.') > 10:  # Many subdomains (potential DGA)
                feature_bonus += 10
            
            # Iodine tunneling specific patterns (high risk)
            if len(query) > 50:  # Iodine queries are typically long
                feature_bonus += 25
            if query.count('.') > 5:  # Multiple subdomains
                feature_bonus += 15
            if any(char.isdigit() for char in query):  # Contains numbers (common in tunneling)
                feature_bonus += 10
            
            # Suspicious query types
            if qtype in ['txt', 'mx', 'aaaa']:  # Often used in tunneling
                feature_bonus += 5
            
            # Feature-based scoring
            for feature_name, feature_value in features.items():
                if isinstance(feature_value, (int, float)) and feature_value > 0:
                    if 'entropy' in feature_name.lower() and feature_value > 4.0:
                        feature_bonus += 10
                    elif 'length' in feature_name.lower() and feature_value > 50:
                        feature_bonus += 5
            
            # Final risk score
            risk_score = base_score + feature_bonus
            
            # Cap at 100
            return min(100, int(risk_score))
            
        except Exception as e:
            logger.error(f"Error calculating DNS risk score: {str(e)}")
            return 50  # Default medium risk

    def get_dns_model_status(self) -> Dict[str, Any]:
        """Get status of DNS detection models."""
        if self.ml_handler is None:
            return {
                'dns_models_loaded': False,
                'dns_isolation_forest': False,
                'dns_autoencoder': False,
                'dns_scaler': False
            }

        try:
            return {
                'dns_models_loaded': bool(getattr(self.ml_handler, 'model_status', {}).get('dns_models', False)),
                'dns_isolation_forest': getattr(self.ml_handler, 'dns_isolation_model', None) is not None,
                'dns_autoencoder': getattr(self.ml_handler, 'dns_autoencoder', None) is not None,
                'dns_scaler': getattr(self.ml_handler, 'dns_scaler', None) is not None
            }
        except Exception as e:
            logger.warning(f"DNS model status unavailable: {e}")
            return {
                'dns_models_loaded': False,
                'dns_isolation_forest': False,
                'dns_autoencoder': False,
                'dns_scaler': False
            }

