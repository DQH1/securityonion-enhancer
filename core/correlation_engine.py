"""
Correlation Engine module for network anomaly detection system.
Contains logic for correlating alerts, calculating risk scores, and generating findings.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import json
import numpy as np

# Set up logging
logger = logging.getLogger(__name__)

class CorrelationEngine:
    """
    Engine for correlating security events and generating comprehensive findings.
    Handles IP risk scoring, evidence grouping, and finding summarization.
    """
    

    def get_threat_info(self, threat_key: str, rule_priority: int = None) -> dict:
        """
        🎯 SINGLE SOURCE OF TRUTH: Get threat information from config.py rules only.
        
        Args:
            threat_key: The threat identifier (matched_scenario, behavior_type, etc.)
            rule_priority: Optional rule priority for fallback scoring
            
        Returns:
            dict: Complete threat information with score, severity, category, etc.
        """
        # Try to match with config.py rules for dynamic scoring
        config_match = self._get_threat_info_from_config(threat_key)
        if config_match:
            return config_match
        
        # Fallback to priority-based scoring if rule_priority provided
        if rule_priority:
            severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
            score_map = {1: 90, 2: 70, 3: 50, 4: 30}
            
            return {
                'score': score_map.get(rule_priority, 50),
                'risk_score': score_map.get(rule_priority, 50),  # Add consistent key
                'severity': severity_map.get(rule_priority, 'medium'),
                'priority': rule_priority,
                'category': f'priority_{rule_priority}',
                'type': 'rule_based',
                'description': f'Priority {rule_priority} rule'
            }
        
        # Ultimate fallback for unknown threats
        return {
            'score': 10,
            'risk_score': 10,  # Add consistent key
            'severity': 'low',
            'priority': 4,
            'category': 'unknown',
            'type': 'unknown',
            'description': 'Unknown threat type'
        }
    
    def _get_threat_info_from_config(self, threat_key: str) -> Optional[dict]:
        """
        🆕 NEW: Get threat information from config.py rules for dynamic scoring.
        This allows correlation engine to use the same rule definitions as detection engine.
        """
        try:
            # Import config rules dynamically
            from config import get_demo_rules, get_dns_rules
            
            # Check connection rules first
            conn_rules = get_demo_rules()
            for rule in conn_rules:
                if rule.get('name') == threat_key:
                    priority = rule.get('priority', 3)
                    severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
                    severity = severity_map.get(priority, 'medium')
                    
                    # Map priority to score
                    score_map = {1: 90, 2: 70, 3: 50, 4: 30}
                    score = score_map.get(priority, 50)
                    
                    return {
                        'score': score,
                        'risk_score': score,  # Add consistent key
                        'severity': severity,
                        'priority': priority,
                        'category': 'rule_based',
                        'type': 'config_rule',
                        'description': rule.get('description', '')
                    }
            
            # Check DNS rules
            dns_rules = get_dns_rules()
            for rule in dns_rules:
                if rule.get('name') == threat_key:
                    priority = rule.get('priority', 2)
                    severity_map = {0: 'critical', 1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
                    severity = severity_map.get(priority, 'medium')
                    
                    # DNS rules get higher scores
                    score_map = {0: 95, 1: 95, 2: 80, 3: 60, 4: 40}
                    score = score_map.get(priority, 60)
                    
                    return {
                        'score': score,
                        'risk_score': score,  # Add consistent key
                        'severity': severity,
                        'priority': priority,
                        'category': 'dns_attack',
                        'type': 'dns_rule',
                        'description': rule.get('description', '')
                    }
            
            return None
            
        except ImportError:
            logger.warning("Could not import config rules for dynamic threat scoring")
            return None
        except Exception as e:
            logger.error(f"Error getting threat info from config: {str(e)}")
            return None
    
    def __init__(self):
        """Initialize the correlation engine."""
        pass
    
    def _summarize_threats(self, ip_alert_list: list, ip: str) -> dict:
        """
        🎯 HELPER: Analyze alerts and generate comprehensive threat summary.
        
        Args:
            ip_alert_list: List of alerts for a specific IP
            ip: IP address being analyzed
            
        Returns:
            dict: Comprehensive threat summary including severity, types, title, etc.
        """
        try:
            if not ip_alert_list:
                return {
                    'highest_severity': 'low',
                    'highest_score': 0,
                    'primary_finding_type': 'unknown',
                    'category': 'unknown',
                    'subcategory': 'unknown',
                    'all_behavior_types': ['unknown'],
                    'all_alert_types': ['unknown'],
                    'dynamic_title': f"Unknown Activity from {ip}"
                }
            
            # Analyze all alerts to determine threat characteristics
            highest_score = 0
            highest_severity = 'low'
            behavior_types = set()
            alert_types = set()
            threat_categories = set()
            
            for alert in ip_alert_list:
                # Get threat information using unified system
                threat_key = (alert.get('matched_scenario') or 
                             alert.get('behavior_type') or 
                             alert.get('type', 'unknown'))
                rule_priority = alert.get('rule_priority')
                
                threat_info = self.get_threat_info(threat_key, rule_priority)
                
                # Track highest severity threat
                if threat_info['score'] > highest_score:
                    highest_score = threat_info['score']
                    highest_severity = threat_info['severity']
                
                # Collect all behavior and alert types
                behavior = (alert.get('matched_scenario') or alert.get('behavior_type') or 
                           alert.get('behavior', 'unknown'))
                alert_type = alert.get('alert_type', alert.get('type', 'unknown'))
                
                behavior_types.add(behavior)
                alert_types.add(alert_type)
                threat_categories.add(threat_info.get('category', 'unknown'))
            
            # Determine primary finding type based on threat analysis
            primary_finding_type, category, subcategory = self._determine_finding_classification(
                behavior_types, threat_categories
            )
            
            # Generate dynamic title based on threats detected
            dynamic_title = self._generate_dynamic_title(behavior_types, ip)
            
            return {
                'highest_severity': highest_severity,
                'highest_score': highest_score,
                'primary_finding_type': primary_finding_type,
                'category': category,
                'subcategory': subcategory,
                'all_behavior_types': list(behavior_types),
                'all_alert_types': list(alert_types),
                'dynamic_title': dynamic_title
            }
            
        except Exception as e:
            logger.error(f"Error in threat summarization: {str(e)}")
            # Return safe fallback
            return {
                'highest_severity': 'medium',
                'highest_score': 30,
                'primary_finding_type': 'security_anomaly',
                'category': 'network_security',
                'subcategory': 'anomaly_detection',
                'all_behavior_types': ['unknown'],
                'all_alert_types': ['unknown'],
                'dynamic_title': f"Security Event from {ip}"
            }
    
    def _determine_finding_classification(self, behavior_types: set, threat_categories: set) -> tuple:
        """
        🎯 HELPER: Determine finding classification based on detected behaviors.
        
        Returns:
            tuple: (finding_type, category, subcategory)
        """
        # DNS threats have highest priority
        if any('dns' in bt.lower() for bt in behavior_types):
            if any('tunneling' in bt.lower() for bt in behavior_types):
                return 'dns_tunneling', 'network_security', 'dns_tunneling'
            elif any('dga' in bt.lower() for bt in behavior_types):
                return 'dns_dga', 'network_security', 'dns_dga'
            else:
                return 'dns_anomaly', 'network_security', 'dns_anomaly'
        
        # Connection-based threats
        elif any(('port_scan' in bt.lower()) or ('port scan' in bt.lower()) or ('vertical port scan' in bt.lower()) or ('horizontal port scan' in bt.lower()) for bt in behavior_types):
            return 'port_scan', 'network_security', 'port_scan'
        elif any(('brute' in bt.lower()) or ('brute-force' in bt.lower()) or ('brute force' in bt.lower()) for bt in behavior_types):
            return 'brute_force', 'network_security', 'authentication_attack'
        elif any(('ddos' in bt.lower()) or ('flood' in bt.lower()) for bt in behavior_types):
            return 'dos_attack', 'network_security', 'dos_attack'
        elif any(('exfiltration' in bt.lower()) or ('data exfiltration' in bt.lower()) for bt in behavior_types):
            return 'data_exfiltration', 'network_security', 'data_exfiltration'
        elif any(('beaconing' in bt.lower()) or ('c2' in bt.lower()) or ('command and control' in bt.lower()) for bt in behavior_types):
            return 'c2_communication', 'network_security', 'command_control'
        
        # Fallback for general anomalies
        else:
            return 'security_anomaly', 'network_security', 'anomaly_detection'
    
    def _generate_dynamic_title(self, behavior_types: set, ip: str) -> str:
        """
        🎯 HELPER: Generate dynamic title based on detected behavior types.
        
        Args:
            behavior_types: Set of detected behavior types
            ip: IP address
            
        Returns:
            str: Dynamic title for the finding
        """
        # Priority threat mapping (DNS first, then critical attacks)
        threat_titles = {
            # DNS threats (highest priority)
            'DNS Tunneling Pattern': 'DNS Tunneling',
            'DNS DGA Attack Pattern': 'DNS DGA Attack',
            'DNS Covert Channel': 'DNS Covert Channel',
            
            # Critical network attacks (updated to match config.py)
            'Distributed Denial of Service (DDoS)': 'DDoS Attack',
            'Vertical Port Scan': 'Port Scanning',
            'Horizontal Port Scan': 'Port Scanning',
            'Brute-Force Attack': 'Brute Force',
            'Data Exfiltration': 'Data Exfiltration',
            'C2 Beaconing': 'C2 Communication',
            'ICMP Data Exfiltration': 'ICMP Tunneling'
        }
        
        # Find matching threats in priority order
        detected_threats = []
        for behavior in behavior_types:
            if behavior in threat_titles:
                detected_threats.append(threat_titles[behavior])
            elif 'dns' in behavior.lower() and 'tunneling' in behavior.lower():
                detected_threats.append('DNS Tunneling')
            elif 'port_scan' in behavior.lower():
                detected_threats.append('Port Scanning')
            elif 'brute' in behavior.lower():
                detected_threats.append('Brute Force')
            elif 'ddos' in behavior.lower() or 'flood' in behavior.lower():
                detected_threats.append('DDoS Attack')
        
        # Generate title
        if detected_threats:
            # Remove duplicates while preserving order
            unique_threats = []
            seen = set()
            for threat in detected_threats:
                if threat not in seen:
                    unique_threats.append(threat)
                    seen.add(threat)
            
            threat_string = ' & '.join(unique_threats[:3])  # Limit to 3 for readability
            return f"{threat_string} from {ip}"
        else:
            return f"Security Event from {ip}"
    
    def correlate_events(self, alerts: list, time_window_minutes: int = 5, session_state=None, existing_findings: list = None, current_time_override: datetime = None) -> list:  # ⚡ OPTIMIZED: Default 5min for demo
        """

        Args:
            alerts: List of alert dictionaries
            time_window_minutes: Fixed window size (not sliding)
            session_state: Optional Streamlit session state for persistent findings
            existing_findings: List of existing findings to merge with
            current_time_override: Optional datetime override for testing
            
        Returns:
            List of findings (existing + new)
        """
        try:
            if not alerts:
                # Return existing findings if no new alerts
                return existing_findings or []
            
            logger.info(f"🔗 Starting FIXED correlation for {len(alerts)} alerts with {time_window_minutes}min window")

            # Initialize with existing findings
            all_findings = (existing_findings or []).copy()
            current_time = current_time_override or datetime.now()
            time_window_seconds = time_window_minutes * 60

            # Sort all alerts by IP and timestamp
            alerts_sorted = sorted(alerts, key=lambda x: (
                x.get('src_ip', x.get('source_ip', x.get('ip', ''))),
                self._parse_timestamp_safe(x.get('timestamp', '')) or current_time
            ))

            # Active finding per IP (FIXED 5-minute window from start_time)
            # Initialize active_findings from existing_findings to extend them
            active_findings: Dict[str, dict] = {}
            
            existing_findings_to_remove = []
            for existing_finding in all_findings:
                existing_ip = existing_finding.get('ip', '')
                if existing_ip:
                    # Use start_time as the base for fixed window calculation
                    start_time = self._parse_timestamp_safe(existing_finding.get('start_time'))
                    if start_time:
                        # Fixed window: start_time + 5 minutes
                        window_end = start_time + timedelta(seconds=time_window_seconds)
                        if current_time <= window_end:
                            # This existing finding is still within its fixed window, add to active_findings
                            active_findings[existing_ip] = existing_finding.copy()
                            existing_findings_to_remove.append(existing_finding)
                        else:
                            logger.debug(f"Fixed window expired for IP {existing_ip}, keeping in all_findings")
            
            for finding_to_remove in existing_findings_to_remove:
                if finding_to_remove in all_findings:
                    all_findings.remove(finding_to_remove)

            for alert in alerts_sorted:
                src_ip = (alert.get('src_ip') or alert.get('source_ip') or alert.get('ip') or alert.get('origin_ip') or '')
                if not src_ip:
                    continue

                alert_time = self._parse_timestamp_safe(alert.get('timestamp', '')) or current_time

                existing = active_findings.get(src_ip)
                if existing:
                    # FIXED: Use start_time for fixed window calculation, not last_updated
                    start_time = self._parse_timestamp_safe(existing.get('start_time'))
                    if not start_time:
                        logger.warning(f"Invalid start_time for finding {existing.get('finding_id')}, using alert_time")
                        start_time = alert_time
                    
                    # Fixed window: start_time + 5 minutes
                    window_end = start_time + timedelta(seconds=time_window_seconds)
                    
                    if alert_time <= window_end:
                        # Extend existing finding within fixed window
                        if 'evidence' not in existing:
                            existing['evidence'] = []
                        if 'related_alerts' not in existing:
                            existing['related_alerts'] = []
                        existing['evidence'].append(alert)
                        existing['related_alerts'].append(alert)
                        existing['total_alerts_count'] = existing.get('total_alerts_count', 0) + 1
                        existing['evidence_count'] = len(existing['evidence'])
                        existing['last_updated'] = alert_time.isoformat()
                        
                        if existing['evidence_count'] != len(existing['evidence']):
                            logger.warning(f"Evidence count mismatch for {existing.get('finding_id')}, fixing...")
                            existing['evidence_count'] = len(existing['evidence'])
                        
                        # Update finding summary with new evidence
                        summary = self._summarize_threats(existing['evidence'], existing['ip'])
                        existing.update({
                            'finding_type': summary['primary_finding_type'],
                            'title': summary['dynamic_title'],
                            'risk_score': max(existing.get('risk_score', 0), summary['highest_score']),
                            'severity': summary['highest_severity'],
                            'behavior_types': summary['all_behavior_types'],
                            'alert_types': summary['all_alert_types'],
                            'category': summary['category'],
                            'subcategory': summary['subcategory']
                        })
                        
                        logger.debug(f"Extended finding for IP {src_ip} within fixed window: {start_time} to {window_end}")
                    else:
                        logger.debug(f"Fixed window ended for IP {src_ip}, finalizing existing finding with {existing.get('evidence_count', 0)} alerts")
                        logger.debug(f"Window: {start_time} to {window_end}, Alert time: {alert_time}")
                        
                        # Finalize existing finding by adding to all_findings
                        all_findings.append(existing)
                        
                        # Create new finding for this alert (new fixed window starts)
                        threat_summary = self._summarize_threats([alert], src_ip)
                        new_finding = {
                            'finding_id': f"finding_{src_ip}_{int(alert_time.timestamp())}",
                            'finding_type': threat_summary['primary_finding_type'],
                            'ip': src_ip,
                            'title': threat_summary['dynamic_title'],
                            'description': f"Detected 1 security alerts from {src_ip}",
                            'risk_score': threat_summary['highest_score'],
                            'severity': threat_summary['highest_severity'],
                            'evidence_count': 1,  # Unique evidence types
                            'total_alerts_count': 1,  # Total alerts (including duplicates)
                            'evidence': [alert],
                            'related_alerts': [alert],
                            'ip_profile': self._create_ip_profile_from_alerts(src_ip, [alert]),
                            'created_at': alert_time.isoformat(),
                            'last_updated': alert_time.isoformat(),
                            'start_time': alert_time.isoformat(),  # New fixed window starts here
                            'status': 'New',
                            'attack_type': threat_summary['primary_finding_type'],
                            'alert_types': threat_summary['all_alert_types'],
                            'behavior_types': threat_summary['all_behavior_types'],
                            'category': threat_summary['category'],
                            'subcategory': threat_summary['subcategory'],
                            'correlation_window': f"{time_window_minutes} minutes"
                        }
                        active_findings[src_ip] = new_finding
                        
                        logger.debug(f"Created new finding for IP {src_ip} with new fixed window: {alert_time}")
                else:
                    # Start new active finding for this IP
                    threat_summary = self._summarize_threats([alert], src_ip)
                    new_finding = {
                        'finding_id': f"finding_{src_ip}_{int(alert_time.timestamp())}",
                        'finding_type': threat_summary['primary_finding_type'],
                        'ip': src_ip,
                        'title': threat_summary['dynamic_title'],
                        'description': f"Detected 1 security alerts from {src_ip}",
                        'risk_score': threat_summary['highest_score'],
                        'severity': threat_summary['highest_severity'],
                        'evidence_count': 1,  
                        'total_alerts_count': 1,  
                        'evidence': [alert],
                        'related_alerts': [alert],
                        'ip_profile': self._create_ip_profile_from_alerts(src_ip, [alert]),
                        'created_at': alert_time.isoformat(),
                        'last_updated': alert_time.isoformat(),
                        'start_time': alert_time.isoformat(),  # Fixed window starts here
                        'status': 'New',
                        'attack_type': threat_summary['primary_finding_type'],
                        'alert_types': threat_summary['all_alert_types'],
                        'behavior_types': threat_summary['all_behavior_types'],
                        'category': threat_summary['category'],
                        'subcategory': threat_summary['subcategory'],
                        'correlation_window': f"{time_window_minutes} minutes"
                    }
                    active_findings[src_ip] = new_finding
                    
                    logger.debug(f"Started new finding for IP {src_ip} with fixed window: {alert_time}")

            # FIXED: Finalize all active findings and refresh summaries
            for finding in active_findings.values():
                # All findings in active_findings should have evidence (either from extension or new creation)
                if finding.get('evidence') and len(finding['evidence']) > 0:
                    summary = self._summarize_threats(finding['evidence'], finding['ip'])
                    finding.update({
                        'finding_type': summary['primary_finding_type'],
                        'title': summary['dynamic_title'],
                        'risk_score': max(finding.get('risk_score', 0), summary['highest_score']),
                        'severity': summary['highest_severity'],
                        'evidence_count': len(finding['evidence']),
                        'behavior_types': summary['all_behavior_types'],
                        'alert_types': summary['all_alert_types'],
                        'category': summary['category'],
                        'subcategory': summary['subcategory']
                    })
                else:
                    logger.warning(f"Finding {finding.get('finding_id')} has no evidence, skipping")
                    continue
                    
                all_findings.append(finding)

            # Persist to session if provided
            if session_state and hasattr(session_state, 'findings'):
                for finding in all_findings:
                    self._update_session_findings(finding, session_state, time_window_minutes)

            logger.info(f"🎯 FIXED correlation completed: {len(all_findings)} total findings (existing + new)")
            return all_findings
            
            
        except Exception as e:
            logger.error(f"Error in FIXED correlation: {str(e)}")
            return []
    
    def _get_alert_risk_score(self, alert: dict) -> int:
        """
        🎯 UNIFIED: Get risk score using single source of truth.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            Risk score (0-100)
        """
        try:
            # Get threat key in priority order
            threat_key = (alert.get('matched_scenario') or 
                         alert.get('behavior_type') or 
                         alert.get('type', 'unknown'))
            
            # Get rule priority for fallback
            rule_priority = alert.get('rule_priority')
            
            # Use unified method
            threat_info = self.get_threat_info(threat_key, rule_priority)
            return threat_info['score']
            
        except Exception as e:
            logger.error(f"Error calculating alert risk score: {str(e)}")
            return 10  # Default low risk
    
    def _create_ip_profile_from_alerts(self, ip: str, alerts: list) -> dict:
        """
        Create IP profile from alerts for risk calculation.
        This method extracts behavioral data from alerts to create a profile.
        
        Args:
            ip: IP address
            alerts: List of alerts for this IP
            
        Returns:
            IP profile dictionary
        """
        try:
            profile = {
                'ip': ip,
                'connection_count': len(alerts),
                'unique_dest_ports': set(),
                'unique_destinations': set(),
                'state_counts': {},
                'alert_types': defaultdict(int),
                'behavior_types': defaultdict(int),
                'first_seen': None,
                'last_seen': None
            }
            
            for alert in alerts:
                # Count alert types
                alert_type = alert.get('alert_type', alert.get('type', 'unknown'))
                profile['alert_types'][alert_type] += 1
                
                # Count behavior types
                behavior = (alert.get('matched_scenario') or alert.get('behavior_type') or 
                           alert.get('behavior', 'unknown'))
                profile['behavior_types'][behavior] += 1
                
                # Extract connection details if available
                conn_details = alert.get('connection_details', {})
                if conn_details:
                    dst_ip = conn_details.get('id.resp_h', '')
                    dst_port = conn_details.get('id.resp_p', 0)
                    
                    if dst_ip and dst_ip != '-':
                        profile['unique_destinations'].add(dst_ip)
                    if dst_port and dst_port != 0:
                        profile['unique_dest_ports'].add(dst_port)
                
                # Track timeline
                timestamp = alert.get('timestamp', '')
                if timestamp:
                    if not profile['first_seen'] or timestamp < profile['first_seen']:
                        profile['first_seen'] = timestamp
                    if not profile['last_seen'] or timestamp > profile['last_seen']:
                        profile['last_seen'] = timestamp
            
            # Convert sets to lists for JSON serialization
            profile['unique_dest_ports'] = list(profile['unique_dest_ports'])
            profile['unique_destinations'] = list(profile['unique_destinations'])
            profile['alert_types'] = dict(profile['alert_types'])
            profile['behavior_types'] = dict(profile['behavior_types'])
            
            return profile
            
        except Exception as e:
            logger.error(f"Error creating IP profile: {str(e)}")
            return {'ip': ip, 'connection_count': len(alerts)}
    


    def _create_alert_key(self, alert: dict) -> str:
        """
        Create unique key for alert deduplication.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            Unique string key for deduplication
        """
        try:
            alert_type = alert.get('type', 'unknown')
            src_ip = alert.get('src_ip', alert.get('ip', ''))
            matched_scenario = alert.get('matched_scenario', '')
            detector = alert.get('detector', '')
            timestamp = alert.get('timestamp', '')
            
            # Connection details
            conn_details = alert.get('connection_details', {})
            dst_ip = conn_details.get('id.resp_h', alert.get('dst_ip', ''))
            dst_port = conn_details.get('id.resp_p', alert.get('dst_port', ''))
            
            alert_id = alert.get('alert_id', '')
            original_index = alert.get('original_log_index', '')
            
            # Exclude timestamp for correlation - alerts cùng IP cần merge được
            # Timestamp được xử lý bởi time window logic
            return f"{alert_type}_{src_ip}_{matched_scenario}_{detector}_{dst_ip}_{dst_port}"
            
        except Exception as e:
            logger.warning(f"Error creating alert key: {str(e)}")
            # Fallback to basic key with microsecond precision
            import time
            microsecond = int(time.time() * 1000000) % 1000000
            return f"{alert.get('type', 'unknown')}_{alert.get('src_ip', 'unknown')}_{microsecond}"
    
    def _update_session_findings(self, finding: dict, session_state, time_window_minutes: int) -> None:
        """
        Update session state findings with new finding or correlate with existing ones.
        This method handles the persistent finding logic for Streamlit sessions.
        
        Args:
            finding: New finding to process
            session_state: Streamlit session state object
            time_window_minutes: Time window for correlation
        """
        try:
            primary_ip = finding['ip']
            current_time = datetime.now()
            
            # Search for existing finding in session state
            matched_finding = None
            for finding_id, existing_finding in session_state.findings.items():
                if existing_finding['ip'] == primary_ip:
                    # Check if finding is within time window
                    last_updated = existing_finding.get('last_updated')
                    if last_updated:
                        last_updated_dt = self._parse_timestamp_safe(last_updated)
                        if last_updated_dt:
                            time_diff = (current_time - last_updated_dt).total_seconds()
                            if time_diff <= (time_window_minutes * 60):
                                matched_finding = existing_finding
                                break
                    else:
                        # No timestamp, include finding
                        matched_finding = existing_finding
            
            if matched_finding:
                #  IMPROVED: Update existing finding with better merging logic
                logger.info(f"🔄 Merging new alerts into existing finding for IP: {primary_ip}")
                
                #  FIXED: Safe evidence merging with deduplication
                if 'evidence' in finding and 'evidence' in matched_finding:
                    # Create set of existing alert keys for fast lookup
                    existing_alert_keys = set()
                    for alert in matched_finding['evidence']:
                        alert_key = self._create_alert_key(alert)
                        existing_alert_keys.add(alert_key)
                    
                    # Add only new alerts (deduplication)
                    new_evidence = []
                    for alert in finding['evidence']:
                        alert_key = self._create_alert_key(alert)
                        if alert_key not in existing_alert_keys:
                            new_evidence.append(alert)
                            existing_alert_keys.add(alert_key)
                    
                    # Extend evidence and update count
                    matched_finding['evidence'].extend(new_evidence)
                    matched_finding['evidence_count'] = len(matched_finding['evidence'])
                    
                    if 'total_alerts_count' not in matched_finding:
                        matched_finding['total_alerts_count'] = 0
                    matched_finding['total_alerts_count'] += len(finding.get('evidence', []))
                
                if 'related_alerts' in finding and 'related_alerts' in matched_finding:
                    existing_related_keys = set()
                    for alert in matched_finding['related_alerts']:
                        alert_key = self._create_alert_key(alert)
                        existing_related_keys.add(alert_key)
                    
                    new_related_alerts = []
                    for alert in finding['related_alerts']:
                        alert_key = self._create_alert_key(alert)
                        if alert_key not in existing_related_keys:
                            new_related_alerts.append(alert)  
                            existing_related_keys.add(alert_key)
                    
                    matched_finding['related_alerts'].extend(new_related_alerts)
                
                # Update timestamp
                matched_finding['last_updated'] = current_time.isoformat()
                
                # Update risk score (use higher score)
                if 'risk_score' in finding and 'risk_score' in matched_finding:
                    matched_finding['risk_score'] = max(matched_finding['risk_score'], finding['risk_score'])
                
                # Merge behavior types
                if 'behavior_types' in finding and 'behavior_types' in matched_finding:
                    existing_behaviors = set(matched_finding.get('behavior_types', []))
                    new_behaviors = set(finding.get('behavior_types', []))
                    matched_finding['behavior_types'] = list(existing_behaviors.union(new_behaviors))
                
                # Merge alert types
                if 'alert_types' in finding and 'alert_types' in matched_finding:
                    existing_alert_types = set(matched_finding.get('alert_types', []))
                    new_alert_types = set(finding.get('alert_types', []))
                    matched_finding['alert_types'] = list(existing_alert_types.union(new_alert_types))
                
                # Update description to reflect merged alerts
                if 'evidence_count' in matched_finding:
                    matched_finding['description'] = f"Detected {matched_finding['evidence_count']} security alerts from {primary_ip} (merged)"
                
                logger.debug(f" Successfully merged finding for IP: {primary_ip}")
            else:
                # Create new finding in session state
                finding_id = f"finding_{primary_ip}_{int(current_time.timestamp())}"
                finding['last_updated'] = current_time.isoformat()
                
                if 'total_alerts_count' not in finding:
                    finding['total_alerts_count'] = len(finding.get('evidence', []))
                
                session_state.findings[finding_id] = finding
                logger.debug(f"🆕 Created new session finding for IP: {primary_ip} with {finding['total_alerts_count']} total alerts")
                
        except Exception as e:
            logger.error(f"Error updating session findings: {str(e)}")
    
    def calculate_ip_risk_score(self, ip_profile: dict, associated_alerts: list) -> int:
        """
         FIXED: Calculate IP risk score using simplified, explainable logic.
        
        Philosophy: Base score from highest severity alert + behavioral pattern bonus
        
        Args:
            ip_profile: IP profile dictionary with behavioral data
            associated_alerts: List of alerts associated with this IP
            
        Returns:
            Risk score from 0-100
        """
        try:
            #  FIXED: Validate inputs
            if not associated_alerts:
                logger.warning("No associated alerts for risk score calculation")
                return 0
            
            if not ip_profile:
                logger.warning("No IP profile for risk score calculation")
                ip_profile = {'connection_count': 0, 'unique_dest_ports': [], 'unique_destinations': [], 'state_counts': {}}
            
            highest_alert_score = 0
            for alert in associated_alerts:
                alert_score = self._get_alert_risk_score(alert)
                highest_alert_score = max(highest_alert_score, alert_score)
            
            if highest_alert_score == 0:
                highest_alert_score = 10  # Minimum base score for any alert
            
            base_score = highest_alert_score
            
            behavioral_bonus = 0
            
            #  FIXED: Safe field access with defaults
            connection_count = ip_profile.get('connection_count', 0)
            unique_dest_ports = ip_profile.get('unique_dest_ports', [])
            unique_destinations = ip_profile.get('unique_destinations', [])
            state_counts = ip_profile.get('state_counts', {})
            
            # Volume indicators (simplified to 3 tiers)
            unique_ports = len(unique_dest_ports) if isinstance(unique_dest_ports, list) else 0
            unique_dest_count = len(unique_destinations) if isinstance(unique_destinations, list) else 0
            
            # High volume behavior (up to 15 points)
            if connection_count > 100 or unique_ports > 20 or unique_dest_count > 10:
                behavioral_bonus += 15  # High volume/scanning behavior
            elif connection_count > 20 or unique_ports > 5 or unique_dest_count > 3:
                behavioral_bonus += 8   # Medium volume behavior
            elif connection_count > 5:
                behavioral_bonus += 3   # Low volume behavior
            
            # Connection failure analysis (up to 10 points)
            if state_counts and isinstance(state_counts, dict):
                failed_connections = state_counts.get('REJ', 0) + state_counts.get('S0', 0)
                total_connections = sum(state_counts.values())
                
                if total_connections > 0:
                    failure_rate = failed_connections / total_connections
                    if failure_rate > 0.5:  # High failure rate suggests scanning/brute force
                        behavioral_bonus += 10
                    elif failure_rate > 0.2:
                        behavioral_bonus += 5
            
            # Alert diversity bonus (up to 10 points)
            unique_alert_types = len(set(
                alert.get('matched_scenario') or alert.get('behavior_type') or alert.get('type', '')
                for alert in associated_alerts
            ))
            
            if unique_alert_types >= 3:
                behavioral_bonus += 10  # Multiple attack vectors
            elif unique_alert_types >= 2:
                behavioral_bonus += 5   # Dual attack vectors
            
            # 🔥 STEP 3: Final calculation with explanation
            final_score = min(base_score + behavioral_bonus, 100)
            
            #  FIXED: Ensure final score is never 0
            if final_score == 0:
                final_score = max(10, base_score)  # At least base score or 10
            
            logger.debug(f"Risk calculation for IP: base_score={base_score}, "
                        f"behavioral_bonus={behavioral_bonus}, final={final_score}")
            
            return final_score
            
        except Exception as e:
            logger.error(f"Error calculating IP risk score: {str(e)}")
            #  FIXED: Return minimum risk score instead of 0
            return 10
    
    def get_ip_investigation_details(self, ip_address: str, all_alerts: list) -> Optional[dict]:
        """
        Generate comprehensive investigation details for a specific IP address.
        
        Args:
            ip_address: IP address to investigate
            all_alerts: List of all alerts to search through
            
        Returns:
            Dictionary with investigation details or None if no data found
        """
        try:
            # Filter alerts for this IP
            ip_alerts = []
            for alert in all_alerts:
                alert_ip = alert.get('ip', alert.get('src_ip', ''))
                if alert_ip == ip_address:
                    ip_alerts.append(alert)
            
            if not ip_alerts:
                return None
            
            # Analyze alert patterns
            alert_types = defaultdict(int)
            first_seen = None
            last_seen = None
            unique_destinations = set()
            unique_ports = set()
            
            for alert in ip_alerts:
                # Count alert types
                alert_type = alert.get('type', 'unknown')
                alert_types[alert_type] += 1
                
                # Track timeline
                timestamp = alert.get('timestamp', '')
                if timestamp:
                    if not first_seen or timestamp < first_seen:
                        first_seen = timestamp
                    if not last_seen or timestamp > last_seen:
                        last_seen = timestamp
                
                # Track destinations and ports
                conn_details = alert.get('connection_details', {})
                if conn_details:
                    dst_ip = conn_details.get('id.resp_h', '')
                    dst_port = conn_details.get('id.resp_p', 0)
                    
                    if dst_ip and dst_ip != '-':
                        unique_destinations.add(dst_ip)
                    if dst_port and dst_port != 0:
                        unique_ports.add(dst_port)
            
            # Generate investigation summary
            investigation_details = {
                'ip_address': ip_address,
                'total_alerts': len(ip_alerts),
                'alert_type_breakdown': dict(alert_types),
                'timeline': {
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'duration': self._calculate_duration(first_seen, last_seen)
                },
                'network_behavior': {
                    'unique_destinations': len(unique_destinations),
                    'unique_ports': len(unique_ports),
                    'destinations_list': list(unique_destinations)[:10],  # Limit for display
                    'ports_list': sorted(list(unique_ports))[:20]  # Limit for display
                },
                'severity_assessment': self._assess_severity(alert_types, len(ip_alerts)),
                'recommended_actions': self._generate_recommendations(alert_types, len(ip_alerts))
            }
            
            return investigation_details
            
        except Exception as e:
            logger.error(f"Error generating IP investigation details: {str(e)}")
            return None
    
    def summarize_finding_for_llm(self, finding: dict) -> dict:
        """
        V2.0 - Enhanced Pre-Analysis Report Generation for LLM Processing
        
        Improvements:
        - Dynamic evidence categorization
        - Enhanced connection pattern analysis  
        - Improved timeline processing
        - Better error handling and fallbacks
        - Optimized for LLM consumption per SYSTEM_PROMPT requirements
        
        Args:
            finding: Complete Finding dictionary (potentially large and complex)
            
        Returns:
            dict: Structured Pre-Analysis Report optimized for LLM analysis
        """
        # Null check at the beginning
        if not finding:
            return self._create_error_fallback(None, "Finding is None or empty")
        
        try:
            # 1. Initialize Pre-Analysis Report
            pre_analysis_report = {}
            
            # 2. Extract Finding Summary (general information)
            pre_analysis_report['finding_summary'] = {
                'title': finding.get('title', 'Unknown Finding'),
                'risk_score': finding.get('risk_score', 0),
                'ip': finding.get('ip', 'Unknown IP'),
                'evidence_count': finding.get('evidence_count', 0)
            }
            
            # 3. Enhanced Evidence Classification with Dynamic Categories
            evidence_list = finding.get('evidence', [])
            evidence_stats = defaultdict(int)  # Dynamic categories
            
            # Priority categories for consistent ordering (DNS ELEVATED)
            PRIORITY_CATEGORIES = [
                # DNS THREATS (HIGHEST PRIORITY) - Priority 1
                'DNS DGA Attack Pattern', 'DNS Tunneling Pattern',
                
                # CONNECTION THREATS (HIGH PRIORITY) - Priority 1
                'Distributed Denial of Service (DDoS)', 'Vertical Port Scan', 'Horizontal Port Scan', 'Brute-Force Attack',
                'Data Exfiltration', 'C2 Beaconing', 'ICMP Data Exfiltration',
                
                # DNS THREATS (HIGH PRIORITY) - Priority 2
                'DNS Covert Channel',
                
                # CONNECTION THREATS (MEDIUM PRIORITY) - Priority 2
                'Suspicious Change in Connection Outcomes', 'General Behavioral Anomaly',
                
                # CONNECTION THREATS (LOW PRIORITY) - Priority 3-4
                'Suspicious Network Connection', 'General Network Anomaly',
                
                # DNS THREATS (LOW PRIORITY) - Priority 4
                'Normal DNS Query',
                
            ]
            
            # Count evidence with enhanced categorization
            for evidence in evidence_list:
                category = self._categorize_evidence_v2(evidence)
                evidence_stats[category] += 1
            
            # Sort categories by priority, then by count
            def category_sort_key(item):
                category, count = item
                try:
                    priority_index = PRIORITY_CATEGORIES.index(category)
                except ValueError:
                    priority_index = len(PRIORITY_CATEGORIES)  # Unknown categories last
                return (priority_index, -count)  # Lower priority index first, higher count first
            
            sorted_evidence_stats = dict(sorted(evidence_stats.items(), key=category_sort_key))
            pre_analysis_report['evidence_statistics'] = sorted_evidence_stats
            
            # 4. Enhanced Evidence Grouping and Analysis
            key_evidence_details = []
            grouped_by_category = defaultdict(list)
            
            # Group evidence by normalized categories
            for ev in evidence_list:
                category = self._categorize_evidence_v2(ev)
                grouped_by_category[category].append(ev)
            
            # Create enhanced summary for each category with COMPLETE information
            for category, group in grouped_by_category.items():
                count = len(group)
                
                # Enhanced evidence selection - pick highest confidence/severity
                representative_evidence = self._select_best_evidence(group)
                
                # Aggregate connection patterns for the entire group
                connection_analysis = self._aggregate_connection_patterns(group)
                
                # CREATE COMPLETE EVIDENCE SEQUENCE for LLM analysis
                evidence_sequence = []
                connection_sequence = []
                
                # Sort group by timestamp for chronological order
                sorted_group = sorted(group, key=lambda x: x.get('timestamp', ''))
                
                for i, ev in enumerate(sorted_group):
                    # Individual evidence summary
                    ev_summary = {
                        'sequence_id': i + 1,
                        'timestamp': ev.get('timestamp', 'N/A'),
                        'type': ev.get('type', 'N/A'),
                        'confidence': ev.get('confidence', 'N/A'),
                        'matched_scenario': ev.get('matched_scenario', 'N/A'),
                        'detector': ev.get('detector', 'N/A')
                    }
                    evidence_sequence.append(ev_summary)
                    
                    # Individual connection details for pattern analysis
                    conn_details = ev.get('connection_details', {})
                    if conn_details:
                        conn_summary = {
                            'sequence_id': i + 1,
                            'src': f"{conn_details.get('id.orig_h', 'N/A')}:{conn_details.get('id.orig_p', 'N/A')}",
                            'dst': f"{conn_details.get('id.resp_h', 'N/A')}:{conn_details.get('id.resp_p', 'N/A')}",
                            'proto': conn_details.get('proto', 'N/A'),
                            'service': conn_details.get('service', 'N/A'),
                            'state': conn_details.get('conn_state', 'N/A'),
                            'duration': conn_details.get('duration', 'N/A'),
                            'bytes_sent': conn_details.get('orig_bytes', 0),
                            'bytes_recv': conn_details.get('resp_bytes', 0)
                        }
                        connection_sequence.append(conn_summary)
                
                # Create COMPREHENSIVE evidence detail with complete information
                evidence_detail = {
                    'timestamp': representative_evidence.get('timestamp', 'N/A'),
                    'type': representative_evidence.get('type', 'N/A'),
                    'summary': f"{category} ({count} event{'s' if count > 1 else ''})",
                    'confidence_score': self._calculate_evidence_confidence(representative_evidence),
                    
                    # ORIGINAL: Representative evidence details
                    'representative_evidence': {
                        'connection_details': representative_evidence.get('connection_details', {}),
                        'technical_details': self._extract_technical_details(representative_evidence)
                    },
                    
                    # NEW: Complete evidence sequence for LLM pattern analysis
                    'complete_evidence_sequence': evidence_sequence,
                    'complete_connection_sequence': connection_sequence,
                    
                    # ENHANCED: Network analysis with more details
                    'network_analysis': {
                        **connection_analysis,
                        'total_connections': len(connection_sequence),
                        'connection_timeline': {
                            'first_connection': connection_sequence[0] if connection_sequence else {},
                            'last_connection': connection_sequence[-1] if connection_sequence else {},
                            'pattern_diversity': len(set(c.get('service', 'unknown') for c in connection_sequence))
                        }
                    }
                }
                key_evidence_details.append(evidence_detail)
            
            # Sort by confidence score and event count
            key_evidence_details.sort(
                key=lambda x: (x.get('confidence_score', 0), self._extract_event_count_from_summary(x.get('summary', ''))), 
                reverse=True
            )
            
            # Limit to top 10 for LLM processing efficiency
            pre_analysis_report['key_evidence_details'] = key_evidence_details[:10]
            
            # 5. Enhanced Timeline Analysis
            timeline_summary = self._enhanced_timeline_analysis(evidence_list)
            pre_analysis_report['timeline_summary'] = timeline_summary
            
            # 6. Additional Context for LLM
            pre_analysis_report['context_metadata'] = {
                'total_unique_categories': len(evidence_stats),
                'highest_risk_category': max(evidence_stats.items(), key=lambda x: x[1])[0] if evidence_stats else 'None',
                'analysis_complexity': 'High' if len(evidence_list) > 10 else 'Medium' if len(evidence_list) > 3 else 'Low'
            }
            
            return pre_analysis_report
            
        except Exception as e:
            logger.error(f"Error in enhanced LLM summarization: {str(e)}", exc_info=True)
            # Enhanced error fallback with partial data
            return self._create_error_fallback(finding, str(e))

    def _categorize_evidence_v2(self, evidence: dict) -> str:
        """
        Enhanced evidence categorization with priority hierarchy and normalization.
        
        Priority: matched_scenario > behavior_type > evidence_type (normalized)
        IMPORTANT: Preserve source information (DNS vs Connection) in category names
        """
        # Priority 1: Use matched_scenario if available (most specific)
        scenario = evidence.get('matched_scenario', '').strip()
        if scenario:
            # Check if it's DNS-related first (DNS has higher priority)
            if 'dns' in scenario.lower():
                # Don't add "DNS" prefix if _normalize_category_name already includes it
                normalized = self._normalize_category_name(scenario)
                if normalized.startswith('DNS '):
                    return normalized
                else:
                    return f"DNS {normalized}"
            # Then check evidence_type for connection anomalies
            evidence_type = evidence.get('type', '').strip()
            if evidence_type in ['ml_anomaly', 'behavior_anomaly']:
                # Only add "Connection" prefix for actual connection-based anomalies
                # Port scan, brute force, etc. don't need "Connection" prefix
                if scenario in ['port_scan', 'brute_force', 'brute_force_attack']:
                    return self._normalize_category_name(scenario)
                else:
                    return f"Connection {self._normalize_category_name(scenario)}"
            else:
                return self._normalize_category_name(scenario)
        
        # Priority 2: Use behavior_type (specific behavior) with source prefix
        behavior = evidence.get('behavior_type', '') or ''
        if behavior and isinstance(behavior, str):
            behavior = behavior.strip()
        if behavior:
            evidence_type = evidence.get('type', '').strip()
            if evidence_type in ['ml_anomaly', 'behavior_anomaly']:
                return f"Connection {self._normalize_category_name(behavior)}"
            else:
                return self._normalize_category_name(behavior)
        
        # Priority 3: Map evidence_type with clear source identification
        evidence_type = evidence.get('type', '').strip()
        
        if evidence_type == 'ml_anomaly':
            confidence = evidence.get('confidence', 'Low')
            return f"Connection ML Anomaly - {confidence}"
        elif evidence_type == 'behavior_anomaly':
            return "Connection Behavior Anomaly"
        elif evidence_type == 'dns_tunneling':
            return "DNS Tunneling"


        elif evidence_type == 'suricata_alert':
            # Try to extract more specific info from alert
            alert_sig = evidence.get('alert', {}).get('signature', '').lower()
            if 'ssh' in alert_sig and ('brute' in alert_sig or 'force' in alert_sig):
                return "SSH Brute Force"
            elif 'scan' in alert_sig:
                return "Port Scan"
            else:
                return "Suricata Alert"
        else:
            return self._normalize_category_name(evidence_type) if evidence_type else "Unknown Activity"

    def _normalize_category_name(self, category: str) -> str:
        """Normalize category names for consistency."""
        if not category:
            return "Unknown Activity"
        
        category_lower = category.lower()
        
        # Comprehensive normalization mapping
        normalization_map = {
            # Attack types
            'port_scan': 'Port Scan',
            'data_exfiltration': 'Data Exfiltration', 
            'c2_beaconing': 'C2 Beaconing',
            'connection_flood': 'Connection Flood',

            'dns_tunneling': 'DNS Tunneling',
            'icmp_tunneling': 'ICMP Tunneling',
            
            # Specific attack patterns (more specific first)
            'ssh brute-force attack': 'Brute-Force Attack',
            'ssh brute force attack': 'Brute-Force Attack',
            'brute-force attack': 'Brute-Force Attack',
            'brute force attack': 'Brute-Force Attack',
            'port scan / ddos attack': 'Port Scan',
            'dns-based attack (tunneling/exfiltration)': 'Data Exfiltration',
            'network authentication attack': 'Suspicious Change in Connection Outcomes',
            
            # Keywords to category mapping (less specific)
            'scan': 'Port Scan',
            'brute': 'Brute Force Attack',
            'flood': 'Connection Flood',
            'exfil': 'Data Exfiltration',
            'tunnel': 'Tunneling Activity',
            'beacon': 'C2 Beaconing',
            'ddos': 'DDoS Attack',
            'malware': 'Malware Activity'
        }
        
        # Direct mapping first
        if category_lower in normalization_map:
            return normalization_map[category_lower]
        
        # Keyword-based mapping
        for keyword, normalized in normalization_map.items():
            if keyword in category_lower:
                return normalized
        
        # Fallback: capitalize properly
        return ' '.join(word.capitalize() for word in category.replace('_', ' ').split())

    def _select_best_evidence(self, evidence_group: list) -> dict:
        """Select the most representative evidence from a group based on confidence and severity."""
        if not evidence_group:
            return {}
        
        # Score each evidence
        best_evidence = evidence_group[0]
        best_score = 0
        
        for evidence in evidence_group:
            score = 0
            
            # Confidence scoring
            confidence = evidence.get('confidence', 'Low')
            if confidence == 'High':
                score += 30
            elif confidence == 'Medium':
                score += 20
            elif confidence == 'Low':
                score += 10
            
            # Evidence type scoring (threat intel highest priority)
            evidence_type = evidence.get('type', '')
            if evidence_type == 'behavior_anomaly':
                score += 20
            elif evidence_type == 'ml_anomaly':
                score += 15
            
            # Technical detail richness
            if evidence.get('connection_details'):
                score += 10
            if evidence.get('matched_scenario'):
                score += 5
            
            if score > best_score:
                best_score = score
                best_evidence = evidence
        
        return best_evidence

    def _aggregate_connection_patterns(self, evidence_group: list) -> dict:
        """Aggregate network connection patterns from all evidence in group."""
        if not evidence_group:
            return {}
        
        destination_ips = set()
        destination_ports = set()
        protocols = set()
        connection_states = defaultdict(int)
        
        for evidence in evidence_group:
            conn_details = evidence.get('connection_details', {})
            
            # Collect destination IPs
            dest_ip = conn_details.get('id.resp_h') or conn_details.get('target_ip')
            if dest_ip and dest_ip != '-':
                destination_ips.add(dest_ip)
            
            # Collect destination ports
            dest_port = conn_details.get('id.resp_p')
            if dest_port and dest_port != 0 and dest_port != '-':
                destination_ports.add(str(dest_port))
            
            # Collect protocols
            protocol = conn_details.get('proto') or conn_details.get('protocol')
            if protocol and protocol != '-':
                protocols.add(protocol.upper())
            
            # Collect connection states
            state = conn_details.get('conn_state')
            if state and state != '-':
                connection_states[state] += 1
        
        return {
            'unique_destinations': len(destination_ips),
            'destination_ips': sorted(list(destination_ips))[:5],  # Top 5 for brevity
            'unique_ports': len(destination_ports),
            'destination_ports': sorted(list(destination_ports), key=lambda x: int(x) if x.isdigit() else 999)[:10],
            'protocols': sorted(list(protocols)),
            'connection_states': dict(connection_states)
        }

    def _calculate_evidence_confidence(self, evidence: dict) -> int:
        """Calculate a confidence score (0-100) for evidence quality."""
        score = 50  # Base score
        
        # Evidence type confidence
        evidence_type = evidence.get('type', '')
        if evidence_type == 'behavior_anomaly':
            score += 20
        elif evidence_type == 'ml_anomaly':
            confidence = evidence.get('confidence', 'Low')
            if confidence == 'High':
                score += 25
            elif confidence == 'Medium':
                score += 15
            else:
                score += 5
        
        # Data richness
        if evidence.get('connection_details'):
            score += 10
        if evidence.get('matched_scenario'):
            score += 10
        if evidence.get('details'):
            score += 5
        
        return min(score, 100)

    def _extract_technical_details(self, evidence: dict) -> dict:
        """Extract technical details relevant for MITRE mapping."""
        details = {}
        
        # DNS-specific technical details
        if evidence.get('type') == 'dns_tunneling':
            dns_details = evidence.get('dns_details', {})
            conn_details = evidence.get('connection_details', {})
            
            # Extract DNS query information
            details['query_name'] = dns_details.get('query') or conn_details.get('query', 'Unknown')
            details['tunnel_type'] = 'DNS'
            details['query_type'] = dns_details.get('qtype') or conn_details.get('qtype_name', 'Unknown')
            details['response_code'] = dns_details.get('rcode') or conn_details.get('rcode_name', 'Unknown')
            
            # Extract feature-based indicators
            features = dns_details.get('features', {})
            if features:
                if features.get('query_length'):
                    details['query_length'] = features.get('query_length')
                if features.get('query_entropy'):
                    details['query_entropy'] = round(features.get('query_entropy'), 2)
                if features.get('subdomain_count'):
                    details['subdomain_count'] = features.get('subdomain_count')
                if features.get('has_base64_pattern'):
                    details['encoded_data'] = 'Base64 patterns detected'
                elif features.get('has_hex_pattern'):
                    details['encoded_data'] = 'Hex patterns detected'
            
            # Add ML confidence
            ml_details = dns_details.get('ml_details', {})
            if ml_details:
                details['ml_confidence'] = ml_details.get('confidence', 'Unknown')
                details['detector'] = ml_details.get('detector', 'DNS ML')
        
        # Connection technical details
        conn = evidence.get('connection_details', {})
        if conn:
            details['protocol'] = conn.get('proto') or conn.get('protocol', 'Unknown')
            details['service'] = conn.get('service', 'Unknown')
            details['destination_port'] = conn.get('id.resp_p', 'Unknown')
            # Add more connection-specific details
            if conn.get('orig_bytes'):
                details['orig_bytes'] = conn.get('orig_bytes')
            if conn.get('resp_bytes'):
                details['resp_bytes'] = conn.get('resp_bytes')
            if conn.get('duration'):
                details['duration'] = conn.get('duration')
        
        # Behavior details
        details['behavior_type'] = evidence.get('behavior_type', 'Unknown')
        details['matched_scenario'] = evidence.get('matched_scenario', 'Unknown')
        
        # ML details
        if evidence.get('type') == 'ml_anomaly':
            details['ml_confidence'] = evidence.get('confidence', 'Unknown')
            details['detector'] = evidence.get('detector', 'Unknown')
            details['anomaly_score'] = evidence.get('anomaly_score', 'Unknown')
        
        # Behavioral anomaly details
        if evidence.get('type') == 'behavior_anomaly':
            details['behavior_confidence'] = evidence.get('confidence', 'Unknown')
            if evidence.get('threshold_exceeded'):
                details['threshold_exceeded'] = evidence.get('threshold_exceeded')
        
        return {k: v for k, v in details.items() if v != 'Unknown' and v != ''}

    def _enhanced_timeline_analysis(self, evidence_list: list) -> dict:
        """Enhanced timeline analysis with proper timestamp handling and debugging."""
        if not evidence_list:
            return {}
        
        # Extract and validate timestamps with debugging
        valid_timestamps = []
        timestamp_debug = []
        
        for i, evidence in enumerate(evidence_list):

            timestamp = evidence.get('timestamp', '')
            if timestamp:
                #  FIX: Use unified timestamp parsing instead of duplicate code
                parsed_ts = self._parse_timestamp_safe(timestamp)
                if parsed_ts:
                    valid_timestamps.append(parsed_ts)
                    timestamp_debug.append(f"Evidence {i}: {timestamp}")
                else:
                    logger.warning(f"Could not parse timestamp: {timestamp}")
            else:
                logger.warning(f"Evidence {i} missing timestamp")
        
        if not valid_timestamps:
            return {
                'duration': 'Unknown', 
                'note': 'No valid timestamps found',
                'debug_info': timestamp_debug
            }
        
        # Sort timestamps
        valid_timestamps.sort()
        
        first_timestamp = valid_timestamps[0]
        last_timestamp = valid_timestamps[-1]
        
        # Calculate duration with millisecond precision
        calculated_duration = self._calculate_duration_enhanced(first_timestamp, last_timestamp)
        
        # Debug information
        timeline_result = {
            'first_evidence_at': first_timestamp,
            'last_evidence_at': last_timestamp,
            'duration': calculated_duration,
            'total_events': len(evidence_list),
            'events_with_timestamps': len(valid_timestamps),
            'timeline_completeness': f"{len(valid_timestamps)}/{len(evidence_list)} events"
        }
        
        # Add debug info if duration is suspiciously short
        if calculated_duration == "0 seconds" or "0 seconds" in calculated_duration:
            timeline_result['debug_info'] = {
                'all_timestamps': valid_timestamps,
                'timestamp_count': len(valid_timestamps),
                'unique_timestamps': len(set(valid_timestamps)),
                'note': 'Duration is 0 - possibly all events occurred simultaneously'
            }
        
        return timeline_result

    def _extract_event_count_from_summary(self, summary: str) -> int:
        """Extract event count from summary text for sorting."""
        try:
            if '(' in summary and ' event' in summary:
                part = summary.split('(')[1]
                count_part = part.split(' event')[0]
                return int(count_part)
            return 0
        except (ValueError, IndexError):
            return 0

    def _create_error_fallback(self, finding: dict, error_message: str) -> dict:
        """Create a structured error fallback with partial data for LLM processing."""
        return {
            'status': 'partial_analysis_due_to_error',
            'error_details': {
                'message': error_message,
                'timestamp': datetime.now().isoformat()
            },
            'finding_summary': {
                'title': finding.get('title', 'Unknown Finding'),
                'risk_score': finding.get('risk_score', 0),
                'ip': finding.get('ip', 'Unknown IP'),
                'evidence_count': len(finding.get('evidence', []))
            },
            'evidence_statistics': {
                'Error': 1,
                'Total_Evidence_Available': len(finding.get('evidence', []))
            },
            'key_evidence_details': [{
                'timestamp': 'N/A',
                'type': 'error_analysis',
                'summary': f"Analysis partially failed: {error_message}",
                'confidence_score': 0,
                'connection_details': {},
                'network_analysis': {},
                'technical_details': {}
            }],
            'timeline_summary': {
                'duration': 'Analysis Error',
                'note': 'Timeline analysis failed due to processing error'
            },
            'context_metadata': {
                'total_unique_categories': 1,
                'highest_risk_category': 'Error',
                'analysis_complexity': 'Error'
            }
        }

    def _generate_evidence_summary(self, evidence: dict) -> str:
        """Generate human-readable summary for evidence."""
        try:
            evidence_type = evidence.get('type', '')
            
            if evidence_type == 'ml_anomaly':
                detector = evidence.get('detector', 'ML Model')
                confidence = evidence.get('confidence', 'Unknown')
                matched_scenario = evidence.get('matched_scenario', 'Anomalous behavior')
                return f"{detector} detected {matched_scenario} with {confidence} confidence"
            
            elif evidence_type == 'behavior_anomaly':
                behavior_type = evidence.get('behavior_type', 'Unknown behavior')
                details = evidence.get('details', '')
                if details:
                    return details
                else:
                    return f"Behavioral anomaly: {behavior_type}"
            
            
            
            else:
                # Generic summary
                details = evidence.get('details', '')
                if details:
                    return details
                else:
                    return f"Security event: {evidence_type}"
                    
        except Exception as e:
            logger.error(f"Error generating evidence summary: {str(e)}")
            return "Security event detected"
    
    def _calculate_duration(self, start_time: str, end_time: str) -> str:
        """
        Calculate duration between two timestamps.
        Now uses the enhanced method for consistency.
        """
        return self._calculate_duration_enhanced(start_time, end_time)

    def _calculate_duration_enhanced(self, start_time: str, end_time: str) -> str:
        """Enhanced duration calculation with millisecond precision and better debugging."""
        try:
            if not start_time or not end_time:
                return "Unknown duration"
            
            if start_time == end_time:
                return "0 seconds (simultaneous events)"
            

            start_dt = self._parse_timestamp_safe(start_time)
            end_dt = self._parse_timestamp_safe(end_time)
            
            if not start_dt or not end_dt:
                return "Invalid timestamp format"
            
            duration = end_dt - start_dt
            total_seconds = duration.total_seconds()
            
            # Handle negative duration (clock skew or ordering issues)
            if total_seconds < 0:
                return f"Invalid duration ({total_seconds:.3f}s - negative)"
            
            # Enhanced formatting with millisecond precision for short durations
            if total_seconds == 0:
                return "0 seconds (same timestamp)"
            elif total_seconds < 1:
                milliseconds = int(total_seconds * 1000)
                return f"{milliseconds} milliseconds"
            elif total_seconds < 60:
                return f"{total_seconds:.1f} seconds"
            elif total_seconds < 3600:
                minutes = int(total_seconds // 60)
                remaining_seconds = int(total_seconds % 60)
                return f"{minutes}m {remaining_seconds}s"
            elif total_seconds < 86400:
                hours = int(total_seconds // 3600)
                minutes = int((total_seconds % 3600) // 60)
                return f"{hours}h {minutes}m"
            else:
                days = int(total_seconds // 86400)
                hours = int((total_seconds % 86400) // 3600)
                return f"{days}d {hours}h"
                
        except Exception as e:
            logger.error(f"Error calculating enhanced duration: {str(e)}")
            logger.error(f"Start: {start_time}, End: {end_time}")
            return f"Duration calculation error: {str(e)}"
    
    def _assess_severity(self, alert_types: Dict[str, int], total_alerts: int) -> str:
        """Assess overall severity based on alert patterns."""
        try:
            # High severity indicators
            if alert_types.get('behavior_anomaly', 0) > 10:
                return "High"
            
            if alert_types.get('ml_anomaly', 0) > 5:
                return "High"
            
            if total_alerts > 20:
                return "Medium"
            
            if total_alerts > 5:
                return "Low"
            
            return "Informational"
            
        except Exception:
            return "Unknown"
    
    def _generate_recommendations(self, alert_types: Dict[str, int], total_alerts: int) -> List[str]:
        """Generate actionable recommendations based on alert patterns."""
        recommendations = []
        
        try:
            if alert_types.get('behavior_anomaly', 0) > 5:
                recommendations.append("Monitor this IP for continued suspicious behavior")
                recommendations.append("Consider rate limiting or temporary blocking")
            
            if alert_types.get('ml_anomaly', 0) > 3:
                recommendations.append("Review ML model predictions for false positives")
                recommendations.append("Correlate with other security tools")
            
            if total_alerts > 10:
                recommendations.append("Prioritize investigation of this IP")
                recommendations.append("Check for lateral movement indicators")
            
            if not recommendations:
                recommendations.append("Continue monitoring")
                recommendations.append("Document findings for future reference")
            
            return recommendations[:5]  # Limit to top 5 recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            return ["Review security logs", "Continue monitoring"]

    # REMOVED: correlate_and_update_findings - consolidated into correlate_events

    def _parse_timestamp_safe(self, timestamp_str: str) -> Optional[datetime]:
        """
         FIXED: Unified timestamp parsing with comprehensive format support.
        Eliminates code duplication and handles various timestamp formats safely.
        
        Args:
            timestamp_str: Timestamp string in various formats
            
        Returns:
            Parsed datetime object or None if parsing fails
        """
        if not timestamp_str:
            return None
            
        try:
            # Handle various timestamp formats
            if isinstance(timestamp_str, datetime):
                return timestamp_str
                
            #  FIXED: Handle ISO format with 'Z' suffix (UTC)
            if timestamp_str.endswith('Z'):
                # Convert 'Z' to '+00:00' for proper timezone handling
                timestamp_str = timestamp_str.replace('Z', '+00:00')
                
            #  FIXED: Handle ISO format with timezone offset
            if '+' in timestamp_str or '-' in timestamp_str[-6:]:
                return datetime.fromisoformat(timestamp_str)
                
            #  FIXED: Handle ISO format without timezone (assume local time)
            return datetime.fromisoformat(timestamp_str)
            
        except Exception as e:
            #  FIXED: Try alternative parsing methods
            try:
                # Try parsing with dateutil for more flexible format support
                from dateutil import parser
                return parser.parse(timestamp_str)
            except:
                try:
                    # Try parsing common formats manually
                    import re
                    
                    # Handle ISO format with milliseconds
                    iso_pattern = r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?'
                    match = re.match(iso_pattern, timestamp_str)
                    if match:
                        date_part = match.group(1)
                        time_part = match.group(2)
                        ms_part = match.group(3) or '.0'
                        tz_part = match.group(4) or ''
                        
                        # Reconstruct ISO string
                        iso_string = f"{date_part}T{time_part}{ms_part}{tz_part}"
                        if tz_part == 'Z':
                            iso_string = iso_string.replace('Z', '+00:00')
                        
                        return datetime.fromisoformat(iso_string)
                    
                    # Handle Unix timestamp
                    if timestamp_str.isdigit():
                        return datetime.fromtimestamp(int(timestamp_str))
                        
                except:
                    pass
                    
            logger.warning(f"Could not parse timestamp '{timestamp_str}': {e}")
            return None




    def _calculate_finding_risk_score(self, evidence_list: List[Dict[str, Any]]) -> int:
        """
        🎯 UNIFIED: Calculate finding risk score using unified threat definitions.
        Algorithm: Highest threat score + simplified volume bonus for unique attack types.
        """
        if not evidence_list:
            return 0

        max_score = 0
        unique_attack_types = set()
        
        # Find highest threat score and collect unique attack types
        for event in evidence_list:
            threat_key = (event.get('matched_scenario') or 
                         event.get('behavior_type') or 
                         event.get('type', 'unknown'))
            
            rule_priority = event.get('rule_priority')
            threat_info = self.get_threat_info(threat_key, rule_priority)
            
            score = threat_info['score']
            if score > max_score:
                max_score = score
                
            # Only count significant threats for diversity bonus
            if score >= 30:  # Only meaningful threats
                unique_attack_types.add(threat_key)
        
        # Simple volume bonus: +5 points per additional unique attack type
        diversity_bonus = max(0, (len(unique_attack_types) - 1) * 5)
        diversity_bonus = min(diversity_bonus, 15)  # Cap at 15 points
        
        final_score = min(max_score + diversity_bonus, 100)
        
        return int(final_score) 


def _sanitize_for_json(obj):
    """
    Recursively convert numpy types to Python native types for JSON serialization.
    Preserves unicode and special characters.
    """
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_for_json(v) for v in obj]
    # Handle numpy arrays explicitly (e.g., SHAP outputs)
    elif isinstance(obj, np.ndarray):
        return [_sanitize_for_json(v) for v in obj.tolist()]
    elif isinstance(obj, np.generic):
        return obj.item()
    elif isinstance(obj, (np.bool_, bool)):
        return bool(obj)
    elif isinstance(obj, (np.integer, int)):
        return int(obj)
    elif isinstance(obj, (np.floating, float)):
        return float(obj)
    # Handle datetime objects (e.g., finding['start_time'])
    elif isinstance(obj, datetime):
        return obj.isoformat()
    # Handle tuples/sets by converting to lists
    elif isinstance(obj, (tuple, set)):
        return [_sanitize_for_json(v) for v in obj]
    # Preserve strings as-is (including unicode)
    elif isinstance(obj, str):
        return obj
    else:
        return obj

def write_findings_to_jsonl(findings, output_path):
    """
    Ghi list findings ra file JSONL (mỗi dòng 1 JSON object, UTF-8, append mode), thêm output_timestamp, auto convert numpy types.
    """
    # Ensure output directory exists (robust for first run)
    import os
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    
    processed_finding_ids = set()
    
    # Load existing findings từ file để kiểm tra duplicate và thay đổi
    existing_findings = {}  # Changed from set to dict to store finding data
    if os.path.exists(output_path):
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            existing = json.loads(line)
                            finding_id = existing.get('finding_id')
                            if finding_id:
                                existing_findings[finding_id] = existing
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.warning(f"Error reading existing findings for duplicate check: {str(e)}")
    
    # Ghi findings mới hoặc cập nhật findings có thay đổi
    new_findings_count = 0
    updated_findings_count = 0
    
    with open(output_path, 'w', encoding='utf-8') as f:  # Changed from 'a' to 'w' for overwrite
        # First, write all existing findings that don't need updates
        for finding_id, existing_finding in existing_findings.items():
            # Check if this finding needs to be updated
            needs_update = False
            for new_finding in findings:
                if new_finding.get('finding_id') == finding_id:
                    # Check for important changes
                    if (new_finding.get('finding_type') != existing_finding.get('finding_type') or
                        new_finding.get('severity') != existing_finding.get('severity') or
                        new_finding.get('risk_score') != existing_finding.get('risk_score') or
                        new_finding.get('evidence_count', 0) != existing_finding.get('evidence_count', 0)):
                        needs_update = True
                    break
            
            if not needs_update:
                # Write existing finding unchanged
                f.write(json.dumps(_sanitize_for_json(existing_finding), ensure_ascii=False) + '\n')
        
        # Then, write new findings and updated findings
        for finding in findings:
            finding_id = finding.get('finding_id')
            
            if not finding_id:
                continue
                
            # Check if this is an update to existing finding
            if finding_id in existing_findings:
                existing_finding = existing_findings[finding_id]
                # Check for important changes
                if (finding.get('finding_type') != existing_finding.get('finding_type') or
                    finding.get('severity') != existing_finding.get('severity') or
                    finding.get('risk_score') != existing_finding.get('risk_score') or
                    finding.get('evidence_count', 0) != existing_finding.get('evidence_count', 0)):
                    
                    # Update the finding
                    finding_with_ts = dict(finding)
                    finding_with_ts['output_timestamp'] = datetime.utcnow().isoformat() + 'Z'
                    finding_sanitized = _sanitize_for_json(finding_with_ts)
                    f.write(json.dumps(finding_sanitized, ensure_ascii=False) + '\n')
                    updated_findings_count += 1
                    logger.info(f"Updated finding {finding_id}: {existing_finding.get('finding_type')} -> {finding.get('finding_type')}")
                else:
                    # No important changes, write existing finding unchanged
                    f.write(json.dumps(_sanitize_for_json(existing_finding), ensure_ascii=False) + '\n')
            else:
                # New finding
                if finding_id not in processed_finding_ids:
                    finding_with_ts = dict(finding)
                    finding_with_ts['output_timestamp'] = datetime.utcnow().isoformat() + 'Z'
                    finding_sanitized = _sanitize_for_json(finding_with_ts)
                    f.write(json.dumps(finding_sanitized, ensure_ascii=False) + '\n')
                    new_findings_count += 1
                    processed_finding_ids.add(finding_id)
    
    logger.info(f"Smart Update: Wrote {new_findings_count} new findings, updated {updated_findings_count} existing findings to {output_path}")
    return new_findings_count + updated_findings_count

def write_compact_alerts_to_jsonl(findings, output_path, overwrite: bool = False):
    """
    Write compact, per-finding JSONL lines suitable for Security Onion ingestion.
    Ensures a single line per finding_id by performing an upsert (read, merge, rewrite).

    Fields:
    - timestamp, finding_id, finding_type, src_ip, dst_ip, dst_port, proto
    - severity, risk_score, detector, matched_scenario, evidence_count
    - first_ev_ts, last_ev_ts, sample_dst_ports, ai_explanation
    """
    import os
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)


    # Build a fresh compact index when overwrite=True, otherwise merge with existing
    existing_compact = {}
    if not overwrite and os.path.exists(output_path):
        try:
            with open(output_path, 'r', encoding='utf-8') as rf:
                for line in rf:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        fid = obj.get('finding_id')
                        if fid:
                            if fid not in existing_compact:
                                existing_compact[fid] = []
                            existing_compact[fid].append(obj)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.warning(f"Error reading existing compact alerts: {str(e)}")

    for finding in findings or []:
        evidence_list = finding.get('evidence', []) or []
        ev_count = finding.get('evidence_count', len(evidence_list))

        # Timestamps and sample ports
        first_ev_ts = None
        last_ev_ts = None
        sample_dst_ports = []

        if evidence_list:
            first_ev = evidence_list[0]
            first_ev_ts = first_ev.get('timestamp', finding.get('created_at'))
            last_ev = evidence_list[-1]
            last_ev_ts = last_ev.get('timestamp', finding.get('created_at'))
            for ev in evidence_list[:10]:
                conn_tmp = ev.get('connection_details', {})
                dst_port_tmp = conn_tmp.get('id.resp_p')
                if dst_port_tmp and dst_port_tmp not in sample_dst_ports:
                    sample_dst_ports.append(dst_port_tmp)

        # Representative connection details
        first_evidence = (evidence_list or [{}])[0]
        conn = first_evidence.get('connection_details', {}) or {}

        # Explanation extraction (same logic as before)
        explanations = []
        scenario_priority = {
            'C2 Beaconing': 100,
            'DNS Tunneling Pattern': 95,
            'DNS DGA Attack Pattern': 90,
            'Vertical Port Scan': 75,
            'Horizontal Port Scan': 75,
            'DDoS Attack': 70,
            'Brute-Force Attack': 70,
            'Data Exfiltration': 70,
            'General Behavioral Anomaly': 10
        }

        conn_evidence = []
        dns_evidence = []
        for evidence in evidence_list:
            if evidence.get('type') in ['ml_anomaly', 'behavior_anomaly']:
                # Check if this is DNS-related behavior anomaly
                if evidence.get('behavior_type') in ['dns_dga', 'dns_tunneling']:
                    dns_evidence.append(evidence)
                else:
                    conn_evidence.append(evidence)
            elif evidence.get('type') in ['dns_tunneling', 'dns_anomaly']:
                dns_evidence.append(evidence)

        # z-scores from best connection evidence
        if conn_evidence:
            conn_evidence.sort(key=lambda x: (
                scenario_priority.get(x.get('matched_scenario', ''), 0),
                x.get('risk_score', 0)
            ), reverse=True)
            best_conn_evidence = conn_evidence[0]
            all_z_scores = {}
            ml_evidence = best_conn_evidence.get('ml_evidence', {})
            z_score_evidence = ml_evidence.get('z_score_evidence', {})
            if z_score_evidence:
                for feature_name, z_score in z_score_evidence.items():
                    if isinstance(z_score, (int, float)) and z_score != 0:
                        all_z_scores[feature_name] = (feature_name, z_score, abs(z_score))
            direct_z_score_evidence = best_conn_evidence.get('z_score_evidence', {})
            if direct_z_score_evidence:
                for feature_name, z_score in direct_z_score_evidence.items():
                    if isinstance(z_score, (int, float)) and z_score != 0:
                        all_z_scores[feature_name] = (feature_name, z_score, abs(z_score))
            for key, value in best_conn_evidence.items():
                if key.startswith('z_') and isinstance(value, (int, float)) and value != 0:
                    all_z_scores[key] = (key, value, abs(value))
            if all_z_scores:
                z_scores_list = list(all_z_scores.values())
                z_scores_list.sort(key=lambda x: x[2], reverse=True)
                top_3_z_scores = [{'feature': name, 'z_score': round(original_score, 3)}
                                  for name, original_score, _ in z_scores_list[:3]]
                z_strings = [f"{item['feature']}={item['z_score']}" for item in top_3_z_scores]
                explanations.append(f"Behavioral: {'; '.join(z_strings)}")

        # SHAP from best DNS evidence
        if dns_evidence:
            dns_evidence.sort(key=lambda x: (
                scenario_priority.get(x.get('matched_scenario', ''), 0),
                x.get('risk_score', 0)
            ), reverse=True)
            best_dns_evidence = dns_evidence[0]
            dns_shap_scores = {}
            
            # Check multiple locations for SHAP values
            shap_locations = [
                best_dns_evidence.get('shap_values', {}),
                best_dns_evidence.get('ml_evidence', {}).get('shap_values', {}),
                best_dns_evidence.get('feature_importance', {}),
                # Add DNS-specific explanation fields
                best_dns_evidence.get('explanation', {}).get('isolation_forest_shap', {}).get('top_features', []),
                best_dns_evidence.get('explanation', {}).get('isolation_forest_shap', {}).get('top_features', [])
            ]
            
            for i, shap_data in enumerate(shap_locations):
                if isinstance(shap_data, dict):
                    # Handle regular SHAP dict format
                    for feature_name, shap_value in shap_data.items():
                        if isinstance(shap_value, (int, float)) and shap_value != 0:
                            dns_shap_scores[feature_name] = (feature_name, shap_value, abs(shap_value))
                elif isinstance(shap_data, list) and i >= 3:
                    # Handle DNS SHAP list format from explanation field
                    for feature_data in shap_data:
                        if isinstance(feature_data, dict):
                            feature_name = feature_data.get('feature', 'Unknown')
                            shap_value = feature_data.get('shap_value', 0)
                            if isinstance(shap_value, (int, float)) and shap_value != 0:
                                dns_shap_scores[feature_name] = (feature_name, shap_value, abs(shap_value))
            
            if dns_shap_scores:
                shap_list = list(dns_shap_scores.values())
                shap_list.sort(key=lambda x: x[2], reverse=True)
                top_3_shap = shap_list[:3]
                shap_strings = [f"{name}={score:.3f}" for name, score in [(item[0], item[1]) for item in top_3_shap]]
                explanations.append(f"Content: {'; '.join(shap_strings)}")

        ai_explanation = " | ".join(explanations) if explanations else "No explanation available"

        # Extract behavior history to preserve evolution information
        behavior_history = finding.get('behavior_types', [])
        if not behavior_history:
            # Fallback: extract from evidence if behavior_types not available
            evidence_behaviors = set()
            for ev in evidence_list:
                if ev.get('matched_scenario'):
                    evidence_behaviors.add(ev.get('matched_scenario'))
            behavior_history = list(evidence_behaviors) if evidence_behaviors else []
        
        compact = {
            'timestamp': (
                finding.get('last_updated') or
                last_ev_ts or
                finding.get('created_at', datetime.utcnow().isoformat() + 'Z')
            ),
            'finding_id': finding.get('finding_id', ''),
            'finding_type': finding.get('finding_type', ''),
            'src_ip': finding.get('ip', ''),
            'dst_ip': conn.get('id.resp_h', ''),
            'dst_port': conn.get('id.resp_p', ''),
            'proto': conn.get('proto', ''),
            'severity': finding.get('severity', 'low'),
            'risk_score': finding.get('risk_score', 0),
            'detector': first_evidence.get('detector', 'Unknown'),
            'matched_scenario': (finding.get('matched_scenario') or finding.get('title', '')),
            'evidence_count': finding.get('total_alerts_count', ev_count),
            'first_ev_ts': first_ev_ts,
            'last_ev_ts': last_ev_ts,
            'sample_dst_ports': sample_dst_ports,
            'ai_explanation': ai_explanation,
            'behavior_history': behavior_history  
        }

        fid = compact.get('finding_id')
        if not fid:
            continue


        if fid not in existing_compact:
            existing_compact[fid] = []
        
        existing_compact[fid].append(compact)

    try:
        with open(output_path, 'w', encoding='utf-8') as wf:
            all_records = []
            for finding_id, finding_states in existing_compact.items():
                if isinstance(finding_states, list):
                    all_records.extend(finding_states)
                else:
                    all_records.append(finding_states)
            
            try:
                all_records.sort(key=lambda x: x.get('timestamp', ''))
            except Exception:
                pass
            
            for obj in all_records:
                wf.write(json.dumps(_sanitize_for_json(obj), ensure_ascii=False) + '\n')
        
        total_states = sum(len(states) if isinstance(states, list) else 1 for states in existing_compact.values())
        logger.info(f"Compact append complete: wrote {total_states} finding states to {output_path}")
    except Exception as e:
        logger.error(f"Error writing compact alerts: {str(e)}")