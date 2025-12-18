#!/usr/bin/env python3
"""
Configuration file for Network Anomaly Detection System
Contains all constants and thresholds used throughout the system.
"""

import re



# Check for optional dependencies with detailed error reporting
try:
    import shap
    SHAP_AVAILABLE = True
    SHAP_VERSION = shap.__version__
except ImportError as e:
    SHAP_AVAILABLE = False
    SHAP_VERSION = None
    SHAP_ERROR = str(e)

try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
    TENSORFLOW_VERSION = tf.__version__
except ImportError as e:
    TENSORFLOW_AVAILABLE = False
    TENSORFLOW_VERSION = None
    TENSORFLOW_ERROR = str(e)

# Dependency status report function
def get_dependency_status():
    """Get comprehensive status of all optional dependencies."""
    status = {
        'tensorflow': {
            'available': TENSORFLOW_AVAILABLE,
            'version': TENSORFLOW_VERSION,
            'error': globals().get('TENSORFLOW_ERROR'),
            'features_affected': ['Autoencoder anomaly detection', 'Deep learning models']
        },
        'shap': {
            'available': SHAP_AVAILABLE,
            'version': SHAP_VERSION,
            'error': globals().get('SHAP_ERROR'),
            'features_affected': ['Model explanations', 'Feature importance analysis']
        }
    }
    return status

def check_minimum_requirements():
    """Check if minimum required dependencies are available."""
    required_packages = [
        'pandas', 'numpy', 'scikit-learn', 'joblib', 'streamlit', 'requests'
    ]
    
    missing_packages = []
    available_packages = {}
    
    for package in required_packages:
        try:
            module = __import__(package.replace('-', '_'))
            version = getattr(module, '__version__', 'unknown')
            available_packages[package] = version
        except ImportError:
            missing_packages.append(package)
    
    return {
        'all_available': len(missing_packages) == 0,
        'missing': missing_packages,
        'available': available_packages
    }

# Connection log column structure
CONN_LOG_COLUMNS = [
    'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
    'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state',
    'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts',
    'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents'
]

# DNS log column structure
DNS_LOG_COLUMNS = [
    'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
    'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name',
    'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD',
    'RA', 'Z', 'answers', 'TTLs', 'rejected'
]

# Anomaly detection thresholds  
PROFILE_CLEANUP_MINUTES = 5  # Minutes to keep inactive IP profiles
PORT_SCAN_THRESHOLD = 20  # Number of rejected connections or unique ports

# Production ML Model Thresholds (v7_stable Conservative Approach)
PRODUCTION_THRESHOLDS = {
    'autoencoder_conservative': 0.5,        # Tăng từ 0.4 lên 0.5 để giảm số lượng alerts
    'isolation_forest_conservative': 0.15,  # Tăng từ 0.10 lên 0.15 để giảm số lượng alerts
    'min_confidence_alert': 0.7,           # Minimum confidence for alert generation
    'false_positive_tolerance_pct': 10      # Maximum false positive rate tolerance (%)
}


# File paths
MODEL_DIRECTORY = "model_final_lab2"  #  Sửa: trỏ đến model thực tế
PERSISTENT_ALERTS_DIRECTORY = "persistent_alerts"
LIVE_LOGS_DIRECTORY = "live_logs"
CONN_LOG_PATH = "live_logs/conn.log"  # Main conn.log file for processing

# Model file names - Updated to use actual lab models
# CONN.LOG Models - Using lab versions (actual files)
PREPROCESSOR_FILE = "complete_pipeline_cic_master.joblib"  #  Sửa: file thực tế
ISOLATION_FOREST_FILE = "iso_forest_model_cic_master.joblib"  #  Sửa: file thực tế
AUTOENCODER_FILE = "autoencoder_best_cic_master.keras"  #  Sửa: file thực tế
AUTOENCODER_THRESHOLD_FILE = "ae_threshold_cic_master.json"  #  Sửa: file thực tế

# DNS Model file names - Updated to use actual lab models
DNS_MODEL_DIRECTORY = "model_dns_lab"  #  Sửa: trỏ đến model thực tế
DNS_ISOLATION_FOREST_FILE = "dns_tunneling_isolation_forest.pkl"  #  Đúng
DNS_AUTOENCODER_FILE = "dns_tunneling_autoencoder.keras"  #  Đúng
DNS_SCALER_FILE = "dns_tunneling_scaler.pkl"  #  Đúng
DNS_METADATA_FILE = "dns_pipeline_metadata.json"  #  Đúng

# Isolation Forest threshold selection policy for conn.log
# Allowed values:
#  - 'file' (default): use saved file policy (current behavior: 5% threshold)
#  - 'p10': use threshold_10_percent from file
#  - 'p5' : use threshold_5_percent from file
#  - 'p1' : use threshold_1_percent from file
#  - 'zero': use threshold_zero from file
ISOF_THRESHOLD_POLICY = 'p10'

# DNS Isolation Forest threshold selection policy for dns.log
# Allowed values: 'file','p10','p5','p1','zero'
# Default 'p1' to honor stricter DNS preference
DNS_ISOF_THRESHOLD_POLICY = 'p1'

# Logging configuration
LOG_VERSION = "1.0"
DEFAULT_ENCODING = "utf-8"

REDIS_HOST = "0.tcp.ap.ngrok.io"
REDIS_PORT = 16456
REDIS_PASSWORD = None  
WAIT_TIMEOUT = 10

REDIS_KEYS = {
    'conn': 'zeek_conn_logs',  
    'dns': 'zeek_dns_logs'     
}

FIFO_CONFIG = {
    'max_queue_size': 20000,      
    'processing_batch_size': 1000, 
    'priority_processing': True,  
    'conn_processing_weight': 3,   
    'dns_processing_weight': 1,    
    'collection_window_seconds': 0.5, 
    'processing_cycle_size': 1000,   
    'backlog_threshold': 2000,      
    'enable_priority_processing': True,  
    'process_backlog_first': True,       
    'max_backlog_threshold': 2000,
    
    # 🆕 NEW: BACKPRESSURE MECHANISM CONFIG
    'backpressure': {
        'enabled': True,                    # Enable backpressure mechanism
        'max_cpu_usage': 80.0,             # Max CPU usage before throttling (%)
        'max_memory_usage': 85.0,          # Max memory usage before throttling (%)
        'max_queue_utilization': 90.0,     # Max queue utilization before throttling (%)
        'min_processing_rate': 50.0,       # Min processing rate before throttling (logs/sec)
        'throttling_factor': 0.5,          # Reduce collection rate by this factor when throttling
        'recovery_threshold': 0.7,         # Recovery threshold (reduce throttling when below this)
        'adaptive_batch_sizing': True,     # Enable adaptive batch size based on system load
        'max_batch_size': 500,             # Maximum batch size when system is healthy
        'min_batch_size': 50,              # Minimum batch size when throttling
        'collection_rate_control': True,   # Enable adaptive collection rate control
        'max_collection_window': 2.0,      # Maximum collection window when throttling (seconds)
        'min_collection_window': 0.1,      # Minimum collection window (seconds)
        'graceful_degradation': True,      # Enable graceful degradation when overloaded
        'log_drop_strategy': 'throttle_only' # 'intelligent', 'oldest_first', or 'throttle_only'
    }
}



# Redis connection configuration
REDIS_CONFIG = {
    'host': REDIS_HOST,
    'port': REDIS_PORT,
    'db': 0,
    'socket_connect_timeout': 5,
    'decode_responses': True
}


# Helper function để truy cập dữ liệu an toàn
def safe_get(record, key, default=0.0, type_converter=float):
    """Safely gets a value from a dictionary, handling missing keys and type errors."""
    try:
        val = record.get(key)
        if val is None or val == '' or val == '-':
            return default
        return type_converter(val)
    except (ValueError, TypeError):
        return default

def get_demo_rules():
    """
    FINAL RULESET CONN.LOG (AI-Driven Detection, Feature-Driven Classification)
    This version fully trusts the AI for detection and uses the rich stateful features for classification.
    """
    return [
        # =================================================================
        # PRIORITY 1: CLASSIFICATION FOR HIGH-CONFIDENCE ATTACKS
        # =================================================================
        {
            "name": "Distributed Denial of Service (DDoS)",
            "priority": 1,
            "description": "AI detected an attack where multiple sources are targeting a single service.",
            "conditions": lambda r, anom_flags, z_scores: (
                (anom_flags['isof_anomaly'] or anom_flags['ae_anomaly']) and
                # Classification using the dedicated DDoS feature
                safe_get(r, 'ddos_group_unique_src_ip_count', type_converter=int) > 20
            ),
            "get_details": lambda flags: ("Critical", "AI Classified: DDoS Attack")
        },

        {
            "name": "Vertical Port Scan",
            "priority": 1,
            "description": "AI detected anomalous behavior consistent with a vertical port scan.",
            "conditions": lambda r, anom_flags, z_scores: (
                (anom_flags['isof_anomaly'] or anom_flags['ae_anomaly']) and
                # Classification based on raw group features and IP Profiler
                (
                    safe_get(r, 'vertical_scan_unique_dst_port_count', type_converter=int) > 10 or
                    safe_get(r, 'ip_profile_id.resp_p_rate') > 10
                )
            ),
            "get_details": lambda flags: ("Critical", "AI Classified: Vertical Scan")
        },

        {
            "name": "Horizontal Port Scan",
            "priority": 1,
            "description": "AI detected anomalous behavior consistent with a horizontal network scan.",
            "conditions": lambda r, anom_flags, z_scores: (
                (anom_flags['isof_anomaly'] or anom_flags['ae_anomaly']) and
                # Classification based on raw group features and IP Profiler
                (
                    safe_get(r, 'horizontal_scan_unique_dst_ip_count', type_converter=int) > 10 or
                    safe_get(r, 'ip_profile_id.resp_h_rate') > 10
                )
            ),
            "get_details": lambda flags: ("Critical", "AI Classified: Horizontal Scan")
        },

        {
            "name": "C2 Beaconing",
            "priority": 1,
            "description": "AI detected an unnaturally consistent communication pattern, indicative of a C2 beacon.",
            # Sửa lại lambda để nhận đủ 3 tham số
            "conditions": lambda r, anom_flags, z_scores: (
                (anom_flags['isof_anomaly'] or anom_flags['ae_anomaly']) and
                

                safe_get(z_scores, 'z_beacon_group_count') > 5.0 and
                
                safe_get(z_scores, 'z_beacon_channel_timediff_std') < -1.5
            ),
            "get_details": lambda flags: ("High", "AI Classified: Machine-like Beaconing")
        },
        
        {
            "name": "ICMP Data Exfiltration",
            "priority": 1,
            "description": "AI detected anomalous ICMP traffic with characteristics of a covert channel.",
            "conditions": lambda r, anom_flags, z_scores: (
                (anom_flags['isof_anomaly'] or anom_flags['ae_anomaly']) and
                r.get('proto') == 'icmp' and
                # Điều kiện 1: Kích thước gói tin vẫn phải lớn
                safe_get(r, 'orig_bytes', type_converter=int) > 200 and
                # Điều kiện 2 (MỚI): Phải là một chuỗi các gói tin, không phải một lần ping duy nhất
                safe_get(r, 'ip_profile_uid_rate') > 5 
            ),
            "get_details": lambda flags: ("High", "AI Classified: ICMP Tunneling")
        },

        {
            "name": "Data Exfiltration",
            "priority": 1,
            "description": "AI detected a device sending an unusually large amount of data.",
             "conditions": lambda r, anom_flags, z_scores: (
                (anom_flags['isof_anomaly'] or anom_flags['ae_anomaly']) and
                r.get('conn_state') == 'SF' and
                # Classification based on high average outbound data from IP Profiler
                safe_get(r, 'ip_profile_mean_orig_bytes') > 50000 # 50KB average
            ),
            "get_details": lambda flags: ("High", "AI Classified: Anomalous Data Volume")
        },

        {
            "name": "Brute-Force Attack",
            "priority": 1,
            "description": "AI detected a high rate of rapid, failed connections to an authentication service.",
            "conditions": lambda r, anom_flags, z_scores: (
                (anom_flags['isof_anomaly'] or anom_flags['ae_anomaly']) and
                # Classification based on IP Profiler features
                safe_get(r, 'ip_profile_uid_rate') > 25 and # Very high connection rate
                safe_get(r, 'ip_profile_mean_duration') < 1.0 and # Very short connections
                safe_get(r, 'id.resp_p', type_converter=int) in [22, 3389] # Targeting SSH or RDP
            ),
            "get_details": lambda flags: ("Critical", "AI Classified: Brute-Force Attack")
        },
        # =================================================================
        # PRIORITY 2: GENERIC ANOMALY (The final catch-all rule)
        # =================================================================
    

        {
            "name": "General Behavioral Anomaly",
            "priority": 3,
            "description": "The AI models detected a statistical anomaly that does not match a specific, known attack pattern.",
            "conditions": lambda r, anom_flags, z_scores: (
                anom_flags['isof_anomaly'] or anom_flags['ae_anomaly']
            ),
            "get_details": lambda flags: (
                "Medium" if (flags['isof_anomaly'] and flags['ae_anomaly']) else "Low",
                "AI Classified: Consensus Anomaly" if (flags['isof_anomaly'] and flags['ae_anomaly']) else ("AI Classified: Behavioral Pattern Anomaly" if flags['ae_anomaly'] else "AI Classified: Statistical Pattern Anomaly")
            )
        }
    ]

def get_dns_rules():
    """
    🎯 DNS-SPECIFIC ATTACK DETECTION RULES - DNS.LOG FOCUSED
    
    Tập trung vào các DNS-based attack patterns:
    - DNS Tunneling & Data Exfiltration
    - DNS DGA (Domain Generation Algorithm) - Main demo focus
    - DNS Amplification & Reflection Attacks
    - DNS Cache Poisoning Indicators
    - DNS Covert Channel Communication
    
    ARCHITECTURE:
    - Priority-based rule matching (Priority 1 = Critical, Priority 4 = Low/FP)
    - ML models + DNS domain expertise
    - Production-ready với DNS-specific false positive reduction
    """
    return [
        # =================================================================
        # PRIORITY 1: CRITICAL DNS-LEVEL THREATS  
        # =================================================================
        
        # --- DNS DGA (DOMAIN GENERATION ALGORITHM) DETECTION - STRICT STATEFUL REQUIREMENTS ---
        {
            "name": "DNS DGA Attack Pattern",
            "priority": 1,  # Higher priority than tunneling 
            "description": "Malware domain generation algorithm - requires STRONG DGA indicators (stateful attack)",
            "conditions": lambda dns_record, features, isof_anomaly, ae_anomaly: (
                # STRICT DGA characteristics - only strong indicators
                (
                    # Very low linguistic score (strong DGA signature)
                    (features.get('ngram_score', 1.0) != 'N/A' and 
                     float(features.get('ngram_score', 1.0)) < 0.1) or  # Much stricter threshold
                    
                    # Very random character patterns (strong DGA randomness)
                    (float(features.get('char_diversity', 0)) > 0.8 and  # Much stricter threshold
                     features.get('vowel_consonant_ratio', 0) != 'N/A' and
                     float(features.get('vowel_consonant_ratio', 0)) < 0.2) or  # Much stricter
                    
                    # Very high entropy with random patterns (strong DGA)
                    (float(features.get('query_entropy', 0)) > 4.0 and  # Much stricter threshold
                     float(features.get('char_diversity', 0)) > 0.8 and
                     int(features.get('query_length', 0)) > 25) or  # Much stricter
                     
                    # Very long random domains (strong DGA pattern)
                    (int(features.get('query_length', 0)) > 30 and
                     float(features.get('char_diversity', 0)) > 0.8 and
                     features.get('ngram_score', 1.0) != 'N/A' and
                     float(features.get('ngram_score', 1.0)) < 0.15) or  # Much stricter
                     
                    # Multiple strong DGA indicators combined
                    (int(features.get('query_length', 0)) > 20 and
                     float(features.get('char_diversity', 0)) > 0.7 and
                     float(features.get('query_entropy', 0)) > 3.8 and
                     features.get('ngram_score', 1.0) != 'N/A' and
                     float(features.get('ngram_score', 1.0)) < 0.2)
                ) and
                # BOTH ML models must agree (consensus required)
                (isof_anomaly and ae_anomaly) and
                # CRITICAL: Exclude common false positives
                '.tunnel.lab' not in str(dns_record.get('query', '')).lower() and
                dns_record.get('qtype_name', '') not in ['TXT', 'NULL'] and
                # Exclude short common queries
                int(features.get('query_length', 0)) > 10 and
                # Exclude common system queries
                not any(pattern in str(dns_record.get('query', '')).lower() 
                       for pattern in ['wpad', 'isatap', '_ldap', '_kerberos', '_msdcs', 'dc.', 'microsoft.com', 'windows.com'])
            ),
            "get_details": lambda isof, ae: (
                "Critical",
                "AI Classified: Strong DGA Pattern Detection"
            )
        },
        
        # --- DNS TUNNELING DETECTION ---
        {
            "name": "DNS Tunneling Pattern",
            "priority": 0,
            "description": "Data exfiltration or command & control via DNS queries - high-confidence tunneling indicators",
            "conditions": lambda dns_record, features, isof_anomaly, ae_anomaly: (
                # Strong tunneling indicators từ DNS training features
                (
                    # Very long DNS queries (strong indicator) - reduced threshold
                    int(features.get('query_length', 0)) > 50 or  # Reduced from 80
                    
                    # High entropy queries (encoded data) - reduced threshold
                    float(features.get('query_entropy', 0)) > 3.2 or  # Reduced further to capture borderline tunneling
                    
                    # Multiple encoding patterns detected
                    (features.get('has_base64_pattern', 0) == 1 and 
                     features.get('has_hex_pattern', 0) == 1) or
                    
                    # Suspicious query types with long queries - reduced threshold
                    (dns_record.get('qtype_name', '') in ['TXT', 'NULL'] and
                     int(features.get('query_length', 0)) > 20) or  # Reduced from 40 (favor tunneling over DGA for TXT/NULL)
                     
                    # Very high character diversity (encoding indicator) - reduced threshold
                    float(features.get('char_diversity', 0)) > 0.65 or  # Reduced from 0.75
                    
                    # Multiple suspicious patterns combined - reduced thresholds
                    (int(features.get('subdomain_count', 0)) > 3 and  # Reduced from 4
                     float(features.get('query_entropy', 0)) > 3.0 and  # Reduced from 3.0
                     int(features.get('query_length', 0)) > 40) or  # Reduced from 50
                     
                    # Tunnel.lab specific patterns (iodine tunneling)
                    ('.tunnel.lab' in str(dns_record.get('query', '')).lower() and
                     (float(features.get('query_entropy', 0)) > 3.0 or
                      int(features.get('query_length', 0)) > 15 or
                      features.get('has_base64_pattern', 0) == 1)) or
                     
                    # High entropy with base64 patterns
                    (float(features.get('query_entropy', 0)) > 3.5 and
                     features.get('has_base64_pattern', 0) == 1)
                ) and
                # ML detection for tunneling patterns
                (isof_anomaly or ae_anomaly) and
                # CRITICAL: Exclude DGA patterns from tunneling detection
                not (
                    # DGA characteristics - exclude from tunneling
                    (dns_record.get('rcode_name', '') == 'NXDOMAIN' and
                     float(features.get('char_diversity', 0)) > 0.6 and
                     int(features.get('query_length', 0)) > 15 and
                     '.tunnel.lab' not in str(dns_record.get('query', '')).lower()) or
                    # DGA with low ngram score
                    (features.get('ngram_score', 1.0) != 'N/A' and
                     float(features.get('ngram_score', 1.0)) < 0.2 and
                     float(features.get('char_diversity', 0)) > 0.6 and
                     '.attacker.com' not in str(dns_record.get('query', '')).lower()) or
                    # Exclude obvious false positives
                    any(pattern in str(dns_record.get('query', '')).lower() 
                        for pattern in ['_ldap', '_kerberos', '_msdcs', 'dc.', 'microsoft.com', 'windows.com']) or
                    # Common CDN/cloud patterns
                    any(pattern in str(dns_record.get('query', '')).lower()
                        for pattern in ['cloudfront', 'amazonaws', 'azure', 'googleapis'])
                )
            ),
            "get_details": lambda isof, ae: (
                "Critical" if (isof and ae) else "High",
                "AI Classified: Consensus DNS Tunneling" if (isof and ae) else (
                    "AI Classified: DNS Tunneling Pattern" if ae else "AI Classified: DNS Anomaly Detection"
                )
            )
        },
        
        # =================================================================
        # PRIORITY 2: SUSPICIOUS DNS BEHAVIORS
        # =================================================================
        
        # --- DNS ANOMALY (GENERIC) - For stateless detection ---
        {
            "name": "DNS Anomaly",
            "priority": 2,
            "description": "DNS query anomaly detected by ML models - stateless detection",
            "conditions": lambda dns_record, features, isof_anomaly, ae_anomaly: (
                # ML models detected anomaly but not strong enough for DGA/Tunneling
                (isof_anomaly or ae_anomaly) and
                # Exclude queries that should be handled by other rules
                not (
                    # DGA patterns (handled by DGA rule)
                    (int(features.get('query_length', 0)) > 20 and
                     float(features.get('char_diversity', 0)) > 0.7) or
                    # Tunneling patterns (handled by tunneling rule)  
                    (int(features.get('query_length', 0)) > 50 or
                     float(features.get('query_entropy', 0)) > 3.2) or
                    # Common system queries
                    any(pattern in str(dns_record.get('query', '')).lower() 
                        for pattern in ['wpad', 'isatap', '_ldap', '_kerberos', '_msdcs', 'dc.', 'microsoft.com', 'windows.com'])
                )
            ),
            "get_details": lambda isof, ae: (
                "Medium" if (isof and ae) else "Low",
                "AI Classified: DNS Anomaly" if (isof and ae) else "AI Classified: DNS Pattern Anomaly"
            )
        },
        
        # --- DNS COVERT CHANNEL COMMUNICATION ---
        {
            "name": "DNS Covert Channel",
            "priority": 2,
            "description": "Data hiding in DNS protocol - covert communication patterns",
            "conditions": lambda dns_record, features, isof_anomaly, ae_anomaly: (
                # Covert channel indicators từ DNS training features
                (
                    # TXT records with encoded data
                    (dns_record.get('qtype_name', '') == 'TXT' and
                     features.get('has_base64_pattern', 0) == 1) or
                    
                    # NULL records (unusual in legitimate traffic)
                    dns_record.get('qtype_name', '') == 'NULL' or
                    
                    # Long subdomains with encoding patterns
                    (features.get('has_long_subdomain', 0) == 1 and
                     features.get('suspicious_length', 0) == 1) or
                     
                    # High entropy with specific query types
                    (float(features.get('query_entropy', 0)) > 3.5 and  # Reduced for demo
                     dns_record.get('qtype_name', '') in ['CNAME', 'MX', 'TXT'])
                ) and
                # ML consensus for covert patterns
                (isof_anomaly and ae_anomaly) and
                # Exclude normal DNS operations
                not (
                    dns_record.get('qtype_name', '') in ['A', 'AAAA'] and
                    int(features.get('query_length', 0)) < 50
                )
            ),
            "get_details": lambda isof, ae: (
                "High",
                "AI Classified: Consensus Covert Channel"
            )
        },
        
        
        

    ] 

#  FIX: Safe conversion functions for classification rules
def safe_int(value, default=0):
    """Safely convert value to int, handling '-' and other invalid values."""
    if value == '-' or value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def safe_float(value, default=0.0):
    """Safely convert value to float, handling '-' and other invalid values."""
    if value == '-' or value is None:
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default 