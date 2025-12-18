"""
Data processing module for network anomaly detection system.
Contains functions for data cleaning, feature engineering, and preprocessing.
ENHANCED: Now matches training pipeline exactly to prevent data leakage and ensure consistency.
"""

import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
import logging
import joblib
import os
import re
import math
import warnings
import datetime
import traceback
# Tắt pandas FutureWarning để output sạch hơn
warnings.filterwarnings('ignore', category=FutureWarning, module='pandas')
pd.set_option('future.no_silent_downcasting', True)

# Import our modules
from config import CONN_LOG_COLUMNS, DNS_LOG_COLUMNS, DNS_ISOF_THRESHOLD_POLICY
# from utils.transformers import BehavioralBaselineTransformer  # Not used directly here
from utils.feature_engineering import engineer_enhanced_features


# DNS-specific feature definitions (matching sentinel_core_training.py exactly)
DNS_FEATURE_COLUMNS: List[str] = [
    'query_length', 'query_entropy', 'subdomain_count', 'numeric_ratio', 'ngram_score',
    'has_base64_pattern', 'has_hex_pattern', 'has_long_subdomain', 'suspicious_length',
    'char_diversity', 'vowel_consonant_ratio', 'compressed_pattern', 'unusual_tld',
    'avg_ttl', 'min_ttl', 'is_qtype_txt', 'is_qtype_null', 'is_nxdomain'
]


def log_transform_func(x):
    """Log transform used inside sklearn FunctionTransformer.

    - Preserves pandas types (DataFrame/Series) to keep feature names when possible
    - Ensures 2D output shape for sklearn steps
    - Robust to strings, objects, NaNs, and infs
    """
    try:
        # If input is a pandas DataFrame, transform and return DataFrame to preserve column names
        if isinstance(x, pd.DataFrame):
            df = x.copy()
            # Coerce object columns to numeric safely
            for col in df.columns:
                if df[col].dtype == object:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)
            df = df.replace([np.inf, -np.inf], 0.0).fillna(0.0)
            df_out = np.log1p(np.abs(df.astype(float)))
            # Return as DataFrame with same columns and index
            return pd.DataFrame(df_out, columns=df.columns, index=df.index)

        # If input is a pandas Series, return a single-column DataFrame with the same name
        if isinstance(x, pd.Series):
            s = pd.to_numeric(x, errors='coerce').fillna(0.0)
            s = s.replace([np.inf, -np.inf], 0.0)
            arr = np.log1p(np.abs(s.to_numpy(dtype=float))).reshape(-1, 1)
            col_name = x.name if x.name is not None else 0
            return pd.DataFrame(arr, columns=[col_name], index=x.index)

        # Fallback: numpy input
        arr = np.asarray(x)
        if arr.dtype == object:
            arr = pd.to_numeric(arr.ravel(), errors='coerce').fillna(0.0).to_numpy().reshape(arr.shape)
        arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
        transformed = np.log1p(np.abs(arr.astype(float)))
        if transformed.ndim == 0:
            return np.array([[float(transformed)]], dtype=float)
        if transformed.ndim == 1:
            return transformed.reshape(-1, 1)
        return transformed
    except Exception:
        # Robust fallback maintaining shape and names when possible
        if isinstance(x, pd.DataFrame):
            return pd.DataFrame(np.zeros((len(x), x.shape[1]), dtype=float), columns=x.columns, index=x.index)
        if isinstance(x, pd.Series):
            col_name = x.name if x.name is not None else 0
            return pd.DataFrame(np.zeros((len(x), 1), dtype=float), columns=[col_name], index=x.index)
        arr = np.asarray(x)
        if arr.ndim == 0:
            return np.array([[0.0]], dtype=float)
        if arr.ndim == 1:
            return np.zeros((arr.shape[0], 1), dtype=float)
        return np.zeros_like(arr, dtype=float)

class ProductionDataProcessor:
    
    def __init__(self, model_dir: str = 'model_final_lab2', model_version: str = None, logger: Optional[logging.Logger] = None, detection_engine=None):
        """
        Initialize the production data processor toolkit.
        
        Args:
            model_dir: Directory containing trained models (for reference only)
            model_version: Specific model version (for reference only)
            logger: Logger instance for debugging
            detection_engine: Detection Engine instance (for reference only)
        """
        self.model_dir = model_dir
        self.model_version = model_version
        self.logger = logger or logging.getLogger(__name__)
        
        # Store Detection Engine reference for reference only
        self.detection_engine = detection_engine
        
        self.complete_pipeline = None  
        self.training_metadata = None  
        self.top_services_list = None  
        self.model_ae = None  
        

        
        self.logger.info("✅ ProductionDataProcessor initialized as STATELESS toolkit")
        self.logger.info("   Models and pipeline must be set by MLHandler")
    
    def set_models_from_handler(self, complete_pipeline, training_metadata, top_services_list, model_ae):
        """
        ✅ NEW: Set models and metadata from MLHandler (the orchestrator).
        This method allows MLHandler to inject the loaded models.
        
        Args:
            complete_pipeline: Trained pipeline from MLHandler
            training_metadata: Training metadata from MLHandler
            top_services_list: Top services list from MLHandler
            model_ae: Autoencoder model from MLHandler
        """
        self.complete_pipeline = complete_pipeline
        self.training_metadata = training_metadata
        self.top_services_list = top_services_list
        self.model_ae = model_ae
        
        self.logger.info("✅ Models and metadata set from MLHandler")
        self.logger.info(f"   Pipeline: {'Loaded' if complete_pipeline else 'None'}")
        self.logger.info(f"   Training metadata: {'Loaded' if training_metadata else 'None'}")
        self.logger.info(f"   Top services: {len(top_services_list) if top_services_list else 0} services")
        self.logger.info(f"   Autoencoder: {'Loaded' if model_ae else 'None'}")
    

    
    def parse_zeek_log_line(self, log_line: str, columns: List[str]) -> Dict[str, str]:
        """
        CENTRALIZED function to parse any Zeek log line (conn.log, dns.log, etc).
        Eliminates duplicate parsing logic across the codebase.
        
        Args:
            log_line: Raw log line (tab-separated)
            columns: Column names for the log type
            
        Returns:
            Dictionary with field names as keys
        """
        try:
            fields = log_line.strip().split('\t')
            
            # Handle variable field counts in Zeek logs
            if len(fields) < len(columns):
                # Pad with '-' for missing fields
                fields.extend(['-'] * (len(columns) - len(fields)))
            elif len(fields) > len(columns):
                # Truncate extra fields
                fields = fields[:len(columns)]
            
            return dict(zip(columns, fields))
            
        except Exception as e:
            # Return empty record on error
            return {col: '-' for col in columns}

    def parse_conn_record(self, log_line: str) -> Dict[str, str]:
        """Parse conn.log line using centralized function.
        Auto-detect and convert Redis JSON -> Zeek if needed to avoid downstream errors.
        """
        try:
            line = log_line if isinstance(log_line, str) else str(log_line)
            if line.lstrip().startswith('{'):
                # Convert Redis JSON conn log to standard Zeek line
                from core.data_processor import parse_redis_conn_log
                converted = parse_redis_conn_log(line)
                if converted:
                    line = converted
            return self.parse_zeek_log_line(line, CONN_LOG_COLUMNS)
        except Exception:
            return {col: '-' for col in CONN_LOG_COLUMNS}

    def parse_dns_record(self, log_line: str) -> Dict[str, str]:
        """Parse dns.log line using centralized function."""
        return self.parse_zeek_log_line(log_line, DNS_LOG_COLUMNS)

    def safe_int_convert(self, value: str) -> int:
        """Safely convert string to integer."""
        try:
            if value == '-' or not value:
                return 0
            return int(float(value))
        except (ValueError, TypeError):
            return 0

    def safe_float_convert(self, value: str) -> float:
        """Safely convert string to float."""
        try:
            if value == '-' or not value:
                return 0.0
            return float(value)
        except (ValueError, TypeError):
            return 0.0

    def process_complete_record(self, record: Dict[str, str]) -> Dict[str, Any]:
        """
        Process complete conn.log record with proper type conversion for all fields.
        EXACTLY matches the training pipeline data cleaning.
        
        
        Args:
            record: Raw record dictionary from conn.log parsing (may include IP Profiler features)
            
        Returns:
            Processed record with appropriate data types for all fields
        """
        # Define field types for proper conversion (same as training)
        int_fields = ['id.orig_p', 'id.resp_p', 'orig_bytes', 'resp_bytes', 
                     'missed_bytes', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']
        float_fields = ['ts', 'duration']
        bool_fields = ['local_orig', 'local_resp']
        
        processed = {}
        
        # ✅ FIX: Process CONN_LOG_COLUMNS first (basic conn.log fields)
        for field in CONN_LOG_COLUMNS:
            value = record.get(field, '')
            
            if field in int_fields:
                processed[field] = self.safe_int_convert(value)
            elif field in float_fields:
                processed[field] = self.safe_float_convert(value)
            elif field in bool_fields:
                # Convert T/F to boolean, default to False for unknown values
                processed[field] = value.upper() == 'T' if value in ['T', 'F'] else False
            else:
                # String fields - keep as-is, replace '-' with empty string for clarity
                processed[field] = value if value != '-' else ''
        
        for field, value in record.items():
            if field not in CONN_LOG_COLUMNS:
                # This is an additional feature (IP Profiler, group features, etc.)
                if isinstance(value, (int, float, bool)):
                    # Numeric/boolean features - keep as-is
                    processed[field] = value
                elif isinstance(value, str):
                    # String features - try to convert to numeric if possible
                    try:
                        if '.' in value:
                            processed[field] = float(value)
                        else:
                            processed[field] = int(value)
                    except (ValueError, TypeError):
                        # Keep as string if conversion fails
                        processed[field] = value
                else:
                    # Other types - keep as-is
                    processed[field] = value
        
        return processed




class DNSProductionDataProcessor:
    """
    Production data processor for DNS anomaly detection that ensures EXACT consistency 
    with sentinel_core_training.py pipeline.
    """
    
    def __init__(self, model_dir: str = 'model_dns_lab', model_version: str = None, logger: Optional[logging.Logger] = None, disable_model_loading: bool = False):
        """
        Initialize the DNS production data processor.
        
        Args:
            model_dir: Directory containing trained DNS models and preprocessor
            model_version: Specific model version to load (auto-detects if None)
            logger: Logger instance for debugging
            disable_model_loading: If True, skip loading models (for injection from MLHandler)
        """
        self.model_dir = model_dir
        self.model_version = model_version
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize model placeholders
        self.scaler = None
        self.isolation_model = None
        self.autoencoder_model = None
        self.training_metadata = None
        self.dns_iso_threshold = 0.07  # Default fallback
        self.dns_ae_threshold = 0.2    # Default fallback
        
        # Auto-detect model version if not specified
        if self.model_version is None:
            self.model_version = self._find_latest_dns_model_version()
        
        # Load the trained models and metadata (skip if disabled for injection)
        if not disable_model_loading:
            self._load_trained_dns_artifacts()
        else:
            self.logger.info("Model loading disabled - expecting model injection from MLHandler")
    
    def inject_models_from_handler(self, isolation_model, autoencoder_model, scaler, iso_threshold, ae_threshold):
        """
        Inject models from MLHandler to avoid duplicate loading.
        
        Args:
            isolation_model: DNS Isolation Forest model
            autoencoder_model: DNS Autoencoder model  
            scaler: DNS Scaler
            iso_threshold: DNS Isolation Forest threshold
            ae_threshold: DNS Autoencoder threshold
        """
        self.isolation_model = isolation_model
        self.autoencoder_model = autoencoder_model
        self.scaler = scaler
        self.dns_iso_threshold = iso_threshold
        self.dns_ae_threshold = ae_threshold
        self.logger.info("Models injected from MLHandler successfully")
    
    def _find_latest_dns_model_version(self) -> str:
        """Find the latest trained DNS model version in the directory."""
        import glob
        pattern = os.path.join(self.model_dir, 'dns_tunneling_isolation_forest.pkl')
        files = glob.glob(pattern)
        if not files:
            raise FileNotFoundError(f"No trained DNS models found in {self.model_dir}")
        
        # For DNS, we'll use a simple version detection
        # In practice, you might want to implement more sophisticated versioning
        return 'latest'
    
    def _load_trained_dns_artifacts(self):
        """Load the trained DNS models and metadata."""
        try:
            # Load Isolation Forest model
            iso_path = os.path.join(self.model_dir, 'dns_tunneling_isolation_forest.pkl')
            if os.path.exists(iso_path):
                self.isolation_model = joblib.load(iso_path)
                self.logger.info(f"Loaded DNS Isolation Forest model: {iso_path}")
            
            # Load Autoencoder model
            ae_path = os.path.join(self.model_dir, 'dns_tunneling_autoencoder.keras')
            if os.path.exists(ae_path):
                try:
                    import tensorflow as tf
                    # Try to load with compile=False to avoid optimizer issues
                    self.autoencoder_model = tf.keras.models.load_model(ae_path, compile=False)
                    # Recompile with default settings
                    self.autoencoder_model.compile(optimizer='adam', loss='mse')
                    self.logger.info(f"Loaded DNS Autoencoder model: {ae_path}")
                except Exception as ae_error:
                    self.logger.warning(f"Failed to load DNS Autoencoder model: {ae_error}")
                    self.logger.info("DNS Autoencoder will be disabled - using Isolation Forest only")
                    # Try alternative loading method
                    try:
                        # Try loading with custom_objects to handle custom layers
                        self.autoencoder_model = tf.keras.models.load_model(
                            ae_path, 
                            compile=False,
                            custom_objects={'tf': tf}
                        )
                        self.autoencoder_model.compile(optimizer='adam', loss='mse')
                        self.logger.info(f"Loaded DNS Autoencoder model with custom_objects: {ae_path}")
                    except Exception as ae_error2:
                        self.logger.warning(f"Alternative loading also failed: {ae_error2}")
                        self.autoencoder_model = None
            
            # Load scaler
            scaler_path = os.path.join(self.model_dir, 'dns_tunneling_scaler.pkl')
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                self.logger.info(f"Loaded DNS scaler: {scaler_path}")
            
            # Load training metadata
            metadata_path = os.path.join(self.model_dir, 'dns_pipeline_metadata.json')
            if os.path.exists(metadata_path):
                import json
                with open(metadata_path, 'r') as f:
                    self.training_metadata = json.load(f)
                self.logger.info(f"Loaded DNS training metadata: {metadata_path}")
            
            # Load DNS thresholds
            self._load_dns_thresholds()
            
        except Exception as e:
            self.logger.error(f"Failed to load DNS trained artifacts: {e}")
            self.logger.info("DNS models will be disabled - continuing with connection models only")
            # Set defaults to prevent crashes
            self.isolation_model = None
            self.autoencoder_model = None
            self.scaler = None
            self.training_metadata = {}

    def parse_dns_record(self, log_line: str) -> Dict[str, str]:
        """Parse a Zeek dns.log line into a field dictionary (same padding/truncation as conn)."""
        try:
            fields = str(log_line).strip().split('\t')
            if len(fields) < len(DNS_LOG_COLUMNS):
                fields.extend(['-'] * (len(DNS_LOG_COLUMNS) - len(fields)))
            elif len(fields) > len(DNS_LOG_COLUMNS):
                fields = fields[:len(DNS_LOG_COLUMNS)]
            return dict(zip(DNS_LOG_COLUMNS, fields))
        except Exception:
            return {col: '-' for col in DNS_LOG_COLUMNS}

    def parse_redis_dns_log(self, redis_log_line: str) -> Optional[str]:
        """Convert a Redis JSON DNS log line to standard Zeek dns.log line using module helper."""
        try:
            # Reuse module-level helper for consistency
            return parse_redis_dns_log(redis_log_line)
        except Exception:
            return None
    
    def process_complete_record(self, record: Dict[str, str]) -> Dict[str, Any]:
        """
        Process complete DNS record with proper type conversion for all fields.
        EXACTLY matches the training pipeline data cleaning.
        
        Args:
            record: Raw record dictionary from dns.log parsing
            
        Returns:
            Processed record with appropriate data types for all fields
        """
        # Define field types for proper conversion (same as training)
        int_fields = ['id.orig_p', 'id.resp_p', 'TTL']
        float_fields = ['ts']
        bool_fields = ['local_orig', 'local_resp']
        
        processed = {}
        
        # DNS log columns (standard Zeek dns.log format)
        dns_columns = [
            'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
            'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name',
            'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD',
            'RA', 'Z', 'answers', 'TTLs', 'rejected'
        ]
        
        for field in dns_columns:
            value = record.get(field, '')
            
            if field in int_fields:
                processed[field] = self.safe_int_convert(value)
            elif field in float_fields:
                processed[field] = self.safe_float_convert(value)
            elif field in bool_fields:
                # Convert T/F to boolean, default to False for unknown values
                processed[field] = value.upper() == 'T' if value in ['T', 'F'] else False
            else:
                # String fields - keep as-is, replace '-' with empty string for clarity
                processed[field] = value if value != '-' else ''
        
        return processed

    def safe_int_convert(self, value: str) -> int:
        """Safely convert string to integer for DNS records."""
        try:
            if value == '-' or value == '' or pd.isna(value):
                return 0
            return int(float(value))
        except (ValueError, TypeError):
            return 0

    def safe_float_convert(self, value: str) -> float:
        """Safely convert string to float for DNS records."""
        try:
            if value == '-' or value == '' or pd.isna(value):
                return 0.0
            return float(value)
        except (ValueError, TypeError):
            return 0.0

    def _load_dns_thresholds(self):
        """Load DNS thresholds from training files."""
        try:
            import json
            
            # Load DNS Isolation Forest threshold
            dns_iso_threshold_files = [
                f'dns_iso_threshold.json',  # Primary: dns_master version
                f'iso_threshold_dns_v1.json',
                f'iso_threshold_dns_v2.json'
            ]
            
            for threshold_file in dns_iso_threshold_files:
                threshold_path = os.path.join(self.model_dir, threshold_file)
                try:
                    if os.path.exists(threshold_path):
                        with open(threshold_path, 'r') as f:
                            threshold_data = json.load(f)
                        # Select DNS threshold based on policy
                        policy = DNS_ISOF_THRESHOLD_POLICY or 'file'
                        if policy == 'p10':
                            self.dns_iso_threshold = threshold_data.get("threshold_10_percent", threshold_data.get("threshold_5_percent", 0.07))
                        elif policy == 'p5':
                            self.dns_iso_threshold = threshold_data.get("threshold_5_percent", 0.07)
                        elif policy == 'p1':
                            self.dns_iso_threshold = threshold_data.get("threshold_1_percent", threshold_data.get("threshold_5_percent", 0.07))
                        elif policy == 'zero':
                            self.dns_iso_threshold = threshold_data.get("threshold_zero", 0.0)
                        else:  # 'file' default
                            self.dns_iso_threshold = threshold_data.get("threshold_5_percent", threshold_data.get("threshold_1_percent", 0.07))
                        self.logger.info(f"Loaded DNS Isolation Forest threshold (policy={policy}): {self.dns_iso_threshold:.6f} from {threshold_path}")
                        break
                except Exception as e:
                    self.logger.warning(f"Could not load DNS Isolation Forest threshold from {threshold_path}: {str(e)}")
                    continue
            else:
                self.logger.warning("No valid DNS Isolation Forest threshold file found")
                self.dns_iso_threshold = 0.07  # Default fallback
            
            # Load DNS Autoencoder threshold
            dns_ae_threshold_files = [
                f'dns_ae_threshold.json',  # Primary: dns_master version
                f'ae_threshold_dns_v1.json',
                f'ae_threshold_dns_v2.json'
            ]
            
            for threshold_file in dns_ae_threshold_files:
                threshold_path = os.path.join(self.model_dir, threshold_file)
                try:
                    if os.path.exists(threshold_path):
                        import json
                        with open(threshold_path, 'r') as f:
                            threshold_data = json.load(f)
                        self.dns_ae_threshold = threshold_data.get("threshold", 0.2)
                        self.logger.info(f"Loaded DNS Autoencoder threshold: {self.dns_ae_threshold:.6f} from {threshold_path}")
                        break
                except Exception as e:
                    self.logger.warning(f"Could not load DNS Autoencoder threshold from {threshold_path}: {str(e)}")
                    continue
            else:
                self.logger.warning("No valid DNS Autoencoder threshold file found")
                self.dns_ae_threshold = 0.2  # Default fallback
                
        except Exception as e:
            self.logger.error(f"Error loading DNS thresholds: {str(e)}")
            self.dns_iso_threshold = 0.07
            self.dns_ae_threshold = 0.2
    
    def _calculate_entropy(self, text):
        """Calculate entropy of text (EXACTLY same as training)."""
        if not text or pd.isna(text):
            return 0
        char_counts = {}
        text_str = str(text)
        for char in text_str:
            char_counts[char] = char_counts.get(char, 0) + 1
        entropy = 0
        text_length = len(text_str)
        if text_length == 0:
            return 0
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy
    
    def _detect_dns_tunneling_patterns(self, query):
        """Detect DNS tunneling patterns (EXACT MATCH with sentinel_core_training.py)."""
        if not query or pd.isna(query):
            return {k: 0 for k in ['has_base64_pattern', 'has_hex_pattern', 'has_long_subdomain', 'suspicious_length', 'char_diversity', 'vowel_consonant_ratio', 'compressed_pattern', 'unusual_tld']}
        
        query_str = str(query).lower()
        parts = query_str.split('.')
        max_subdomain_len = max([len(part) for part in parts]) if parts else 0
        vowels = 'aeiou'
        vowel_count = sum(1 for char in query_str if char in vowels)
        consonant_count = sum(1 for char in query_str if char.isalpha() and char not in vowels)
        unique_chars = len(set(query_str.replace('.', '')))
        total_chars = len(query_str.replace('.', ''))
        unusual_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.onion', '.bit']
        
        # Match training caps and regex exactly
        char_diversity = unique_chars / total_chars if total_chars > 0 else 0
        char_diversity = min(char_diversity, 1.0)
        vowel_consonant_ratio = vowel_count / consonant_count if consonant_count > 0 else 0
        vowel_consonant_ratio = min(vowel_consonant_ratio, 10.0)
        
        return {
            'has_base64_pattern': int(bool(re.search(r'[a-zA-Z0-9+/]{20,}', query_str))),
            'has_hex_pattern': int(bool(re.search(r'[0-9a-f]{16,}', query_str))),
            'has_long_subdomain': 1 if max_subdomain_len > 20 else 0,
            'suspicious_length': 1 if len(query_str) > 50 else 0,
            'char_diversity': char_diversity,
            'vowel_consonant_ratio': vowel_consonant_ratio,
            'compressed_pattern': 1 if re.search(r'([a-z0-9])\\1{3,}', query_str) else 0,
            'unusual_tld': 1 if any(tld in query_str for tld in unusual_tlds) else 0
        }
    
    def _calculate_numeric_ratio(self, text):
        """Calculate numeric ratio (EXACT MATCH with sentinel_core_training.py)."""
        if not text or pd.isna(text):
            return 0
        text_str = str(text)
        if len(text_str) == 0:
            return 0
        ratio = sum(1 for char in text_str if char.isdigit()) / len(text_str)
        return min(ratio, 1.0)
    
    def _calculate_ngram_score(self, domain):
        """Calculate n-gram score (EXACT MATCH with sentinel_core_training.py)."""
        if not domain or pd.isna(domain):
            return 0.0
        domain_str, domain_parts = str(domain).lower(), str(domain).lower().split('.')
        # Training concatenates all subdomain parts (excluding TLD) for analysis
        analysis_target = ".".join(domain_parts[:-1]) if len(domain_parts) >= 2 else domain_str
        if len(analysis_target) < 2:
            return 0.0
        common_bigrams = {'th': 100, 'he': 95, 'in': 90, 'er': 85, 'an': 80, 're': 75, 'ed': 70, 'nd': 65, 'on': 60, 'en': 55, 'at': 50, 'ou': 45, 'it': 40, 'is': 35, 'or': 30, 'ti': 25, 'ar': 20, 'te': 18, 'ng': 16, 'al': 14, 'se': 12, 'st': 10, 'as': 8, 'to': 6, 'le': 5, 'co': 4, 'ma': 3, 'de': 2, 'me': 1}
        common_trigrams = {'the': 100, 'and': 95, 'ing': 90, 'her': 85, 'hat': 80, 'his': 75, 'tha': 70, 'ere': 65, 'for': 60, 'ent': 55, 'ion': 50, 'ter': 45, 'was': 40, 'you': 35, 'ith': 30, 'ver': 25, 'all': 20, 'wit': 18, 'thi': 16, 'tio': 14, 'com': 12, 'con': 10, 'pro': 8, 'ser': 6}
        bigrams = [analysis_target[i:i+2] for i in range(len(analysis_target)-1)]
        trigrams = [analysis_target[i:i+3] for i in range(len(analysis_target)-2)]
        bigram_score = sum(common_bigrams.get(bg, 0) for bg in bigrams)
        trigram_score = sum(common_trigrams.get(tg, 0) for tg in trigrams)
        max_bigram = len(bigrams) * 100
        max_trigram = len(trigrams) * 100
        norm_bigram = bigram_score / max_bigram if max_bigram > 0 else 0
        norm_trigram = trigram_score / max_trigram if max_trigram > 0 else 0
        return min((0.3 * norm_bigram + 0.7 * norm_trigram), 1.0)
    
    def _parse_ttl_values(self, ttl_string):
        """Parse TTL values (EXACTLY same as training)."""
        # Handle NumPy arrays and pandas Series properly
        try:
            # Check if it's an empty array/list first
            if isinstance(ttl_string, (list, np.ndarray)):
                if len(ttl_string) == 0:
                    return {'avg_ttl': 300, 'min_ttl': 300}
                # For arrays, check if all elements are NaN
                if hasattr(ttl_string, '__iter__') and all(pd.isna(x) for x in ttl_string):
                    return {'avg_ttl': 300, 'min_ttl': 300}
            else:
                # For scalar values, use pd.isna safely
                if pd.isna(ttl_string):
                    return {'avg_ttl': 300, 'min_ttl': 300}
            
            # Convert to string and handle string comparison safely
            ttl_str = str(ttl_string)
            if ttl_str == '-' or ttl_str == '':
                return {'avg_ttl': 300, 'min_ttl': 300}
            
            # Handle list/array input directly
            if isinstance(ttl_string, (list, np.ndarray)):
                ttl_values = [float(x) for x in ttl_string if not pd.isna(x) and str(x).strip() != '-']
            else:
                # Handle string input (comma-separated)
                ttl_values = [float(x.strip()) for x in ttl_str.split(',') if x.strip() and x.strip() != '-']
            
            if ttl_values:
                return {'avg_ttl': np.mean(ttl_values), 'min_ttl': np.min(ttl_values)}
            else:
                return {'avg_ttl': 300, 'min_ttl': 300}
        except (ValueError, TypeError):
            return {'avg_ttl': 300, 'min_ttl': 300}
    
    def engineer_dns_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Engineer DNS features (EXACTLY same as sentinel_core_training.py).
        
        Args:
            df: DataFrame with DNS records
            
        Returns:
            DataFrame with engineered features
        """
        # Ensure required columns exist
        for col in ['query', 'qtype_name', 'rcode_name', 'TTLs']:
            if col not in df.columns:
                df[col] = '-'
        
        # Calculate basic features (EXACTLY same as training)
        df['query_length'] = df['query'].apply(lambda x: len(str(x)) if pd.notna(x) else 0)
        df['subdomain_count'] = df['query'].apply(lambda x: str(x).count('.') if pd.notna(x) else 0)
        df['query_entropy'] = df['query'].apply(self._calculate_entropy)
        df['numeric_ratio'] = df['query'].apply(self._calculate_numeric_ratio)
        df['ngram_score'] = df['query'].apply(self._calculate_ngram_score)
        
        # Apply pattern detection (EXACTLY same as training)
        self.logger.info("  Applying DNS pattern detection...")
        tunneling_patterns = df['query'].apply(self._detect_dns_tunneling_patterns)
        tunneling_df = pd.DataFrame(tunneling_patterns.tolist(), index=df.index)
        
        # Apply TTL parsing (EXACTLY same as training)
        ttl_patterns = df['TTLs'].apply(self._parse_ttl_values)
        ttl_df = pd.DataFrame(ttl_patterns.tolist(), index=df.index)
        
        # Join the new feature DataFrames back to the main one
        # Remove any duplicate columns before joining
        for col in tunneling_df.columns:
            if col in df.columns:
                df = df.drop(columns=[col])
        for col in ttl_df.columns:
            if col in df.columns:
                df = df.drop(columns=[col])
        
        df = df.join([tunneling_df, ttl_df])
        
        # Add query type indicators (EXACTLY same as training)
        df['is_qtype_txt'] = (df['qtype_name'].astype(str).str.upper() == 'TXT').astype(int)
        df['is_qtype_null'] = (df['qtype_name'].astype(str).str.upper() == 'NULL').astype(int)
        df['is_nxdomain'] = (df['rcode_name'].astype(str).str.upper() == 'NXDOMAIN').astype(int)
        
        # Ensure all feature columns are present and filled
        df[DNS_FEATURE_COLUMNS] = df[DNS_FEATURE_COLUMNS].fillna(0)
        
        return df
    
    def preprocess_single_dns_query(self, dns_record: Dict[str, Any]) -> np.ndarray:
        """
        Preprocess a single DNS query for anomaly detection.
        
        Args:
            dns_record: Dictionary containing DNS query data
            
        Returns:
            Preprocessed features as numpy array ready for model prediction
        """
        try:
            # STEP 1: Convert to DataFrame
            df = pd.DataFrame([dns_record])
            
            # STEP 2: Engineer features (EXACTLY same as training)
            df_features = self.engineer_dns_features(df)
            
            # STEP 3: Apply trained scaler (EXACTLY same as training)
            if self.scaler is None:
                raise ValueError("No trained DNS scaler loaded")
            
            # Select only the feature columns
            X_features = df_features[DNS_FEATURE_COLUMNS]
            
            # Transform using the fitted scaler
            X_scaled = self.scaler.transform(X_features)
            
            self.logger.info(f"Preprocessed DNS query: {X_scaled.shape}")
            return X_scaled
            
        except Exception as e:
            self.logger.error(f"❌ DNS preprocessing failed: {e}")
            raise
    
    def preprocess_batch_dns_queries(self, dns_records: List[Dict[str, Any]]) -> np.ndarray:
        """
        Preprocess a batch of DNS queries for anomaly detection.
        
        Args:
            dns_records: List of DNS query dictionaries
            
        Returns:
            Preprocessed features as numpy array ready for model prediction
        """
        try:
            # STEP 1: Convert to DataFrame
            df = pd.DataFrame(dns_records)
            
            # STEP 2: Engineer features (EXACTLY same as training)
            df_features = self.engineer_dns_features(df)
            
            # STEP 3: Apply trained scaler (EXACTLY same as training)
            if self.scaler is None:
                raise ValueError("No trained DNS scaler loaded")
            
            # Select only the feature columns
            X_features = df_features[DNS_FEATURE_COLUMNS]
            
            # Transform using the fitted scaler
            X_scaled = self.scaler.transform(X_features)
            
            self.logger.info(f"Preprocessed DNS batch: {X_scaled.shape}")
            return X_scaled
            
        except Exception as e:
            self.logger.error(f"❌ DNS batch preprocessing failed: {e}")
            raise
    
    def predict_dns_anomaly(self, dns_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict DNS anomaly using both Isolation Forest and Autoencoder.
        
        Args:
            dns_record: Dictionary containing DNS query data
            
        Returns:
            Dictionary with prediction results
        """
        try:
            # Preprocess the DNS query
            X_scaled = self.preprocess_single_dns_query(dns_record)
            
            # Calculate features for the query
            query = dns_record.get('query', '')
            features = {
                'query_length': len(query),
                'subdomain_count': query.count('.'),
                'query_entropy': self._calculate_entropy(query),
                'numeric_ratio': self._calculate_numeric_ratio(query),
                'ngram_score': self._calculate_ngram_score(query)
            }
            
            # Add tunneling patterns
            tunneling_patterns = self._detect_dns_tunneling_patterns(query)
            features.update(tunneling_patterns)
            
            # Add TTL features
            ttl_patterns = self._parse_ttl_values(dns_record.get('TTLs', '-'))
            features.update(ttl_patterns)
            
            # Add query type features
            features['is_qtype_txt'] = int(dns_record.get('qtype_name', '').upper() == 'TXT')
            features['is_qtype_null'] = int(dns_record.get('qtype_name', '').upper() == 'NULL')
            features['is_nxdomain'] = int(dns_record.get('rcode_name', '').upper() == 'NXDOMAIN')
            
            results = {
                'query': dns_record.get('query', ''),
                'timestamp': dns_record.get('ts', 0),
                'preprocessed_features': X_scaled,  # TRẢ VỀ NUMPY ARRAY THAY VÌ SỐ FEATURES
                'features': features
            }
            
            # Isolation Forest prediction
            if self.isolation_model is not None:
                iso_score = self.isolation_model.decision_function(X_scaled)[0]
                # FIX: Use threshold-based detection instead of predict() method
                # Isolation Forest scores are lower (more negative) for anomalies
                iso_threshold = getattr(self, 'dns_iso_threshold', 0.07)  # Default fallback
                results['isolation_forest'] = {
                    'score': float(iso_score),
                    'threshold': float(iso_threshold),
                    'is_anomaly': bool(iso_score < iso_threshold)
                }
            
            # Autoencoder prediction
            if self.autoencoder_model is not None:
                reconstruction = self.autoencoder_model.predict(X_scaled, verbose=0)
                reconstruction_error = np.mean(np.square(X_scaled - reconstruction))
                # Use loaded threshold instead of hardcoded value
                ae_threshold = getattr(self, 'dns_ae_threshold', 0.2)  # Default fallback
                results['autoencoder'] = {
                    'reconstruction_error': float(reconstruction_error),
                    'threshold': float(ae_threshold),
                    'is_anomaly': bool(reconstruction_error > ae_threshold),
                    # Include reconstruction for downstream XAI formatting
                    'reconstruction': reconstruction.flatten().tolist() if hasattr(reconstruction, 'flatten') else None
                }
            
            return results
            
        except Exception as e:
            self.logger.error(f"❌ DNS prediction failed: {e}")
            raise
    
    def validate_dns_preprocessing_consistency(self) -> bool:
        """
        Validate that DNS preprocessing is consistent with training pipeline.
        
        Returns:
            True if consistent, False otherwise
        """
        try:
            # Create a test DNS query with known values
            test_dns_record = {
                'ts': 1234567890.0,
                'uid': 'test_dns_uid',
                'id.orig_h': '192.168.1.100',
                'id.orig_p': 12345,
                'id.resp_h': '192.168.1.1',
                'id.resp_p': 53,
                'proto': 'udp',
                'trans_id': 12345,
                'rtt': 0.1,
                'query': 'test.example.com',
                'qclass': 1,
                'qclass_name': 'C_INTERNET',
                'qtype': 1,
                'qtype_name': 'A',
                'rcode': 0,
                'rcode_name': 'NOERROR',
                'AA': False,
                'TC': False,
                'RD': True,
                'RA': True,
                'Z': False,
                'answers': '-',
                'TTLs': '300',
                'rejected': False
            }
            
            # Preprocess the test DNS query
            X_test = self.preprocess_single_dns_query(test_dns_record)
            
            # Check output shape matches expected
            expected_features = len(DNS_FEATURE_COLUMNS)
            
            if X_test.shape[1] != expected_features:
                self.logger.error(f"❌ DNS feature count mismatch: expected {expected_features}, got {X_test.shape[1]}")
                return False
            
            self.logger.info(f"DNS preprocessing consistency validated: {X_test.shape}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ DNS preprocessing validation failed: {e}")
            return False 

def parse_redis_conn_log(redis_log_line: str) -> str:
    """
    Parse Redis JSON log format and extract conn.log message.
    
    Args:
        redis_log_line: Raw Redis log line with JSON format
        
    Returns:
        Standard conn.log line format for processing
    """
    try:
        import json
        
        # Validate input
        if not redis_log_line or not redis_log_line.strip():
            print("Error: Empty Redis log line")
            return None
        
        # Parse the outer JSON structure first
        try:
            redis_data = json.loads(redis_log_line)
            message_str = redis_data.get('message', '')
            

            conn_data = json.loads(message_str)
        except json.JSONDecodeError as e:
            print(f"Error parsing Redis JSON: {str(e)}")
            return None
        
        # Validate conn_data
        if not conn_data:
            print("Error: Empty conn_data after parsing")
            return None
        

        def preserve_field_value(value, field_name):
            """Preserve data types and precision during conversion."""
            if value is None or value == '':
                return ''
            
            # Special handling for numeric fields
            if field_name in ['ts', 'id.orig_p', 'id.resp_p', 'duration', 'orig_bytes', 'resp_bytes', 
                             'missed_bytes', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']:
                try:
                    # Preserve numeric precision
                    if isinstance(value, (int, float)):
                        return str(value)
                    elif isinstance(value, str) and value.strip():
                        # Try to convert and preserve
                        return str(float(value))
                    else:
                        return '0'
                except (ValueError, TypeError):
                    return '0'
            
            # Special handling for boolean fields
            elif field_name in ['local_orig', 'local_resp']:
                if isinstance(value, bool):
                    return 'T' if value else 'F'
                elif isinstance(value, str):
                    return 'T' if value.lower() in ['true', 't', '1'] else 'F'
                else:
                    return 'F'
            
            # Default: preserve as string
            return str(value)
        
        # ✅ FIXED: Map Redis fields to expected conn.log fields
        orig_bytes = conn_data.get('orig_bytes') or 0  # Payload bytes
        resp_bytes = conn_data.get('resp_bytes') or 0  # Payload bytes  
        orig_ip_bytes = conn_data.get('orig_ip_bytes') or 0  # IP level bytes
        resp_ip_bytes = conn_data.get('resp_ip_bytes') or 0  # IP level bytes
        duration = conn_data.get('duration') or 0.0
        
        conn_log_fields = [
            preserve_field_value(conn_data.get('ts', ''), 'ts'),           # Timestamp
            preserve_field_value(conn_data.get('uid', ''), 'uid'),         # UID
            preserve_field_value(conn_data.get('id.orig_h', ''), 'id.orig_h'), # Source IP
            preserve_field_value(conn_data.get('id.orig_p', ''), 'id.orig_p'), # Source Port
            preserve_field_value(conn_data.get('id.resp_h', ''), 'id.resp_h'), # Destination IP
            preserve_field_value(conn_data.get('id.resp_p', ''), 'id.resp_p'), # Destination Port
            preserve_field_value(conn_data.get('proto', ''), 'proto'),     # Protocol
            preserve_field_value(conn_data.get('service', ''), 'service'), # Service
            preserve_field_value(duration, 'duration'),                   # Duration (with fallback)
            preserve_field_value(orig_bytes, 'orig_bytes'),               # Origin bytes (payload)
            preserve_field_value(resp_bytes, 'resp_bytes'),               # Response bytes (payload)
            preserve_field_value(conn_data.get('conn_state', ''), 'conn_state'), # Connection state
            preserve_field_value(conn_data.get('local_orig', ''), 'local_orig'), # Local origin
            preserve_field_value(conn_data.get('local_resp', ''), 'local_resp'), # Local response
            preserve_field_value(conn_data.get('missed_bytes', ''), 'missed_bytes'), # Missed bytes
            preserve_field_value(conn_data.get('history', ''), 'history'), # History
            preserve_field_value(conn_data.get('orig_pkts', ''), 'orig_pkts'), # Origin packets
            preserve_field_value(conn_data.get('orig_ip_bytes', ''), 'orig_ip_bytes'), # Origin IP bytes
            preserve_field_value(conn_data.get('resp_pkts', ''), 'resp_pkts'), # Response packets
            preserve_field_value(conn_data.get('resp_ip_bytes', ''), 'resp_ip_bytes'), # Response IP bytes
            preserve_field_value(conn_data.get('tunnel_parents', ''), 'tunnel_parents') # Tunnel parents
        ]
        
        # Validate field count (should be 21 fields for conn.log)
        if len(conn_log_fields) != 21:
            print(f"Error: Invalid field count {len(conn_log_fields)}, expected 21")
            return None
        
        # Validate critical fields
        if not conn_data.get('ts') or not conn_data.get('uid'):
            print("Error: Missing critical fields (ts, uid)")
            return None
        
        # Join with tabs to create standard conn.log format
        conn_log_line = '\t'.join(conn_log_fields)
        
        return conn_log_line
        
    except Exception as e:
        print(f"Error parsing Redis conn.log: {str(e)}")
        return None

def parse_redis_dns_log(redis_log_line: str) -> str:
    """
    Parse Redis JSON log format and extract dns.log message.
    
    Args:
        redis_log_line: Raw Redis log line with JSON format
        
    Returns:
        Standard dns.log line format for processing
    """
    try:
        import json
        
        # Validate input
        if not redis_log_line or not redis_log_line.strip():
            print("Error: Empty Redis log line")
            return None
        
        # Parse the outer JSON structure
        redis_data = json.loads(redis_log_line)
        message_str = redis_data.get('message', '')
        

        try:
            dns_data = json.loads(message_str)
        except json.JSONDecodeError as e:
            print(f"Error parsing DNS message JSON: {str(e)}")
            print(f"Message content: {message_str[:100]}...")
            return None
        
        # Validate dns_data
        if not dns_data:
            print("Error: Empty dns_data after parsing")
            return None
        
        # ✅ FIXED: Handle special DNS fields (answers and TTLs can be lists)
        def serialize_field(value):
            if isinstance(value, list):
                return ','.join(str(item) for item in value)  # ✅ FIXED: 'item' thay vì 'value'
            return str(value)
        
        # Convert to standard dns.log format (tab-separated)
        # Handle missing fields gracefully with validation
        dns_log_fields = [
            str(dns_data.get('ts', '')),
            str(dns_data.get('uid', '')),
            str(dns_data.get('id.orig_h', '')),
            str(dns_data.get('id.orig_p', '')),
            str(dns_data.get('id.resp_h', '')),
            str(dns_data.get('id.resp_p', '')),
            str(dns_data.get('proto', '')),
            str(dns_data.get('trans_id', '')),
            str(dns_data.get('rtt', '')),
            str(dns_data.get('query', '')),
            str(dns_data.get('qclass', '')),
            str(dns_data.get('qclass_name', '')),
            str(dns_data.get('qtype', '')),
            str(dns_data.get('qtype_name', '')),
            str(dns_data.get('rcode', '')),
            str(dns_data.get('rcode_name', '')),
            str(dns_data.get('AA', '')),
            str(dns_data.get('TC', '')),
            str(dns_data.get('RD', '')),
            str(dns_data.get('RA', '')),
            str(dns_data.get('Z', '')),
            serialize_field(dns_data.get('answers', '')),
            serialize_field(dns_data.get('TTLs', '')),
            str(dns_data.get('rejected', ''))
        ]
        
        # Validate field count (should be 24 fields for dns.log)
        if len(dns_log_fields) != 24:
            print(f"Error: Invalid field count {len(dns_log_fields)}, expected 24")
            return None
        
        # Validate critical fields
        if not dns_data.get('ts') or not dns_data.get('uid') or not dns_data.get('query'):
            print("Error: Missing critical fields (ts, uid, query)")
            return None
        
        # Join with tabs to create standard dns.log format
        dns_log_line = '\t'.join(dns_log_fields)
        
        return dns_log_line
        
    except Exception as e:
        print(f"Error parsing Redis dns.log: {str(e)}")
        return None 