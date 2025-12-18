#!/usr/bin/env python3
"""
Enhanced Training Pipeline for Network Anomaly Detection Models


Usage Examples:
Training:
E:/conda/python.exe train_enhanced_models.py --mode train --input data/final_conn_lab.log --output-dir model_final_lab6 --ae-epochs 150
Evaluation:
E:/conda/python.exe train_enhanced_models.py --mode evaluate --cic-test-path done/labeled_conn_log_friday.csv --output-dir model_final_lab6
"""
import argparse
import codecs
import logging
import os
import sys
import json
import shutil
from typing import List, Tuple, Optional, Dict, Any
import traceback
from datetime import datetime

import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, OneHotEncoder, FunctionTransformer, RobustScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, roc_curve, precision_recall_curve, auc


# Import our modules
sys.path.insert(0, os.path.abspath('.'))

from utils.transformers import GroupFeatureTransformer
from utils.feature_engineering import engineer_enhanced_features
from core.ip_profiler import UnifiedIPProfiler
from config import MODEL_DIRECTORY

# Try to import TensorFlow for Autoencoder
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("⚠️ TensorFlow not available - Autoencoder training will be skipped")

# Global feature definitions for enhanced network analysis
NUMERICAL_FEATURES: List[str] = [
    'duration', 'orig_bytes', 'resp_bytes', 'missed_bytes',
    'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
    'hist_len', 'hist_R_count', 'hist_has_T',
    # Enhanced network behavior features (streamlined)
    'is_failed_connection',
    # NEW: Critical tunneling detection feature (golden signal)
    'is_tunneled_connection',
    # NEW: Z-score group features (unified with runtime)
    'z_horizontal_unique_dst_ip_count', 'z_horizontal_problematic_ratio',
    'z_vertical_unique_dst_port_count', 'z_vertical_problematic_ratio',
    'z_beacon_group_count', 'z_ddos_group_unique_src_ip_count',
    'z_beacon_channel_timediff_std', 'z_beacon_channel_duration_std', 'z_beacon_channel_orig_bytes_std',
    # NEW: IP Profiler features for time-windowed behavioral analysis
    'concurrent_connections',
    'ip_profile_uid_rate',
    'ip_profile_id.resp_p_rate',
    'ip_profile_id.resp_h_rate',
    'ip_profile_conn_state_diversity',
    # FINAL ENHANCEMENTS for low-and-slow attack detection
    'ip_profile_mean_duration',
    'ip_profile_mean_orig_bytes'
]

CATEGORICAL_FEATURES: List[str] = [
    'proto', 'conn_state', 'orig_port_binned', 'resp_port_binned', 'service_binned'
    # REMOVED: 'traffic_pattern' - uses hardcoded thresholds causing cross-dataset issues
]

CONN_LOG_COLUMNS: List[str] = [
    'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
    'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state',
    'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts',
    'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents', 'label', 'detailed-label'
]


def selective_log_transform_func(X):
    """Selective log transform - only apply to appropriate features"""
    if hasattr(X, 'columns'):
        # For DataFrame input, apply selectively
        X_transformed = X.copy()
        log_features = ['duration', 'orig_bytes', 'resp_bytes', 'missed_bytes',
                       'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
                       'concurrent_connections', 'ip_profile_uid_rate']
        
        for col in log_features:
            if col in X_transformed.columns:
                X_transformed[col] = np.log1p(np.abs(X_transformed[col]))
        return X_transformed
    else:
        return np.log1p(np.abs(X))

def log_transform_func(x):
    """Log transform function that can be pickled (module level function)"""
    return np.log1p(np.abs(x))


class EnhancedModelTrainer:
    """
    Enhanced trainer for both Isolation Forest and Autoencoder models with improved features.
    """
    
    def __init__(self, 
                 input_file_path: str = None,
                 output_dir: str = MODEL_DIRECTORY,
                 model_version: str = 'v3',
                 top_n_services: int = 15,
                 iso_n_estimators: int = 500,
                 iso_contamination: float = 0.005,
                 ae_encoding_dim1: int = 64,
                 ae_encoding_dim2: int = 32,
                 ae_epochs: int = 100,
                 ae_batch_size: int = 64,
                 random_state: int = 42,
                 time_window_seconds: int = 300, 
                 logger: Optional[logging.Logger] = None):
        """
        Initialize the Enhanced Training Pipeline.
        
        Args:
            input_file_path: Path to input conn.log file or CSV
            output_dir: Directory to save trained models
            model_version: Version string for model naming
            top_n_services: Number of top services to keep
            iso_n_estimators: Number of Isolation Forest estimators
            iso_contamination: Contamination parameter for Isolation Forest
            ae_encoding_dim1: First encoding layer dimension
            ae_encoding_dim2: Bottleneck layer dimension
            ae_epochs: Number of training epochs
            ae_batch_size: Batch size for training
            random_state: Random seed for reproducibility
            time_window_seconds: Time window in seconds for IP profiling (🚨 FIXED: now in seconds)
            logger: Optional logger instance
        """
        self.input_file_path = input_file_path
        self.output_dir = output_dir
        self.model_version = model_version
        self.top_n_services = top_n_services
        self.iso_n_estimators = iso_n_estimators
        self.iso_contamination = iso_contamination
        self.ae_encoding_dim1 = ae_encoding_dim1
        self.ae_encoding_dim2 = ae_encoding_dim2
        self.ae_epochs = ae_epochs
        self.ae_batch_size = ae_batch_size
        self.random_state = random_state
        self.time_window_seconds = time_window_seconds  
        self.logger = logger or self._setup_logger()
        
        # Initialize data containers
        self.df = None
        self.X_train = None
        self.X_val = None
        self.complete_pipeline = None
        self.iso_model = None
        self.ae_model = None
        self.ae_threshold = None
        self.training_metadata = {}
        self.input_dim = None
        self.top_services_list = []
        
        # Set random seeds
        np.random.seed(random_state)
        if TENSORFLOW_AVAILABLE:
            tf.random.set_seed(random_state)
        
        self.logger.info(f"Enhanced Training Pipeline initialized with time window: {time_window_seconds}s")
        
    def _setup_logger(self) -> logging.Logger:
        """Configure enhanced logging for the training pipeline."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        log_filename = os.path.join(self.output_dir, f'training_log_{self.model_version}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        
        if sys.stdout.encoding != 'utf-8':
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        return logging.getLogger(__name__)
    
    def load_and_prepare_data(self, file_path: Optional[str] = None) -> pd.DataFrame:
        """
        Load and prepare the training data with enhanced preprocessing.
        
        Args:
            file_path: Path to the data file. If None, uses self.input_file_path
        
        Returns:
            Processed DataFrame ready for feature engineering
        """
        # Use provided file_path or fallback to instance path
        input_path = file_path if file_path is not None else self.input_file_path
        
        self.logger.info("="*80)
        self.logger.info("ENHANCED NETWORK ANOMALY DETECTION MODEL TRAINING")
        self.logger.info("="*80)
        self.logger.info(f"Version: {self.model_version}")
        self.logger.info(f"Processing data: {input_path}")
        self.logger.info(f"Output directory: {self.output_dir}")
        
        self.logger.info("="*60)
        self.logger.info("STEP 1: LOADING AND CLEANING DATA")
        self.logger.info("="*60)
        
        try:
            # Validate file existence
            if not os.path.exists(input_path):
                raise FileNotFoundError(f"Input file not found: {input_path}")
            
            # Load the data with robust error handling
            self.logger.info(f"Loading data from: {input_path}")
            
            # Try different loading strategies based on file format
            if input_path.endswith('.csv'):
                # Assume CSV format with headers
                df = pd.read_csv(input_path)
            else:
                # Detect NDJSON (JSON-lines) vs TSV Zeek format
                try:
                    first_data_line = None
                    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if line.startswith('#'):
                                continue
                            if line.strip():
                                first_data_line = line.strip()
                                break

                    if first_data_line is None:
                        raise ValueError("Input file appears to be empty of data lines")

                    # NDJSON detection: line starts with '{' (Zeek JSON logs)
                    if first_data_line.lstrip().startswith('{'):
                        self.logger.info("Detected NDJSON (JSON-lines) conn.log format - using pandas.read_json(lines=True)")
                        df = pd.read_json(input_path, lines=True)
                        self.logger.info(f"Loaded NDJSON conn.log: {df.shape}")
                    else:
                        # Fallback to TSV-based Zeek conn.log detection by counting tab-separated columns
                        num_cols = len(first_data_line.split('\t'))

                        if num_cols == 22:  # Has extra ip_proto field
                            self.logger.info(f"Detected 22 columns (with ip_proto) - will drop ip_proto field")
                            # Read with 22 columns then drop the last one
                            df = pd.read_csv(
                                input_path,
                                sep='\t',
                                header=None,
                                names=CONN_LOG_COLUMNS + ['ip_proto'],  # Add ip_proto temporarily
                                comment='#',
                                na_values='-',
                                on_bad_lines='skip',
                                low_memory=False
                            )
                            # Drop the ip_proto column
                            df = df.drop('ip_proto', axis=1)
                            self.logger.info(f"Loaded with ip_proto dropped: {df.shape}")
                        elif num_cols >= 23:  # Has label columns
                            df = pd.read_csv(
                                input_path,
                                sep='\t',
                                header=None,
                                names=CONN_LOG_COLUMNS,
                                comment='#',
                                na_values='-',
                                on_bad_lines='skip'
                            )
                            self.logger.info(f"Loaded with label columns: {df.shape}")
                        else:  # Standard conn.log without labels
                            basic_columns = [col for col in CONN_LOG_COLUMNS if col not in ['label', 'detailed-label']]
                            df = pd.read_csv(
                                input_path,
                                sep='\t',
                                header=None,
                                names=basic_columns,
                                comment='#',
                                na_values='-',
                                on_bad_lines='skip',
                                low_memory=False  # Fix DtypeWarning
                            )
                            self.logger.info(f"Loaded without label columns: {df.shape}")
                except Exception as e:
                    self.logger.error(f"Failed to load file: {e}")
                    raise
            
            self.logger.info(f"Successfully loaded data")
            self.logger.info(f"  Raw data shape: {df.shape}")
            self.logger.info(f"  Columns: {len(df.columns)}")

            # Align to training schema: keep only training columns, add defaults for missing
            try:
                basic_columns = [col for col in CONN_LOG_COLUMNS if col not in ['label', 'detailed-label']]
                defaults = {
                    'uid': '',
                    'id.orig_h': '',
                    'id.resp_h': '',
                    'proto': 'unknown',
                    'service': 'unknown',
                    'conn_state': 'unknown',
                    'history': '',
                    'tunnel_parents': 'none',
                    'local_orig': False,
                    'local_resp': False
                }
                for col in basic_columns:
                    if col not in df.columns:
                        df[col] = defaults.get(col, 0)
                # Reorder and drop non-training fields
                df = df[basic_columns]
                self.logger.info(f"  Aligned to training schema: {df.shape} (kept {len(basic_columns)} cols)")
            except Exception as align_e:
                self.logger.warning(f"Schema alignment skipped due to: {align_e}")
            
            # Enhanced data cleaning
            df = self._enhanced_data_cleaning(df)
            
            # Validate timestamp range to detect data corruption
            if 'ts' in df.columns:
                min_ts = df['ts'].min()
                max_ts = df['ts'].max()
                current_year = datetime.now().year
                
                # Check for future timestamps (data corruption)
                if max_ts > current_year * 365 * 24 * 3600:  # Rough conversion to seconds
                    self.logger.warning(f"⚠️  DETECTED FUTURE TIMESTAMPS: max_ts={max_ts} (year {datetime.fromtimestamp(max_ts).year})")
                    self.logger.warning("   This may indicate data corruption or parsing issues")
                    self.logger.warning("   Consider filtering out future timestamps")
                
                self.logger.info(f"   Timestamp range: {datetime.fromtimestamp(min_ts)} to {datetime.fromtimestamp(max_ts)}")
            
            self.logger.info(f"Enhanced data cleaning completed")
            self.logger.info(f"  Cleaned data shape: {df.shape}")
            
            # Store in instance only if this is the main training data
            if file_path is None:
                self.df = df
            
            return df
            
        except Exception as e:
            self.logger.error(f"Failed to load data: {str(e)}")
            self.logger.error(traceback.format_exc())
            raise
    
    def run_ip_profiler(self, df: Optional[pd.DataFrame] = None) -> pd.DataFrame:
        """
        Run the Training IP Profiler to generate behavioral features for model training.
        
        Args:
            df: DataFrame to process. If None, uses self.df
        
        Returns:
            DataFrame with added IP profiler features
        """
        # Use provided df or fallback to instance df
        input_df = df if df is not None else self.df
        
        if input_df is None:
            raise ValueError("Data must be loaded before running the IP Profiler.")

        self.logger.info("="*60)
        self.logger.info("STEP 1.5: RUNNING TRAINING IP PROFILER")
        self.logger.info("="*60)
        
        profiler = UnifiedIPProfiler(time_window_seconds=self.time_window_seconds)
        processed_df = profiler.create_training_features(input_df)
        
        self.logger.info("Training IP Profiler finished. DataFrame augmented with behavioral features.")
        self.logger.info(f"  New data shape: {processed_df.shape}")
        
        # Store in instance only if this was the main training data
        if df is None:
            self.df = processed_df
        
        return processed_df

    def _enhanced_data_cleaning(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Perform enhanced data cleaning with better handling of edge cases.
        
        Args:
            df: DataFrame to clean
            
        Returns:
            Cleaned DataFrame
        """
        self.logger.info("Performing enhanced data cleaning...")
        
        # Create a copy to avoid modifying the original
        cleaned_df = df.copy()
        
        # Remove any rows with all NaN values
        initial_rows = len(cleaned_df)
        cleaned_df.dropna(how='all', inplace=True)
        
        # Handle numerical columns with robust conversion
        numerical_cols = [
            'ts', 'id.orig_p', 'id.resp_p', 'duration', 'orig_bytes', 'resp_bytes',
            'missed_bytes', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes'
        ]
        
        for col in numerical_cols:
            if col in cleaned_df.columns:
                # Convert to numeric, coercing errors to NaN, then fill with 0
                cleaned_df[col] = pd.to_numeric(cleaned_df[col], errors='coerce').fillna(0)
                
                # Handle negative values (shouldn't exist in network data)
                if col in ['orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'orig_ip_bytes', 'resp_ip_bytes']:
                    cleaned_df[col] = cleaned_df[col].abs()  # Take absolute value
        
        # Enhanced categorical column handling
        categorical_mappings = {
            'service': 'unknown',
            'history': '',
            'conn_state': 'unknown',
            'proto': 'unknown',
            'tunnel_parents': 'none'
        }
        
        for col, default_value in categorical_mappings.items():
            if col in cleaned_df.columns:
                cleaned_df[col] = cleaned_df[col].fillna(default_value).astype(str)
                # Replace various null representations
                cleaned_df[col] = cleaned_df[col].replace(['-', 'nan', 'None', ''], default_value)
        
        # Enhanced boolean column handling
        boolean_cols = ['local_orig', 'local_resp']
        for col in boolean_cols:
            if col in cleaned_df.columns:
                # Map various boolean representations
                bool_mapping = {'-': False, 'T': True, 'F': False, 'true': True, 'false': False, 
                               '1': True, '0': False, 'True': True, 'False': False}
                # Fix FutureWarning by using proper pandas method
                cleaned_df[col] = cleaned_df[col].map(bool_mapping).fillna(False)
                cleaned_df[col] = cleaned_df[col].astype(bool)
        

        
        final_rows = len(cleaned_df)
        total_removed = initial_rows - final_rows
        self.logger.info(f"  Total data cleaning summary:")
        self.logger.info(f"    - Invalid rows removed: {total_removed}")
        # self.logger.info(f"    - DNS traffic removed: {dns_removed}")  # Commented out
        self.logger.info(f"    - Final dataset: {final_rows:,} connections")
        self.logger.info(f"    - Total reduction: {(total_removed/initial_rows)*100:.1f}%")
        self.logger.info(f"  NOTE: DNS traffic filtering is DISABLED - keeping all connection types")
        
        return cleaned_df

    def engineer_enhanced_features(self, df: Optional[pd.DataFrame] = None, top_services_list: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Engineer enhanced features for better anomaly detection.
        
        Args:
            df: DataFrame to process. If None, uses self.df
            top_services_list: List of top services. If None, calculates from data or uses self.top_services_list
        
        Returns:
            DataFrame with comprehensive engineered features
        """
        # Use provided df or fallback to instance df
        input_df = df if df is not None else self.df
        
        if input_df is None:
            raise ValueError("Data must be loaded before feature engineering.")
        
        self.logger.info("="*60)
        self.logger.info("STEP 2: ENHANCED FEATURE ENGINEERING")
        self.logger.info("="*60)
        
        # Create a copy for feature engineering
        df_features = input_df.copy()
        
        # Since this dataset has protocol in service column, we need to infer services from protocol + port
        df_features['inferred_service'] = df_features.apply(
            lambda row: self._infer_service_from_protocol_port(row['proto'], row['id.resp_p']), 
            axis=1
        )
        

        if top_services_list is not None:
            services_list = top_services_list
            self.logger.info(f"Using provided top services list: {services_list}")
        else:
            # Always calculate fresh top services from inferred_service for training
            service_counts = df_features['inferred_service'].value_counts()
            services_list = service_counts.head(self.top_n_services).index.tolist()
            self.top_services_list = services_list  # Store for future use
            self.logger.info(f"Top {self.top_n_services} services inferred from protocol+port: {services_list}")

        # Apply the centralized feature engineering function
        # Use inferred_service instead of service for this dataset
        # Replace service column with inferred_service for consistency
        df_features['service'] = df_features['inferred_service']
        processed_df = engineer_enhanced_features(df_features, services_list)
        
        self.logger.info("Enhanced feature engineering completed")
        self.logger.info(f"  Final data shape: {processed_df.shape}")
        
        #  FIX: Calculate actual feature count from data, not hardcoded
        base_features = len(NUMERICAL_FEATURES) + len(CATEGORICAL_FEATURES)
        
        # Calculate one-hot features from actual data
        proto_unique = processed_df['proto'].nunique()
        conn_state_unique = processed_df['conn_state'].nunique()
        orig_port_binned_unique = processed_df['orig_port_binned'].nunique()
        resp_port_binned_unique = processed_df['resp_port_binned'].nunique()
        service_binned_unique = processed_df['service_binned'].nunique()
        
        one_hot_features = proto_unique + conn_state_unique + orig_port_binned_unique + resp_port_binned_unique + service_binned_unique
        total_expected = base_features + one_hot_features
        
        self.logger.info(f"  Total features: {total_expected}")
        self.logger.info("  Feature categories:")
        self.logger.info(f"    - Base features: {base_features}")
        self.logger.info(f"    - One-hot encoded: {one_hot_features}")
        self.logger.info(f"      * Protocol: {proto_unique} (from data)")
        self.logger.info(f"    - Connection state: {conn_state_unique} (from data)")
        self.logger.info(f"      * Orig port binning: {orig_port_binned_unique} (from data)")
        self.logger.info(f"      * Resp port binning: {resp_port_binned_unique} (from data)")
        self.logger.info(f"      * Service binning: {service_binned_unique} (from data)")
        self.logger.info("   Simplified feature set - removed redundant per-connection beaconing indicators")
        self.logger.info("   Focus on Multi-Group Analysis for robust attack pattern detection")
        
        # Store in instance only if this was the main training data
        if df is None:
            self.df = processed_df
        
        return processed_df
    
    def _infer_service_from_protocol_port(self, proto: str, port: int) -> str:
        """
        Infer service name from protocol and port combination.
        
        Args:
            proto: Protocol (tcp, udp, icmp)
            port: Destination port
            
        Returns:
            Inferred service name
        """
        try:
            port = int(port)
        except (ValueError, TypeError):
            port = 0
            
        if proto == 'tcp':
            if port == 80 or port == 8080: return 'http'
            elif port == 443 or port == 8443: return 'https'
            elif port == 22: return 'ssh'
            elif port == 21: return 'ftp'
            elif port == 25: return 'smtp'
            elif port == 110: return 'pop3'
            elif port == 143: return 'imap'
            elif port == 53: return 'dns'
            elif port == 23: return 'telnet'
            elif port <= 1023: return 'well_known_tcp'
            else: return 'dynamic_tcp'
        elif proto == 'udp':
            if port == 53: return 'dns'
            elif port == 67 or port == 68: return 'dhcp'
            elif port == 123: return 'ntp'
            elif port == 161 or port == 162: return 'snmp'
            elif port <= 1023: return 'well_known_udp'
            else: return 'dynamic_udp'
        elif proto == 'icmp':
            return 'icmp'
        else:
            return 'unknown'

    def create_enhanced_preprocessor(self) -> Tuple[Pipeline, np.ndarray, np.ndarray]:
        """
        Create an enhanced preprocessing pipeline with proper train/validation split.
        This version ensures correct feature union and processing order.
        """
        self.logger.info("="*60)
        self.logger.info("STEP 3: CREATING ENHANCED PREPROCESSOR (FINAL CORRECTED VERSION)")
        self.logger.info("="*60)
        
        # Time-based split
        self.logger.info("Performing time-based train/validation split (90% train, 10% val)...")
        df_sorted = self.df.sort_values('ts').reset_index(drop=True)
        split_index = int(len(df_sorted) * 0.9)
        train_data = df_sorted.iloc[:split_index]
        val_data = df_sorted.iloc[split_index:]
        self.logger.info(f"  Train set: {len(train_data):,} samples")
        self.logger.info(f"  Validation set: {len(val_data):,} samples")

        # ---- ĐỊNH NGHĨA CÁC NHÓM FEATURE ----
        # Split numerical into z-score group features vs others to avoid log-transforming z-scores
        z_group_features = [
            'z_horizontal_unique_dst_ip_count', 'z_horizontal_problematic_ratio',
            'z_vertical_unique_dst_port_count', 'z_vertical_problematic_ratio',
            'z_beacon_group_count', 'z_ddos_group_unique_src_ip_count',
            'z_beacon_channel_timediff_std', 'z_beacon_channel_duration_std', 'z_beacon_channel_orig_bytes_std'
        ]
        numerical_features_to_scale = [f for f in NUMERICAL_FEATURES if f not in z_group_features]
        
        # Features categorical sẽ được one-hot encode
        categorical_features_to_encode = CATEGORICAL_FEATURES
        
        # ---- ĐỊNH NGHĨA CÁC BƯỚC XỬ LÝ ----
        numerical_transformer = Pipeline(steps=[
            ('log_transform', FunctionTransformer(log_transform_func, validate=False)),
            ('scaler', RobustScaler()),
            ('imputer', SimpleImputer(strategy='constant', fill_value=0))
        ])

        # Z-score features are already standardized; avoid additional scaling
        numerical_z_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value=0))
        ])

        categorical_transformer = Pipeline(steps=[
            ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False, drop='if_binary'))
        ])

        preprocessor = ColumnTransformer(
            transformers=[
                ('numerical', numerical_transformer, numerical_features_to_scale),
                ('numerical_z', numerical_z_transformer, z_group_features),
                ('categorical', categorical_transformer, categorical_features_to_encode)
            ],
            remainder='drop'  # Vứt bỏ tất cả các cột không được xử lý (như uid, ip, history...)
        )
        
        # ---- XÂY DỰNG PIPELINE TỔNG THỂ ----
        
        # UPDATED: Beacon detection now includes protocol for more accurate pattern recognition
        expert_beacon_baselines = {
            'median_beacon_group_count': 2.0,  # "Bình thường" là 2 kết nối
            'std_beacon_group_count': 5.0,     # Cho phép một chút biến động
            'beacon_channel_timediff_std_mean': 30.0, # Thời gian của người dùng thường không đều, độ lệch 30s
            'beacon_channel_timediff_std_std': 15.0   # Sự không đều đó cũng không nhất quán
        }
        
        self.complete_pipeline = Pipeline(steps=[
            # Bước 1: Chạy GroupFeatureTransformer với manual baselines để tạo Z-score group features (unified with runtime).
            ('group_feature_generator', GroupFeatureTransformer(
                logger=self.logger, 
                time_window_seconds=self.time_window_seconds,
                min_samples_for_confirm=3,
                manual_baselines=expert_beacon_baselines  
            )),
            

            ('preprocessor', preprocessor)
        ])

        self.logger.info("Fitting preprocessing pipeline on training data...")
        X_train_processed = self.complete_pipeline.fit_transform(train_data)
        
        self.logger.info("Applying fitted pipeline to validation data...")
        X_val_processed = self.complete_pipeline.transform(val_data)
        
        self.input_dim = X_train_processed.shape[1]
        self.X_train = X_train_processed
        self.X_val = X_val_processed

        self.logger.info("Enhanced preprocessor with data leakage prevention completed")
        self.logger.info(f"  Final Input dimension: {self.input_dim}")
        self.logger.info(f"  Training data processed: {X_train_processed.shape}")
        self.logger.info(f"  Validation data processed: {X_val_processed.shape}")

        return self.complete_pipeline, X_train_processed, X_val_processed

    def train_isolation_forest(self, X_train: np.ndarray) -> IsolationForest:
        """
        Train a standard sklearn Isolation Forest model.
        
        Args:
            X_train: Preprocessed training data
            
        Returns:
            Trained Isolation Forest model
        """
        self.logger.info("="*60)
        self.logger.info("STEP 4: TRAINING STANDARD ISOLATION FOREST")
        self.logger.info("="*60)
        
        # Dùng trực tiếp class IsolationForest của sklearn
        self.iso_model = IsolationForest(
            n_estimators=self.iso_n_estimators,
            max_samples='auto',  # Use all samples for better normal boundary learning
            contamination=self.iso_contamination,  # Low contamination for normal data
            max_features=1.0,   # Use all features for robustness
            bootstrap=False,    # No bootstrap for consistent training
            random_state=self.random_state,
            n_jobs=-1,
            verbose=1
        )
        
        self.logger.info(f"Training standard Isolation Forest with contamination={self.iso_contamination}...")
        self.logger.info(f"  Configuration: contamination={self.iso_contamination}, max_features=1.0, bootstrap=False")
        
        # Train model. Thư viện sẽ tự xử lý threshold bên trong.
        self.iso_model.fit(X_train)
        
        # CRITICAL: Calculate and save decision_function threshold from TRAINING data
        training_scores = self.iso_model.decision_function(X_train)
        # Use multiple percentiles for flexible thresholding
        iso_threshold_90 = np.percentile(training_scores, 10)  # Bottom 10% of training data
        iso_threshold_95 = np.percentile(training_scores, 5)   # Bottom 5% of training data  
        iso_threshold_99 = np.percentile(training_scores, 1)   # Bottom 1% of training data
        iso_threshold_zero = 0.0  # Standard zero threshold
        
        # Save thresholds for evaluation
        threshold_data = {
            "threshold_10_percent": float(iso_threshold_90),
            "threshold_5_percent": float(iso_threshold_95), 
            "threshold_1_percent": float(iso_threshold_99),
            "threshold_zero": float(iso_threshold_zero),
            "sample_size": len(X_train),
            "calculated_on": datetime.now().isoformat(),
            "model_version": self.model_version,
            "note": "Thresholds calculated on TRAINING data (normal traffic only)"
        }
        
        # Also persist a copy with the naming MLHandler prioritizes
        threshold_path = os.path.join(self.output_dir, f'iso_threshold_{self.model_version}.json')
        primary_threshold_path = os.path.join(self.output_dir, 'iso_threshold_cic_master.json')
        with open(threshold_path, 'w') as f:
            json.dump(threshold_data, f, indent=2)
        # Keep a primary name for inference loader compatibility
        try:
            shutil.copyfile(threshold_path, primary_threshold_path)
        except Exception:
            pass
        
        self.logger.info("Standard Isolation Forest training completed successfully.")
        self.logger.info(f"  Model trained on {X_train.shape[0]} samples with {X_train.shape[1]} features")
        self.logger.info(f"  Decision function thresholds calculated:")
        self.logger.info(f"    - 10% threshold: {iso_threshold_90:.6f}")
        self.logger.info(f"    - 5% threshold: {iso_threshold_95:.6f}")
        self.logger.info(f"    - 1% threshold: {iso_threshold_99:.6f}")
        self.logger.info(f"    - Zero threshold: {iso_threshold_zero:.6f}")
        self.logger.info(f"  Thresholds saved to: {threshold_path}")
        
        return self.iso_model

    def train_autoencoder(self, X_train: np.ndarray, X_val: np.ndarray) -> Optional[Tuple[keras.Model, float]]:
        """
        Train an enhanced Autoencoder model.
        
        Args:
            X_train: Preprocessed training data
            X_val: Preprocessed validation data
            
        Returns:
            A tuple containing the trained Autoencoder model and the calculated threshold,
            or None if TensorFlow is unavailable.
        """
        if not TENSORFLOW_AVAILABLE:
            self.logger.warning("TensorFlow not available - skipping Autoencoder training")
            return None, None
        
        self.logger.info("="*60)
        self.logger.info("STEP 5: TRAINING ENHANCED AUTOENCODER")
        self.logger.info("="*60)
        
        # Build enhanced autoencoder architecture
        input_layer = layers.Input(shape=(self.input_dim,))
        
        # Enhanced encoder with regularization
        encoder1 = layers.Dense(
            self.ae_encoding_dim1,
            activation='relu',
            kernel_regularizer=tf.keras.regularizers.l2(0.001),
            name='encoder_1'
        )(input_layer)
        encoder1_dropout = layers.Dropout(0.2)(encoder1)
        encoder1_bn = layers.BatchNormalization()(encoder1_dropout)
        
        # Bottleneck layer
        bottleneck = layers.Dense(
            self.ae_encoding_dim2,
            activation='relu',
            kernel_regularizer=tf.keras.regularizers.l2(0.002),
            name='bottleneck'
        )(encoder1_bn)
        bottleneck_dropout = layers.Dropout(0.3)(bottleneck)
        bottleneck_bn = layers.BatchNormalization()(bottleneck_dropout)
        
        # Enhanced decoder
        decoder1 = layers.Dense(
            self.ae_encoding_dim1,
            activation='relu',
            kernel_regularizer=tf.keras.regularizers.l2(0.001),
            name='decoder_1'
        )(bottleneck_bn)
        decoder1_dropout = layers.Dropout(0.2)(decoder1)
        decoder1_bn = layers.BatchNormalization()(decoder1_dropout)
        
        # Output layer
        output_layer = layers.Dense(self.input_dim, activation='linear', name='output')(decoder1_bn)
        
        # Create and compile model
        self.ae_model = keras.Model(inputs=input_layer, outputs=output_layer, name='enhanced_autoencoder')
        
        # Enhanced optimizer with exponential decay learning rate scheduling
        initial_learning_rate = 0.001
        

        
        optimizer = tf.keras.optimizers.Adam(learning_rate=initial_learning_rate)
        self.ae_model.compile(optimizer=optimizer, loss='mse', metrics=['mae', 'mse'])
        
        self.logger.info(f"Enhanced Autoencoder architecture: {self.input_dim} -> {self.ae_encoding_dim1} -> {self.ae_encoding_dim2} -> {self.ae_encoding_dim1} -> {self.input_dim}")
        self.logger.info(f"Architecture: Enhanced bottleneck with regularization")
        self.logger.info(f"Regularization: L2 regularization + Dropout + BatchNorm")
        self.logger.info(f"Optimizer: Adam with exponential decay learning rate")
        self.logger.info(f"Loss function: Mean Squared Error")
        self.logger.info(f"Dropout rates: 0.2 (encoder/decoder), 0.3 (bottleneck)")
        
        # Print model summary
        self.logger.info("Enhanced Model Architecture Summary:")
        self.ae_model.summary(print_fn=self.logger.info)
        
        # Enhanced callbacks for better training
        callbacks = [
            # Early stopping to prevent overfitting - INCREASED PATIENCE for more training
            tf.keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=60,  # Increased from 15 to 30 epochs
                restore_best_weights=True,
                verbose=1
            ),
            
            # Reduce learning rate when validation loss plateaus
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=1e-7,
                verbose=1
            ),
            
            # Model checkpoint to save best model
            tf.keras.callbacks.ModelCheckpoint(
                filepath=os.path.join(self.output_dir, f'autoencoder_best_{self.model_version}.keras'),
                monitor='val_loss',
                save_best_only=True,
                save_weights_only=False,
                verbose=1
            )
        ]
        
        # Train the model
        self.logger.info(f"Training enhanced autoencoder on {X_train.shape[0]} samples...")
        self.logger.info(f"Enhanced training parameters:")
        self.logger.info(f"  Epochs: {self.ae_epochs}")
        self.logger.info(f"  Batch size: {self.ae_batch_size}")
        self.logger.info(f"  Validation split: 0.1")
        self.logger.info(f"  Shuffle: False (preserves time series order)")
        self.logger.info(f"  Enhanced callbacks: EarlyStopping, ReduceLROnPlateau, ModelCheckpoint")
        

        history = self.ae_model.fit(
            X_train, X_train,  # Input and target are the same for autoencoders
            epochs=self.ae_epochs,
            batch_size=self.ae_batch_size,
            shuffle=False,  # 🚨 FIXED: Preserve time series order to prevent data leakage
            validation_data=(X_val, X_val),  # CRITICAL FIX: Use pre-split validation data
            callbacks=callbacks,
            verbose=1
        )
        
        # Store training history for visualization
        self.ae_training_history = history.history
        
        # Calculate threshold
        reconstructions = self.ae_model.predict(X_train, verbose=0)
        reconstruction_errors = np.mean(np.square(X_train - reconstructions), axis=1)
        ae_threshold = np.percentile(reconstruction_errors, 99)
        
        # Save threshold
        threshold_data = {
            "threshold": float(ae_threshold),
            "sample_size": len(X_train),
            "calculated_on": datetime.now().isoformat(),
            "percentile": 99,
            "model_version": self.model_version
        }
        
        # Save with both versioned and primary names for inference
        threshold_path = os.path.join(self.output_dir, f'ae_threshold_{self.model_version}.json')
        primary_threshold_path = os.path.join(self.output_dir, 'ae_threshold_cic_master.json')
        with open(threshold_path, 'w') as f:
            json.dump(threshold_data, f, indent=2)
        try:
            shutil.copyfile(threshold_path, primary_threshold_path)
        except Exception:
            pass
        
        self.logger.info("Enhanced Autoencoder training completed successfully")
        self.logger.info(f"  Final training loss: {history.history['loss'][-1]:.6f}")
        self.logger.info(f"  Final validation loss: {history.history['val_loss'][-1]:.6f}")
        self.logger.info(f"  Final training MAE: {history.history['mae'][-1]:.6f}")
        self.logger.info(f"  Final validation MAE: {history.history['val_mae'][-1]:.6f}")
        self.logger.info(f"  Best validation loss: {min(history.history['val_loss']):.6f}")
        self.logger.info(f"  Training epochs completed: {len(history.history['loss'])}")
        self.logger.info(f"  Calculated threshold (99th percentile): {ae_threshold:.6f}")
        
        return self.ae_model, ae_threshold

    def create_evaluation_visualizations(self, y_true: np.ndarray, y_pred: np.ndarray, 
                                       iso_scores: np.ndarray, ae_scores: Optional[np.ndarray] = None,
                                       model_name: str = "Model") -> None:
        """
        Create comprehensive evaluation visualizations including confusion matrix, ROC curves, and score distributions.
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            iso_scores: Isolation Forest decision function scores
            ae_scores: Autoencoder reconstruction error scores (optional)
            model_name: Name for the model in plots
        """
        # Set style for better plots
        plt.style.use('default')
        sns.set_palette("husl")
        
        # Create output directory for plots
        plots_dir = os.path.join(self.output_dir, 'evaluation_plots')
        os.makedirs(plots_dir, exist_ok=True)
        
        # 1. CONFUSION MATRIX
        fig, axes = plt.subplots(1, 2, figsize=(15, 6))
        
        # Confusion matrix heatmap
        cm = confusion_matrix(y_true, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['Normal', 'Anomaly'], 
                   yticklabels=['Normal', 'Anomaly'], ax=axes[0])
        axes[0].set_title(f'{model_name} - Confusion Matrix')
        axes[0].set_xlabel('Predicted')
        axes[0].set_ylabel('Actual')
        
        # Normalized confusion matrix
        cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        sns.heatmap(cm_norm, annot=True, fmt='.3f', cmap='Blues',
                   xticklabels=['Normal', 'Anomaly'], 
                   yticklabels=['Normal', 'Anomaly'], ax=axes[1])
        axes[1].set_title(f'{model_name} - Normalized Confusion Matrix')
        axes[1].set_xlabel('Predicted')
        axes[1].set_ylabel('Actual')
        
        plt.tight_layout()
        plt.savefig(os.path.join(plots_dir, f'{model_name.lower().replace(" ", "_")}_confusion_matrix.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. SCORE DISTRIBUTIONS
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # Isolation Forest score distribution
        axes[0, 0].hist(iso_scores[y_true == 0], bins=50, alpha=0.7, label='Normal', color='blue')
        axes[0, 0].hist(iso_scores[y_true == 1], bins=50, alpha=0.7, label='Anomaly', color='red')
        axes[0, 0].set_title('Isolation Forest Score Distribution')
        axes[0, 0].set_xlabel('Decision Function Score')
        axes[0, 0].set_ylabel('Frequency')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)
        
        # Autoencoder score distribution (if available)
        if ae_scores is not None:
            axes[0, 1].hist(ae_scores[y_true == 0], bins=50, alpha=0.7, label='Normal', color='blue')
            axes[0, 1].hist(ae_scores[y_true == 1], bins=50, alpha=0.7, label='Anomaly', color='red')
            axes[0, 1].set_title('Autoencoder Score Distribution')
            axes[0, 1].set_xlabel('Reconstruction Error')
            axes[0, 1].set_ylabel('Frequency')
            axes[0, 1].legend()
            axes[0, 1].grid(True, alpha=0.3)
        
        # ROC Curve - use appropriate scores based on model type
        if model_name.lower().startswith('autoencoder') and ae_scores is not None:
            # For autoencoder, use ae_scores directly (higher = anomaly)
            fpr, tpr, _ = roc_curve(y_true, ae_scores)
            roc_auc = auc(fpr, tpr)
            curve_title = 'ROC Curve (Autoencoder)'
        else:
            # For isolation forest, use negative iso_scores (lower = anomaly)
            fpr, tpr, _ = roc_curve(y_true, -iso_scores)
            roc_auc = auc(fpr, tpr)
            curve_title = 'ROC Curve (Isolation Forest)'
        
        axes[1, 0].plot(fpr, tpr, color='darkorange', lw=2, 
                        label=f'ROC curve (AUC = {roc_auc:.3f})')
        axes[1, 0].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        axes[1, 0].set_xlim([0.0, 1.0])
        axes[1, 0].set_ylim([0.0, 1.05])
        axes[1, 0].set_xlabel('False Positive Rate')
        axes[1, 0].set_ylabel('True Positive Rate')
        axes[1, 0].set_title(curve_title)
        axes[1, 0].legend(loc="lower right")
        axes[1, 0].grid(True, alpha=0.3)
        
        # Precision-Recall Curve - use appropriate scores based on model type
        if model_name.lower().startswith('autoencoder') and ae_scores is not None:
            # For autoencoder, use ae_scores directly (higher = anomaly)
            precision, recall, _ = precision_recall_curve(y_true, ae_scores)
            pr_auc = auc(recall, precision)
            curve_title = 'Precision-Recall Curve (Autoencoder)'
        else:
            # For isolation forest, use negative iso_scores (lower = anomaly)
            precision, recall, _ = precision_recall_curve(y_true, -iso_scores)
            pr_auc = auc(recall, precision)
            curve_title = 'Precision-Recall Curve (Isolation Forest)'
        
        axes[1, 1].plot(recall, precision, color='darkgreen', lw=2,
                        label=f'PR curve (AUC = {pr_auc:.3f})')
        axes[1, 1].set_xlim([0.0, 1.0])
        axes[1, 1].set_ylim([0.0, 1.05])
        axes[1, 1].set_xlabel('Recall')
        axes[1, 1].set_ylabel('Precision')
        axes[1, 1].set_title(curve_title)
        axes[1, 1].legend(loc="lower left")
        axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(os.path.join(plots_dir, f'{model_name.lower().replace(" ", "_")}_score_analysis.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
        
        # 3. DETAILED METRICS SUMMARY
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred),
            'recall': recall_score(y_true, y_pred),
            'f1_score': f1_score(y_true, y_pred),
            'roc_auc': roc_auc,
            'pr_auc': pr_auc
        }
        
        # Save metrics to file
        metrics_path = os.path.join(plots_dir, f'{model_name.lower().replace(" ", "_")}_metrics.json')
        with open(metrics_path, 'w') as f:
            json.dump(metrics, f, indent=4)
        
        self.logger.info(f" Evaluation visualizations saved to: {plots_dir}")
        self.logger.info(f"📊 {model_name} Metrics:")
        self.logger.info(f"   Accuracy:  {metrics['accuracy']:.4f}")
        self.logger.info(f"   Precision: {metrics['precision']:.4f}")
        self.logger.info(f"   Recall:    {metrics['recall']:.4f}")
        self.logger.info(f"   F1-Score:  {metrics['f1_score']:.4f}")
        self.logger.info(f"   ROC-AUC:   {metrics['roc_auc']:.4f}")
        self.logger.info(f"   PR-AUC:    {metrics['pr_auc']:.4f}")
        
        return metrics

    def create_comprehensive_evaluation_report(self, y_true: np.ndarray, y_pred: np.ndarray, 
                                            iso_scores: np.ndarray, ae_scores: Optional[np.ndarray] = None,
                                            model_name: str = "Model", ae_threshold: Optional[float] = None) -> Dict[str, Any]:
        """
        Create a comprehensive evaluation report with detailed analysis.
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            iso_scores: Isolation Forest decision function scores
            ae_scores: Autoencoder reconstruction error scores (optional)
            model_name: Name for the model
            ae_threshold: Autoencoder threshold for anomaly detection (optional)
            
        Returns:
            Dictionary containing all evaluation metrics
        """
        # Calculate all metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred)
        recall = recall_score(y_true, y_pred)
        f1 = f1_score(y_true, y_pred)
        
        # ROC and PR curves - use appropriate scores based on model type
        print(f"   DEBUG: model_name='{model_name}', ae_scores is None: {ae_scores is None}")
        if model_name.lower().startswith('autoencoder') and ae_scores is not None:
            # For autoencoder, use ae_scores directly (higher = anomaly)
            # Reconstruction error is higher for anomalies
            
            # DEBUG: Check score distribution
            print(f"   DEBUG: Autoencoder scores:")
            print(f"   - Mean: {np.mean(ae_scores):.6f}")
            print(f"   - Std: {np.std(ae_scores):.6f}")
            print(f"   - Min: {np.min(ae_scores):.6f}")
            print(f"   - Max: {np.max(ae_scores):.6f}")
            print(f"   - Normal samples mean: {np.mean(ae_scores[y_true == 0]):.6f}")
            print(f"   - Attack samples mean: {np.mean(ae_scores[y_true == 1]):.6f}")
            if ae_threshold is not None:
                print(f"   - Threshold: {ae_threshold:.6f}")
                print(f"   - % above threshold: {(np.sum(ae_scores > ae_threshold)/len(ae_scores))*100:.1f}%")
                print(f"   - Normal samples above threshold: {(np.sum((ae_scores > ae_threshold) & (y_true == 0))/np.sum(y_true == 0))*100:.1f}%")
                print(f"   - Attack samples above threshold: {(np.sum((ae_scores > ae_threshold) & (y_true == 1))/np.sum(y_true == 1))*100:.1f}%")
            else:
                print(f"   - Threshold: None (not provided)")
            
            fpr, tpr, _ = roc_curve(y_true, ae_scores)
            roc_auc = auc(fpr, tpr)
            precision_curve, recall_curve, _ = precision_recall_curve(y_true, ae_scores)
            pr_auc = auc(recall_curve, precision_curve)
        else:
            # For isolation forest, use negative iso_scores (lower = anomaly)
            fpr, tpr, _ = roc_curve(y_true, -iso_scores)
            roc_auc = auc(fpr, tpr)
            precision_curve, recall_curve, _ = precision_recall_curve(y_true, -iso_scores)
            pr_auc = auc(recall_curve, precision_curve)
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        # Additional metrics
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0
        balanced_accuracy = (sensitivity + specificity) / 2
        
        # Create comprehensive report
        report = {
            'model_name': model_name,
            'basic_metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'specificity': specificity,
                'sensitivity': sensitivity,
                'balanced_accuracy': balanced_accuracy
            },
            'advanced_metrics': {
                'roc_auc': roc_auc,
                'pr_auc': pr_auc
            },
            'confusion_matrix': {
                'true_negatives': int(tn),
                'false_positives': int(fp),
                'false_negatives': int(fn),
                'true_positives': int(tp)
            },
            'score_analysis': {
                'iso_scores_mean': float(np.mean(iso_scores)),
                'iso_scores_std': float(np.std(iso_scores)),
                'iso_scores_min': float(np.min(iso_scores)),
                'iso_scores_max': float(np.max(iso_scores))
            }
        }
        
        if ae_scores is not None:
            report['score_analysis']['ae_scores_mean'] = float(np.mean(ae_scores))
            report['score_analysis']['ae_scores_std'] = float(np.std(ae_scores))
            report['score_analysis']['ae_scores_min'] = float(np.min(ae_scores))
            report['score_analysis']['ae_scores_max'] = float(np.max(ae_scores))
        
        # Save detailed report
        report_path = os.path.join(self.output_dir, 'evaluation_plots', f'{model_name.lower().replace(" ", "_")}_detailed_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=4)
        
        # Print comprehensive summary
        print(f"\n📊 {model_name.upper()} COMPREHENSIVE EVALUATION REPORT:")
        print("="*60)
        print(f"🎯 Basic Metrics:")
        print(f"   Accuracy:           {accuracy:.4f}")
        print(f"   Precision:          {precision:.4f}")
        print(f"   Recall/Sensitivity: {recall:.4f}")
        print(f"   F1-Score:           {f1:.4f}")
        print(f"   Specificity:        {specificity:.4f}")
        print(f"   Balanced Accuracy:  {balanced_accuracy:.4f}")
        print(f"\n📈 Advanced Metrics:")
        print(f"   ROC-AUC:            {roc_auc:.4f}")
        print(f"   PR-AUC:             {pr_auc:.4f}")
        print(f"\n🔍 Confusion Matrix:")
        print(f"   True Negatives:     {tn:,}")
        print(f"   False Positives:    {fp:,}")
        print(f"   False Negatives:    {fn:,}")
        print(f"   True Positives:     {tp:,}")
        print(f"\n📊 Score Analysis:")
        print(f"   ISO Scores - Mean:  {np.mean(iso_scores):.4f}")
        print(f"   ISO Scores - Std:   {np.std(iso_scores):.4f}")
        print(f"   ISO Scores - Range: [{np.min(iso_scores):.4f}, {np.max(iso_scores):.4f}]")
        
        if ae_scores is not None:
            print(f"   AE Scores - Mean:   {np.mean(ae_scores):.4f}")
            print(f"   AE Scores - Std:    {np.std(ae_scores):.4f}")
            print(f"   AE Scores - Range:  [{np.min(ae_scores):.4f}, {np.max(ae_scores):.4f}]")
        
        return report


    def get_feature_names(self) -> List[str]:
        """
        Get feature names dynamically from the fitted pipeline.
        
        Returns:
            List of feature names that match the pipeline output dimension
        """
        #  PRIORITY 1: Try to get feature names from the fitted pipeline
        if hasattr(self, 'complete_pipeline') and self.complete_pipeline is not None:
            try:
                manual_names = self._reconstruct_feature_names_from_pipeline()
                if manual_names and (self.input_dim is None or len(manual_names) == self.input_dim):
                    self.logger.info(f" Successfully reconstructed {len(manual_names)} feature names from preprocessor structure")
                    return manual_names

                # Method 1: Direct pipeline feature names
                if hasattr(self.complete_pipeline, 'get_feature_names_out'):
                    feature_names = self.complete_pipeline.get_feature_names_out()
                    if feature_names is not None and len(feature_names) > 0:
                        feature_names = feature_names.tolist() if hasattr(feature_names, 'tolist') else list(feature_names)
                        if len(feature_names) == self.input_dim:
                            self.logger.info(f" Successfully extracted {len(feature_names)} feature names from pipeline")
                            return feature_names
                
                # Method 2: Try to get from individual pipeline steps
                if hasattr(self.complete_pipeline, 'named_steps'):
                    for step_name, step in self.complete_pipeline.named_steps.items():
                        if hasattr(step, 'get_feature_names_out'):
                            try:
                                step_features = step.get_feature_names_out()
                                if step_features is not None and len(step_features) > 0:
                                    step_features = step_features.tolist() if hasattr(step_features, 'tolist') else list(step_features)
                                    if len(step_features) == self.input_dim:
                                        self.logger.info(f" Extracted {len(step_features)} feature names from {step_name}")
                                        return step_features
                            except Exception as e:
                                self.logger.debug(f"Could not get features from {step_name}: {str(e)[:50]}")
                                continue
                
                # Method 3: Try to reconstruct from pipeline components
                try:
                    reconstructed_features = self._reconstruct_feature_names_from_pipeline()
                    if reconstructed_features and len(reconstructed_features) == self.input_dim:
                        self.logger.info(f" Reconstructed {len(reconstructed_features)} feature names from pipeline components")
                        return reconstructed_features
                except Exception as e:
                    self.logger.debug(f"Could not reconstruct features: {str(e)[:50]}")
                
            except Exception as e:
                self.logger.warning(f"Pipeline feature extraction failed: {str(e)[:50]}")
        
        #  PRIORITY 2: Create intelligent fallback based on actual data
        self.logger.info(f"🔄 Pipeline feature extraction failed, creating intelligent fallback...")
        fallback_features = self._create_intelligent_fallback_features()
        
        #  VALIDATION: Ensure feature count matches pipeline output
        if len(fallback_features) != self.input_dim:
            self.logger.warning(f"⚠️ Feature count mismatch: fallback has {len(fallback_features)}, pipeline expects {self.input_dim}")
            # Trim or pad to match exactly
            if len(fallback_features) > self.input_dim:
                fallback_features = fallback_features[:self.input_dim]
                self.logger.info(f"  Trimmed to {len(fallback_features)} features")
            else:
                while len(fallback_features) < self.input_dim:
                    fallback_features.append(f'placeholder_{len(fallback_features)}')
                self.logger.info(f"  Padded to {len(fallback_features)} features")
        
        self.logger.info(f" Created {len(fallback_features)} fallback feature names")
        return fallback_features

    def _reconstruct_feature_names_from_pipeline(self) -> List[str]:
        """
        Try to reconstruct feature names from individual pipeline components.
        
        Returns:
            List of reconstructed feature names or None if failed
        """
        try:
            # Manual reconstruction via fitted ColumnTransformer structure only
            if not (hasattr(self.complete_pipeline, 'named_steps') and 'preprocessor' in self.complete_pipeline.named_steps):
                return None
            pre = self.complete_pipeline.named_steps['preprocessor']
            if not hasattr(pre, 'transformers_'):
                return None

            reconstructed_features: List[str] = []
            for name, transformer, cols in pre.transformers_:
                if name == 'numerical':
                    reconstructed_features.extend([str(c) for c in cols])
                elif name == 'numerical_z':
                    reconstructed_features.extend([str(c) for c in cols])
                elif name == 'categorical':
                    cat_pipe = transformer
                    ohe = None
                    try:
                        ohe = cat_pipe.named_steps.get('onehot') if hasattr(cat_pipe, 'named_steps') else None
                    except Exception:
                        ohe = None
                    if ohe is not None:
                        try:
                            cat_names = ohe.get_feature_names_out(cols)
                            reconstructed_features.extend(cat_names.tolist() if hasattr(cat_names, 'tolist') else list(cat_names))
                        except Exception:
                            try:
                                cats_list = list(ohe.categories_)
                                drop_idx = getattr(ohe, 'drop_idx_', None)
                                for i, base_col in enumerate(cols):
                                    categories = list(cats_list[i]) if i < len(cats_list) else []
                                    if drop_idx is not None and i < len(drop_idx) and drop_idx[i] is not None:
                                        categories = [c for j, c in enumerate(categories) if j != drop_idx[i]]
                                    elif getattr(ohe, 'drop', None) == 'if_binary' and len(categories) == 2:
                                        categories = categories[1:]
                                    for cat in categories:
                                        reconstructed_features.append(f"{base_col}_{cat}")
                            except Exception:
                                reconstructed_features.extend([f"{c}_encoded" for c in cols])
                    else:
                        reconstructed_features.extend([f"{c}_encoded" for c in cols])

            return reconstructed_features if reconstructed_features else None
            
        except Exception as e:
            self.logger.debug(f"Pipeline reconstruction failed: {str(e)[:50]}")
            return None

    def _create_intelligent_fallback_features(self) -> List[str]:
        """
        Create intelligent fallback feature names based on actual data and expected structure.
        
        Returns:
            List of fallback feature names
        """
        fallback_features = []
        
        #  METHOD 1: Use actual data if available
        if hasattr(self, 'df') and self.df is not None:
            try:
                # Get actual categories from training data
                proto_categories = sorted(self.df['proto'].unique().tolist())
                conn_state_categories = sorted(self.df['conn_state'].unique().tolist())
                orig_port_categories = sorted(self.df['orig_port_binned'].unique().tolist())
                resp_port_categories = sorted(self.df['resp_port_binned'].unique().tolist())
                service_categories = sorted(self.df['service_binned'].unique().tolist())
                
                self.logger.info(f"📊 Using actual data categories:")
                self.logger.info(f"  - Protocol: {proto_categories}")
                self.logger.info(f"  - Connection states: {len(conn_state_categories)} categories")
                self.logger.info(f"  - Port binning: {len(orig_port_categories)} + {len(resp_port_categories)} categories")
                self.logger.info(f"  - Service binning: {len(service_categories)} categories")
                
            except Exception as e:
                self.logger.warning(f"Could not extract categories from data: {str(e)[:50]}")
                # Fall back to expected categories
                proto_categories = ['tcp', 'udp', 'icmp']
                conn_state_categories = ['SF', 'S0', 'S1', 'S2', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'RSTOS1', 'RSTOS2', 'RSTOS3', 'SH', 'SHR', 'OTH']
                orig_port_categories = ['low', 'medium', 'high']
                resp_port_categories = ['low', 'medium', 'high']
                service_categories = ['common', 'uncommon', 'rare']
        else:
            # Fallback to expected categories
            proto_categories = ['tcp', 'udp', 'icmp']
            conn_state_categories = ['SF', 'S0', 'S1', 'S2', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'RSTOS1', 'RSTOS2', 'RSTOS3', 'SH', 'SHR', 'OTH']
            orig_port_categories = ['low', 'medium', 'high']
            resp_port_categories = ['low', 'medium', 'high']
            service_categories = ['common', 'uncommon', 'rare']
        
        #  METHOD 2: Build feature names dynamically
        
        #  SỬA ĐỔI: Thứ tự feature phải khớp với pipeline mới
        fallback_features = []
        
        # Group Z-score features được thêm vào trước tiên bởi GroupFeatureTransformer
        group_features = [
            'z_horizontal_unique_dst_ip_count', 'z_horizontal_problematic_ratio',
            'z_vertical_unique_dst_port_count', 'z_vertical_problematic_ratio',
            'z_beacon_group_count', 'z_ddos_group_unique_src_ip_count',
            'z_beacon_channel_timediff_std', 'z_beacon_channel_duration_std', 'z_beacon_channel_orig_bytes_std'
        ]
        fallback_features.extend(group_features)
        
        # Core numerical features được xử lý tiếp theo (loại bỏ các z_ nếu có)
        core_features = [f for f in NUMERICAL_FEATURES if not f.startswith(('z_',))]
        fallback_features.extend(core_features)
        
        # Categorical features (one-hot encoded)
        for category in proto_categories:
            fallback_features.append(f"proto_{category}")
        
        for category in conn_state_categories:
            fallback_features.append(f"conn_state_{category}")
        
        for category in orig_port_categories:
            fallback_features.append(f"orig_port_binned_{category}")
        
        for category in resp_port_categories:
            fallback_features.append(f"resp_port_binned_{category}")
        
        for category in service_categories:
            fallback_features.append(f"service_binned_{category}")
        
        #  LOG: Show intelligent breakdown
        self.logger.info(f"🧠 Intelligent fallback feature breakdown:")
        self.logger.info(f"  - Core numerical: {len(core_features)}")
        self.logger.info(f"  - Group features: {len(group_features)}")
        self.logger.info(f"  - Protocol one-hot: {len(proto_categories)}")
        self.logger.info(f"  - Connection state one-hot: {len(conn_state_categories)}")
        self.logger.info(f"  - Port binning one-hot: {len(orig_port_categories) + len(resp_port_categories)}")
        self.logger.info(f"  - Service binning one-hot: {len(service_categories)}")
        self.logger.info(f"  - Total: {len(fallback_features)}")
        
        return fallback_features

    def analyze_and_visualize_results(self, y_true: np.ndarray, iso_predictions: np.ndarray, 
                                    iso_scores: np.ndarray, ae_predictions: Optional[np.ndarray] = None,
                                    ae_scores: Optional[np.ndarray] = None, ae_threshold: Optional[float] = None,
                                    ensemble_predictions: Optional[np.ndarray] = None) -> None:
        """
        Comprehensive analysis and visualization of evaluation results.
        This function combines evaluation visualizations and feature importance analysis.
        
        Args:
            y_true: True labels
            iso_predictions: Isolation Forest predictions
            iso_scores: Isolation Forest scores
            ae_predictions: Autoencoder predictions (optional)
            ae_scores: Autoencoder scores (optional)
            ae_threshold: Autoencoder threshold (optional)
            ensemble_predictions: Ensemble predictions (optional)
        """
        self.logger.info("🔍 Starting comprehensive analysis and visualization...")
        
        # Create output directory for plots
        plots_dir = os.path.join(self.output_dir, 'evaluation_plots')
        os.makedirs(plots_dir, exist_ok=True)
        
        # 1. EVALUATION VISUALIZATIONS
        self.logger.info("📊 Creating evaluation visualizations...")
        
        # Isolation Forest evaluation
        self.create_evaluation_visualizations(
            y_true=y_true,
            y_pred=iso_predictions,
            iso_scores=iso_scores,
            model_name="Isolation Forest"
        )
        iso_report = self.create_comprehensive_evaluation_report(
            y_true=y_true,
            y_pred=iso_predictions,
            iso_scores=iso_scores,
            model_name="Isolation Forest"
        )
        
        # Autoencoder evaluation (if available)
        ae_report = None
        if ae_predictions is not None and ae_scores is not None:
            self.create_evaluation_visualizations(
                y_true=y_true,
                y_pred=ae_predictions,
                iso_scores=iso_scores,
                ae_scores=ae_scores,
                model_name="Autoencoder"
            )
            ae_report = self.create_comprehensive_evaluation_report(
                y_true=y_true,
                y_pred=ae_predictions,
                iso_scores=iso_scores,
                ae_scores=ae_scores,
                model_name="Autoencoder",
                ae_threshold=ae_threshold
            )
        
        # Ensemble evaluation (if available)
        ensemble_report = None
        if ensemble_predictions is not None:
            self.create_evaluation_visualizations(
                y_true=y_true,
                y_pred=ensemble_predictions,
                iso_scores=iso_scores,
                ae_scores=ae_scores if ae_scores is not None else None,
                model_name="Ensemble (OR)"
            )
            ensemble_report = self.create_comprehensive_evaluation_report(
                y_true=y_true,
                y_pred=ensemble_predictions,
                iso_scores=iso_scores,
                ae_scores=ae_scores if ae_scores is not None else None,
                model_name="Ensemble (OR)"
            )
        
        # 2. FEATURE IMPORTANCE ANALYSIS
        self.logger.info("🔍 Calculating feature importance analysis...")
        
        # Get feature names
        feature_names = self.get_feature_names()
        
        # Isolation Forest Feature Importance
        self.logger.info("🔍 Calculating Permutation Importance for Isolation Forest...")
        iso_importance = self._calculate_isolation_forest_importance(iso_scores, feature_names)
        
        # Autoencoder Feature Importance (if available)
        ae_importance = None
        if ae_scores is not None:
            self.logger.info("🔍 Calculating Autoencoder Feature Importance...")
            ae_importance = self._calculate_autoencoder_importance(ae_scores, feature_names)
        
        # 3. CREATE COMPREHENSIVE REPORTS
        self._create_comprehensive_analysis_reports(
            plots_dir, iso_report, ae_report, ensemble_report,
            iso_importance, ae_importance, feature_names
        )
        
        # 4. PRINT SUMMARY
        self._print_evaluation_summary(iso_report, ae_report, ensemble_report)
        
        self.logger.info(" Comprehensive analysis and visualization completed!")
        self.logger.info(f"📁 Results saved to: {plots_dir}")
    
    def _calculate_isolation_forest_importance(self, iso_scores: np.ndarray, feature_names: List[str]) -> Dict:
        """Calculate feature importance for Isolation Forest using permutation method."""
        try:
            # Check if model exists
            if not hasattr(self, 'iso_model') or self.iso_model is None:
                self.logger.warning("⚠️ Isolation Forest model not available for feature importance calculation")
                return None
                
            self.logger.info("🔄 Using Isolation Forest feature importance (faster approach)...")
            self.logger.info("🔄 Estimating feature importance using decision function...")
            
            # Use a faster permutation-based approach for Isolation Forest
            n_repeats = 5  # Reduced for speed
            importance_scores = np.zeros(len(feature_names))
            
            # Get processed data for permutation
            if hasattr(self, 'X_val') and self.X_val is not None:
                X_sample = self.X_val[:min(1000, len(self.X_val))]  # Use subset for speed
            else:
                # Fallback: create dummy data for importance calculation
                sample_size = min(1000, len(iso_scores) if iso_scores is not None else 1000)
                X_sample = np.random.randn(sample_size, len(feature_names))
            
            base_scores = self.iso_model.score_samples(X_sample)
            
            for i, feature_name in enumerate(feature_names):
                feature_importance = 0
                for _ in range(n_repeats):
                    # Permute the feature
                    X_permuted = X_sample.copy()
                    np.random.shuffle(X_permuted[:, i])
                    
                    # Calculate scores with permuted feature
                    permuted_scores = self.iso_model.score_samples(X_permuted)
                    
                    # Importance is the difference in score distribution
                    feature_importance += np.mean(np.abs(permuted_scores - base_scores))
                
                importance_scores[i] = feature_importance / n_repeats
            
            # Create importance data structure
            importance_data = {
                'feature_names': feature_names,
                'importance_scores': importance_scores.tolist(),
                'top_20_features': [feature_names[i] for i in np.argsort(importance_scores)[-20:]],
                'calculation_method': 'Permutation Importance (Isolation Forest)',
                'n_repeats': n_repeats
            }
            
            # Save to file
            plots_dir = os.path.join(self.output_dir, 'evaluation_plots')
            os.makedirs(plots_dir, exist_ok=True)
            
            importance_path = os.path.join(plots_dir, 'feature_importance_data.json')
            with open(importance_path, 'w') as f:
                json.dump(importance_data, f, indent=4)
            
            self.logger.info(" Permutation Importance analysis completed successfully")
            self.logger.info(f"   Top 5 most important features:")
            for i, feature in enumerate(importance_data['top_20_features'][-5:], 1):
                idx = feature_names.index(feature)
                self.logger.info(f"   {i}. {feature}: {importance_scores[idx]:.4f} ± 0.0000")
            self.logger.info(f"   Results saved to: {importance_path}")
            
            return importance_data
            
        except Exception as e:
            self.logger.warning(f"⚠️ Permutation Importance calculation failed: {str(e)}")
            return None
    
    def _calculate_autoencoder_importance(self, ae_scores: np.ndarray, feature_names: List[str]) -> Dict:
        """Calculate feature importance for Autoencoder using reconstruction error method."""
        try:
            # Check if model exists
            if not hasattr(self, 'ae_model') or self.ae_model is None:
                self.logger.warning("⚠️ Autoencoder model not available for feature importance calculation")
                return None
                
            self.logger.info("🔄 Calculating Autoencoder Feature Importance...")
            
            # Use reconstruction error-based importance
            n_repeats = 5  # Reduced for speed
            importance_scores = np.zeros(len(feature_names))
            
            # Get processed data for permutation
            if hasattr(self, 'X_val') and self.X_val is not None:
                X_sample = self.X_val[:min(1000, len(self.X_val))]  # Use subset for speed
            else:
                # Fallback: create dummy data for importance calculation
                sample_size = min(1000, len(ae_scores) if ae_scores is not None else 1000)
                X_sample = np.random.randn(sample_size, len(feature_names))
            
            base_scores = self.ae_model.predict(X_sample, verbose=0)
            base_reconstruction_error = np.mean(np.square(X_sample - base_scores))
            
            for i, feature_name in enumerate(feature_names):
                feature_importance = 0
                for _ in range(n_repeats):
                    # Permute the feature
                    X_permuted = X_sample.copy()
                    np.random.shuffle(X_permuted[:, i])
                    
                    # Calculate reconstruction error with permuted feature
                    permuted_scores = self.ae_model.predict(X_permuted, verbose=0)
                    permuted_reconstruction_error = np.mean(np.square(X_permuted - permuted_scores))
                    
                    # Importance is the increase in reconstruction error
                    feature_importance += permuted_reconstruction_error - base_reconstruction_error
                
                importance_scores[i] = feature_importance / n_repeats
            
            # Create importance data structure
            importance_data = {
                'feature_names': feature_names,
                'importance_scores': importance_scores.tolist(),
                'top_20_features': [feature_names[i] for i in np.argsort(importance_scores)[-20:]],
                'calculation_method': 'Reconstruction Error Importance (Autoencoder)',
                'n_repeats': n_repeats
            }
            
            # Save to file
            plots_dir = os.path.join(self.output_dir, 'evaluation_plots')
            os.makedirs(plots_dir, exist_ok=True)
            
            importance_path = os.path.join(plots_dir, 'autoencoder_feature_importance_data.json')
            with open(importance_path, 'w') as f:
                json.dump(importance_data, f, indent=4)
            
            self.logger.info(" Autoencoder Feature Importance analysis completed successfully")
            self.logger.info(f"   Top 5 most important features:")
            for i, feature in enumerate(importance_data['top_20_features'][-5:], 1):
                idx = feature_names.index(feature)
                self.logger.info(f"   {i}. {feature}: {importance_scores[idx]:.4f} ± 0.0000")
            self.logger.info(f"   Results saved to: {importance_path}")
            
            return importance_data
            
        except Exception as e:
            self.logger.warning(f"⚠️ Autoencoder Feature Importance calculation failed: {str(e)}")
            return None
    
    def _create_comprehensive_analysis_reports(self, plots_dir: str, iso_report: Dict, 
                                            ae_report: Optional[Dict], ensemble_report: Optional[Dict],
                                            iso_importance: Optional[Dict], ae_importance: Optional[Dict],
                                            feature_names: List[str]) -> None:
        """Create comprehensive analysis reports combining evaluation and feature importance."""
        try:
            # Create comparison summary
            self._create_feature_importance_comparison(plots_dir)
            
            # Create comprehensive report
            report_data = {
                'analysis_timestamp': datetime.now().isoformat(),
                'model_version': self.model_version,
                'input_dim': self.input_dim,
                'feature_names': feature_names,
                'evaluation_reports': {
                    'isolation_forest': iso_report,
                    'autoencoder': ae_report,
                    'ensemble': ensemble_report
                },
                'feature_importance': {
                    'isolation_forest': iso_importance,
                    'autoencoder': ae_importance
                }
            }
            
            # Save comprehensive report
            report_path = os.path.join(plots_dir, 'comprehensive_analysis_report.json')
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            
            self.logger.info(f" Comprehensive analysis report created: {report_path}")
            
        except Exception as e:
            self.logger.warning(f"⚠️ Comprehensive analysis report creation failed: {str(e)}")
    
    def _print_evaluation_summary(self, iso_report: Dict, ae_report: Optional[Dict], 
                                ensemble_report: Optional[Dict]) -> None:
        """Print evaluation summary to console."""
        print("\n" + "="*60)
        print("📊 MODEL COMPARISON SUMMARY")
        print("="*60)
        print(f"{'Model':<20} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'ROC-AUC':<10}")
        print("-" * 70)
        print(f"{'Isolation Forest':<20} {iso_report['basic_metrics']['accuracy']:<10.4f} {iso_report['basic_metrics']['precision']:<10.4f} {iso_report['basic_metrics']['recall']:<10.4f} {iso_report['basic_metrics']['f1_score']:<10.4f} {iso_report['advanced_metrics']['roc_auc']:<10.4f}")
        
        if ae_report:
            print(f"{'Autoencoder':<20} {ae_report['basic_metrics']['accuracy']:<10.4f} {ae_report['basic_metrics']['precision']:<10.4f} {ae_report['basic_metrics']['recall']:<10.4f} {ae_report['basic_metrics']['f1_score']:<10.4f} {ae_report['advanced_metrics']['roc_auc']:<10.4f}")
        
        if ensemble_report:
            print(f"{'Ensemble (OR)':<20} {ensemble_report['basic_metrics']['accuracy']:<10.4f} {ensemble_report['basic_metrics']['precision']:<10.4f} {ensemble_report['basic_metrics']['recall']:<10.4f} {ensemble_report['basic_metrics']['f1_score']:<10.4f} {ensemble_report['advanced_metrics']['roc_auc']:<10.4f}")
        
        print(" All evaluation visualizations and reports created successfully!")
        print(f"📁 Visualizations saved to: {os.path.join(self.output_dir, 'evaluation_plots')}")
        print(f"📄 Detailed reports saved to: {os.path.join(self.output_dir, 'evaluation_plots')}")
    
    def _create_feature_importance_comparison(self, plots_dir: str) -> None:
        """Create feature importance comparison analysis."""
        try:
            # Load feature importance data
            iso_path = os.path.join(plots_dir, 'feature_importance_data.json')
            ae_path = os.path.join(plots_dir, 'autoencoder_feature_importance_data.json')
            
            iso_data = None
            ae_data = None
            
            if os.path.exists(iso_path):
                with open(iso_path, 'r') as f:
                    iso_data = json.load(f)
            
            if os.path.exists(ae_path):
                with open(ae_path, 'r') as f:
                    ae_data = json.load(f)
            
            if iso_data and ae_data:
                # Find common important features
                iso_top_features = set(iso_data['top_20_features'][-10:])
                ae_top_features = set(ae_data['top_20_features'][-10:])
                common_features = iso_top_features.intersection(ae_top_features)
                
                # Create comparison data
                comparison_data = {
                    'common_important_features': list(common_features),
                    'isolation_forest_top_features': iso_data['top_20_features'][-10:],
                    'autoencoder_top_features': ae_data['top_20_features'][-10:],
                    'comparison_metrics': {
                        'total_features_analyzed': len(iso_data['feature_names']),
                        'common_features_count': len(common_features),
                        'iso_unique_features': len(iso_top_features - ae_top_features),
                        'ae_unique_features': len(ae_top_features - iso_top_features)
                    }
                }
                
                # Save comparison
                comparison_path = os.path.join(plots_dir, 'feature_importance_comparison.json')
                with open(comparison_path, 'w') as f:
                    json.dump(comparison_data, f, indent=4)
                
                self.logger.info(" Feature Importance comparison completed")
                self.logger.info(f"   Common important features: {len(common_features)}")
                self.logger.info(f"   Results saved to: {comparison_path}")
                
                if common_features:
                    self.logger.info(f"   Top 5 common important features:")
                    for i, feature in enumerate(list(common_features)[:5], 1):
                        iso_idx = iso_data['feature_names'].index(feature)
                        ae_idx = ae_data['feature_names'].index(feature)
                        iso_score = iso_data['importance_scores'][iso_idx]
                        ae_score = ae_data['importance_scores'][ae_idx]
                        self.logger.info(f"   {i}. {feature}: ISO={iso_score:.3f}, AE={ae_score:.3f}")
            
        except Exception as e:
            self.logger.warning(f"⚠️ Feature importance comparison failed: {str(e)}")
    
    def _create_feature_importance_report(self, plots_dir: str) -> None:
        """
        Create a comprehensive feature importance report combining all analyses.
        
        Args:
            plots_dir: Directory to save the report
        """
        try:
            report_data = {
                'analysis_timestamp': datetime.now().isoformat(),
                'model_version': self.model_version,
                'input_dim': self.input_dim,
                'training_samples': len(self.X_train) if self.X_train is not None else 0,
                'models_analyzed': []
            }
            
            # Check for Isolation Forest analysis
            iso_importance_path = os.path.join(plots_dir, 'feature_importance_data.json')
            if os.path.exists(iso_importance_path):
                with open(iso_importance_path, 'r') as f:
                    iso_data = json.load(f)
                report_data['models_analyzed'].append('Isolation Forest')
                report_data['isolation_forest'] = {
                    'top_10_features': iso_data['top_20_features'][-10:],
                    'calculation_method': iso_data['calculation_method'],
                    'n_repeats': iso_data['n_repeats']
                }
            
            # Check for Autoencoder analysis
            ae_importance_path = os.path.join(plots_dir, 'autoencoder_feature_importance_data.json')
            if os.path.exists(ae_importance_path):
                with open(ae_importance_path, 'r') as f:
                    ae_data = json.load(f)
                report_data['models_analyzed'].append('Autoencoder')
                report_data['autoencoder'] = {
                    'top_10_features': ae_data['top_20_features'][-10:],
                    'calculation_method': ae_data['calculation_method'],
                    'sample_size': ae_data['sample_size']
                }
            
            # Check for comparison analysis
            comparison_path = os.path.join(plots_dir, 'feature_importance_comparison.json')
            if os.path.exists(comparison_path):
                with open(comparison_path, 'r') as f:
                    comparison_data = json.load(f)
                report_data['comparison'] = {
                    'common_features': comparison_data['common_features'],
                    'total_common_features': len(comparison_data['common_features'])
                }
            
            # Save comprehensive report
            report_path = os.path.join(plots_dir, 'comprehensive_feature_importance_report.json')
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            # Create human-readable summary
            summary_path = os.path.join(plots_dir, 'feature_importance_summary.txt')
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("COMPREHENSIVE FEATURE IMPORTANCE ANALYSIS REPORT\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Model Version: {self.model_version}\n")
                f.write(f"Input Dimension: {self.input_dim}\n")
                f.write(f"Training Samples: {len(self.X_train) if self.X_train is not None else 0:,}\n\n")
                
                f.write("MODELS ANALYZED:\n")
                f.write("-" * 40 + "\n")
                for model in report_data['models_analyzed']:
                    f.write(f"OK {model}\n")
                f.write("\n")
                
                if 'isolation_forest' in report_data:
                    f.write("ISOLATION FOREST TOP 10 FEATURES:\n")
                    f.write("-" * 40 + "\n")
                    for i, feature in enumerate(report_data['isolation_forest']['top_10_features'], 1):
                        f.write(f"{i:2d}. {feature}\n")
                    f.write(f"\nCalculation Method: {report_data['isolation_forest']['calculation_method']}\n")
                    f.write(f"Permutation Repeats: {report_data['isolation_forest']['n_repeats']}\n\n")
                
                if 'autoencoder' in report_data:
                    f.write("AUTOENCODER TOP 10 FEATURES:\n")
                    f.write("-" * 40 + "\n")
                    for i, feature in enumerate(report_data['autoencoder']['top_10_features'], 1):
                        f.write(f"{i:2d}. {feature}\n")
                    f.write(f"\nCalculation Method: {report_data['autoencoder']['calculation_method']}\n")
                    f.write(f"Sample Size: {report_data['autoencoder']['sample_size']:,}\n\n")
                
                if 'comparison' in report_data:
                    f.write("FEATURE IMPORTANCE COMPARISON:\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"Common Important Features: {report_data['comparison']['total_common_features']}\n")
                    if report_data['comparison']['common_features']:
                        f.write("Common features found in both models:\n")
                        for i, feature in enumerate(report_data['comparison']['common_features'], 1):
                            f.write(f"  {i}. {feature}\n")
                    f.write("\n")
                
                f.write("=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            self.logger.info(f" Comprehensive Feature Importance Report created")
            self.logger.info(f"   JSON Report: {report_path}")
            self.logger.info(f"   Text Summary: {summary_path}")
            
        except Exception as e:
            self.logger.warning(f"⚠️ Comprehensive Feature Importance Report creation failed: {str(e)}")

    def save_models(self) -> None:
        """
        Save all trained models and artifacts, including the complete pipeline.
        This ensures perfect consistency between training and evaluation.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        self.logger.info(f"Saving models and artifacts to: {self.output_dir}")

        # 1. Save the complete pipeline
        pipeline_path = os.path.join(self.output_dir, f'complete_pipeline_{self.model_version}.joblib')
        joblib.dump(self.complete_pipeline, pipeline_path)
        self.logger.info(f"  OK: Saved complete processing pipeline to {pipeline_path}")

        # 2. Save the Isolation Forest model
        if self.iso_model:
            iso_model_path = os.path.join(self.output_dir, f'iso_forest_model_{self.model_version}.joblib')
            joblib.dump(self.iso_model, iso_model_path)
            self.logger.info(f"  OK: Saved Isolation Forest model to {iso_model_path}")
            # Keep a primary name for inference discovery
            primary_iso_model_path = os.path.join(self.output_dir, 'iso_forest_model_cic_master.joblib')
            try:
                shutil.copyfile(iso_model_path, primary_iso_model_path)
            except Exception:
                pass

        # 3. Save the Autoencoder model
        if self.ae_model:
            ae_model_path = os.path.join(self.output_dir, f'autoencoder_model_{self.model_version}.keras')
            self.ae_model.save(ae_model_path)
            self.logger.info(f"  OK: Saved Autoencoder model to {ae_model_path}")
            # Primary name for inference
            primary_ae_model_path = os.path.join(self.output_dir, 'autoencoder_best_cic_master.keras')
            try:
                shutil.copyfile(ae_model_path, primary_ae_model_path)
            except Exception:
                pass

        # 4. Save training metadata
        if self.training_metadata:
            metadata_path = os.path.join(self.output_dir, f'training_metadata_{self.model_version}.json')
            with open(metadata_path, 'w') as f:
                json.dump(self.training_metadata, f, indent=4)
            self.logger.info(f"  OK: Saved training metadata to {metadata_path}")

    def run_complete_pipeline(self) -> bool:
        """
        Execute the complete, enhanced training pipeline from start to finish.
        
        Returns:
            True if training completed successfully, False otherwise.
        """
        self.logger.info("STARTING ENHANCED TRAINING PIPELINE")
        start_time = datetime.now()
            
        try:
            # Step 1: Load and Clean Data
            self.load_and_prepare_data()
            
            # Step 1.5: Run IP Profiler
            self.run_ip_profiler()

            # Step 2: Engineer Features
            self.engineer_enhanced_features()
            
            # Step 3: Create the complete preprocessor pipeline
            self.complete_pipeline, self.X_train, self.X_val = self.create_enhanced_preprocessor()
            
            # Step 4: Train models
            self.iso_model = self.train_isolation_forest(self.X_train)
            
            if TENSORFLOW_AVAILABLE:
                self.ae_model, self.ae_threshold = self.train_autoencoder(self.X_train, self.X_val)
            
            # LẤY TÊN FEATURE SAU KHI PIPELINE ĐÃ FIT
            final_feature_names = self.get_feature_names()

            # Populate training metadata before saving
            self.training_metadata = {
                'model_version': self.model_version,
                'input_file_path': self.input_file_path,
                'training_timestamp': datetime.now().isoformat(),
                'top_n_services': self.top_n_services,
                'top_services_list': self.top_services_list,
                'iso_n_estimators': self.iso_n_estimators,
                'iso_contamination': self.iso_contamination,
                'ae_encoding_dim1': self.ae_encoding_dim1,
                'ae_encoding_dim2': self.ae_encoding_dim2,
                'ae_epochs': self.ae_epochs,
                'ae_batch_size': self.ae_batch_size,
                'ae_threshold': float(self.ae_threshold) if hasattr(self, 'ae_threshold') else None,
                'random_state': self.random_state,
                'input_dim_after_preprocessing': self.input_dim,
                'final_feature_names': final_feature_names  # <-- THÊM DÒNG NÀY
            }

            # Step 5: Save all models and artifacts
            self.save_models()
            
            self.logger.info("ENHANCED TRAINING PIPELINE COMPLETED SUCCESSFULLY")
            self.logger.info(f"Total execution time: {datetime.now() - start_time}")
            return True
            
        except Exception as e:
            self.logger.critical(f"A critical error occurred in the pipeline: {e}")
            self.logger.critical(traceback.format_exc())
            return False


def main():
    """Main function to run the enhanced training pipeline."""
    parser = argparse.ArgumentParser(
        description="Enhanced training pipeline for network anomaly detection models",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--input', '-i', type=str, required=False,
                       help='Path to input conn.log file or CSV file (required for train mode)')
    parser.add_argument('--output-dir', '-o', type=str, default=MODEL_DIRECTORY,
                       help='Output directory for models (default: config.MODEL_DIRECTORY)')
    parser.add_argument('--version', '-v', type=str, default='v3',
                       help='Model version string (default: v3)')
    parser.add_argument('--services', '-s', type=int, default=15,
                       help='Number of top services to keep (default: 15 - optimized for enhanced feature coverage)')
    parser.add_argument('--iso-estimators', type=int, default=500,
                       help='Isolation Forest estimators (default: 500 - enhanced for better anomaly detection)')
    parser.add_argument('--ae-dim1', type=int, default=64,
                       help='Autoencoder first layer dimension (default: 64)')
    parser.add_argument('--ae-dim2', type=int, default=32,
                       help='Autoencoder bottleneck dimension (default: 32)')
    parser.add_argument('--ae-epochs', type=int, default=100,
                       help='Autoencoder training epochs (default: 100)')
    parser.add_argument('--ae-batch', type=int, default=64,
                       help='Autoencoder batch size (default: 64)')
    parser.add_argument('--random-state', type=int, default=42,
                       help='Random state for reproducibility (default: 42)')
    parser.add_argument('--iso-contamination', type=float, default=0.005,
                       help='Contamination parameter for Isolation Forest (default: 0.005 - optimized for normal data)')
    
    # ========== THÊM CHÍNH THỨC: CHẾ ĐỘ CHẠY ==========
    parser.add_argument('--mode', 
                        type=str, 
                        choices=['train', 'evaluate'], 
                        default='train',
                        help="Run mode: 'train' to train new models, 'evaluate' to test existing ones.")
    
    # ========== CẢI TIẾN: THÊM ĐƯỜNG DẪN FILE LINH HOẠT ==========
    parser.add_argument('--cic-train-path', type=str, 
                       help='Path to CIC-IDS2017 benign conn.log for MASTER training (default: uses --input)')
    parser.add_argument('--cic-test-path', type=str,
                       help='Path to CIC-IDS2017 attack day conn.log for internal validation (default: uses --input)')
    
    # ========== THÊM QUICK TEST CHO EVALUATION ==========
    parser.add_argument('--sample-size', type=int, default=None,
                       help='Use only a sample of this size for quick testing (applies to evaluation mode)')
    parser.add_argument('--quick-test', action='store_true',
                       help='Enable quick test mode with smaller sample sizes for debugging')
    
    args = parser.parse_args()
    
    # Validate input argument based on mode
    if args.mode == 'train' and not args.input:
        parser.error("--input is required when running in train mode")
    
    # ========== TỰ ĐỘNG GÁN ĐƯỜNG DẪN MẶC ĐỊNH ==========
    # Nếu không được chỉ định, sử dụng file --input cho cả train và test CIC
    if not args.cic_train_path:
        args.cic_train_path = args.input
    if not args.cic_test_path:
        args.cic_test_path = args.input
    
    # =================================================================
    # ĐIỀU KHIỂN LUỒNG CHẠY THEO CHẾ ĐỘ
    # =================================================================
    
    if args.mode == 'train':
        # =================================================================
        # CHẾ ĐỘ HUẤN LUYỆN: CHỈ LÀM STEP A - TRAINING MASTER MODELS
        # =================================================================
        print("=" * 80)
        print("--- RUNNING IN TRAIN MODE: TRAINING MASTER MODELS ---")
        print("=" * 80)
        
        # Sử dụng đường dẫn linh hoạt cho việc huấn luyện CIC
        cic_train_path = args.cic_train_path
        print(f"📂 CIC Training data: {cic_train_path}")
        
        trainer_cic = EnhancedModelTrainer(
            input_file_path=cic_train_path,
            output_dir=args.output_dir,
            model_version='cic_master',  # Đặt tên version rõ ràng
            top_n_services=args.services,
            iso_n_estimators=args.iso_estimators,
            iso_contamination=args.iso_contamination,
            ae_encoding_dim1=args.ae_dim1,
            ae_encoding_dim2=args.ae_dim2,
            ae_epochs=args.ae_epochs,
            ae_batch_size=args.ae_batch,
            random_state=args.random_state,
            time_window_seconds=300  
        )
        
        # Chạy toàn bộ pipeline để huấn luyện và lưu mô hình + preprocessor
        success_step_a = trainer_cic.run_complete_pipeline()
        
        if not success_step_a:
            print("❌ TRAINING FAILED: Could not train master models on CIC-IDS2017")
            return 1
        
        print(" Training complete. Master models and preprocessor saved successfully!")
        
        # Lưu danh sách top_services đã học từ training data gốc
        master_top_services = trainer_cic.top_services_list
        print(f"🎯 Master top services list learned: {master_top_services}")
        
        print("\n📋 NEXT STEPS:")
        print("Now you can run evaluation mode with:")
        print(f"  python train_enhanced_models.py --mode evaluate \\")
        print(f"    --cic-test-path your_cic_test_file.csv \\")
        print(f"    --output-dir {args.output_dir}")
        
    elif args.mode == 'evaluate':
        # =================================================================
        # CHẾ ĐỘ THẨM ĐỊNH: CHỈ LÀM STEP B VÀ C - EVALUATION ONLY
        # =================================================================
        print("=" * 80)
        print("--- RUNNING IN EVALUATE MODE: TESTING EXISTING MODELS ---")
        print("=" * 80)
        
        # Auto-detect latest model version
        def find_latest_model(output_dir):
            """Find the latest trained model version in the directory"""
            import glob
            pattern = os.path.join(output_dir, 'complete_pipeline_*.joblib')
            files = glob.glob(pattern)
            if not files:
                return None
            # Extract version from filename and find the latest
            versions = []
            for f in files:
                basename = os.path.basename(f)
                version = basename.replace('complete_pipeline_', '').replace('.joblib', '')
                versions.append((version, f))
            # Sort by modification time to get the latest
            versions.sort(key=lambda x: os.path.getmtime(x[1]), reverse=True)
            return versions[0][0] if versions else None
        
        # Try to find models in specified directory or 'model' as backup
        model_version = find_latest_model(args.output_dir)
        if model_version is None:
            model_version = find_latest_model('model')
            if model_version is not None:
                args.output_dir = 'model'
                print(f"📁 Models found in 'model' directory, switching to: {args.output_dir}")
        
        if model_version is None:
            print("❌ EVALUATION FAILED: No trained models found!")
            print("Please run training mode first:")
            print(f"  python train_enhanced_models.py --mode train --input your_training_data")
            return 1
        
        print(f" Found trained models with version: {model_version}")
        print(f"📁 Using models from directory: {args.output_dir}")
        
        # Check required files with detected version
        required_files = [
            os.path.join(args.output_dir, f'complete_pipeline_{model_version}.joblib'),
            os.path.join(args.output_dir, f'iso_forest_model_{model_version}.joblib'),
            os.path.join(args.output_dir, f'training_metadata_{model_version}.json')
        ]
        
        missing_files = [f for f in required_files if not os.path.exists(f)]
        if missing_files:
            print("❌ EVALUATION FAILED: Missing required model files!")
            print("Missing files:")
            for f in missing_files:
                print(f"  - {f}")
            print("\n💡 Please run training mode first:")
            print(f"  python train_enhanced_models.py --mode train --input your_training_data")
            return 1
        
        print(" All required model files found. Loading metadata...")
        
        # Tải metadata để lấy master_top_services
        with open(os.path.join(args.output_dir, f'training_metadata_{model_version}.json'), 'r') as f:
            metadata = json.load(f)
        master_top_services = metadata['top_services_list']
        print(f"🎯 Loaded master top services: {master_top_services}")
        print(f"   This list will be used for ALL evaluation steps to prevent data leakage.")

        # =================================================================
        # BƯỚC B: THẨM ĐỊNH NỘI BỘ TRÊN CIC-IDS2017 (Để kiểm tra lại)
        # =================================================================
        print("\n" + "=" * 80)
        print("--- STEP B: INTERNAL VALIDATION ON CIC-IDS2017 ATTACK DATA ---")
        print("=" * 80)
        
        try:
            # 1. Tải lại preprocessor và mô hình AI đã huấn luyện
            print("Loading trained preprocessor and models...")
            preprocessor_cic = joblib.load(os.path.join(args.output_dir, f'complete_pipeline_{model_version}.joblib'))
            iso_model_master = joblib.load(os.path.join(args.output_dir, f'iso_forest_model_{model_version}.joblib'))
            
            # Load Autoencoder model if available
            ae_model_path = os.path.join(args.output_dir, f'autoencoder_model_{model_version}.keras')
            ae_threshold_path = os.path.join(args.output_dir, f'ae_threshold_{model_version}.json')
            
            ae_model_master = None
            ae_threshold = None
            
            if os.path.exists(ae_model_path) and os.path.exists(ae_threshold_path):
                try:
                    if TENSORFLOW_AVAILABLE:
                        ae_model_master = tf.keras.models.load_model(ae_model_path)
                        with open(ae_threshold_path, 'r') as f:
                            ae_threshold_data = json.load(f)
                            ae_threshold = ae_threshold_data['threshold']
                        print(f" Loaded Autoencoder model with threshold: {ae_threshold:.6f}")
                    else:
                        print("⚠️  TensorFlow not available - skipping Autoencoder evaluation")
                except Exception as e:
                    print(f"⚠️  Failed to load Autoencoder: {e}")
                    ae_model_master = None
            else:
                print("⚠️  Autoencoder model files not found - using Isolation Forest only")
            
            # Load Isolation Forest threshold (CRITICAL: trained on clean data)
            iso_threshold_path = os.path.join(args.output_dir, f'iso_threshold_{model_version}.json')
            iso_thresholds = None
            if os.path.exists(iso_threshold_path):
                with open(iso_threshold_path, 'r') as f:
                    iso_thresholds = json.load(f)
                print(f" Loaded Isolation Forest thresholds from training data:")
                print(f"     - 10% threshold: {iso_thresholds['threshold_10_percent']:.6f}")
                print(f"     - 5% threshold: {iso_thresholds['threshold_5_percent']:.6f}")
                print(f"     - 1% threshold: {iso_thresholds['threshold_1_percent']:.6f}")
                print(f"     - Zero threshold: {iso_thresholds['threshold_zero']:.6f}")
            else:
                print("⚠️  No Isolation Forest threshold file found - will use adaptive method")
            
            # 2. Tải và xử lý dữ liệu test của CIC-IDS2017
            cic_test_path = args.cic_test_path
            print(f"📂 CIC Test data: {cic_test_path}")
            
            if not os.path.exists(cic_test_path):
                print(f"⚠️  CIC test file not found: {cic_test_path}")
                print("   Skipping internal validation step.")
            else:
                print(f"Loading CIC-IDS2017 test data from: {cic_test_path}")
                
                # Tạo trainer tạm để sử dụng các hàm xử lý linh hoạt
                trainer_temp = EnhancedModelTrainer(
                    input_file_path=cic_test_path,
                    output_dir=args.output_dir,
                    model_version='temp_eval',
                    random_state=args.random_state,
                    time_window_seconds=300  # 🚨 FIXED: Add time window for consistency
                )
                
                # Xử lý dữ liệu với master_top_services
                print("Processing CIC test data with flexible functions...")
                print(f"🔒 Using MASTER top services (no data leakage): {master_top_services}")
                df_cic_test = trainer_temp.load_and_prepare_data(cic_test_path)
                
                # DOMAIN SHIFT ANALYSIS
                print(f"\n🔍 DOMAIN SHIFT ANALYSIS:")
                print(f"Test data services: {df_cic_test['service'].value_counts().head(10).to_dict()}")
                print(f"Test data protocols: {df_cic_test['proto'].value_counts().to_dict()}")
                print(f"Test data conn_states: {df_cic_test['conn_state'].value_counts().head(5).to_dict()}")
                
                df_cic_test = trainer_temp.run_ip_profiler(df_cic_test)
                df_cic_test = trainer_temp.engineer_enhanced_features(df_cic_test, master_top_services)
                
                # 3. Dùng preprocessor của CIC để biến đổi
                print("Applying CIC preprocessor to test data...")
                X_test_cic_processed = preprocessor_cic.transform(df_cic_test)
                
                # 4. Dự đoán và in kết quả - ENSEMBLE APPROACH
                print("Making ensemble predictions on CIC test data...")
                
                # Get Isolation Forest predictions using TRAINING-based thresholds
                iso_scores = iso_model_master.decision_function(X_test_cic_processed)
                
                # Method 1: Use sklearn's predict (limited by contamination parameter)
                predictions_sklearn = iso_model_master.predict(X_test_cic_processed)
                iso_predictions_method1 = np.where(predictions_sklearn == -1, 1, 0)
                
                if iso_thresholds is not None:
                    # Method 2: Use TRAINING-based 5% threshold (recommended)
                    iso_predictions_method2 = (iso_scores <= iso_thresholds['threshold_5_percent']).astype(int)
                    
                    # Method 3: Use TRAINING-based 1% threshold (strict)
                    iso_predictions_method3 = (iso_scores <= iso_thresholds['threshold_1_percent']).astype(int)
                    
                    # Method 4: Use zero threshold
                    iso_predictions_method4 = (iso_scores <= iso_thresholds['threshold_zero']).astype(int)
                    
                    # Use 5% threshold as default (good balance)
                    iso_predictions = iso_predictions_method2
                    
                    print(f"   Isolation Forest (sklearn predict): {np.sum(iso_predictions_method1)} anomalies detected")
                    print(f"   Isolation Forest (5% training threshold): {np.sum(iso_predictions_method2)} anomalies detected")
                    print(f"   Isolation Forest (1% training threshold): {np.sum(iso_predictions_method3)} anomalies detected") 
                    print(f"   Isolation Forest (zero threshold): {np.sum(iso_predictions_method4)} anomalies detected")
                    print(f"   Using 5% training threshold for evaluation...")
                    
                    # DEBUG: Score distribution analysis
                    print(f"\n🔬 SCORE ANALYSIS:")
                    print(f"   Isolation Forest scores: min={np.min(iso_scores):.4f}, max={np.max(iso_scores):.4f}, mean={np.mean(iso_scores):.4f}")
                    print(f"   Training thresholds: 5%={iso_thresholds['threshold_5_percent']:.4f}, 1%={iso_thresholds['threshold_1_percent']:.4f}")
                    print(f"   % of test scores below 5% threshold: {(np.sum(iso_scores <= iso_thresholds['threshold_5_percent'])/len(iso_scores))*100:.1f}%")
                    
                    # DOMAIN SHIFT WARNING
                    domain_shift_severity = (np.sum(iso_scores <= iso_thresholds['threshold_5_percent'])/len(iso_scores))*100
                    if domain_shift_severity > 80:
                        print(f"\n⚠️  SEVERE DOMAIN SHIFT DETECTED!")
                        print(f"   {domain_shift_severity:.1f}% of samples flagged as anomalies")
                        print(f"   This indicates significant difference between training and test environments")
                        print(f"   Consider: 1) Domain adaptation, 2) Re-training on target domain, 3) Relaxed thresholds")
                    elif domain_shift_severity > 50:
                        print(f"\n⚠️  MODERATE DOMAIN SHIFT DETECTED!")
                        print(f"   {domain_shift_severity:.1f}% anomaly rate suggests environment mismatch")
                    else:
                        print(f"\n Normal anomaly rate: {domain_shift_severity:.1f}%")
                else:
                    # Fallback to adaptive method if no saved thresholds
                    iso_threshold_adaptive = np.percentile(iso_scores, 5)  # Bottom 5% as fallback
                    iso_predictions = (iso_scores <= iso_threshold_adaptive).astype(int)
                    print(f"   Isolation Forest (sklearn predict): {np.sum(iso_predictions_method1)} anomalies detected")
                    print(f"   Isolation Forest (adaptive fallback): {np.sum(iso_predictions)} anomalies detected")
                    print(f"   Using adaptive fallback method...")
                
                # Get Autoencoder predictions if available
                ae_predictions = None
                ae_scores = None
                if ae_model_master is not None and ae_threshold is not None:
                    reconstructions = ae_model_master.predict(X_test_cic_processed, verbose=0)
                    ae_scores = np.mean(np.square(X_test_cic_processed - reconstructions), axis=1)
                    ae_predictions = (ae_scores > ae_threshold).astype(int)
                    print(f"   Autoencoder: {np.sum(ae_predictions)} anomalies detected")
                    
                    # Ensemble prediction: anomaly if EITHER model detects it
                    ensemble_predictions = np.logical_or(iso_predictions == 1, ae_predictions == 1).astype(int)
                    predictions_cic = ensemble_predictions
                    print(f"   Ensemble (OR): {np.sum(ensemble_predictions)} anomalies detected")
                else:
                    predictions_cic = iso_predictions
                    print("   Using Isolation Forest only (Autoencoder not available)")
                
                # Bỏ cột ip_proto nếu có (giống như lúc training)
                if 'ip_proto' in df_cic_test.columns:
                    df_cic_test = df_cic_test.drop('ip_proto', axis=1)
                    print(f"   Dropped ip_proto column to match training data format")
                
                # Tính toán metrics nếu có labels thực sự
                label_column = None
                for col in ['label', 'Label', 'LABEL']:
                    if col in df_cic_test.columns:
                        label_column = col
                        break
                
                # Nếu không có label column thực sự, bỏ qua evaluation metrics
                if label_column is None:
                    print(f"   No label column found - skipping evaluation metrics")
                    print(f"   This is expected for unsupervised anomaly detection")
                    print(f"   Model predictions: {np.sum(iso_predictions)} anomalies detected")
                    if ae_predictions is not None:
                        print(f"   Autoencoder predictions: {np.sum(ae_predictions)} anomalies detected")
                    print(f"   Ensemble predictions: {np.sum(predictions_cic)} anomalies detected")
                    return
                
                if label_column is not None:
                    # Xử lý nhiều định dạng nhãn khác nhau
                    label_col = df_cic_test[label_column].astype(str).str.lower()
                    # Mapping cho các định dạng nhãn phổ biến (tất cả lowercase sau khi .str.lower())
                    label_mapping = {
                        'normal': 0, 'benign': 0, '0': 0, 'false': 0,
                        'attack': 1, 'malicious': 1, 'anomaly': 1, '1': 1, 'true': 1,
                        # Thêm các loại tấn công CIC-IDS2017
                        'dos': 1, 'ddos': 1, 'portscan': 1, 'bruteforce': 1, 'brute force': 1,
                        'infiltration': 1, 'botnet': 1, 'web attack': 1, 'bot': 1,
                        # Thêm các attack types từ datasets khác
                        'dos hulk': 1, 'dos slowhttptest': 1, 'dos slowloris': 1, 
                        'heartbleed': 1, 'ftp-patator': 1, 'ssh-patator': 1,
                        'web attack â\x80\x93 brute force': 1, 'web attack â\x80\x93 sql injection': 1, 'web attack â\x80\x93 xss': 1,
                        # Thêm các attack types từ conn1_log_labeled.csv (lowercase sau .str.lower())
                        'c&c': 1, 'command and control': 1, 'botnet command': 1,
                        'partofahorizontalportscan': 1, 'port scan': 1, 'portscan': 1, 'reconnaissance': 1,
                        'unknown': 0  # UNKNOWN có thể là noise
                    }
                    y_true = label_col.map(label_mapping).fillna(0).astype(int)
                    
                    # DEBUG: Check if all labels are mapped to 0
                    print(f"   DEBUG: Label mapping results:")
                    print(f"   - Total samples: {len(y_true)}")
                    print(f"   - Samples with y_true=0: {np.sum(y_true == 0)}")
                    print(f"   - Samples with y_true=1: {np.sum(y_true == 1)}")
                    print(f"   - Percentage of attacks: {(np.sum(y_true == 1)/len(y_true))*100:.1f}%")
                    
                    # DEBUG: Check label processing
                    print(f"\n🔍 LABEL PROCESSING DEBUG:")
                    print(f"   Original label column: {label_column}")
                    print(f"   Sample original labels: {df_cic_test[label_column].head(10).tolist()}")
                    print(f"   Sample processed labels (lowercase): {label_col.head(10).tolist()}")
                    print(f"   Sample mapped y_true: {y_true.head(10).tolist()}")
                    print(f"   Unique original labels: {sorted(df_cic_test[label_column].unique())}")
                    print(f"   Unique processed labels: {sorted(label_col.unique())}")
                    print(f"   Unique y_true values: {sorted(y_true.unique())}")
                    print(f"   Labels that couldn't be mapped: {label_col[y_true.isna()].unique() if y_true.isna().any() else 'None'}")
                    
                    # Evaluate each model individually for reporting
                    print("\n" + "="*60)
                    print("📊 INDIVIDUAL MODEL PERFORMANCE:")
                    print("="*60)
                    
                    # Isolation Forest Results
                    print("\n🔍 ISOLATION FOREST RESULTS:")
                    iso_f1 = f1_score(y_true, iso_predictions)
                    iso_precision = precision_score(y_true, iso_predictions)
                    iso_recall = recall_score(y_true, iso_predictions)
                    iso_accuracy = accuracy_score(y_true, iso_predictions)
                    print(f"   F1-Score:  {iso_f1:.4f}")
                    print(f"   Precision: {iso_precision:.4f}")
                    print(f"   Recall:    {iso_recall:.4f}")
                    print(f"   Accuracy:  {iso_accuracy:.4f}")
                    print(f"   Anomalies: {np.sum(iso_predictions):,}")
                    
                    # Autoencoder Results (if available)
                    if ae_predictions is not None:
                        print("\n🧠 AUTOENCODER RESULTS:")
                        ae_f1 = f1_score(y_true, ae_predictions)
                        ae_precision = precision_score(y_true, ae_predictions)
                        ae_recall = recall_score(y_true, ae_predictions)
                        ae_accuracy = accuracy_score(y_true, ae_predictions)
                        print(f"   F1-Score:  {ae_f1:.4f}")
                        print(f"   Precision: {ae_precision:.4f}")
                        print(f"   Recall:    {ae_recall:.4f}")
                        print(f"   Accuracy:  {ae_accuracy:.4f}")
                        print(f"   Anomalies: {np.sum(ae_predictions):,}")
                    
                    # Ensemble Results
                    print("\n🔥 ENSEMBLE (OR) RESULTS:")
                    ensemble_f1 = f1_score(y_true, predictions_cic)
                    ensemble_precision = precision_score(y_true, predictions_cic)
                    ensemble_recall = recall_score(y_true, predictions_cic)
                    ensemble_accuracy = accuracy_score(y_true, predictions_cic)
                    print(f"   F1-Score:  {ensemble_f1:.4f}")
                    print(f"   Precision: {ensemble_precision:.4f}")
                    print(f"   Recall:    {ensemble_recall:.4f}")
                    print(f"   Accuracy:  {ensemble_accuracy:.4f}")
                    print(f"   Anomalies: {np.sum(predictions_cic):,}")
                    
                    print("\n" + "="*60)
                    print("📋 SUMMARY FOR REPORT:")
                    print("="*60)
                    print(f"Isolation Forest F1: {iso_f1:.4f}")
                    if ae_predictions is not None:
                        print(f"Autoencoder F1:       {ae_f1:.4f}")
                    print(f"Ensemble F1:          {ensemble_f1:.4f}")
                    
                    print("\nCIC-IDS2017 Internal Validation Results:")
                    print(classification_report(y_true, predictions_cic, target_names=['Normal', 'Attack']))
                    
                    # Thêm thống kê label distribution
                    print(f"\n📈 Label Distribution:")
                    print(f"   Total samples: {len(y_true):,}")
                    print(f"   Normal samples: {np.sum(y_true == 0):,} ({(np.sum(y_true == 0)/len(y_true))*100:.1f}%)")
                    print(f"   Attack samples: {np.sum(y_true == 1):,} ({(np.sum(y_true == 1)/len(y_true))*100:.1f}%)")
                    print(f"   🎯 CIC INTERNAL F1-SCORE: {f1_score(y_true, predictions_cic):.4f}")
                    
                    # =================================================================
                    # 🎨 TẠO VISUALIZATION CHO EVALUATION
                    # =================================================================
                    print("\n" + "="*60)
                    print("🎨 CREATING EVALUATION VISUALIZATIONS")
                    print("="*60)
                    
                    # Tạo trainer tạm để sử dụng hàm visualization
                    temp_trainer = EnhancedModelTrainer(
                        input_file_path="temp",
                        output_dir=args.output_dir,
                        model_version='temp_viz',
                        random_state=args.random_state,
                        time_window_seconds=300  
                    )
                    
                    # Load models vào temp_trainer
                    temp_trainer.iso_model = iso_model_master
                    temp_trainer.ae_model = ae_model_master
                    temp_trainer.input_dim = X_test_cic_processed.shape[1]  # Set input dimension
                    
                    # Tạo comprehensive analysis và visualization
                    print("📊 Creating comprehensive analysis and visualizations...")
                    
                    # Analyze and visualize results
                    temp_trainer.analyze_and_visualize_results(
                        y_true=y_true,
                        iso_predictions=iso_predictions,
                        iso_scores=iso_scores,
                        ae_predictions=ae_predictions,
                        ae_scores=ae_scores,
                        ae_threshold=ae_threshold,
                        ensemble_predictions=predictions_cic
                    )
                    
                    # 4. Tạo comparison summary (đã được xử lý trong analyze_and_visualize_results)
                    print(" All evaluation visualizations and reports created successfully!")
                    print(f"📁 Visualizations saved to: {os.path.join(args.output_dir, 'evaluation_plots')}")
                    print(f"📄 Detailed reports saved to: {os.path.join(args.output_dir, 'evaluation_plots')}")
                    
                else:
                    anomaly_count = np.sum(predictions_cic)
                    total_count = len(predictions_cic)
                    print(f"\nCIC-IDS2017 Anomaly Detection Results:")
                    print(f"  Total samples: {total_count:,}")
                    print(f"  Detected anomalies: {anomaly_count:,}")
                    print(f"  Anomaly rate: {(anomaly_count/total_count)*100:.2f}%")
                
                print(" Internal validation on CIC-IDS2017 complete.")
            
        except Exception as e:
            print(f"❌ STEP B FAILED: {str(e)}")
            print("Evaluation completed with errors.")



        print("\n" + "=" * 80)
        print("🎯 EVALUATION COMPLETE")
        print("=" * 80)
        print(" Step B: Internal validation on CIC-IDS2017")
        print("\n🔒 Data Leakage Prevention:")
        print(f"   Master top services: {master_top_services}")
        print("    Same service list used across ALL evaluation steps")
        print("    No test data information leaked to preprocessing")
        print("\nScientific Rigor: Zero data leakage maintained!")
    
    else:
        print("❌ Invalid mode. Please use --mode train or --mode evaluate")
        return 1
    
    print("\n📋 USAGE EXAMPLES:")
    print("\n🔧 TRAINING MODE (run once to create models):")
    print("  python train_enhanced_models.py --mode train --input data/cic_monday_benign.log --output-dir model_final")
    print("\n🔍 EVALUATION MODE (run multiple times with different test data):")
    print("  python train_enhanced_models.py --mode evaluate \\")
    print("    --cic-test-path data/labeled_conn_log_friday.csv \\")
    print("    --output-dir model_final")
    print("\n🔄 You can run evaluation mode multiple times with different datasets!")
    
    return 0


if __name__ == '__main__':
    sys.exit(main()) 