"""
Machine Learning handler module for network anomaly detection system.
Contains the MLHandler class for loading and running ML models.
"""

import pandas as pd
import numpy as np
import joblib
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

from config import (
    CONN_LOG_COLUMNS,
    PRODUCTION_THRESHOLDS,
    AUTOENCODER_THRESHOLD_FILE,
    DNS_MODEL_DIRECTORY,
    ISOF_THRESHOLD_POLICY,
    DNS_ISOF_THRESHOLD_POLICY
)
from core.data_processor import ProductionDataProcessor, DNSProductionDataProcessor, log_transform_func
from utils.transformers import GroupFeatureTransformer
from core.ip_profiler import UnifiedIPProfiler
from utils.feature_engineering import engineer_enhanced_features

# Try to import SHAP, note availability
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

# Try to import TensorFlow for Autoencoder
try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

# Set up logging
logger = logging.getLogger(__name__)

# Add debug logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger.setLevel(logging.DEBUG)

# Add file handler for debug logs
debug_handler = logging.FileHandler('debug_ml_handler.log')
debug_handler.setLevel(logging.DEBUG)
debug_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
debug_handler.setFormatter(debug_formatter)
logger.addHandler(debug_handler)


class MLHandler:
    """
    Machine Learning handler for loading and running ML models.
    Handles Isolation Forest, Autoencoder, SHAP explainer, and DNS Tunneling Detection.
    """
    
    def __init__(self, conn_processor=None, dns_processor=None):
        """Initialize the ML handler with models and state.
        
        Args:
            conn_processor: ProductionDataProcessor instance from DetectionEngine (optional)
            dns_processor: DNSProductionDataProcessor instance from DetectionEngine (optional)
        """
        self.preprocessor = None
        self.model = None
        self.model_ae = None
        self.ae_threshold = None
        self.iso_threshold = None  # NEW: Isolation Forest threshold
        self.explainer = None
        self.feature_names = None
        self.training_metadata = None  # NEW: Store training metadata
        self.top_services_list = None  # NEW: Store top services from training
        # Ensure attribute exists before first load; used across methods
        self.complete_pipeline = None
        # NEW: Track presence and configuration of GroupFeatureTransformer from trained pipeline
        self.gft_present = False
        self.gft_params = {}
        # NEW: Runtime fallback GroupFeatureTransformer (used only if pipeline lacks it)
        self.runtime_group_transformer: Optional[GroupFeatureTransformer] = None
        self.runtime_gft_fitted: bool = False
        self.runtime_gft_warmup_rows: int = 0
        self.runtime_gft_min_rows: int = 200
        self.model_status = {
            'preprocessor': False, 
            'isolation_forest': False, 
            'autoencoder': False,
            'dns_models': False
        }
        
        # DNS Tunneling models (new)
        self.dns_isolation_model = None
        self.dns_autoencoder = None
        self.dns_scaler = None
        self.dns_iso_threshold = None  # NEW: DNS Isolation Forest threshold
        self.dns_ae_threshold = None   # NEW: DNS Autoencoder threshold
        self.dns_explainer = None      #  THÊM DNS EXPLAINER
        self.dns_feature_names = []    #  THÊM DNS FEATURE NAMES
        
        self.conn_processor = conn_processor
        
        self.dns_processor = dns_processor
        
        if conn_processor and hasattr(conn_processor, 'ip_profiler'):
            self.training_profiler = conn_processor.ip_profiler
            logging.getLogger(__name__).info("Using shared IP profiler from DetectionEngine")
        else:
            self.training_profiler = UnifiedIPProfiler(time_window_seconds=300)
            logging.getLogger(__name__).warning("No shared IP profiler found - created new instance")
        
    def load_models(self) -> bool:
        """⚡ OPTIMIZED: Load all available ML models including DNS tunneling detection."""
        # Idempotent: if models are already loaded, return True
        if (self.model_status.get('preprocessor') or self.complete_pipeline) and \
           (self.model_status.get('isolation_forest') or self.model) and \
           (self.model_status.get('autoencoder') or self.model_ae) and \
           (self.model_status.get('dns_models') or (self.dns_isolation_model is not None or self.dns_autoencoder is not None)):
            logging.getLogger(__name__).info("Models already loaded; skipping reload")
            return True

        success = False
        
        import threading
        
        success_conn = self._load_connection_models()
        
        # Load DNS tunneling models (new)
        success_dns = self._load_dns_models()
        
        if success_conn or success_dns:
            success = True
            logging.getLogger(__name__).info("ML models loaded successfully")
        else:
            logging.getLogger(__name__).error("No ML models loaded successfully - system will operate with behavioral detection only")
            
        return success
    
    def _load_connection_models(self) -> bool:
        success = False
        
        # Workaround for log_transform_func pickle issue
        import sys
        # Make function available for unpickling from different modules
        try:
            sys.modules['__main__'].log_transform_func = log_transform_func
            # Also make it available in current module context
            globals()['log_transform_func'] = log_transform_func
        except Exception as e:
            logging.getLogger(__name__).warning(f"Could not set up log_transform_func workaround: {e}")
        
        try:
            if self.conn_processor is None:
                logging.getLogger(__name__).info(" Initializing ProductionDataProcessor as toolkit")
                self.conn_processor = ProductionDataProcessor()
            
            success = self._load_all_models_and_inject_to_processor()
            
            if success:
                logging.getLogger(__name__).info(" Connection models loaded successfully by MLHandler")
            else:
                logging.getLogger(__name__).warning(" Connection models failed to load")
            
            return success
            
        except Exception as e:
            logging.getLogger(__name__).error(f" Error loading connection models: {str(e)}")
            return False
    
    def _load_all_models_and_inject_to_processor(self) -> bool:
        """
         NEW: Load all models and inject them into ProductionDataProcessor.
        This method centralizes ALL model loading in MLHandler.
        
        Returns:
            True if at least one model loaded successfully
        """
        try:
            success = False
            
            #  STEP 1: Load pipeline from model directory
            pipeline_loaded = self._load_pipeline()
            
            #  STEP 2: Load training metadata
            metadata_loaded = self._load_training_metadata()
            
            #  STEP 3: Load Isolation Forest model
            iso_loaded = self._load_isolation_forest()
            
            #  STEP 4: Load Autoencoder model
            ae_loaded = self._load_autoencoder()
            
            #  STEP 5: Inject all loaded models into ProductionDataProcessor
            if pipeline_loaded or metadata_loaded or iso_loaded or ae_loaded:
                self._inject_models_to_processor()
                success = True
            
            return success
            
        except Exception as e:
            logging.getLogger(__name__).error(f" Error in model loading orchestration: {str(e)}")
            return False
    
    def _load_pipeline(self) -> bool:
        """ NEW: Load trained pipeline from model directory."""
        try:
            if not self.conn_processor:
                return False
            
            model_dir = self.conn_processor.model_dir
            model_version = self.conn_processor.model_version or 'cic_master'
            
            # Try to find pipeline file
            pipeline_files = [
                f'complete_pipeline_{model_version}.joblib',
                'complete_pipeline_cic_master.joblib'
            ]
            
            for pipeline_file in pipeline_files:
                pipeline_path = os.path.join(model_dir, pipeline_file)
                if os.path.exists(pipeline_path):
                    try:
                        self.complete_pipeline = joblib.load(pipeline_path)
                        logging.getLogger(__name__).info(f"Pipeline loaded from {pipeline_path}")
                        # Skip automatic feature name extraction - use training metadata instead
                        logging.getLogger(__name__).info("Feature names will be loaded from training metadata (skipping pipeline extraction)")
                        try:
                            named_steps = getattr(self.complete_pipeline, 'named_steps', {})
                            if isinstance(named_steps, dict) and 'group_feature_generator' in named_steps:
                                gft = named_steps['group_feature_generator']
                                self.gft_present = True
                                self.gft_params = {
                                    'time_window_seconds': getattr(gft, 'time_window_seconds', None),
                                    'min_samples_for_confirm': getattr(gft, 'min_samples_for_confirm', None)
                                }
                                logging.getLogger(__name__).info(
                                    "GroupFeatureTransformer detected in pipeline: "
                                    f"time_window_seconds={self.gft_params['time_window_seconds']}, "
                                    f"min_samples_for_confirm={self.gft_params['min_samples_for_confirm']}"
                                )
                            else:
                                self.gft_present = False
                                self.gft_params = {}
                                logging.getLogger(__name__).warning("GroupFeatureTransformer not found in trained pipeline; runtime will use pipeline as-is")
                        except Exception as gft_e:
                            logging.getLogger(__name__).warning(f"Unable to introspect GroupFeatureTransformer: {gft_e}")
                        self.model_status['preprocessor'] = True
                        return True
                    except Exception as e:
                        logging.getLogger(__name__).warning(f" Failed to load pipeline from {pipeline_path}: {e}")
                        continue
            
            logging.getLogger(__name__).warning(" No pipeline could be loaded")
            return False
            
        except Exception as e:
            logging.getLogger(__name__).error(f" Error loading pipeline: {e}")
            return False
    
    def _load_training_metadata(self) -> bool:
        """ NEW: Load training metadata from model directory."""
        try:
            if not self.conn_processor:
                return False
            
            model_dir = self.conn_processor.model_dir
            model_version = self.conn_processor.model_version or 'cic_master'
            
            # Try to find metadata file
            metadata_files = [
                f'training_metadata_{model_version}.json',
                'training_metadata_cic_master.json'
            ]
            
            for metadata_file in metadata_files:
                metadata_path = os.path.join(model_dir, metadata_file)
                if os.path.exists(metadata_path):
                    try:
                        import json
                        with open(metadata_path, 'r') as f:
                            self.training_metadata = json.load(f)
                        
                        self.top_services_list = self.training_metadata.get('top_services_list', [])
                        logging.getLogger(__name__).info(f" Training metadata loaded from {metadata_path}")
                        logging.getLogger(__name__).info(f"   Top services: {self.top_services_list}")
                        return True
                    except Exception as e:
                        logging.getLogger(__name__).warning(f" Failed to load metadata from {metadata_path}: {e}")
                        continue
            
            logging.getLogger(__name__).warning(" No training metadata could be loaded")
            self.top_services_list = ['http', 'ssl', 'dns', 'unknown', 'ssh', 'ftp', 'smtp', 'pop3']
            return False
            
        except Exception as e:
            logging.getLogger(__name__).error(f" Error loading training metadata: {e}")
            self.top_services_list = ['http', 'ssl', 'dns', 'unknown', 'ssh', 'ftp', 'smtp', 'pop3']
            return False
    
    def _load_isolation_forest(self) -> bool:
        """ NEW: Load Isolation Forest model from model directory."""
        try:
            if not self.conn_processor:
                return False
            
            model_dir = self.conn_processor.model_dir
            model_version = self.conn_processor.model_version or 'cic_master'
            
            # Try to find Isolation Forest model file
            iso_files = [
                f'iso_forest_model_{model_version}.joblib',
                'iso_forest_model_cic_master.joblib'
            ]
            
            for iso_file in iso_files:
                iso_path = os.path.join(model_dir, iso_file)
                if os.path.exists(iso_path):
                    try:
                        self.model = joblib.load(iso_path)
                        logging.getLogger(__name__).info(f" Isolation Forest loaded from {iso_path}")
                        self.model_status['isolation_forest'] = True
                        
                        # Load threshold
                        self._load_isolation_forest_threshold()
                        
                        # Initialize SHAP explainer
                        if SHAP_AVAILABLE:
                            try:
                                # Try to create SHAP explainer with error handling
                                self.explainer = shap.TreeExplainer(self.model)
                                logging.getLogger(__name__).info(" SHAP explainer initialized")
                            except Exception as e:
                                logging.getLogger(__name__).warning(f" SHAP explainer failed: {e}")
                                logging.getLogger(__name__).info("   SHAP explanations will be disabled - continuing without explainer")
                                self.explainer = None
                        else:
                            self.explainer = None
                        
                        return True
                    except Exception as e:
                        logging.getLogger(__name__).warning(f" Failed to load Isolation Forest from {iso_path}: {e}")
                        continue
            
            logging.getLogger(__name__).warning(" No Isolation Forest model could be loaded")
            return False
            
        except Exception as e:
            logging.getLogger(__name__).error(f" Error loading Isolation Forest: {e}")
            return False
    
    def _load_autoencoder(self) -> bool:
        """ NEW: Load Autoencoder model from model directory."""
        try:
            if not TENSORFLOW_AVAILABLE:
                logging.getLogger(__name__).info("ℹ️ TensorFlow not available - Autoencoder disabled")
                return False
            
            if not self.conn_processor:
                return False
            
            model_dir = self.conn_processor.model_dir
            model_version = self.conn_processor.model_version or 'cic_master'
            
            # Try to find Autoencoder model file
            ae_files = [
                f'autoencoder_best_{model_version}.keras',
                f'autoencoder_model_{model_version}.keras',
                'autoencoder_best_cic_master.keras',
                'autoencoder_model_cic_master.keras'
            ]
            
            for ae_file in ae_files:
                ae_path = os.path.join(model_dir, ae_file)
                if os.path.exists(ae_path):
                    try:
                        import tensorflow as tf
                        self.model_ae = tf.keras.models.load_model(ae_path)
                        logging.getLogger(__name__).info(f" Autoencoder loaded from {ae_path}")
                        self.model_status['autoencoder'] = True
                        
                        # Load threshold from training metadata
                        if self.training_metadata:
                            ae_threshold = self.training_metadata.get('ae_threshold')
                            if ae_threshold is not None:
                                self.ae_threshold = ae_threshold
                                logging.getLogger(__name__).info(f" Autoencoder threshold: {self.ae_threshold}")
                            else:
                                self._calculate_ae_threshold()
                        else:
                            self._calculate_ae_threshold()
                        
                        return True
                    except Exception as e:
                        logging.getLogger(__name__).warning(f" Failed to load Autoencoder from {ae_path}: {e}")
                        continue
            
            logging.getLogger(__name__).warning(" No Autoencoder model could be loaded")
            return False
            
        except Exception as e:
            logging.getLogger(__name__).error(f" Error loading Autoencoder: {e}")
            return False
    
    def _inject_models_to_processor(self):
        """
         NEW: Inject all loaded models into ProductionDataProcessor.
        This ensures ProductionDataProcessor has access to models without loading them.
        """
        try:
            if self.conn_processor and hasattr(self.conn_processor, 'set_models_from_handler'):
                self.conn_processor.set_models_from_handler(
                    complete_pipeline=self.complete_pipeline,
                    training_metadata=self.training_metadata,
                    top_services_list=self.top_services_list,
                    model_ae=self.model_ae
                )
                logging.getLogger(__name__).info(" Models injected into ProductionDataProcessor")
                
                self._extract_feature_names()
                
            else:
                logging.getLogger(__name__).warning(" ProductionDataProcessor does not support model injection")
                
        except Exception as e:
            logging.getLogger(__name__).error(f" Error injecting models to processor: {e}")
    
    def _extract_feature_names(self) -> None:
        """ REFACTORED: Extract feature names from injected models or training metadata."""
        try:
            #  PRIORITY 1: Get feature names from ProductionDataProcessor's injected training metadata
            if (self.conn_processor and 
                self.conn_processor.training_metadata and 
                'final_feature_names' in self.conn_processor.training_metadata):
                
                self.feature_names = self.conn_processor.training_metadata['final_feature_names']
                logging.getLogger(__name__).info(f" PRIORITY 1: Got {len(self.feature_names)} features from ProductionDataProcessor")
                logging.getLogger(__name__).info(f"   Feature breakdown:")
                logging.getLogger(__name__).info(f"     - Group features (0-9): {self.feature_names[:10]}")
                logging.getLogger(__name__).info(f"     - Core numerical (10-29): {len(self.feature_names[10:30])} features")
                logging.getLogger(__name__).info(f"     - One-hot encoded (30-54): {len(self.feature_names[30:])} features")
                logging.getLogger(__name__).info(f"   Total: {len(self.feature_names)} features (matches training exactly)")
                return
            
            #  PRIORITY 2: Get feature names from MLHandler's training metadata
            if self.training_metadata and 'final_feature_names' in self.training_metadata:
                self.feature_names = self.training_metadata['final_feature_names']
                logging.getLogger(__name__).info(f" PRIORITY 2: Got {len(self.feature_names)} features from MLHandler")
                return
            
            self.feature_names = [
                # Group features (0-9)
                'beacon_group_count', 'beacon_group_cv',
                'beacon_channel_timediff_std', 'beacon_channel_duration_std', 'beacon_channel_orig_bytes_std',
                'horizontal_scan_unique_dst_ip_count', 'horizontal_scan_problematic_ratio',
                'vertical_scan_unique_dst_port_count', 'vertical_scan_problematic_ratio',
                'ddos_group_unique_src_ip_count',
                # Core numerical (10-29)
                'duration', 'orig_bytes', 'resp_bytes', 'missed_bytes', 'orig_pkts', 'orig_ip_bytes',
                'resp_pkts', 'resp_ip_bytes', 'hist_len', 'hist_R_count', 'hist_has_T',
                'is_failed_connection', 'is_tunneled_connection', 'concurrent_connections',
                'ip_profile_uid_rate', 'ip_profile_id.resp_p_rate', 'ip_profile_id.resp_h_rate',
                'ip_profile_conn_state_diversity', 'ip_profile_mean_duration', 'ip_profile_mean_orig_bytes',
                # One-hot encoded (30-54)
                'proto_icmp', 'proto_tcp', 'proto_udp', 'proto_unknown_transport',
                'conn_state_OTH', 'conn_state_REJ', 'conn_state_RSTO', 'conn_state_RSTR',
                'conn_state_RSTRH', 'conn_state_S0', 'conn_state_S1', 'conn_state_S2',
                'conn_state_S3', 'conn_state_SF', 'conn_state_SH', 'conn_state_SHR',
                'orig_port_binned_high', 'orig_port_binned_low', 'orig_port_binned_medium',
                'resp_port_binned_high', 'resp_port_binned_low', 'resp_port_binned_medium',
                'service_binned_common', 'service_binned_rare', 'service_binned_uncommon'
            ]
            logging.getLogger(__name__).info(f" PRIORITY 3: Using exact training feature names: {len(self.feature_names)} features")
            
        except Exception as e:
            logging.getLogger(__name__).warning(f" Could not extract feature names: {str(e)}")
            # Use exact training feature names as fallback
            self.feature_names = [
                'beacon_group_count', 'beacon_group_cv', 'beacon_channel_timediff_std',
                'beacon_channel_duration_std', 'beacon_channel_orig_bytes_std',
                'horizontal_scan_unique_dst_ip_count', 'horizontal_scan_problematic_ratio',
                'vertical_scan_unique_dst_port_count', 'vertical_scan_problematic_ratio',
                'ddos_group_unique_src_ip_count'
            ] + [f'Feature_{i}' for i in range(45)]  # 10 group + 45 core = 55 total
            logging.getLogger(__name__).warning(" Using fallback feature names (55 features)")
    
    def _load_saved_threshold(self) -> bool:
        """Load previously calculated threshold from training files."""
        #  FIX: Use the same model directory as ProductionDataProcessor
        if not self.conn_processor:
            logging.getLogger(__name__).warning(" No ProductionDataProcessor available for threshold loading")
            return False
            
        model_dir = self.conn_processor.model_dir
        logging.getLogger(__name__).info(f" Loading thresholds from ProductionDataProcessor model directory: {model_dir}")
        
        #  FIX: Use exact filename from training
        ae_threshold_files = [
            'ae_threshold_cic_master.json',  # Exact filename from training
            f'ae_threshold_{self.conn_processor.model_version}.json',  # Dynamic version
            AUTOENCODER_THRESHOLD_FILE  # fallback to config
        ]
        
        for threshold_file in ae_threshold_files:
            threshold_path = os.path.join(model_dir, threshold_file)
            try:
                if os.path.exists(threshold_path):
                    with open(threshold_path, 'r') as f:
                        threshold_data = json.load(f)
                    self.ae_threshold = threshold_data.get("threshold", 0.5)
                    logging.getLogger(__name__).info(f" Loaded saved Autoencoder threshold: {self.ae_threshold:.6f} from {threshold_path}")
                    return True
            except Exception as e:
                logging.getLogger(__name__).warning(f" Could not load Autoencoder threshold from {threshold_path}: {str(e)}")
                continue
        
        logging.getLogger(__name__).warning(" No Autoencoder threshold files found in ProductionDataProcessor model directory")
        return False
    
    def _load_isolation_forest_threshold(self) -> bool:
        """Load Isolation Forest threshold from training files."""
        #  FIX: Use the same model directory as ProductionDataProcessor
        if not self.conn_processor:
            logging.getLogger(__name__).warning(" No ProductionDataProcessor available for threshold loading")
            return False
        
        model_dir = self.conn_processor.model_dir
        logging.getLogger(__name__).info(f" Loading Isolation Forest threshold from ProductionDataProcessor model directory: {model_dir}")
        
        #  FIX: Use exact filename from training
        iso_threshold_files = [
            'iso_threshold_cic_master.json',  # Exact filename from training
            f'iso_threshold_{self.conn_processor.model_version}.json',  # Dynamic version
            'iso_threshold_cic_master.json'  # Fallback
        ]
        
        for threshold_file in iso_threshold_files:
            threshold_path = os.path.join(model_dir, threshold_file)
            try:
                if os.path.exists(threshold_path):
                    with open(threshold_path, 'r') as f:
                        threshold_data = json.load(f)
                    # Select threshold based on policy
                    policy = ISOF_THRESHOLD_POLICY or 'file'
                    if policy == 'p10':
                        self.iso_threshold = threshold_data.get("threshold_10_percent", threshold_data.get("threshold_5_percent", 0.07))
                    elif policy == 'p5':
                        self.iso_threshold = threshold_data.get("threshold_5_percent", 0.07)
                    elif policy == 'p1':
                        self.iso_threshold = threshold_data.get("threshold_1_percent", threshold_data.get("threshold_5_percent", 0.07))
                    elif policy == 'zero':
                        self.iso_threshold = threshold_data.get("threshold_zero", 0.0)
                    else:  # 'file' default
                        self.iso_threshold = threshold_data.get("threshold_5_percent", 0.07)
                    logging.getLogger(__name__).info(f" Loaded saved Isolation Forest threshold: {self.iso_threshold:.6f} from {threshold_path}")
                    return True
            except Exception as e:
                logging.getLogger(__name__).warning(f" Could not load Isolation Forest threshold from {threshold_path}: {str(e)}")
                continue
        
        logging.getLogger(__name__).warning(" No valid Isolation Forest threshold file found in ProductionDataProcessor model directory")
        return False
    
    def _save_threshold(self, threshold: float, sample_size: int) -> None:
        """Save calculated threshold to file for future use."""
        #  FIX: Use the same model directory as ProductionDataProcessor
        if not self.conn_processor:
            logging.getLogger(__name__).warning(" No ProductionDataProcessor available for threshold saving")
            return
            
        model_dir = self.conn_processor.model_dir
        logging.getLogger(__name__).info(f" Saving threshold to ProductionDataProcessor model directory: {model_dir}")
        threshold_path = os.path.join(model_dir, AUTOENCODER_THRESHOLD_FILE)
        
        try:
            os.makedirs(model_dir, exist_ok=True)
            threshold_data = {
                "threshold": float(threshold),
                "sample_size": int(sample_size),
                "calculated_on": datetime.now().isoformat(),
                "percentile": 99,
                "data_source": "data/merged_conn_compatible.log"
            }
            with open(threshold_path, 'w') as f:
                json.dump(threshold_data, f, indent=2)
            logging.getLogger(__name__).info(f" Threshold saved to {threshold_path}")
        except Exception as e:
            logging.getLogger(__name__).warning(f" Could not save threshold: {str(e)}")
    
    def _calculate_ae_threshold(self) -> None:
        """
        Load pre-calculated anomaly threshold for Autoencoder from training.
        Fallback to calculation if not available.
        """
        if not self.model_ae or not self.conn_processor or not self.conn_processor.complete_pipeline:
            logger.warning(" Cannot load AE threshold: Model or pipeline not loaded.")
            return

        # Try to load saved threshold first (priority)
        if self._load_saved_threshold():
            # A valid threshold was loaded from file, no need to recalculate.
            logger.info(" Autoencoder threshold loaded from saved file")
            return
            
        try:
            logging.getLogger(__name__).info(" Calculating Autoencoder anomaly threshold from benign data...")
            # Use live log file instead of old data
            conn_log_path = "live_logs/conn.log"
            if not os.path.exists(conn_log_path) or os.path.getsize(conn_log_path) == 0:
                logging.getLogger(__name__).warning(f" Live log file not found or empty: {conn_log_path}. Using default threshold.")
                # Fallback to a reasonably high default if no data is available
                self.ae_threshold = 0.5 
                return

            reconstruction_errors = []
            chunk_size = 10000  # Process 10,000 lines at a time

            # Use pandas read_csv with chunks to handle large files
            for chunk in pd.read_csv(conn_log_path, sep='\t', header=None, names=CONN_LOG_COLUMNS, on_bad_lines='skip', chunksize=chunk_size):
                # Drop rows with incorrect number of columns if any slipped through
                chunk.dropna(inplace=True)
                if chunk.empty:
                    continue

                logging.getLogger(__name__).info(f"Processing a chunk of {len(chunk)} benign records...")
                
                try:
                    # Convert chunk to list of connection dictionaries
                    connections_list = chunk.to_dict('records')
                    
                    conn_dict_with_stateful = self.training_profiler.process_connection_incremental(connections_list[0].copy())
                    single_df = pd.DataFrame([conn_dict_with_stateful])
                    
                    # Apply enhanced features
                    top_services = self.conn_processor.top_services_list if self.conn_processor and self.conn_processor.top_services_list else self.top_services_list
                    df_fully_featured = engineer_enhanced_features(single_df, top_services)
                    
                    # Apply pipeline transform
                    if self.conn_processor and self.conn_processor.complete_pipeline:
                        X_chunk = self.conn_processor.complete_pipeline.transform(df_fully_featured)
                    else:
                        X_chunk = self.complete_pipeline.transform(df_fully_featured)
                    
                    if X_chunk is None or X_chunk.size == 0:
                        logging.getLogger(__name__).warning(f"Skipping chunk - preprocessing failed")
                        continue
                        
                except Exception as e:
                    logging.getLogger(__name__).warning(f"Training pipeline failed for chunk, skipping: {e}")
                    continue
                
                # Get reconstructions and calculate errors
                reconstructions = self.model_ae.predict(X_chunk, verbose=0)
                errors = np.mean(np.square(X_chunk - reconstructions), axis=1)
                reconstruction_errors.extend(errors)

            if not reconstruction_errors:
                logging.getLogger(__name__).error("No valid reconstruction errors could be calculated from the data file.")
                self.ae_threshold = 0.5 # Fallback
                return

            # Set the threshold to the 99th percentile of the reconstruction errors
            calculated_threshold = np.percentile(reconstruction_errors, 99)
            self.ae_threshold = calculated_threshold
            
            logging.getLogger(__name__).info(f"✓ Autoencoder threshold calculated and set to 99th percentile: {self.ae_threshold:.6f}")
            
            # Save the calculated threshold for future runs
            self._save_threshold(calculated_threshold, len(reconstruction_errors))
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error calculating Autoencoder threshold: {str(e)}")
            # Fallback to a safe, high default on error
            self.ae_threshold = 0.5
    
    def predict_with_autoencoder(self, X_processed: np.ndarray) -> Tuple[bool, float, Optional[np.ndarray]]:
        """Predict anomaly using Autoencoder reconstruction error."""
        try:
            if not self.model_ae or self.ae_threshold is None:
                return False, 0.0, None
            
            X_batch = X_processed.reshape(1, -1)
            reconstruction = self.model_ae.predict(X_batch, verbose=0)
            reconstruction_error = np.mean(np.square(X_processed - reconstruction[0]))
            is_anomaly = reconstruction_error > self.ae_threshold
            
            return is_anomaly, reconstruction_error, reconstruction[0]
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Autoencoder prediction error: {str(e)}")
            return False, 0.0, None

    def predict_single_log(self, log_line: str) -> Dict[str, Any]:
        """Predict anomaly scores for a single conn.log line using trained pipeline."""
        try:
            if not self.conn_processor:
                logger.error("ProductionDataProcessor not available")
                return None
            
            connection_dict = self.conn_processor.parse_conn_record(log_line)
            if not connection_dict:
                logger.error("Failed to parse log line")
                return None
            
            conn_dict_with_stateful = self.training_profiler.process_connection_incremental(connection_dict.copy())
            single_df = pd.DataFrame([conn_dict_with_stateful])
            
            # Apply enhanced features
            top_services = self.conn_processor.top_services_list if self.conn_processor and self.conn_processor.top_services_list else self.top_services_list
            df_fully_featured = engineer_enhanced_features(single_df, top_services)
            
            # Apply pipeline transform
            if self.conn_processor and self.conn_processor.complete_pipeline:
                X_single = self.conn_processor.complete_pipeline.transform(df_fully_featured)
            else:
                X_single = self.complete_pipeline.transform(df_fully_featured)
            
            if X_single is None or X_single.size == 0:
                logging.getLogger(__name__).error("Pipeline preprocessing returned empty result")
                return None
            
            #  VALIDATION: Check feature count matches training (55 features)
            expected_features = 55  # From training
            if X_single.shape[1] != expected_features:
                logging.getLogger(__name__).warning(f"Feature count mismatch: expected {expected_features}, got {X_single.shape[1]}")
                logging.getLogger(__name__).info(f"   This may indicate pipeline inconsistency - continuing with {X_single.shape[1]} features")
            else:
                logging.getLogger(__name__).info(f" Feature count matches training pipeline exactly: {X_single.shape[1]} features")
            
            prediction_result = {
                'record': connection_dict,
                'features': X_single.flatten(),  # Flatten to 1D array
                'isof_score': None,
                'isof_anomaly': False,
                'ae_error': None,
                'ae_anomaly': False,
                'shap_values': None,
                'feature_names': self.feature_names,
                'pipeline_version': self.conn_processor.model_version,
                'feature_count': X_single.shape[1]
            }
            
            #  FIX: Ensure thresholds are loaded before processing
            if self.iso_threshold is None:
                logging.getLogger(__name__).info(" Loading Isolation Forest threshold...")
                self._load_isolation_forest_threshold()
            
            if self.ae_threshold is None:
                logging.getLogger(__name__).info(" Loading Autoencoder threshold...")
                self._calculate_ae_threshold()
            
            #  FIX: Isolation Forest prediction with proper threshold
            if self.model:
                try:
                    isof_score = self.model.decision_function(X_single)[0]
                    prediction_result['isof_score'] = float(isof_score)
                    
                    iso_threshold = self.iso_threshold
                    if iso_threshold is None:
                        logging.getLogger(__name__).warning(" No Isolation Forest threshold loaded, using default")
                        iso_threshold = PRODUCTION_THRESHOLDS['isolation_forest_conservative']
                    
                    prediction_result['isof_anomaly'] = bool(isof_score < iso_threshold)
                    logging.getLogger(__name__).info(f" Isolation Forest: score={isof_score:.6f}, threshold={iso_threshold:.6f}, anomaly={prediction_result['isof_anomaly']}")
                    
                    if prediction_result['isof_anomaly'] and self.explainer is not None and SHAP_AVAILABLE:
                        try:
                            shap_values = self.explainer.shap_values(X_single)[0]
                            prediction_result['shap_values'] = shap_values.tolist()  # Convert to list for JSON
                            logging.getLogger(__name__).info(f" SHAP values calculated for anomaly")
                        except Exception as e:
                            logging.getLogger(__name__).warning(f" Could not calculate SHAP values: {str(e)}")
                            
                except Exception as e:
                    logging.getLogger(__name__).error(f" Isolation Forest prediction failed: {str(e)}")
            
            #  FIX: Autoencoder prediction with proper threshold
            if self.model_ae and self.ae_threshold is not None:
                try:
                    #  FIX: Use loaded threshold from training
                    ae_threshold = self.ae_threshold
                    logging.getLogger(__name__).info(f" Autoencoder threshold from training: {ae_threshold:.6f}")
                    
                    # Get reconstruction error
                    reconstruction = self.model_ae.predict(X_single, verbose=0)
                    ae_error = np.mean(np.square(X_single - reconstruction))
                    prediction_result['ae_error'] = float(ae_error)
                    
                    #  FIX: Compare with training threshold
                    prediction_result['ae_anomaly'] = bool(ae_error > ae_threshold)
                    logging.getLogger(__name__).info(f" Autoencoder: error={ae_error:.6f}, threshold={ae_threshold:.6f}, anomaly={prediction_result['ae_anomaly']}")
                    
                    # Store reconstruction for analysis
                    prediction_result['ae_reconstruction'] = reconstruction.flatten().tolist()
                    
                except Exception as e:
                    logging.getLogger(__name__).error(f" Autoencoder prediction failed: {str(e)}")
            
            isof_anomaly = prediction_result.get('isof_anomaly', False)
            ae_anomaly = prediction_result.get('ae_anomaly', False)
            final_anomaly = isof_anomaly or ae_anomaly
            prediction_result['final_anomaly'] = final_anomaly
            
            logging.getLogger(__name__).info(f" Single log prediction completed:")
            logging.getLogger(__name__).info(f"   - Isolation Forest: {isof_anomaly}")
            logging.getLogger(__name__).info(f"   - Final decision: {final_anomaly}")
            
            return prediction_result
                
        except Exception as e:
            logging.getLogger(__name__).error(f" Error processing log line: {str(e)}")
            logging.getLogger(__name__).debug(f"Error details: {type(e).__name__}: {str(e)}")
            return None

    def predict_batch_logs(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """
         FINAL & OPTIMIZED: Process log batch efficiently using incremental updates.
        This is the fastest, most consistent, and most robust implementation.
        """
        try:
            # Lazy readiness: auto-initialize processor/models if missing
            if not self.conn_processor:
                logging.getLogger(__name__).info("[LAZY] Initializing ProductionDataProcessor...")
                try:
                    self.conn_processor = ProductionDataProcessor()
                except Exception as e:
                    logging.getLogger(__name__).error(f"Failed to initialize ProductionDataProcessor: {e}")
                    return []

            # If no models or pipeline yet, attempt to load connection models now
            pipeline_ready = (
                (self.conn_processor and getattr(self.conn_processor, 'complete_pipeline', None) is not None)
                or (self.complete_pipeline is not None)
            )
            models_ready = (self.model is not None) or (self.model_ae is not None)

            if not pipeline_ready or not models_ready:
                logging.getLogger(__name__).info("[LAZY] Loading ML models (pipeline/models not ready yet)...")
                try:
                    self._load_connection_models()
                    # Recompute readiness after load
                    pipeline_ready = (
                        (self.conn_processor and getattr(self.conn_processor, 'complete_pipeline', None) is not None)
                        or (self.complete_pipeline is not None)
                    )
                    models_ready = (self.model is not None) or (self.model_ae is not None)
                except Exception as e:
                    logging.getLogger(__name__).warning(f"Lazy load attempt failed: {e}")

            if not pipeline_ready or not models_ready:
                logging.getLogger(__name__).error("MLHandler is not ready (processor, pipeline, or models missing).")
                return []
                
            logging.getLogger(__name__).info(f" Starting FINAL OPTIMIZED batch processing for {len(log_lines)} logs...")
            all_results = []

            # 1. Parse all logs once
            parsed_connections = []
            for i, log_line in enumerate(log_lines):
                try:
                    conn_dict = self.conn_processor.parse_conn_record(log_line)
                    if conn_dict:
                        conn_dict['_original_index'] = i
                        parsed_connections.append(conn_dict)
                except Exception as e:
                    logging.getLogger(__name__).warning(f"Skipping unparsable log line {i}: {e}")

            if not parsed_connections:
                logging.getLogger(__name__).warning("No valid connections found in the batch.")
                return []
            
            logging.getLogger(__name__).info(f"Successfully parsed {len(parsed_connections)} connections.")

            try:
                parsed_connections.sort(key=lambda r: float(r.get('ts') or 0.0))
                
                if parsed_connections:
                    newest_ts = float(parsed_connections[-1].get('ts') or 0.0)
                    oldest_ts = float(parsed_connections[0].get('ts') or 0.0)
                    time_span = newest_ts - oldest_ts
                    
  
            except Exception as _e_sort:
                logging.getLogger(__name__).warning(f"Could not sort/filter batch by ts due to: {_e_sort}")

            #  FIX: Ensure thresholds are loaded before processing
            if self.iso_threshold is None:
                logging.getLogger(__name__).info(" Loading Isolation Forest threshold...")
                self._load_isolation_forest_threshold()
            
            if self.ae_threshold is None:
                logging.getLogger(__name__).info(" Loading Autoencoder threshold...")
                self._calculate_ae_threshold()

            # 2. Process batch with incremental IP profiler (per-connection) to preserve state, then apply stateless and group features in batch
            enriched_rows = []
            for conn_dict in parsed_connections:
                try:
                    enriched_rows.append(self.training_profiler.process_connection_incremental(conn_dict.copy()))
                except Exception as e:
                    logging.getLogger(__name__).warning(f"Skipping connection due to IP profiler error: {e}")
                    continue

            if not enriched_rows:
                logging.getLogger(__name__).warning("No enriched connections after IP profiling.")
                return []

            df_stateful = pd.DataFrame(enriched_rows)
            # Preserve original index for mapping
            if '_original_index' not in df_stateful.columns:
                df_stateful['_original_index'] = [r.get('_original_index', i) for i, r in enumerate(parsed_connections)]

            # Stateless features once per batch
            top_services = (self.conn_processor.top_services_list if (self.conn_processor and self.conn_processor.top_services_list)
                            else (self.top_services_list or ['http', 'ssl', 'dns', 'unknown', 'ssh', 'ftp', 'smtp', 'pop3']))
            df_stateless = engineer_enhanced_features(df_stateful, top_services)

            # Group features: prefer GFT in trained pipeline; otherwise runtime GFT fallback on whole batch
            pipeline_obj = self.conn_processor.complete_pipeline if (self.conn_processor and self.conn_processor.complete_pipeline) else self.complete_pipeline
            has_gft_in_pipeline = hasattr(pipeline_obj, 'named_steps') and isinstance(getattr(pipeline_obj, 'named_steps'), dict) and ('group_feature_generator' in pipeline_obj.named_steps)

            df_for_evidence = df_stateless
            if not has_gft_in_pipeline:
                # FIXED: Simplified runtime GFT fallback logic
                if not self.runtime_group_transformer:
                    gft_kwargs = {
                        'logger': logging.getLogger(__name__),
                        'time_window_seconds': int(self.gft_params.get('time_window_seconds', 300) or 300),
                        'min_samples_for_confirm': int(self.gft_params.get('min_samples_for_confirm', 3) or 3)
                        # FIXED: Removed fast_mode and n_jobs parameters (no longer supported)
                    }
                    self.runtime_group_transformer = GroupFeatureTransformer(**gft_kwargs)
                    self.runtime_gft_fitted = False
                
                # FIXED: Simplified warm-up logic
                if not self.runtime_gft_fitted:
                    try:
                        self.runtime_gft_warmup_rows += len(df_stateless)
                        self.runtime_group_transformer.fit(df_stateless)
                        if self.runtime_gft_warmup_rows >= self.runtime_gft_min_rows:
                            self.runtime_gft_fitted = True
                            logging.getLogger(__name__).info(f"Runtime GFT warm-up complete ({self.runtime_gft_warmup_rows} rows)")
                    except Exception as fit_e:
                        logging.getLogger(__name__).warning(f"Runtime GFT warm-up failed: {fit_e}")
                        self.runtime_gft_fitted = True  # Continue anyway
                
                # FIXED: Transform with fallback
                try:
                    df_grouped = self.runtime_group_transformer.transform(df_stateless)
                    df_for_evidence = df_grouped
                    X_processed = pipeline_obj.transform(df_grouped)
                except Exception as tr_e:
                    logging.getLogger(__name__).warning(f"Runtime GFT transform failed: {tr_e}; using stateless features")
                    df_for_evidence = df_stateless
                    X_processed = pipeline_obj.transform(df_stateless)
            else:
                # FIXED: Use GFT step inside pipeline for evidence
                try:
                    gft_step = pipeline_obj.named_steps.get('group_feature_generator')
                    if gft_step is not None:
                        df_for_evidence = gft_step.transform(df_stateless)
                except Exception:
                    df_for_evidence = df_stateless
                X_processed = pipeline_obj.transform(df_stateless)

            # 3. Prediction for each row using precomputed X_processed
            for row_idx, (orig_idx, conn_record) in enumerate(zip(df_stateful['_original_index'].tolist(), df_stateful.to_dict(orient='records'))):
                try:
                    vec = X_processed[row_idx:row_idx+1]
                    iso_score, isof_anomaly = None, False
                    ae_error, ae_anomaly = None, False
                    ae_reconstruction = None

                    if self.model is not None:
                        iso_score = self.model.decision_function(vec)[0]
                        iso_threshold = self.iso_threshold if self.iso_threshold is not None else PRODUCTION_THRESHOLDS['isolation_forest_conservative']
                        isof_anomaly = bool(iso_score < iso_threshold)

                    if self.model_ae is not None:
                        ae_reconstruction = self.model_ae.predict(vec, verbose=0)
                        ae_error = float(np.mean(np.square(vec - ae_reconstruction)))
                        ae_anomaly = bool(ae_error > self.ae_threshold)

                    final_anomaly = isof_anomaly or ae_anomaly
                    shap_values = None
                    if self.explainer and final_anomaly:
                        try:
                            shap_values = self.explainer.shap_values(vec)[0]
                        except Exception as e:
                            logging.getLogger(__name__).warning(f"SHAP explanation failed: {e}")

                    # Extract evidence from the DataFrame that contains z_* (grouped when fallback GFT was applied; otherwise stateless)
                    src_series = (df_for_evidence.iloc[row_idx] if not df_for_evidence.empty else conn_record)
                    group_features = self._extract_group_features_from_processed(vec, src_series)

                    result = {
                        'original_index': orig_idx,
                        'record': conn_record,
                        'isof_score': iso_score,
                        'isof_anomaly': isof_anomaly,
                        'ae_error': ae_error,
                        'ae_anomaly': ae_anomaly,
                        'ae_reconstruction': ae_reconstruction.tolist() if ae_reconstruction is not None else None,
                        'final_anomaly': final_anomaly,
                        'shap_values': shap_values.tolist() if shap_values is not None else None,
                        'feature_names': self.feature_names,
                        'sliding_window_size': 1,
                        'window_start': conn_record.get('ts', 0),
                        'window_end': conn_record.get('ts', 0),
                        
                        # RAW FEATURES for rule engine (extracted from group_features)
                        'horizontal_scan_unique_dst_ip_count': group_features.get('horizontal_scan_unique_dst_ip_count', 0.0),
                        'horizontal_scan_problematic_ratio': group_features.get('horizontal_scan_problematic_ratio', 0.0),
                        'vertical_scan_unique_dst_port_count': group_features.get('vertical_scan_unique_dst_port_count', 0.0),
                        'vertical_scan_problematic_ratio': group_features.get('vertical_scan_problematic_ratio', 0.0),
                        'beacon_group_count': group_features.get('beacon_group_count', 0.0),
                        'beacon_group_cv': group_features.get('beacon_group_cv', 0.0),
                        'beacon_channel_timediff_std': group_features.get('beacon_channel_timediff_std', 0.0),
                        'beacon_channel_duration_std': group_features.get('beacon_channel_duration_std', 0.0),
                        'beacon_channel_orig_bytes_std': group_features.get('beacon_channel_orig_bytes_std', 0.0),
                        'ddos_group_unique_src_ip_count': group_features.get('ddos_group_unique_src_ip_count', 0.0),
                        
                        # Z-SCORE FEATURES for ML models (extracted from group_features)
                        'z_horizontal_unique_dst_ip_count': group_features.get('z_horizontal_unique_dst_ip_count', 0.0),
                        'z_horizontal_problematic_ratio': group_features.get('z_horizontal_problematic_ratio', 0.0),
                        'z_vertical_unique_dst_port_count': group_features.get('z_vertical_unique_dst_port_count', 0.0),
                        'z_vertical_problematic_ratio': group_features.get('z_vertical_problematic_ratio', 0.0),
                        'z_beacon_group_count': group_features.get('z_beacon_group_count', 0.0),
                        'z_ddos_group_unique_src_ip_count': group_features.get('z_ddos_group_unique_src_ip_count', 0.0),
                        'z_beacon_channel_timediff_std': group_features.get('z_beacon_channel_timediff_std', 0.0),
                        'z_beacon_channel_duration_std': group_features.get('z_beacon_channel_duration_std', 0.0),
                        'z_beacon_channel_orig_bytes_std': group_features.get('z_beacon_channel_orig_bytes_std', 0.0),
                        # IP PROFILE FEATURES (NEW!)
                        'concurrent_connections': group_features.get('concurrent_connections', 0.0),
                        'ip_profile_uid_rate': group_features.get('ip_profile_uid_rate', 0.0),
                        'ip_profile_id.resp_p_rate': group_features.get('ip_profile_id.resp_p_rate', 0.0),
                        'ip_profile_id.resp_h_rate': group_features.get('ip_profile_id.resp_h_rate', 0.0),
                        'ip_profile_conn_state_diversity': group_features.get('ip_profile_conn_state_diversity', 0.0),
                        'ip_profile_mean_duration': group_features.get('ip_profile_mean_duration', 0.0),
                        'ip_profile_mean_orig_bytes': group_features.get('ip_profile_mean_orig_bytes', 0.0)
                    }
                    all_results.append(result)
                except Exception as e:
                    logging.getLogger(__name__).error(f"Failed to finalize prediction for row {row_idx}: {e}", exc_info=True)
                    continue

            logging.getLogger(__name__).info(f"FINAL OPTIMIZED batch processing completed. Generated {len(all_results)} predictions.")
            return all_results
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Critical error in predict_batch_logs: {e}", exc_info=True)
            return []
    


    def _extract_group_features_from_processed(self, X_processed: np.ndarray, connection_data: Any) -> Dict[str, Any]:
        """
        Extract BOTH raw features and z-score features from processed connection data.
        
        Args:
            X_processed: Processed features from ML pipeline
            connection_data: Connection data (dict or pandas Series) containing group features
            
        Returns:
            Dictionary with BOTH raw features and z-score features
        """
        try:
            # Define ALL feature keys (raw + z-score + IP profile)
            all_feature_keys = [
                # RAW FEATURES for rule engine
                'horizontal_scan_unique_dst_ip_count', 'horizontal_scan_problematic_ratio',
                'vertical_scan_unique_dst_port_count', 'vertical_scan_problematic_ratio',
                'beacon_group_count', 'beacon_group_cv',
                'beacon_channel_timediff_std', 'beacon_channel_duration_std', 'beacon_channel_orig_bytes_std',
                'ddos_group_unique_src_ip_count',
                
                # Z-SCORE FEATURES for ML models
                'z_horizontal_unique_dst_ip_count', 'z_horizontal_problematic_ratio',
                'z_vertical_unique_dst_port_count', 'z_vertical_problematic_ratio',
                'z_beacon_group_count', 'z_ddos_group_unique_src_ip_count',
                'z_beacon_channel_timediff_std', 'z_beacon_channel_duration_std', 'z_beacon_channel_orig_bytes_std',
                
                # IP PROFILE FEATURES (NEW!)
                'concurrent_connections', 'ip_profile_uid_rate', 'ip_profile_id.resp_p_rate',
                'ip_profile_id.resp_h_rate', 'ip_profile_conn_state_diversity',
                'ip_profile_mean_duration', 'ip_profile_mean_orig_bytes'
            ]

            out: Dict[str, float] = {}
            if connection_data is not None:
                # Pandas Series
                if hasattr(connection_data, 'index'):
                    for key in all_feature_keys:
                        if key in connection_data.index:
                            try:
                                out[key] = float(connection_data[key])
                            except Exception:
                                out[key] = 0.0
                # Dict-like
                elif hasattr(connection_data, 'get'):
                    for key in all_feature_keys:
                        try:
                            val = connection_data.get(key, 0.0)
                            out[key] = float(val) if val is not None else 0.0
                        except Exception:
                            out[key] = 0.0

            # Ensure all expected features are present with fallback values
            fallback_values = {
                # Raw features fallbacks
                'horizontal_scan_unique_dst_ip_count': 0.0,
                'horizontal_scan_problematic_ratio': 0.0,
                'vertical_scan_unique_dst_port_count': 0.0,
                'vertical_scan_problematic_ratio': 0.0,
                'beacon_group_count': 0.0,
                'beacon_group_cv': 0.0,
                'beacon_channel_timediff_std': 0.0,
                'beacon_channel_duration_std': 0.0,
                'beacon_channel_orig_bytes_std': 0.0,
                'ddos_group_unique_src_ip_count': 0.0,
                
                # Z-score features fallbacks
                'z_horizontal_unique_dst_ip_count': 0.0,
                'z_horizontal_problematic_ratio': 0.0,
                'z_vertical_unique_dst_port_count': 0.0,
                'z_vertical_problematic_ratio': 0.0,
                'z_beacon_group_count': 0.0,
                'z_ddos_group_unique_src_ip_count': 0.0,
                'z_beacon_channel_timediff_std': 0.0,
                'z_beacon_channel_duration_std': 0.0,
                'z_beacon_channel_orig_bytes_std': 0.0,
                'concurrent_connections': 0.0, 'ip_profile_uid_rate': 0.0, 'ip_profile_id.resp_p_rate': 0.0,
                'ip_profile_id.resp_h_rate': 0.0, 'ip_profile_conn_state_diversity': 0.0,
                'ip_profile_mean_duration': 0.0, 'ip_profile_mean_orig_bytes': 0.0
            }
            
            # Fill missing features with fallback values
            for key, fallback_val in fallback_values.items():
                if key not in out:
                    out[key] = fallback_val

            return out
            
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to extract group features: {e}")
            return {
                # Raw features fallbacks
                'horizontal_scan_unique_dst_ip_count': 0.0,
                'horizontal_scan_problematic_ratio': 0.0,
                'vertical_scan_unique_dst_port_count': 0.0,
                'vertical_scan_problematic_ratio': 0.0,
                'beacon_group_count': 0.0,
                'beacon_group_cv': 0.0,
                'beacon_channel_timediff_std': 0.0,
                'beacon_channel_duration_std': 0.0,
                'beacon_channel_orig_bytes_std': 0.0,
                'ddos_group_unique_src_ip_count': 0.0,
                
                # Z-score features fallbacks
                'z_horizontal_unique_dst_ip_count': 0.0,
                'z_horizontal_problematic_ratio': 0.0,
                'z_vertical_unique_dst_port_count': 0.0,
                'z_vertical_problematic_ratio': 0.0,
                'z_beacon_group_count': 0.0,
                'z_ddos_group_unique_src_ip_count': 0.0,
                'z_beacon_channel_timediff_std': 0.0,
                'z_beacon_channel_duration_std': 0.0,
                'z_beacon_channel_orig_bytes_std': 0.0,
                # IP Profile features fallbacks (NEW!)
                'concurrent_connections': 0.0, 'ip_profile_uid_rate': 0.0, 'ip_profile_id.resp_p_rate': 0.0,
                'ip_profile_id.resp_h_rate': 0.0, 'ip_profile_conn_state_diversity': 0.0,
                'ip_profile_mean_duration': 0.0, 'ip_profile_mean_orig_bytes': 0.0
            }


    def force_recalculate_threshold(self) -> bool:
        """Force recalculation of Autoencoder threshold by deleting saved threshold file."""
        try:
            if not self.conn_processor:
                logging.getLogger(__name__).warning(" No ProductionDataProcessor available for threshold recalculation")
                return False
            
            model_dir = self.conn_processor.model_dir
            threshold_path = os.path.join(model_dir, AUTOENCODER_THRESHOLD_FILE)
            
            if os.path.exists(threshold_path):
                os.remove(threshold_path)
                logging.getLogger(__name__).info(" Deleted saved threshold file - forcing recalculation")
            
            self._calculate_ae_threshold()
            
            if self.ae_threshold is not None:
                logging.getLogger(__name__).info(" Threshold recalculation completed successfully")
                return True
            else:
                logging.getLogger(__name__).error(" Threshold recalculation failed")
                return False
                
        except Exception as e:
            logging.getLogger(__name__).error(f" Error during threshold recalculation: {str(e)}")
            return False

    def get_model_status(self) -> Dict[str, Any]:
        """Get the status of all loaded models."""
        return {
            'preprocessor': self.model_status['preprocessor'],
            'isolation_forest': self.model_status['isolation_forest'],
            'autoencoder': self.model_status['autoencoder'],
            'dns_models': self.model_status['dns_models'],
            'shap_available': SHAP_AVAILABLE and self.explainer is not None,
            'tensorflow_available': TENSORFLOW_AVAILABLE,
            'ae_threshold': self.ae_threshold,
            'iso_threshold': self.iso_threshold,
            'dns_ae_threshold': self.dns_ae_threshold,
            'dns_iso_threshold': self.dns_iso_threshold
        }

    def _load_dns_models(self) -> bool:
        """Load DNS tunneling detection models."""
        try:
            if self.model_status.get('dns_models') and (self.dns_isolation_model is not None or self.dns_autoencoder is not None) and self.dns_processor is not None:
                logger.info("DNS models already loaded; skipping reload")
                return True
            if not os.path.exists(DNS_MODEL_DIRECTORY):
                logger.warning(f"DNS model directory not found: {DNS_MODEL_DIRECTORY}")
                self.model_status['dns_models'] = False
                return False
            
            # Load DNS Isolation Forest model
            dns_iso_model_path = os.path.join(DNS_MODEL_DIRECTORY, 'dns_tunneling_isolation_forest.pkl')
            if os.path.exists(dns_iso_model_path):
                with open(dns_iso_model_path, 'rb') as f:
                    self.dns_isolation_model = joblib.load(f)
                logger.info(f"Loaded DNS Isolation Forest model: {dns_iso_model_path}")
            else:
                logger.warning(f"DNS Isolation Forest model not found: {dns_iso_model_path}")
                self.dns_isolation_model = None
            
            # Load DNS Autoencoder model
            dns_ae_model_path = os.path.join(DNS_MODEL_DIRECTORY, 'dns_tunneling_autoencoder.keras')
            if os.path.exists(dns_ae_model_path):
                try:
                    import tensorflow as tf
                    self.dns_autoencoder = tf.keras.models.load_model(dns_ae_model_path)
                    logger.info(f"Loaded DNS Autoencoder model: {dns_ae_model_path}")
                except Exception as e:
                    logger.warning(f"Could not load DNS Autoencoder model: {str(e)}")
                    self.dns_autoencoder = None
            else:
                logger.warning(f"DNS Autoencoder model not found: {dns_ae_model_path}")
                self.dns_autoencoder = None
            
            # Load DNS Scaler
            dns_scaler_path = os.path.join(DNS_MODEL_DIRECTORY, 'dns_tunneling_scaler.pkl')
            if os.path.exists(dns_scaler_path):
                with open(dns_scaler_path, 'rb') as f:
                    self.dns_scaler = joblib.load(f)
                logger.info(f"Loaded DNS Scaler: {dns_scaler_path}")
            else:
                logger.warning(f"DNS Scaler not found: {dns_scaler_path}")
                self.dns_scaler = None
            

            dns_metadata_path = os.path.join(DNS_MODEL_DIRECTORY, 'dns_pipeline_metadata.json')
            if os.path.exists(dns_metadata_path):
                try:
                    with open(dns_metadata_path, 'r') as f:
                        dns_metadata = json.load(f)
                    # Use the correct key for feature names
                    self.dns_feature_names = dns_metadata.get('features', {}).get('list', [])
                    logger.info(f"Loaded DNS feature names: {len(self.dns_feature_names)} features")
                except Exception as e:
                    logger.warning(f"Could not load DNS feature names: {str(e)}")
                    self.dns_feature_names = []
            else:
                logger.warning(f"DNS metadata not found: {dns_metadata_path}")
                self.dns_feature_names = []
            
            #  TẠO DNS SHAP EXPLAINER
            if (self.dns_isolation_model is not None and 
                SHAP_AVAILABLE and 
                len(self.dns_feature_names) > 0):
                try:
                    import shap
                    # Create DNS SHAP explainer
                    self.dns_explainer = shap.TreeExplainer(self.dns_isolation_model)
                    logger.info("Created DNS SHAP explainer")
                except Exception as e:
                    logger.warning(f"Could not create DNS SHAP explainer: {str(e)}")
                    self.dns_explainer = None
            else:
                self.dns_explainer = None
                if not SHAP_AVAILABLE:
                    logger.warning("SHAP not available for DNS explainer")
                elif self.dns_isolation_model is None:
                    logger.warning("DNS Isolation Forest model not available for explainer")
                elif len(self.dns_feature_names) == 0:
                    logger.warning("DNS feature names not available for explainer")
            
            # Load DNS thresholds from files (temporary), then synchronize from processor to avoid dual sources
            self._load_dns_thresholds()
            
            try:
                if self.dns_processor is None:
                    self.dns_processor = DNSProductionDataProcessor(disable_model_loading=True)
                    
                    # INJECT models đã load vào processor (tránh duplicate loading)
                    self.dns_processor.inject_models_from_handler(
                        isolation_model=self.dns_isolation_model,
                        autoencoder_model=self.dns_autoencoder,
                        scaler=self.dns_scaler,
                        iso_threshold=self.dns_iso_threshold,
                        ae_threshold=self.dns_ae_threshold
                    )
                    
                    logger.info("DNSProductionDataProcessor initialized (models injected, no duplicate loading)")
                else:
                    logger.info("DNSProductionDataProcessor already exists, reusing instance")
                
                # Synchronize thresholds from processor as single source of truth
                try:
                    if hasattr(self.dns_processor, 'dns_iso_threshold'):
                        self.dns_iso_threshold = self.dns_processor.dns_iso_threshold
                    if hasattr(self.dns_processor, 'dns_ae_threshold'):
                        self.dns_ae_threshold = self.dns_processor.dns_ae_threshold
                    logger.info("Synchronized DNS thresholds from DNSProductionDataProcessor")
                except Exception as _:
                    pass
            except Exception as e:
                logger.error(f"Failed to initialize DNSProductionDataProcessor: {str(e)}")
                self.dns_processor = None
            
            # Check if at least one model is loaded
            if self.dns_isolation_model is not None or self.dns_autoencoder is not None:
                self.model_status['dns_models'] = True
                logger.info("DNS models loaded successfully")
                return True
            else:
                logger.warning("No DNS models could be loaded")
                self.model_status['dns_models'] = False
                return False
                
        except Exception as e:
            logger.error(f"Error loading DNS models: {str(e)}")
            self.model_status['dns_models'] = False
            return False
    
    def _load_dns_thresholds(self) -> None:
        """Load DNS thresholds from training files."""
        try:
            # Load DNS Isolation Forest threshold
            dns_iso_threshold_files = [
                f'dns_iso_threshold.json',  # Primary: dns_master version
                f'iso_threshold_dns_v1.json',
                f'iso_threshold_dns_v2.json'
            ]
            
            for threshold_file in dns_iso_threshold_files:
                threshold_path = os.path.join(DNS_MODEL_DIRECTORY, threshold_file)
                try:
                    if os.path.exists(threshold_path):
                        with open(threshold_path, 'r') as f:
                            threshold_data = json.load(f)
                        # Select DNS threshold based on policy
                        dns_policy = DNS_ISOF_THRESHOLD_POLICY or 'file'
                        if dns_policy == 'p10':
                            self.dns_iso_threshold = threshold_data.get("threshold_10_percent", threshold_data.get("threshold_5_percent", 0.07))
                        elif dns_policy == 'p5':
                            self.dns_iso_threshold = threshold_data.get("threshold_5_percent", 0.07)
                        elif dns_policy == 'p1':
                            self.dns_iso_threshold = threshold_data.get("threshold_1_percent", threshold_data.get("threshold_5_percent", 0.07))
                        elif dns_policy == 'zero':
                            self.dns_iso_threshold = threshold_data.get("threshold_zero", 0.0)
                        else:  # 'file' default
                            # default to 5% if unspecified in file
                            self.dns_iso_threshold = threshold_data.get("threshold_5_percent", threshold_data.get("threshold_1_percent", 0.07))
                        logger.info(f"Loaded DNS Isolation Forest threshold (policy={dns_policy}): {self.dns_iso_threshold:.6f} from {threshold_path}")
                        break
                except Exception as e:
                    logger.warning(f"Could not load DNS Isolation Forest threshold from {threshold_path}: {str(e)}")
                    continue
            else:
                logger.warning("No valid DNS Isolation Forest threshold file found")
                self.dns_iso_threshold = 0.07  # Default fallback
            
            # Load DNS Autoencoder threshold
            dns_ae_threshold_files = [
                f'dns_ae_threshold.json'
            ]
            
            for threshold_file in dns_ae_threshold_files:
                threshold_path = os.path.join(DNS_MODEL_DIRECTORY, threshold_file)
                try:
                    if os.path.exists(threshold_path):
                        with open(threshold_path, 'r') as f:
                            threshold_data = json.load(f)
                        self.dns_ae_threshold = threshold_data.get("threshold", 0.2)
                        logger.info(f"Loaded DNS Autoencoder threshold: {self.dns_ae_threshold:.6f} from {threshold_path}")
                        break
                except Exception as e:
                    logger.warning(f"Could not load DNS Autoencoder threshold from {threshold_path}: {str(e)}")
                    continue
            else:
                logger.warning("No valid DNS Autoencoder threshold file found")
                self.dns_ae_threshold = 0.2  # Default fallback
                
        except Exception as e:
            logger.error(f"Error loading DNS thresholds: {str(e)}")
            self.dns_iso_threshold = 0.07
            self.dns_ae_threshold = 0.2



    def predict_dns_anomaly(self, dns_record: Dict[str, str]) -> Dict[str, Any]:
        """Predict DNS anomaly using trained models (ML-first; rules classify later)."""
        try:
            if not self.dns_processor:
                return {
                    'is_tunneling': False,
                    'confidence': 'N/A',
                    'error': 'DNSProductionDataProcessor not available'
                }
            
            # Use DNSProductionDataProcessor for prediction
            result = self.dns_processor.predict_dns_anomaly(dns_record)
            if not result:
                return {
                    'is_tunneling': False,
                    'confidence': 'Error',
                    'error': 'Failed to process DNS record'
                }
            
            #  BỔ SUNG SHAP EXPLANATION CHO DNS
            dns_shap_values = None
            if (self.dns_isolation_model is not None and 
                self.dns_explainer is not None and 
                SHAP_AVAILABLE and
                result.get('preprocessed_features') is not None):
                try:
                    import shap
                    # Get preprocessed features for SHAP
                    X_dns = result.get('preprocessed_features')
                    if X_dns is not None and hasattr(X_dns, 'reshape'):
                        # Calculate SHAP values for DNS
                        dns_shap_values = self.dns_explainer.shap_values(X_dns.reshape(1, -1))[0]
                        logger.debug(f"Calculated DNS SHAP values: {len(dns_shap_values)} features")
                    else:
                        logger.warning(f"X_dns is not numpy array: {type(X_dns)}")
                except Exception as e:
                    logger.warning(f"Could not calculate DNS SHAP values: {str(e)}")
                    dns_shap_values = None
            
            # Convert to expected format for detection engine
            formatted_result = {
                'query': result.get('query', ''),
                'timestamp': result.get('timestamp', 0),
                'preprocessed_features': result.get('preprocessed_features', 0),
                'features': result.get('features', {}),
                'shap_values': dns_shap_values,  #  THÊM SHAP VALUES
                'feature_names': self.dns_feature_names if hasattr(self, 'dns_feature_names') else None,  #  THÊM FEATURE NAMES
                'details': {
                    'isolation_forest': result.get('isolation_forest', {}),
                    'autoencoder': result.get('autoencoder', {})
                }
            }
            
            return formatted_result
            
        except Exception as e:
            logger.error(f"Error predicting DNS tunneling: {str(e)}")
            return {
                'is_tunneling': False,
                'confidence': 'Error',
                'error': str(e)
            } 

    def predict_dns_tunneling(self, dns_record: Dict[str, str]) -> Dict[str, Any]:
        return self.predict_dns_anomaly(dns_record)

    def predict_batch_dns_queries(self, dns_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Batch predict DNS anomalies for multiple dns.log records (ML-first; rules classify later).
        Returns a list of results aligned with the input order.
        """
        try:
            if not self.dns_processor or not dns_records:
                return []

            import numpy as np
            import pandas as pd
            from core.data_processor import DNS_FEATURE_COLUMNS

            # Build DataFrame and engineer features exactly as training
            df_raw = pd.DataFrame(dns_records)
            df_features = self.dns_processor.engineer_dns_features(df_raw)

            # Select features and scale using trained scaler
            if self.dns_processor.scaler is None:
                logger.error("No trained DNS scaler loaded")
                return []

            X_features = df_features[DNS_FEATURE_COLUMNS]
            X_scaled = self.dns_processor.scaler.transform(X_features)

            batch_size = X_scaled.shape[0]

            # Isolation Forest batch prediction
            isof_scores = None
            isof_anomalies = None
            if self.dns_isolation_model is not None:
                try:
                    isof_scores = self.dns_isolation_model.decision_function(X_scaled)
                    iso_threshold = self.dns_iso_threshold if self.dns_iso_threshold is not None else 0.07
                    isof_anomalies = isof_scores < iso_threshold
                except Exception as e:
                    logger.warning(f"DNS IF batch prediction failed: {e}")

            # Autoencoder batch prediction
            ae_errors = None
            ae_anomalies = None
            ae_reconstructions = None
            if self.dns_autoencoder is not None:
                try:
                    ae_reconstructions = self.dns_autoencoder.predict(X_scaled, verbose=0)
                    ae_errors = np.mean(np.square(X_scaled - ae_reconstructions), axis=1)
                    ae_threshold = self.dns_ae_threshold if self.dns_ae_threshold is not None else 0.2
                    ae_anomalies = ae_errors > ae_threshold
                except Exception as e:
                    logger.warning(f"DNS AE batch prediction failed: {e}")

            # SHAP for anomalies only
            shap_batch_values = None
            anomaly_indices = []
            if self.dns_explainer is not None and SHAP_AVAILABLE:
                try:
                    for i in range(batch_size):
                        is_anom = (
                            (isof_anomalies is not None and bool(isof_anomalies[i])) or
                            (ae_anomalies is not None and bool(ae_anomalies[i]))
                        )
                        if is_anom:
                            anomaly_indices.append(i)
                    if anomaly_indices:
                        X_anom = X_scaled[anomaly_indices]
                        shap_batch_values = self.dns_explainer.shap_values(X_anom)
                except Exception as e:
                    logger.warning(f"DNS SHAP batch calculation failed: {e}")
                    shap_batch_values = None

            # Assemble per-record results
            results: List[Dict[str, Any]] = []
            shap_idx = 0
            for i in range(batch_size):
                record = dns_records[i]
                features_row = df_features.iloc[i]
                features_dict = {}
                try:
                    for col in DNS_FEATURE_COLUMNS:
                        features_dict[col] = features_row.get(col, 0)
                except Exception:
                    features_dict = {}

                shap_values = None
                is_current_anomaly = (
                    (isof_anomalies is not None and bool(isof_anomalies[i])) or
                    (ae_anomalies is not None and bool(ae_anomalies[i]))
                )
                if is_current_anomaly and shap_batch_values is not None:
                    try:
                        shap_values = shap_batch_values[shap_idx]
                        shap_idx += 1
                    except Exception:
                        shap_values = None

                result = {
                    'query': record.get('query', ''),
                    'timestamp': record.get('ts', 0),
                    'preprocessed_features': X_scaled[i],
                    'features': features_dict,
                    'shap_values': shap_values,
                    'feature_names': self.dns_feature_names if hasattr(self, 'dns_feature_names') else None,
                    'details': {
                        'isolation_forest': {
                            'score': float(isof_scores[i]) if isof_scores is not None else None,
                            'threshold': float(self.dns_iso_threshold) if self.dns_iso_threshold is not None else None,
                            'is_anomaly': bool(isof_anomalies[i]) if isof_anomalies is not None else False
                        },
                        'autoencoder': {
                            'reconstruction_error': float(ae_errors[i]) if ae_errors is not None else None,
                            'threshold': float(self.dns_ae_threshold) if self.dns_ae_threshold is not None else None,
                            'is_anomaly': bool(ae_anomalies[i]) if ae_anomalies is not None else False,
                            'reconstruction': ae_reconstructions[i].tolist() if ae_reconstructions is not None else None
                        }
                    }
                }

                results.append(result)

            logger.info(f" Batch DNS ML prediction completed: {len(results)} results")
            return results

        except Exception as e:
            logger.error(f"Error in predict_batch_dns_queries: {str(e)}")
            return []