import pandas as pd
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
import logging
import os
from collections import deque
from typing import Dict, Any, List
from datetime import datetime

class GroupFeatureTransformer(BaseEstimator, TransformerMixin):
    """
    
    Expected Z-Score Output Features (used in training and runtime):
    - z_horizontal_unique_dst_ip_count, z_horizontal_problematic_ratio
    - z_vertical_unique_dst_port_count, z_vertical_problematic_ratio
    - z_beacon_group_count, z_ddos_group_unique_src_ip_count
    - z_beacon_channel_timediff_std, z_beacon_channel_duration_std, z_beacon_channel_orig_bytes_std
    """
    
    def __init__(self, logger=None, time_window_seconds: int = 300, min_samples_for_confirm: int = 3, manual_baselines=None):
        """
        Initialize the GroupFeatureTransformer.
        
        Args:
            logger: Logger instance for debugging (optional)
            time_window_seconds: Time window for sliding window calculations
            min_samples_for_confirm: Minimum samples needed to confirm group statistics
            manual_baselines: Expert-defined baselines to override automatic calculation
        """
        self.logger = logger or logging.getLogger(__name__)
        self.group_stats_maps_ = {}
        self.is_fitted_ = False
        self.manual_baselines = manual_baselines
        
        # Runtime (stream) state similar to UnifiedIPProfiler style
        self.time_window_seconds = int(time_window_seconds)
        self.min_samples_for_confirm = int(min_samples_for_confirm)
        self.runtime_state: Dict[str, Dict[str, deque]] = {
            'beacon_groups': {},           # key: "src:dst:port:proto" -> deque of {ts, duration, orig_bytes}
            'horizontal_groups': {},       # key: "src:port" -> deque of {ts, dst_ip, conn_state}
            'vertical_groups': {},         # key: "src:dst" -> deque of {ts, dst_port, conn_state}
            'ddos_groups': {},             # key: "dst:port" -> deque of {ts, src_ip}
            'global_buffer': deque()       # deque of {ts, duration, orig_bytes, is_problematic}
        }
        # last_cleanup no longer needed
        self.entity_baselines_: Dict[str, Dict[str, float]] = {}

        self.env_baselines_: Dict[str, float] = {
            'problematic_ratio': 0.0,
            'duration_std': 0.0,
            'orig_bytes_std': 0.0,
            'beacon_channel_timediff_std_mean': 30.0,  # Expert default: 30s for normal user behavior
            'beacon_channel_timediff_std_std': 15.0,   # Expert default: 15s std for Z-score
            'median_horizontal_unique_dst_ip_count': 0.0,
            'median_vertical_unique_dst_port_count': 0.0,
            'median_beacon_group_count': 2.0,
            'median_ddos_unique_src_ip_count': 0.0
        }
        
    def fit(self, X, y=None):
        """
        Learn group statistics from training data only.
        
        Args:
            X: Training DataFrame with network connection data
            y: Ignored (unsupervised transformer)
            
        Returns:
            self: Fitted transformer
        """
        if not isinstance(X, pd.DataFrame):
            raise ValueError("GroupFeatureTransformer requires DataFrame input")
            
        
        X_work = X.copy()
        
        # Ensure numeric types for time and numeric aggregations
        if 'ts' not in X_work.columns:
            raise ValueError("Input DataFrame must contain 'ts' column")
        # Convert timestamp to numeric for time-based grouping
        original_ts = X_work['ts'].copy()
        X_work['ts'] = pd.to_numeric(X_work['ts'], errors='coerce')
        
        # Check for timestamp conversion issues in fit
        if X_work['ts'].isna().any():

            # Use current timestamp as fallback for invalid values
            X_work['ts'] = X_work['ts'].fillna(datetime.now().timestamp())
        for col in ['duration', 'orig_bytes']:
            if col not in X_work.columns:
                X_work[col] = 0
            X_work[col] = pd.to_numeric(X_work[col], errors='coerce').fillna(0)

        # Validate required identifier columns exist
        required_columns = ['id.orig_h', 'id.resp_h', 'id.resp_p', 'conn_state']
        missing = [c for c in required_columns if c not in X_work.columns]
        if missing:
            raise ValueError(f"Input DataFrame missing required columns: {missing}")
        
        
        beacon_group_columns = ['id.orig_h', 'id.resp_h', 'id.resp_p']
        X_work['beacon_group'] = X_work[beacon_group_columns[0]].astype(str)
        for col in beacon_group_columns[1:]:
            X_work['beacon_group'] += ':' + X_work[col].astype(str)
        
        if 'proto' in X_work.columns:
            X_work['beacon_group'] += ':' + X_work['proto'].astype(str)
        else:
            X_work['beacon_group'] += ':unknown'  # Default if protocol not available
        
        # Sort by beacon group and timestamp for interval calculation
        X_work = X_work.sort_values(['beacon_group', 'ts']).reset_index(drop=True)
        
        # Calculate time intervals for beaconing pattern detection
        X_work['beacon_time_interval'] = X_work.groupby('beacon_group')['ts'].diff()
        X_work['beacon_time_interval'] = X_work['beacon_time_interval'].fillna(0)
        
        # Calculate ONLY existing features but with better logic
        beacon_stats = X_work.groupby('beacon_group').agg({
            'beacon_group': 'count',  # Connection count per src_ip:dst_ip:port:proto pair
            'beacon_time_interval': ['mean', 'std'],  # Timing consistency
            'duration': ['mean', 'std'],  # Duration consistency
            'orig_bytes': ['mean', 'std']  # Bytes consistency
        }).reset_index()
        
        beacon_stats.columns = ['beacon_group', 'beacon_group_count', 'beacon_group_mean_interval', 'beacon_group_std_interval', 'beacon_group_mean_duration', 'beacon_group_std_duration', 'beacon_group_mean_orig_bytes', 'beacon_group_std_orig_bytes']
        
        # Calculate coefficient of variation for beaconing regularity
        beacon_stats['beacon_group_cv'] = np.where(
            beacon_stats['beacon_group_mean_interval'] > 0,
            beacon_stats['beacon_group_std_interval'] / beacon_stats['beacon_group_mean_interval'],
            0
        )
        
        # Calculate beacon channel features (matching runtime pipeline)
        beacon_stats['beacon_channel_timediff_std'] = beacon_stats['beacon_group_std_interval']
        beacon_stats['beacon_channel_duration_std'] = beacon_stats['beacon_group_std_duration']
        beacon_stats['beacon_channel_orig_bytes_std'] = beacon_stats['beacon_group_std_orig_bytes']
        
        beacon_stats = beacon_stats.fillna(0)
        
        beacon_stats = beacon_stats[['beacon_group', 'beacon_group_count', 'beacon_group_cv', 'beacon_channel_timediff_std', 'beacon_channel_duration_std', 'beacon_channel_orig_bytes_std']]
        
        beacon_stats = beacon_stats.loc[:, ~beacon_stats.columns.duplicated()]
        
        # ==========================================
        # 2. HORIZONTAL SCAN DETECTION ANALYSIS - CẬP NHẬT TÊN FEATURE
        # ==========================================
        # Computing HORIZONTAL scan group statistics
        
        # CORRECTED: Horizontal scan = src_ip scanning multiple dst_ips (same dest port)
        # Group by: src_ip + dst_port (same source, same dest port, different destinations)
        horizontal_scan_group_columns = ['id.orig_h', 'id.resp_p']
        X_work['horizontal_scan_group'] = X_work[horizontal_scan_group_columns[0]].astype(str) + ':' + X_work[horizontal_scan_group_columns[1]].astype(str)
        
        # CORRECTED: Calculate horizontal scan features (src_ip:port → multiple dst_ips)
        problematic_states = ['REJ', 'S0', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR']
        horizontal_scan_stats = X_work.groupby('horizontal_scan_group').agg({
            'id.resp_h': 'nunique',  # Unique destination IPs per src_ip:port pair (horizontal scan indicator)
            'conn_state': lambda x: (x.isin(problematic_states)).mean()  # Ratio of failed connections
        }).reset_index()
        
        horizontal_scan_stats.columns = ['horizontal_scan_group', 'horizontal_scan_unique_dst_ip_count', 'horizontal_scan_problematic_ratio']
        horizontal_scan_stats = horizontal_scan_stats.fillna(0)
        
        # ==========================================
        # 3. VERTICAL SCAN DETECTION ANALYSIS - CẬP NHẬT TÊN FEATURE
        # ==========================================
        # Computing VERTICAL scan group statistics
        
        # CORRECTED: Vertical scan = src_ip:dst_ip scanning multiple dst_ports  
        # Group by: src_ip + dst_ip (same source, same destination, different ports)
        vertical_scan_group_columns = ['id.orig_h', 'id.resp_h']
        X_work['vertical_scan_group'] = X_work[vertical_scan_group_columns[0]].astype(str) + ':' + X_work[vertical_scan_group_columns[1]].astype(str)
        
        # CORRECTED: Calculate vertical scan features (src_ip:dst_ip → multiple dst_ports)
        vertical_scan_stats = X_work.groupby('vertical_scan_group').agg({
            'id.resp_p': 'nunique',  # Unique destination ports per src_ip:dst_ip pair (vertical scan indicator)
            'conn_state': lambda x: (x.isin(problematic_states)).mean()  # Ratio of failed connections
        }).reset_index()
        
        vertical_scan_stats.columns = ['vertical_scan_group', 'vertical_scan_unique_dst_port_count', 'vertical_scan_problematic_ratio']
        vertical_scan_stats = vertical_scan_stats.fillna(0)
        
        # ==========================================
        # 4. DDoS DETECTION ANALYSIS
        # ==========================================
        self.logger.info("  Computing DDoS group statistics...")
        
        # Use 2 fields for DDoS group (dst_ip:dst_port) for better DDoS detection
        # This allows us to detect when multiple sources target the same destination
        ddos_group_columns = ['id.resp_h', 'id.resp_p']
        X_work['ddos_group'] = X_work[ddos_group_columns[0]].astype(str)
        for col in ddos_group_columns[1:]:
            X_work['ddos_group'] += ':' + X_work[col].astype(str)
        
        # Calculate ONLY existing feature but with better logic
        ddos_stats = X_work.groupby('ddos_group').agg({
            'id.orig_h': 'nunique'  # Unique source IPs targeting this destination (DDoS indicator)
        }).reset_index()
        
        ddos_stats.columns = ['ddos_group', 'ddos_group_unique_src_ip_count']
        ddos_stats = ddos_stats.fillna(0)
        
        # ==========================================
        # 4.5. GLOBAL ENVIRONMENT BASELINES (for runtime fallback/blending)
        # ==========================================
        try:
            # Problematic ratio across the whole dataset
            global_problematic_ratio = float(X_work['conn_state'].isin(problematic_states).mean()) if 'conn_state' in X_work.columns else 0.0
            # Duration and orig_bytes std across environment
            # Use sample std (ddof=1) to align with pandas groupby std in fit
            global_duration_std = float(pd.to_numeric(X_work['duration'], errors='coerce').fillna(0).std(ddof=1))
            global_orig_bytes_std = float(pd.to_numeric(X_work['orig_bytes'], errors='coerce').fillna(0).std(ddof=1))
            # Beacon interval std across all beacon intervals (ignore first zeros)
            if 'beacon_time_interval' in X_work.columns:
                interval_series = pd.to_numeric(X_work['beacon_time_interval'], errors='coerce').replace(0, np.nan).dropna()
                global_beacon_channel_timediff_std = float(interval_series.std(ddof=1)) if not interval_series.empty else 0.0
            else:
                global_beacon_channel_timediff_std = 0.0
            # Medians from group stats as typical environment counts
            median_horizontal_unique = float(horizontal_scan_stats['horizontal_scan_unique_dst_ip_count'].median()) if not horizontal_scan_stats.empty else 0.0
            std_horizontal_unique = float(horizontal_scan_stats['horizontal_scan_unique_dst_ip_count'].std(ddof=1)) if not horizontal_scan_stats.empty else 1.0
            std_horizontal_problematic = float(horizontal_scan_stats['horizontal_scan_problematic_ratio'].std(ddof=1)) if not horizontal_scan_stats.empty else 1.0
            median_vertical_unique = float(vertical_scan_stats['vertical_scan_unique_dst_port_count'].median()) if not vertical_scan_stats.empty else 0.0
            std_vertical_unique = float(vertical_scan_stats['vertical_scan_unique_dst_port_count'].std(ddof=1)) if not vertical_scan_stats.empty else 1.0
            std_vertical_problematic = float(vertical_scan_stats['vertical_scan_problematic_ratio'].std(ddof=1)) if not vertical_scan_stats.empty else 1.0
            median_beacon_count = float(beacon_stats['beacon_group_count'].median()) if not beacon_stats.empty else 0.0
            std_beacon_count = float(beacon_stats['beacon_group_count'].std(ddof=1)) if not beacon_stats.empty else 1.0
            median_ddos_unique = float(ddos_stats['ddos_group_unique_src_ip_count'].median()) if not ddos_stats.empty else 0.0
            std_ddos_unique = float(ddos_stats['ddos_group_unique_src_ip_count'].std(ddof=1)) if not ddos_stats.empty else 1.0

            # Calculate environmental baselines for BEACON features
            if self.manual_baselines:
                self.logger.info("🔧 Using MANUAL baselines for beacon detection...")
                self.env_baselines_.update(self.manual_baselines)
            else:
                self.logger.info("🤖 Calculating AUTOMATIC baselines for beacon detection from data...")
                # LEARN baselines from training data (normal traffic patterns)
                self.env_baselines_.update({
                    'problematic_ratio': global_problematic_ratio,
                    'duration_std': global_duration_std,
                    'orig_bytes_std': global_orig_bytes_std,
                    'beacon_channel_timediff_std_mean': global_beacon_channel_timediff_std if global_beacon_channel_timediff_std > 0.0 else self.env_baselines_['beacon_channel_timediff_std_mean'],
                    'beacon_channel_timediff_std_std': global_beacon_channel_timediff_std * 0.5 if global_beacon_channel_timediff_std > 0.0 else self.env_baselines_['beacon_channel_timediff_std_std'],
                    'median_horizontal_unique_dst_ip_count': median_horizontal_unique,
                    'std_horizontal_unique_dst_ip_count': std_horizontal_unique if std_horizontal_unique > 0 else 1.0,
                    'std_horizontal_problematic_ratio': std_horizontal_problematic if std_horizontal_problematic > 0 else 1.0,
                    'median_vertical_unique_dst_port_count': median_vertical_unique,
                    'std_vertical_unique_dst_port_count': std_vertical_unique if std_vertical_unique > 0 else 1.0,
                    'std_vertical_problematic_ratio': std_vertical_problematic if std_vertical_problematic > 0 else 1.0,
                    'median_beacon_group_count': median_beacon_count,
                    'std_beacon_group_count': std_beacon_count if std_beacon_count > 0 else 1.0,
                    'median_ddos_unique_src_ip_count': median_ddos_unique
                    , 'std_ddos_unique_src_ip_count': std_ddos_unique if std_ddos_unique > 0 else 1.0
                })
            self.logger.info("  Global environment baselines computed for runtime fallback")
        except Exception as e:
            self.logger.warning(f"Global environment baselines computation failed: {e}")

        # ==========================================
        # 4.6. PER-ENTITY BASELINES (EntityBaselineLearner)
        # ==========================================
        try:
            # Build time buckets per entity to capture dynamics
            X_work['time_bucket'] = (pd.to_numeric(X_work['ts'], errors='coerce').fillna(0) // self.time_window_seconds).astype(int)

            # Metrics per entity per bucket
            per_bucket = X_work.groupby(['id.orig_h', 'time_bucket']).agg(
                horizontal_unique_dst_ip_count=('id.resp_h', 'nunique'),
                vertical_unique_dst_port_count=('id.resp_p', 'nunique'),
                problematic_ratio=('conn_state', lambda s: float(s.isin(problematic_states).mean())),
                duration_std=('duration', lambda s: float(pd.to_numeric(s, errors='coerce').std(ddof=1)) if len(s) >= 2 else 0.0),
                orig_bytes_std=('orig_bytes', lambda s: float(pd.to_numeric(s, errors='coerce').std(ddof=1)) if len(s) >= 2 else 0.0)
            ).reset_index()

            # Prepare beacon interval per entity (use precomputed beacon_time_interval)
            intervals = X_work[['id.orig_h', 'beacon_time_interval']].copy()
            intervals['beacon_time_interval'] = pd.to_numeric(intervals['beacon_time_interval'], errors='coerce')
            intervals = intervals.replace(0, np.nan).dropna()

            entity_baselines: Dict[str, Dict[str, float]] = {}
            for entity, df_ent in per_bucket.groupby('id.orig_h'):
                def mean_std(col: str) -> tuple:
                    vals = pd.to_numeric(df_ent[col], errors='coerce').fillna(0.0).to_numpy()
                    if vals.size == 0:
                        return 0.0, 1.0
                    m = float(np.mean(vals))
                    s = float(np.std(vals, ddof=1)) if vals.size >= 2 else 1.0
                    return m, (s if s > 0 else 1.0)

                h_mean, h_std = mean_std('horizontal_unique_dst_ip_count')
                v_mean, v_std = mean_std('vertical_unique_dst_port_count')
                pr_mean, pr_std = mean_std('problematic_ratio')
                dstd_mean, dstd_std = mean_std('duration_std')
                bstd_mean, bstd_std = mean_std('orig_bytes_std')

                # Beacon interval std per entity (use all intervals for this entity)
                ent_intervals = pd.to_numeric(intervals.loc[intervals['id.orig_h'] == entity, 'beacon_time_interval'], errors='coerce')
                if not ent_intervals.empty:
                    beacon_channel_timediff_std_mean = float(ent_intervals.std(ddof=1)) if ent_intervals.size >= 2 else 0.0
                    # FIXED: Add std for std to enable proper Z-score calculation
                    beacon_channel_timediff_std_std = max(beacon_channel_timediff_std_mean * 0.5, 1.0)  # Estimate std of std
                else:
                    beacon_channel_timediff_std_mean = 0.0
                    beacon_channel_timediff_std_std = 1.0  # Default std

                entity_baselines[entity] = {
                    'horizontal_unique_dst_ip_count_mean': h_mean,
                    'horizontal_unique_dst_ip_count_std': h_std,
                    'vertical_unique_dst_port_count_mean': v_mean,
                    'vertical_unique_dst_port_count_std': v_std,
                    'problematic_ratio_mean': pr_mean,
                    'problematic_ratio_std': pr_std,
                    'duration_std_mean': dstd_mean,
                    'duration_std_std': dstd_std,
                    'orig_bytes_std_mean': bstd_mean,
                    'orig_bytes_std_std': bstd_std,
                    'beacon_channel_timediff_std_mean': beacon_channel_timediff_std_mean,  
                    'beacon_channel_timediff_std_std': beacon_channel_timediff_std_std  
                }

            self.entity_baselines_ = entity_baselines
            self.logger.info("  Per-entity baselines computed for runtime personalization")
        except Exception as e:
            self.logger.warning(f"Per-entity baselines computation failed: {e}")

        # ==========================================
        # 5. STORE (TEMPORARY) GROUP STATS FOR BASELINE ONLY
        # ==========================================
        # Not storing group stats anymore to avoid static merge logic in transform.
        
        # Store feature names for sklearn compatibility
        self.feature_names_in_ = list(X.columns)
        
        # Also store n_features_in_ for sklearn compatibility
        self.n_features_in_ = len(X.columns)
        
        self.is_fitted_ = True
        
        self.logger.info(f"  GroupFeatureTransformer fitted successfully:")
        self.logger.info(f"     - Beacon patterns: {len(beacon_stats):,} unique flows")
        self.logger.info(f"     - Horizontal scan patterns: {len(horizontal_scan_stats):,} unique src_ip:port pairs")
        self.logger.info(f"     - Vertical scan patterns: {len(vertical_scan_stats):,} unique src_ip:dst_ip pairs")
        self.logger.info(f"     - DDoS patterns: {len(ddos_stats):,} unique targets")
        
        return self
        
    def transform(self, X, y=None):
        """
        Generate dynamic sliding-window Z-score features per row, unified with runtime logic.
        Returns original columns + only z-score feature columns (for model training consistency).
        """
        if not self.is_fitted_:
            raise ValueError("GroupFeatureTransformer must be fitted before transform")
            
        if not isinstance(X, pd.DataFrame):
            raise ValueError("GroupFeatureTransformer requires DataFrame input")
            
   

        # Generating dynamic sliding-window features

        required_columns = ['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'conn_state', 'duration', 'orig_bytes']
        missing = [c for c in required_columns if c not in X.columns]
        if missing:
            raise ValueError(f"Input DataFrame missing required columns for transform: {missing}")

        # Preserve original columns and add stable row id for joining
        original_cols = list(X.columns)
        # CRITICAL: Create unique row IDs that are guaranteed to be unique
        X_with_id = X.copy()
        X_with_id['__row_id__'] = np.arange(len(X_with_id))

        # Work on a minimized view to reduce memory and speed up ops
        needed_cols = ['__row_id__', 'ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'conn_state', 'duration', 'orig_bytes']
        missing_needed = [c for c in needed_cols if c not in X_with_id.columns]
        if missing_needed:
            raise ValueError(f"Input DataFrame missing required columns for transform: {missing_needed}")
        df = X_with_id[needed_cols].copy()
        
        original_ts = df['ts'].copy()
        df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
        
        # Check for timestamp conversion issues
        if df['ts'].isna().any():
            self.logger.warning(f"Timestamp conversion issues detected: {df['ts'].isna().sum()} invalid timestamps")
            self.logger.warning(f"Sample invalid timestamps: {original_ts[df['ts'].isna()].head().tolist()}")
            # Use current timestamp as fallback for invalid values
            df['ts'] = df['ts'].fillna(datetime.now().timestamp())
        else:
            # Timestamp conversion completed
            pass
        
        df['duration'] = pd.to_numeric(df['duration'], errors='coerce').fillna(0)
        df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)

        df_sorted = df.sort_values('ts')



        enriched_rows: List[Dict[str, Any]] = []
        for rec in df_sorted.to_dict(orient='records'):
            out = self.process_connection_incremental(rec)
            filtered = {k: v for k, v in out.items() if k in self.get_feature_names_out()}
            enriched_rows.append(filtered)
        
        features_df = pd.DataFrame(enriched_rows)

        # Ensure all expected feature columns exist (raw + z-score)
        expected_feature_cols = self.get_feature_names_out()
        for col in expected_feature_cols:
            if col not in features_df.columns:
                features_df[col] = 0.0

        # CRITICAL: Ensure row id is present and properly aligned
        if '__row_id__' not in features_df.columns:
            # This should never happen, but if it does, we need to reconstruct the mapping
            self.logger.warning("__row_id__ missing from features_df - reconstructing mapping")
            # Create a mapping from df_sorted order to features_df order
            features_df['__row_id__'] = df_sorted['__row_id__'].values

        out_df = pd.merge(
            X_with_id, 
            features_df[['__row_id__'] + self.get_feature_names_out()], 
            on='__row_id__', 
            how='left',
            validate='1:1'  # Ensures one-to-one relationship
        )

        # CRITICAL: Verify merge integrity
        if len(out_df) != len(X_with_id):
            self.logger.error(f"Merge integrity failed: X_with_id={len(X_with_id)}, out_df={len(out_df)}")
            raise ValueError(f"Merge produced {len(out_df)} rows but expected {len(X_with_id)} rows")

        # Keep BOTH original columns + raw features + z-score features
        feature_cols = [c for c in out_df.columns if c in self.get_feature_names_out()]
        for col in feature_cols:
            out_df[col] = pd.to_numeric(out_df[col], errors='coerce').fillna(0)
            
        # Safely select original columns to avoid KeyError when original had a column named 'index'
        common_cols = [c for c in original_cols if c in out_df.columns]
        final_df = out_df[common_cols + feature_cols]
        
        # FINAL VERIFICATION: Ensure we have the right number of rows
        if len(final_df) != len(X):
            self.logger.error(f"Final row count mismatch: input={len(X)}, output={len(final_df)}")
            self.logger.error(f"X_with_id shape: {X_with_id.shape}")
            self.logger.error(f"features_df shape: {features_df.shape}")
            self.logger.error(f"out_df shape: {out_df.shape}")
            raise ValueError(f"Transform output has {len(final_df)} rows but input had {len(X)} rows")
            
        # Verify all expected feature columns are present (raw + z-score)
        expected_feature_cols = self.get_feature_names_out()
        missing_feature_cols = [col for col in expected_feature_cols if col not in final_df.columns]
        if missing_feature_cols:
            self.logger.error(f"Missing feature columns: {missing_feature_cols}")
            raise ValueError(f"Expected feature columns missing: {missing_feature_cols}")
            
        return final_df
        
    def fit_transform(self, X, y=None):
        """
        Fit the transformer and transform the data in one step.
        
        Args:
            X: Training DataFrame 
            y: Ignored (unsupervised transformer)
            
        Returns:
            X_transformed: DataFrame with added group features
        """
        return self.fit(X, y).transform(X, y)
        
    def get_feature_names_out(self, input_features=None):
        """
        Get output feature names for compatibility with sklearn Pipelines.
        
        Args:
            input_features: Input feature names from previous pipeline step
            
        Returns:
            List of ALL feature names (raw + z-score) produced by this transformer
        """
        # Return BOTH raw features and z-score features for complete pipeline compatibility
        all_feature_names = [
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
            'z_beacon_channel_timediff_std', 'z_beacon_channel_duration_std', 'z_beacon_channel_orig_bytes_std'
        ]
        
        try:
            return all_feature_names
            
        except Exception as e:
            self.logger.warning(f"Error in get_feature_names_out: {e}")
            # Fallback: return all features
            return all_feature_names
    
    def get_feature_names_in(self):
        """
        Get input feature names for sklearn compatibility.
        
        Returns:
            List of input feature names
        """
        if hasattr(self, 'feature_names_in_'):
            return self.feature_names_in_
        else:
            return [] 

    # =============================
    # Runtime (stream) processing
    # =============================
    def process_connection_incremental(self, conn_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Incrementally update runtime group statistics and return features for one connection.

        Args:
            conn_dict: Connection record dictionary

        Returns:
            Updated connection dictionary with group features added
        """
        try:   
            # Get timestamp from current connection for cleanup
            current_conn_ts = float(conn_dict.get('ts', 0) or 0)
            
            # Always cleanup based on current connection timestamp
            # This ensures sliding window works correctly for both log files and real-time
            self._cleanup_runtime_state(current_conn_ts)
            
            # CRITICAL FIX: Calculate features BEFORE adding connection to runtime state
            # This ensures beacon_count reflects the state BEFORE this connection
            features = self._compute_runtime_features_for_connection(conn_dict)
            
            # Now add connection to runtime state for future processing
            self._add_connection_to_runtime_state(conn_dict)
            
            result = dict(conn_dict)
            result.update(features)
            return result
        except Exception as exc:
            self.logger.error(f"process_connection_incremental failed: {exc}")
            # Return zeros for all expected features
            zero_features = {
                'horizontal_scan_unique_dst_ip_count': 0,
                'horizontal_scan_problematic_ratio': 0.0,
                'vertical_scan_unique_dst_port_count': 0,
                'vertical_scan_problematic_ratio': 0.0,
                'beacon_group_count': 0,
                'beacon_group_cv': 0.0,
                'beacon_channel_timediff_std': 0.0,
                'beacon_channel_duration_std': 0.0,
                'beacon_channel_orig_bytes_std': 0.0,
                'ddos_group_unique_src_ip_count': 0
            }
            fallback = dict(conn_dict)
            fallback.update(zero_features)
            return fallback

    def process_connections_batch(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of connections incrementally and return enriched records."""
        if not connections:
            return []
        results: List[Dict[str, Any]] = []
        for conn in connections:
            results.append(self.process_connection_incremental(conn))
        return results

    def reset(self):
        """Reset runtime state (useful for testing)."""
        self.runtime_state = {
            'beacon_groups': {},
            'horizontal_groups': {},
            'vertical_groups': {},
            'ddos_groups': {},
            'global_buffer': deque()
        }
        self.last_cleanup = datetime.now().timestamp()

    # -------- Internal helpers (runtime) --------
    def _cleanup_runtime_state(self, current_time: float):
        """Evict old entries from all runtime windows based on time_window_seconds."""
        try:
            cutoff = current_time - self.time_window_seconds
            

            # Beacon groups - IMPROVED: Only remove old entries, keep keys
            for key in list(self.runtime_state['beacon_groups'].keys()):
                dq: deque = self.runtime_state['beacon_groups'][key]
                before_count = len(dq)
                # Remove only entries older than cutoff
                while dq and float(dq[0]['ts']) < cutoff:
                    dq.popleft()
                after_count = len(dq)
                if before_count != after_count:
                    pass

            # Horizontal groups - IMPROVED: Only remove old entries, keep keys
            for key in list(self.runtime_state['horizontal_groups'].keys()):
                dq: deque = self.runtime_state['horizontal_groups'][key]
                before_count = len(dq)
                while dq and float(dq[0]['ts']) < cutoff:
                    dq.popleft()
                after_count = len(dq)
                    # Horizontal cleanup completed

            # Vertical groups - IMPROVED: Only remove old entries, keep keys
            for key in list(self.runtime_state['vertical_groups'].keys()):
                dq: deque = self.runtime_state['vertical_groups'][key]
                before_count = len(dq)
                while dq and float(dq[0]['ts']) < cutoff:
                    dq.popleft()
                after_count = len(dq)
                    # Vertical cleanup completed

            # DDoS groups - IMPROVED: Only remove old entries, keep keys
            for key in list(self.runtime_state['ddos_groups'].keys()):
                dq: deque = self.runtime_state['ddos_groups'][key]
                before_count = len(dq)
                while dq and float(dq[0]['ts']) < cutoff:
                    dq.popleft()
                after_count = len(dq)


            gb = self.runtime_state.get('global_buffer', deque())
            before_count = len(gb)
            while gb and float(gb[0]['ts']) < cutoff:
                gb.popleft()
            after_count = len(gb)

                
        except Exception as exc:
            self.logger.error(f"_cleanup_runtime_state failed: {exc}")

    def _compute_runtime_features_for_connection(self, conn: Dict[str, Any]) -> Dict[str, Any]:
        """Update windows for relevant groups and compute features for this connection."""
        ts = float(conn.get('ts', 0) or 0)
        src_ip = str(conn.get('id.orig_h', ''))
        dst_ip = str(conn.get('id.resp_h', ''))
        dst_port = conn.get('id.resp_p')
        proto = conn.get('proto', 'unknown')  # Get protocol for more accurate beacon detection

        # Keys - FIXED: Include protocol in beacon_key for accurate beacon detection
        beacon_key = f"{src_ip}:{dst_ip}:{dst_port}:{proto}"
        horizontal_key = f"{src_ip}:{dst_port}"
        vertical_key = f"{src_ip}:{dst_ip}"
        ddos_key = f"{dst_ip}:{dst_port}"

        # Ensure deques
        beacon_dq = self.runtime_state['beacon_groups'].setdefault(beacon_key, deque())
        horiz_dq = self.runtime_state['horizontal_groups'].setdefault(horizontal_key, deque())
        vert_dq = self.runtime_state['vertical_groups'].setdefault(vertical_key, deque())
        ddos_dq = self.runtime_state['ddos_groups'].setdefault(ddos_key, deque())


        gb = self.runtime_state.get('global_buffer', deque())


        beacon_count = len(beacon_dq)
        
        # Initialize all std features to 0.0
        std_interval = 0.0
        beacon_cv = 0.0
        beacon_dur_std = 0.0
        beacon_ob_std = 0.0
        
        if beacon_count >= 2:
            # Use numpy arrays for faster calculations
            times = np.fromiter((float(e['ts']) for e in beacon_dq), dtype=np.float64, count=beacon_count)
            intervals = np.diff(times)
            if intervals.size >= 1:  # Can compute std from 1+ intervals
                mean_interval = float(intervals.mean())
                std_interval = float(intervals.std(ddof=1)) if intervals.size >= 2 else 0.0
                beacon_cv = float(std_interval / mean_interval) if mean_interval > 0 else 0.0
            else:
                std_interval = 0.0
                beacon_cv = 0.0

            # Duration and orig_bytes std when beacon_count >= 2 (can compute std from 2+ values)
            dur_vals = np.fromiter((float(e['duration']) for e in beacon_dq), dtype=np.float64, count=beacon_count)
            ob_vals = np.fromiter((float(e['orig_bytes']) for e in beacon_dq), dtype=np.float64, count=beacon_count)
            beacon_dur_std = float(dur_vals.std(ddof=1)) if dur_vals.size >= 2 else 0.0
            beacon_ob_std = float(ob_vals.std(ddof=1)) if ob_vals.size >= 2 else 0.0

        if len(horiz_dq) > 0:
            # Use set comprehension for unique IPs
            horiz_unique_dst_ip = len({e['dst_ip'] for e in horiz_dq if e.get('dst_ip')})
            # Vectorized problematic ratio calculation
            problematic_states = self._get_problematic_states()
            if problematic_states:
                problematic_flags = np.fromiter(
                    (1 if e.get('conn_state') in problematic_states else 0 for e in horiz_dq), 
                    dtype=np.int8, count=len(horiz_dq)
                )
                horiz_problematic_ratio = float(problematic_flags.mean())
            else:
                horiz_problematic_ratio = 0.0
        else:
            horiz_unique_dst_ip = 0
            horiz_problematic_ratio = 0.0

        if len(vert_dq) > 0:
            vert_unique_dst_port = len({e['dst_port'] for e in vert_dq if e.get('dst_port') is not None})
            problematic_states = self._get_problematic_states()
            if problematic_states:
                problematic_flags = np.fromiter(
                    (1 if e.get('conn_state') in problematic_states else 0 for e in vert_dq), 
                    dtype=np.int8, count=len(vert_dq)
                )
                vert_problematic_ratio = float(problematic_flags.mean())
            else:
                vert_problematic_ratio = 0.0
        else:
            vert_unique_dst_port = 0
            vert_problematic_ratio = 0.0

        # DDoS calculation
        ddos_unique_src_ip = len({e['src_ip'] for e in ddos_dq if e.get('src_ip')}) if ddos_dq else 0

        # -------- Global baselines from buffer or fitted environment --------
        def compute_env_from_buffer() -> Dict[str, float]:
            if len(gb) == 0:
                return {}
            durations = np.array([r['duration'] for r in gb], dtype=float)
            origs = np.array([r['orig_bytes'] for r in gb], dtype=float)
            probs = np.array([1.0 if r['is_problematic'] else 0.0 for r in gb], dtype=float)
            return {
                'problematic_ratio': float(probs.mean()) if probs.size else self.env_baselines_.get('problematic_ratio', 0.0),
                'duration_std': float(durations.std(ddof=0)) if durations.size else self.env_baselines_.get('duration_std', 0.0),
                'orig_bytes_std': float(origs.std(ddof=0)) if origs.size else self.env_baselines_.get('orig_bytes_std', 0.0)
            }

        env_live = compute_env_from_buffer()
        env_problematic = env_live.get('problematic_ratio', self.env_baselines_.get('problematic_ratio', 0.0))
        env_duration_std = env_live.get('duration_std', self.env_baselines_.get('duration_std', 0.0))
        env_orig_bytes_std = env_live.get('orig_bytes_std', self.env_baselines_.get('orig_bytes_std', 0.0))
        env_interval_std = self.env_baselines_.get('beacon_channel_timediff_std_mean', 0.0)

        # Blend local with environment when data is sparse
        def blend(local: float, env: float, count: int, k: int = 5) -> float:
            try:
                weight = max(0.0, min(1.0, float(count) / float(k)))
                return float(local) * weight + float(env) * (1.0 - weight)
            except Exception:
                return float(local)

        k = max(1, self.min_samples_for_confirm)
        def capped(value: float, cap_multiplier: float, env_ref: float) -> float:
            try:
                cap = max(1.0, cap_multiplier * max(env_ref, 1e-6))
                return float(np.clip(value, 0.0, cap))
            except Exception:
                return float(value)

        if beacon_count >= 2:
            if std_interval > 0.0 and beacon_count >= 4: 
                beacon_channel_timediff_std = blend(capped(std_interval, 10.0, env_interval_std), env_interval_std, max(0, beacon_count - 1), k)
            else:
                beacon_channel_timediff_std = env_interval_std  
            beacon_channel_duration_std = blend(capped(beacon_dur_std, 10.0, env_duration_std), env_duration_std, beacon_count, k)
            beacon_channel_orig_bytes_std = blend(capped(beacon_ob_std, 10.0, env_orig_bytes_std), env_orig_bytes_std, beacon_count, k)
        else:
            beacon_channel_timediff_std = env_interval_std  
            beacon_channel_duration_std = env_duration_std  
            beacon_channel_orig_bytes_std = env_orig_bytes_std  
        horizontal_scan_problematic_ratio = blend(capped(horiz_problematic_ratio, 1.0, 1.0), env_problematic, len(horiz_dq), k)
        vertical_scan_problematic_ratio = blend(capped(vert_problematic_ratio, 1.0, 1.0), env_problematic, len(vert_dq), k)

        features_raw = {
            'horizontal_scan_unique_dst_ip_count': int(horiz_unique_dst_ip),
            'horizontal_scan_problematic_ratio': float(horizontal_scan_problematic_ratio),
            'vertical_scan_unique_dst_port_count': int(vert_unique_dst_port),
            'vertical_scan_problematic_ratio': float(vertical_scan_problematic_ratio),
            'beacon_group_count': int(beacon_count),
            'beacon_group_cv': float(beacon_cv),
            'beacon_channel_timediff_std': float(beacon_channel_timediff_std),
            'beacon_channel_duration_std': float(beacon_channel_duration_std),
            'beacon_channel_orig_bytes_std': float(beacon_channel_orig_bytes_std),
            'ddos_group_unique_src_ip_count': int(ddos_unique_src_ip)
        }
        

        
        # ------- Compute Z-scores using per-entity baseline if available; otherwise environment -------
        eps = 1e-9
        entity = src_ip
        ent_base = self.entity_baselines_.get(entity, {})
        def zs(val: float, mean_key: str, std_key: str, env_mean_key: str, env_std_key: str) -> float:
            mean = ent_base.get(mean_key, self.env_baselines_.get(env_mean_key, 0.0))
            if abs(float(val)) < eps and abs(float(mean)) < eps:
                return 0.0  
            mean = ent_base.get(mean_key, self.env_baselines_.get(env_mean_key, 0.0))
            std = ent_base.get(std_key, self.env_baselines_.get(env_std_key, 1.0))
            if std <= 0:
                std = 1.0
            return (float(val) - float(mean)) / max(float(std), eps)

        z_scores = {
            'z_horizontal_unique_dst_ip_count': zs(features_raw['horizontal_scan_unique_dst_ip_count'],
                                                   'horizontal_unique_dst_ip_count_mean', 'horizontal_unique_dst_ip_count_std',
                                                   'median_horizontal_unique_dst_ip_count', 'std_horizontal_unique_dst_ip_count'),
            'z_horizontal_problematic_ratio': zs(features_raw['horizontal_scan_problematic_ratio'],
                                                 'problematic_ratio_mean', 'problematic_ratio_std',
                                                 'problematic_ratio', 'std_horizontal_problematic_ratio'),
            'z_vertical_unique_dst_port_count': zs(features_raw['vertical_scan_unique_dst_port_count'],
                                                  'vertical_unique_dst_port_count_mean', 'vertical_unique_dst_port_count_std',
                                                  'median_vertical_unique_dst_port_count', 'std_vertical_unique_dst_port_count'),
            'z_vertical_problematic_ratio': zs(features_raw['vertical_scan_problematic_ratio'],
                                               'problematic_ratio_mean', 'problematic_ratio_std',
                                               'problematic_ratio', 'std_vertical_problematic_ratio'),
            # FIXED: Use consistent env_baselines_ keys for beacon features
            'z_beacon_group_count': (features_raw['beacon_group_count'] - self.env_baselines_.get('median_beacon_group_count', 0.0)) / max(self.env_baselines_.get('std_beacon_group_count', 1.0), eps),
            'z_ddos_group_unique_src_ip_count': (features_raw['ddos_group_unique_src_ip_count'] - self.env_baselines_.get('median_ddos_unique_src_ip_count', 0.0)) / max(self.env_baselines_.get('std_ddos_unique_src_ip_count', 1.0), eps),
            'z_beacon_channel_timediff_std': zs(features_raw['beacon_channel_timediff_std'],
                                                'beacon_channel_timediff_std_mean', 'beacon_channel_timediff_std_std',
                                                'beacon_channel_timediff_std_mean', 'beacon_channel_timediff_std_std'),
            # FIXED: Use per-entity baselines for beacon duration and orig_bytes
            'z_beacon_channel_duration_std': zs(features_raw['beacon_channel_duration_std'],
                                                'duration_std_mean', 'duration_std_std',
                                                'duration_std', 'duration_std'),
            'z_beacon_channel_orig_bytes_std': zs(features_raw['beacon_channel_orig_bytes_std'],
                                                  'orig_bytes_std_mean', 'orig_bytes_std_std',
                                                  'orig_bytes_std', 'orig_bytes_std')
        }

        # Final safety: clip z-scores to a reasonable range to prevent extreme values
        for key in list(z_scores.keys()):
            try:
                z_val = float(z_scores[key])
                if np.isnan(z_val) or np.isinf(z_val):
                    z_scores[key] = 0.0
                else:
                    z_scores[key] = float(np.clip(z_val, -8.0, 8.0))
            except Exception:
                z_scores[key] = 0.0

        # ==========================================
        # RETURN BOTH RAW FEATURES AND Z-SCORE FEATURES
        # ==========================================
        # Combine raw features and z-score features into one dictionary
        # This ensures both rule engine (raw) and ML models (z-score) get what they need
        combined_features = {}
        
        # Add raw features for rule engine
        combined_features.update(features_raw)
        
        # Add z-score features for ML models
        combined_features.update(z_scores)
        
        return combined_features

    def _add_connection_to_runtime_state(self, conn_dict: Dict[str, Any]) -> None:
        """Add a connection to the runtime state for group statistics tracking."""
        try:
            ts = float(conn_dict.get('ts', 0) or 0)
            src_ip = str(conn_dict.get('id.orig_h', ''))
            dst_ip = str(conn_dict.get('id.resp_h', ''))
            dst_port = conn_dict.get('id.resp_p')
            proto = conn_dict.get('proto', 'unknown')  # Get protocol for more accurate beacon detection
            
            # Keys for different group types - FIXED: Include protocol in beacon_key for accurate beacon detection
            beacon_key = f"{src_ip}:{dst_ip}:{dst_port}:{proto}"
            horizontal_key = f"{src_ip}:{dst_port}"
            vertical_key = f"{src_ip}:{dst_ip}"
            ddos_key = f"{dst_ip}:{dst_port}"
            
            # Add to beacon groups (with is_problematic field)
            if beacon_key not in self.runtime_state['beacon_groups']:
                self.runtime_state['beacon_groups'][beacon_key] = deque()
            beacon_conn = dict(conn_dict)
            beacon_conn['is_problematic'] = bool(conn_dict.get('conn_state') in self._get_problematic_states())
            self.runtime_state['beacon_groups'][beacon_key].append(beacon_conn)
            
            if horizontal_key not in self.runtime_state['horizontal_groups']:
                self.runtime_state['horizontal_groups'][horizontal_key] = deque()
            horiz_conn = dict(conn_dict)
            horiz_conn['is_problematic'] = bool(conn_dict.get('conn_state') in self._get_problematic_states())
            horiz_conn['dst_ip'] = dst_ip
            self.runtime_state['horizontal_groups'][horizontal_key].append(horiz_conn)
            
            # Add to vertical scan groups (with is_problematic field)
            if vertical_key not in self.runtime_state['vertical_groups']:
                self.runtime_state['vertical_groups'][vertical_key] = deque()
            vert_conn = dict(conn_dict)
            vert_conn['is_problematic'] = bool(conn_dict.get('conn_state') in self._get_problematic_states())
            vert_conn['dst_port'] = dst_port
            self.runtime_state['vertical_groups'][vertical_key].append(vert_conn)
            
            # Add to DDoS groups (with is_problematic field)
            if ddos_key not in self.runtime_state['ddos_groups']:
                self.runtime_state['ddos_groups'][ddos_key] = deque()
            ddos_conn = dict(conn_dict)
            ddos_conn['is_problematic'] = bool(conn_dict.get('conn_state') in self._get_problematic_states())
            # FIXED: Add src_ip field for DDoS calculation
            ddos_conn['src_ip'] = src_ip
            self.runtime_state['ddos_groups'][ddos_key].append(ddos_conn)
            
            # Add to global buffer (with is_problematic field)
            if 'global_buffer' not in self.runtime_state:
                self.runtime_state['global_buffer'] = deque()
            global_conn = dict(conn_dict)
            global_conn['is_problematic'] = bool(conn_dict.get('conn_state') in self._get_problematic_states())
            self.runtime_state['global_buffer'].append(global_conn)             

        except Exception as e:
            pass

    def _get_problematic_states(self) -> set:
        return {
            'REJ', 'S0', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR'
        }