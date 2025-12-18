#!/usr/bin/env python
"""
IP Profiler Module for Network Anomaly Detection

This module provides IP profiling functionality for both training and runtime phases,
generating behavioral features that are crucial for detecting network anomalies.

Key Features Generated (matching train_enhanced_models.py exactly):
- concurrent_connections: Number of concurrent active connections
- ip_profile_uid_rate: Connection rate per IP within time window
- ip_profile_id.resp_p_rate: Unique destination ports per IP
- ip_profile_id.resp_h_rate: Unique destination hosts per IP  
- ip_profile_conn_state_diversity: Unique connection states per IP
- ip_profile_mean_duration: Mean connection duration per IP
- ip_profile_mean_orig_bytes: Mean bytes originated per IP

UNIFIED APPROACH: Single class handles both training (batch) and runtime (stream)
with identical sliding window logic for 100% consistency.
"""

import pandas as pd
from typing import Dict, Any, Optional, List
import numpy as np

from collections import deque
from datetime import datetime

class UnifiedIPProfiler:
    """
    IP Profiler HỢP NHẤT cho cả training (batch) và runtime (stream).
    Sử dụng cùng một logic cửa sổ trượt để đảm bảo tính nhất quán 100%
    và hiệu năng cao cho xử lý thời gian thực.
    
    Features Generated:
    - concurrent_connections: Active connections at each timestamp
    - ip_profile_uid_rate: Connection rate per IP within time window
    - ip_profile_id.resp_p_rate: Unique destination ports per IP
    - ip_profile_id.resp_h_rate: Unique destination hosts per IP  
    - ip_profile_conn_state_diversity: Unique connection states per IP
    - ip_profile_mean_duration: Mean connection duration per IP
    - ip_profile_mean_orig_bytes: Mean bytes originated per IP
    """

    def __init__(self, time_window_seconds: int = 300):
        """
        Initialize the unified IP profiler.

        Args:
            time_window_seconds (int): Time window in seconds for rolling calculations
        """
        self.time_window_seconds = time_window_seconds
        
        # Cấu trúc dữ liệu để LƯU TRỮ TRẠNG THÁI cho chế độ runtime
        # Key là 'id.orig_h', value là một dictionary chứa trạng thái của IP đó
        self.ip_states: Dict[str, Dict[str, Any]] = {}
        
        # Cleanup tracking for runtime mode
        self.last_cleanup = datetime.now().timestamp()
        self.cleanup_interval = 300  # 5 minutes

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        """Safely convert values to float; handle '', '-', None, and bad types."""
        try:
            if value is None:
                return default
            if isinstance(value, (int, float)):
                return float(value)
            s = str(value).strip()
            if s == '' or s == '-':
                return default
            return float(s)
        except (ValueError, TypeError):
            return default

    # --- HÀM CHO TRAINING (BATCH) ---
    def create_training_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Xử lý dữ liệu batch (DataFrame) cho quá trình training.
        Hàm này không lưu trạng thái và được tối ưu cho dữ liệu lớn.
        
        Args:
            df (pd.DataFrame): Input training data sorted by timestamp
            
        Returns:
            pd.DataFrame: Original data with IP profiling features added
        """
        if df.empty:
            return df

        # Ensure timestamp format
        df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
        df.dropna(subset=['ts'], inplace=True)
        df['ts_datetime'] = pd.to_datetime(df['ts'], unit='s')
        df = df.sort_values('ts_datetime').reset_index(drop=True)

        # Calculate concurrent connections
        df = self._calculate_concurrent_connections_batch(df)

        
        all_grouped_features = []
        # Groupby và áp dụng logic sliding window cho từng IP
        for name, group in df.groupby('id.orig_h'):
            if group.empty:
                continue
            
            # Sử dụng logic sliding window hiệu quả
            features_df = self._apply_sliding_window_to_group(name, group)
            if not features_df.empty:
                all_grouped_features.append(features_df)

        if not all_grouped_features:
            df.drop(columns=['ts_datetime'], inplace=True, errors='ignore')
            return df
            
        final_features = pd.concat(all_grouped_features).reset_index()
        
        # Merge features back to original dataframe
        df_enriched = pd.merge(df, final_features, on=['ts_datetime', 'id.orig_h'], how='left')
        
        # Điền các giá trị thiếu
        fill_cols = [col for col in df_enriched.columns if 'ip_profile' in col]
        if fill_cols:
            df_enriched = df_enriched.sort_values(['id.orig_h', 'ts_datetime'])
            # Use backward fill (bfill) instead of forward fill to avoid data leakage
            # This ensures each connection gets features based on its own timestamp, not future data
            df_enriched[fill_cols] = df_enriched.groupby('id.orig_h')[fill_cols].bfill().fillna(0)

        df_enriched.drop(columns=['ts_datetime'], inplace=True, errors='ignore')
        
        return df_enriched

    # --- HÀM CHO RUNTIME (STREAM/INCREMENTAL) ---
    def process_connection_incremental(self, conn_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Xử lý một kết nối đơn lẻ (stream), cập nhật trạng thái và trả về feature.
        Sử dụng CÙNG MỘT logic như create_training_features.
        
        Args:
            conn_dict: Connection dictionary with basic features
            
        Returns:
            Connection dictionary with IP profiling features added
        """
        try:
            source_ip = conn_dict.get('id.orig_h')
            current_time = self._safe_float(conn_dict.get('ts'), 0.0)

            if not source_ip or not current_time:
                return self._get_default_features(conn_dict)

            # Clean up old connections periodically
            current_timestamp = datetime.now().timestamp()
            if current_timestamp - self.last_cleanup > self.cleanup_interval:
                self._cleanup_old_connections(current_timestamp)
                self.last_cleanup = current_timestamp

            # Lấy hoặc tạo mới trạng thái cho IP này
            state = self.ip_states.setdefault(source_ip, {
                'window': deque(), 'port_freq': {}, 'host_freq': {}, 'state_freq': {},
                'dur_sum': 0.0, 'bytes_sum': 0.0
            })
            
            # --- Áp dụng chính xác logic sliding window ---
            self._update_window(state, conn_dict, current_time)
            
            # Tính toán và trả về các feature từ trạng thái hiện tại của cửa sổ
            features = self._calculate_features_from_state(state)
            
            # Calculate concurrent connections for runtime
            concurrent_count = self._calculate_concurrent_connections_runtime(current_time)
            features['concurrent_connections'] = concurrent_count
            
            conn_dict.update(features)
            
            return conn_dict
            
        except Exception as e:
            self.logger.error(f" process_connection_incremental failed: {e}")
            # Return original connection dict on error
            return self._get_default_features(conn_dict)

    def process_connections_batch(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Xử lý một lô kết nối và trả về các feature IP Profiling.
        
        Args:
            connections: List of connection dictionaries
            
        Returns:
            List of connection dictionaries with IP profiling features added
        """
        if not connections:
            return []
        
        
        # Bước 1: Cập nhật toàn bộ trạng thái trước
        for conn in connections:
            source_ip = conn.get('id.orig_h', '')
            timestamp = self._safe_float(conn.get('ts'), 0.0)
            
            if source_ip and timestamp:
                # Lấy hoặc tạo mới trạng thái cho IP này
                state = self.ip_states.setdefault(source_ip, {
                    'window': deque(), 'port_freq': {}, 'host_freq': {}, 'state_freq': {},
                    'dur_sum': 0.0, 'bytes_sum': 0.0
                })
                
                # Cập nhật cửa sổ trượt
                self._update_window(state, conn, timestamp)
        
        # Bước 2: Tính toán feature cho từng connection
        batch_results = []
        for conn in connections:
            source_ip = conn.get('id.orig_h', '')
            timestamp = self._safe_float(conn.get('ts'), 0.0)
            
            if not source_ip or not timestamp:
                # Return default features for invalid connections
                result = self._get_default_features(conn.copy())
            else:
                # Lấy trạng thái hiện tại và tính feature
                state = self.ip_states.get(source_ip)
                if state:
                    features = self._calculate_features_from_state(state)
                    concurrent_count = self._calculate_concurrent_connections_runtime(timestamp)
                    features['concurrent_connections'] = concurrent_count
                    
                    result = conn.copy()
                    result.update(features)
                else:
                    result = self._get_default_features(conn.copy())
            
            batch_results.append(result)
        
        return batch_results

    def _apply_sliding_window_to_group(self, ip_name: str, group_df: pd.DataFrame) -> pd.DataFrame:
        """Logic sliding window cốt lõi, dùng cho cả batch và có thể tái sử dụng"""
        features_list = []
        state = {
            'window': deque(), 'port_freq': {}, 'host_freq': {}, 'state_freq': {},
            'dur_sum': 0.0, 'bytes_sum': 0.0
        }

        for idx, row in group_df.iterrows():
            conn_dict = row.to_dict()
            current_time = float(conn_dict['ts'])
            self._update_window(state, conn_dict, current_time)
            
            features = self._calculate_features_from_state(state)
            features['ts_datetime'] = row['ts_datetime']
            features['id.orig_h'] = ip_name
            features_list.append(features)

        return pd.DataFrame(features_list)

    def _update_window(self, state: Dict, conn_dict: Dict, current_time: float):
        """Cập nhật một cửa sổ trượt với một kết nối mới (thêm mới, bỏ cũ)"""
        window: deque = state['window']
        window_start = current_time - self.time_window_seconds

        # 1. Evict (loại bỏ) các entry cũ
        while window and float(window[0]['ts']) < window_start:
            old = window.popleft()
            state['dur_sum'] -= old.get('duration', 0)
            state['bytes_sum'] -= old.get('orig_bytes', 0)
            self._update_freq_map(state['port_freq'], old.get('id.resp_p'), -1)
            self._update_freq_map(state['host_freq'], old.get('id.resp_h'), -1)
            self._update_freq_map(state['state_freq'], old.get('conn_state'), -1)

        # 2. Add (thêm) entry mới
        new_entry = {
            'ts': current_time,
            'id.resp_p': conn_dict.get('id.resp_p'),
            'id.resp_h': conn_dict.get('id.resp_h'),
            'conn_state': conn_dict.get('conn_state'),
            'duration': self._safe_float(conn_dict.get('duration'), 0.0),
            'orig_bytes': self._safe_float(conn_dict.get('orig_bytes'), 0.0)
        }
        window.append(new_entry)
        
        state['dur_sum'] += new_entry['duration']
        state['bytes_sum'] += new_entry['orig_bytes']
        self._update_freq_map(state['port_freq'], new_entry['id.resp_p'], 1)
        self._update_freq_map(state['host_freq'], new_entry['id.resp_h'], 1)
        self._update_freq_map(state['state_freq'], new_entry['conn_state'], 1)

    def _calculate_features_from_state(self, state: Dict) -> Dict:
        """Tính toán các feature từ trạng thái hiện tại của cửa sổ"""
        count = len(state['window'])
        return {
            'ip_profile_uid_rate': float(count),
            'ip_profile_id.resp_p_rate': float(len(state['port_freq'])),
            'ip_profile_id.resp_h_rate': float(len(state['host_freq'])),
            'ip_profile_conn_state_diversity': float(len(state['state_freq'])),
            'ip_profile_mean_duration': state['dur_sum'] / count if count else 0.0,
            'ip_profile_mean_orig_bytes': state['bytes_sum'] / count if count else 0.0
        }

    def _update_freq_map(self, freq_map: Dict, key: Any, delta: int):
        """Cập nhật frequency map với delta"""
        if key is None: return
        freq_map[key] = freq_map.get(key, 0) + delta
        if freq_map[key] == 0:
            del freq_map[key]
            
    def _get_default_features(self, conn_dict: Dict) -> Dict:
        """Trả về feature mặc định khi có lỗi"""
        features = {
            'concurrent_connections': 1.0,
            'ip_profile_uid_rate': 1.0,
            'ip_profile_id.resp_p_rate': 1.0,
            'ip_profile_id.resp_h_rate': 1.0,
            'ip_profile_conn_state_diversity': 1.0,
            'ip_profile_mean_duration': self._safe_float(conn_dict.get('duration'), 0.0),
            'ip_profile_mean_orig_bytes': self._safe_float(conn_dict.get('orig_bytes'), 0.0)
        }
        return features
        
    def _calculate_concurrent_connections_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """Tính concurrent connections cho chế độ batch, sử dụng thuật toán sweep-line."""
        
        if not all(col in df.columns for col in ['ts', 'duration']):
            raise ValueError("DataFrame must contain 'ts' and 'duration' columns.")
        
        df['duration'] = pd.to_numeric(df['duration'], errors='coerce').fillna(0)
        
        # Sort by timestamp for proper processing
        df_sorted = df.sort_values('ts').reset_index(drop=True)
        
        # Vectorized sweep-line using searchsorted (O(n log n))
        starts = df_sorted['ts'].to_numpy()
        ends = starts + df_sorted['duration'].to_numpy()
        
        starts_sorted = np.sort(starts)
        ends_sorted = np.sort(ends)
        
        # Đếm số kết nối bắt đầu <= t và số kết nối kết thúc < t
        num_starts_le_t = np.searchsorted(starts_sorted, starts, side='right')
        num_ends_lt_t = np.searchsorted(ends_sorted, starts, side='left')
        
        concurrent_counts = (num_starts_le_t - num_ends_lt_t).astype(int)
        
        df_sorted['concurrent_connections'] = concurrent_counts
        
        # Restore original order
        return df_sorted.sort_index()

    def _calculate_concurrent_connections_runtime(self, current_timestamp: float) -> float:
        """Calculate concurrent connections at current timestamp for runtime mode."""
        try:
            concurrent_count = 0
            for ip_state in self.ip_states.values():
                window = ip_state.get('window', deque())
                for conn in window:
                    start_time = conn['ts']
                    end_time = start_time + conn['duration']
                    
                    # Điều kiện đúng: Phải BẮT ĐẦU TRƯỚC (hoặc bằng) và KẾT THÚC SAU (hoặc bằng) thời điểm hiện tại
                    if start_time <= current_timestamp and end_time >= current_timestamp:
                        concurrent_count += 1
            
            return float(concurrent_count)
        except Exception as e:
            self.logger.error(f" _calculate_concurrent_connections_runtime failed: {e}")
            return 1.0

    def _cleanup_old_connections(self, current_time: float):
        """Clean up old connections to prevent memory bloat."""
        try:
            cutoff_time = current_time - self.time_window_seconds
            
            for source_ip in list(self.ip_states.keys()):
                state = self.ip_states[source_ip]
                window = state['window']
                
                # Remove old connections from window
                while window and float(window[0]['ts']) < cutoff_time:
                    old = window.popleft()
                    # Update sums and freqs
                    state['dur_sum'] -= old.get('duration', 0)
                    state['bytes_sum'] -= old.get('orig_bytes', 0)
                    self._update_freq_map(state['port_freq'], old.get('id.resp_p'), -1)
                    self._update_freq_map(state['host_freq'], old.get('id.resp_h'), -1)
                    self._update_freq_map(state['state_freq'], old.get('conn_state'), -1)
                
                # Remove IP if no recent connections
                if not window:
                    del self.ip_states[source_ip]
                    
        except Exception as e:
            self.logger.error(f" _cleanup_old_connections failed: {e}")

    def get_feature_names(self) -> List[str]:
        """Get list of feature names generated by this profiler."""
        return [
            'concurrent_connections',
            'ip_profile_uid_rate',
            'ip_profile_id.resp_p_rate',
            'ip_profile_id.resp_h_rate',
            'ip_profile_conn_state_diversity',
            'ip_profile_mean_duration',
            'ip_profile_mean_orig_bytes'
        ]

    def reset(self):
        """Reset all tracking data (useful for testing)."""
        self.ip_states.clear()
        self.last_cleanup = datetime.now().timestamp()

# Backward compatibility aliases
TrainingIPProfiler = UnifiedIPProfiler
RuntimeIPProfiler = UnifiedIPProfiler
IPProfiler = UnifiedIPProfiler 