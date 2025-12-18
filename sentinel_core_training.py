#!/usr/bin/env python3
"""
Sentinel-Core Training Pipeline v3.0 - Refactored for DNS Tunneling Detection
This version is refactored into a class-based structure for consistency,
maintainability, and professional code quality, matching the conn.log trainer.
"""

import pandas as pd
import numpy as np
import glob
import math
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from tensorflow.keras.models import Sequential
import re
import argparse
import sys
import json

class DNSTrainingPipeline:
    """
    Encapsulates the entire DNS anomaly detection training pipeline.
    Provides a structured, reusable, and maintainable workflow.
    """
    def __init__(self, args):
        """
        Initializes the pipeline with configuration from command-line arguments.
        """
        self.args = args
        self.df = None
        self.feature_columns = [
            'query_length', 'query_entropy', 'subdomain_count', 'numeric_ratio', 'ngram_score',
            'has_base64_pattern', 'has_hex_pattern', 'has_long_subdomain', 'suspicious_length',
            'char_diversity', 'vowel_consonant_ratio', 'compressed_pattern', 'unusual_tld',
            'avg_ttl', 'min_ttl', 'is_qtype_txt', 'is_qtype_null', 'is_nxdomain'
        ]
        self.X_train_scaled = None
        self.X_val_scaled = None
        self.scaler = None
        self.isolation_model = None
        self.autoencoder_model = None

        self._setup_logging()
        tf.random.set_seed(self.args.random_state)
        np.random.seed(self.args.random_state)

    def _setup_logging(self):
        """Configures logging to file and console."""
        os.makedirs(self.args.output_dir, exist_ok=True)
        log_file = os.path.join(self.args.output_dir, 'dns_training_pipeline.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _calculate_entropy(self, text):
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
        
        # Validation để tránh division by zero và NaN values
        char_diversity = unique_chars / total_chars if total_chars > 0 else 0
        vowel_consonant_ratio = vowel_count / consonant_count if consonant_count > 0 else 0
        
        # Đảm bảo các giá trị không vượt quá giới hạn hợp lý
        char_diversity = min(char_diversity, 1.0)  # Không vượt quá 1.0
        vowel_consonant_ratio = min(vowel_consonant_ratio, 10.0)  # Giới hạn tỷ lệ
        
        return {
            # Nâng cấp regex base64
            'has_base64_pattern': int(bool(re.search(r'[a-zA-Z0-9+/]{20,}', query_str))),
            'has_hex_pattern': int(bool(re.search(r'[0-9a-f]{16,}', query_str))),
            'has_long_subdomain': 1 if max_subdomain_len > 20 else 0,
            'suspicious_length': 1 if len(query_str) > 50 else 0,
            'char_diversity': char_diversity,
            'vowel_consonant_ratio': vowel_consonant_ratio,
            # Sửa regex compressed_pattern
            'compressed_pattern': 1 if re.search(r'([a-z0-9])\1{3,}', query_str) else 0,
            'unusual_tld': 1 if any(tld in query_str for tld in unusual_tlds) else 0
        }

    def _calculate_numeric_ratio(self, text):
        if not text or pd.isna(text):
            return 0
        text_str = str(text)
        if len(text_str) == 0:
            return 0
        # Validation để tránh division by zero
        numeric_ratio = sum(1 for char in text_str if char.isdigit()) / len(text_str)
        # Đảm bảo giá trị không vượt quá 1.0
        return min(numeric_ratio, 1.0)

    def _calculate_ngram_score(self, domain):
        if not domain or pd.isna(domain):
            return 0.0
        domain_str, domain_parts = str(domain).lower(), str(domain).lower().split('.')
        # Gộp tất cả các phần của subdomain lại thành một chuỗi duy nhất để phân tích
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
        if not ttl_string or pd.isna(ttl_string) or ttl_string == '-':
            return {'avg_ttl': 300, 'min_ttl': 300}
        try:
            ttl_values = [float(x.strip()) for x in str(ttl_string).split(',') if x.strip() and x.strip() != '-']
            if ttl_values:
                return {'avg_ttl': np.mean(ttl_values), 'min_ttl': np.min(ttl_values)}
            else:
                return {'avg_ttl': 300, 'min_ttl': 300}
        except (ValueError, TypeError):
            return {'avg_ttl': 300, 'min_ttl': 300}

    def _read_zeek_dns_log(self, file_path):
        try:
            # Bước 1: Mở file và tìm dòng header (#fields) trước
            columns = None
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.startswith('#fields'):
                        columns = line.strip().replace('#fields\t', '').split('\t')
                        break
            # Nếu không tìm thấy header, dùng fallback và ghi log cảnh báo
            if columns is None:
                self.logger.warning(f"No '#fields' header found in {file_path}. Using default columns.")
                columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected']
            # Bước 2: Bây giờ mới dùng pandas để đọc dữ liệu, bỏ qua các dòng comment
            df = pd.read_csv(
                file_path, 
                sep='\t',
                comment='#',
                header=None, # Quan trọng: Không đọc dòng nào làm header
                names=columns, # Dùng header chúng ta đã tìm được ở trên
                na_values=['-'],
                encoding='utf-8',
                on_bad_lines='skip'
            )
            return df
        except Exception as e:
            self.logger.error(f"Error reading {file_path} with pandas: {e}")
            return pd.DataFrame()
        
    def load_and_merge_data(self):
        self.logger.info("PHASE 1: DATA COLLECTION")
        dns_files = glob.glob(self.args.input_pattern)
        self.logger.info(f"Found {len(dns_files)} DNS log files matching pattern: {self.args.input_pattern}")
        if not dns_files:
            raise FileNotFoundError("No DNS log files found!")
        
        all_dataframes = [df for file_path in dns_files if not (df := self._read_zeek_dns_log(file_path)).empty]
        if not all_dataframes:
            raise ValueError("No valid data could be read from any DNS log file!")
        
        self.df = pd.concat(all_dataframes, ignore_index=True)
        self.logger.info(f"Successfully merged data. Total DNS queries: {len(self.df):,}")

    def engineer_features(self):
        self.logger.info("\nPHASE 2: FEATURE ENGINEERING")
        
        for col in ['query', 'qtype_name', 'rcode_name', 'TTLs']:
            if col not in self.df.columns:
                self.df[col] = '-'
        
        self.df['query_length'] = self.df['query'].apply(lambda x: len(str(x)) if pd.notna(x) else 0)
        self.df['subdomain_count'] = self.df['query'].apply(lambda x: str(x).count('.') if pd.notna(x) else 0)
        self.df['query_entropy'] = self.df['query'].apply(self._calculate_entropy)
        self.df['numeric_ratio'] = self.df['query'].apply(self._calculate_numeric_ratio)
        self.df['ngram_score'] = self.df['query'].apply(self._calculate_ngram_score)
        
        # OPTIMIZED: Convert series of dicts to a DataFrame in one-shot for performance.
        self.logger.info("  Applying pattern detection and converting to DataFrame...")
        tunneling_patterns = self.df['query'].apply(self._detect_dns_tunneling_patterns)
        tunneling_df = pd.DataFrame(tunneling_patterns.tolist(), index=self.df.index)

        # Apply the same optimization for TTL parsing.
        ttl_patterns = self.df['TTLs'].apply(self._parse_ttl_values)
        ttl_df = pd.DataFrame(ttl_patterns.tolist(), index=self.df.index)

        # Join the new feature DataFrames back to the main one.
        self.df = self.df.join([tunneling_df, ttl_df])
        
        self.df['is_qtype_txt'] = (self.df['qtype_name'].astype(str).str.upper() == 'TXT').astype(int)
        self.df['is_qtype_null'] = (self.df['qtype_name'].astype(str).str.upper() == 'NULL').astype(int)
        self.df['is_nxdomain'] = (self.df['rcode_name'].astype(str).str.upper() == 'NXDOMAIN').astype(int)
        
        # Ensure all feature columns are present and filled
        self.df[self.feature_columns] = self.df[self.feature_columns].fillna(0)
        self.logger.info(f" Feature engineering complete. Total features: {len(self.feature_columns)}")

    def split_and_preprocess_data(self):
        self.logger.info("\nPHASE 3: DATA SPLITTING & PREPROCESSING")
        if 'ts' in self.df.columns:
            self.df['ts'] = pd.to_numeric(self.df['ts'], errors='coerce')
            self.df.dropna(subset=['ts'], inplace=True)
            df_sorted = self.df.sort_values('ts').reset_index(drop=True)
            self.logger.info("Data sorted by timestamp for time-series split.")
        else:
            self.logger.warning("Timestamp 'ts' not found. Using unsorted data for split.")
            df_sorted = self.df

        split_index = int(len(df_sorted) * 0.8)
        train_df, val_df = df_sorted.iloc[:split_index], df_sorted.iloc[split_index:]
        self.logger.info(f"Train/Validation split: {len(train_df):,} / {len(val_df):,} samples.")

        X_train = train_df[self.feature_columns].copy()
        X_val = val_df[self.feature_columns].copy()

        self.scaler = StandardScaler()
        self.X_train_scaled = self.scaler.fit_transform(X_train)
        self.X_val_scaled = self.scaler.transform(X_val)
        self.logger.info(" Data scaling complete (scaler fitted on training data only).")

    def train_models(self):
        self.logger.info("\nPHASE 4: DUAL-ENGINE TRAINING")
        # --- Isolation Forest ---
        self.logger.info("Training Engine 1: Isolation Forest...")
        self.isolation_model = IsolationForest(
            n_estimators=self.args.iso_estimators,
            contamination=self.args.iso_contamination,
            random_state=self.args.random_state, n_jobs=-1
        )
        self.isolation_model.fit(self.X_train_scaled)
        self.logger.info("Isolation Forest training completed.")

        # --- Autoencoder ---
        self.logger.info("Training Engine 2: Autoencoder...")
        input_dim = self.X_train_scaled.shape[1]
        
        # Build simpler autoencoder with regularization to prevent overfitting
        if input_dim <= 20:  # Small dataset case
            self.logger.info("Building SIMPLE autoencoder for small dataset (preventing overfitting)")
            self.autoencoder_model = tf.keras.Sequential([
                layers.Dense(16, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01)),
                layers.Dropout(0.2),
                layers.Dense(8, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01)),
                layers.Dropout(0.2),
                layers.Dense(8, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01)),
                layers.Dropout(0.2),
                layers.Dense(16, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01)),
                layers.Dropout(0.2),
                layers.Dense(input_dim, activation='linear')
            ])
        else:  # Large dataset case - keep original architecture
            self.logger.info("Building STANDARD autoencoder for large dataset")
            self.autoencoder_model = tf.keras.Sequential([
                layers.Dense(64, activation='relu'),
                layers.Dense(32, activation='relu'),
                layers.Dense(16, activation='relu'),
                layers.Dense(8, activation='relu'),
                layers.Dense(16, activation='relu'),
                layers.Dense(32, activation='relu'),
                layers.Dense(64, activation='relu'),
                layers.Dense(input_dim, activation='linear')
            ])
        
        self.autoencoder_model.compile(optimizer='adam', loss='mean_squared_error')
        
        callbacks = [
            tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True, verbose=1),
            tf.keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.2, patience=5, min_lr=1e-6, verbose=1)
        ]
        
        # Train with history capture for overfitting detection
        self.logger.info(f"Starting Autoencoder training with {self.args.ae_epochs} epochs, batch_size={self.args.ae_batch_size}")
        history = self.autoencoder_model.fit(
            self.X_train_scaled, self.X_train_scaled, epochs=self.args.ae_epochs,
            batch_size=self.args.ae_batch_size, shuffle=True,
            validation_data=(self.X_val_scaled, self.X_val_scaled),
            callbacks=callbacks, verbose=1
        )
        
        # Log training metrics to detect overfitting
        final_train_loss = history.history['loss'][-1]
        final_val_loss = history.history['val_loss'][-1]
        min_val_loss = min(history.history['val_loss'])
        min_val_loss_epoch = history.history['val_loss'].index(min_val_loss) + 1
        
        self.logger.info(f"Autoencoder training completed.")
        self.logger.info(f"  Final training loss: {final_train_loss:.6f}")
        self.logger.info(f"  Final validation loss: {final_val_loss:.6f}")
        self.logger.info(f"  Best validation loss: {min_val_loss:.6f} (epoch {min_val_loss_epoch})")
        
        # Check for overfitting
        if final_val_loss > final_train_loss * 1.5:
            self.logger.warning(f"⚠️  POTENTIAL OVERFITTING DETECTED!")
            self.logger.warning(f"    Validation loss ({final_val_loss:.6f}) is {final_val_loss/final_train_loss:.2f}x higher than training loss ({final_train_loss:.6f})")
        elif final_val_loss > final_train_loss * 1.2:
            self.logger.warning(f"⚠️  Mild overfitting detected - validation loss is {final_val_loss/final_train_loss:.2f}x higher")
        else:
            self.logger.info(f"✅ No overfitting detected - validation loss is {final_val_loss/final_train_loss:.2f}x training loss")
        
        # Save training history for analysis
        history_data = {
            "training_loss": history.history['loss'],
            "validation_loss": history.history['val_loss'],
            "epochs_trained": len(history.history['loss']),
            "final_metrics": {
                "final_train_loss": float(final_train_loss),
                "final_val_loss": float(final_val_loss),
                "best_val_loss": float(min_val_loss),
                "best_val_epoch": min_val_loss_epoch,
                "overfitting_ratio": float(final_val_loss / final_train_loss)
            }
        }
        
        history_path = os.path.join(self.args.output_dir, 'training_history.json')
        with open(history_path, 'w') as f:
            json.dump(history_data, f, indent=2)
        self.logger.info(f"Training history saved: {history_path}")

    def calculate_and_save_thresholds(self):
        """Calculate and save thresholds for both Isolation Forest and Autoencoder."""
        self.logger.info("Calculating thresholds from training data...")
        
        # Calculate Isolation Forest thresholds
        if self.isolation_model:
            try:
                # Get anomaly scores from training data
                iso_scores = self.isolation_model.decision_function(self.X_train_scaled)
                
                # Calculate different percentiles
                # Isolation Forest: lower scores = more anomalous
                threshold_10_percent = np.percentile(iso_scores, 10)  # 10% most anomalous (lowest scores)
                threshold_5_percent = np.percentile(iso_scores, 5)    # 5% most anomalous (lowest scores)
                threshold_1_percent = np.percentile(iso_scores, 1)    # 1% most anomalous (lowest scores)
                
                iso_threshold_data = {
                    "threshold_10_percent": float(threshold_10_percent),
                    "threshold_5_percent": float(threshold_5_percent),
                    "threshold_1_percent": float(threshold_1_percent),
                    "threshold_zero": 0.0,
                    "sample_size": len(self.X_train_scaled),
                    "calculated_on": datetime.now().isoformat(),
                    "model_version": "dns_master",
                    "note": "Thresholds calculated on TRAINING data (normal DNS traffic only). Lower scores = more anomalous for Isolation Forest."
                }
                
                iso_threshold_path = os.path.join(self.args.output_dir, 'dns_iso_threshold.json')
                with open(iso_threshold_path, 'w') as f:
                    json.dump(iso_threshold_data, f, indent=2)
                self.logger.info(f" Isolation Forest thresholds saved: {iso_threshold_path}")
                self.logger.info(f"   - 10% threshold: {threshold_10_percent:.6f} (10% most anomalous)")
                self.logger.info(f"   - 5% threshold: {threshold_5_percent:.6f} (5% most anomalous)")
                self.logger.info(f"   - 1% threshold: {threshold_1_percent:.6f} (1% most anomalous)")
                
            except Exception as e:
                self.logger.error(f"Failed to calculate Isolation Forest thresholds: {e}")
        
        # Calculate Autoencoder threshold
        if self.autoencoder_model:
            try:
                # Get reconstruction errors from training data
                reconstructions = self.autoencoder_model.predict(self.X_train_scaled, verbose=0)
                reconstruction_errors = np.mean(np.square(self.X_train_scaled - reconstructions), axis=1)
                
                # Use 99th percentile for threshold
                ae_threshold = np.percentile(reconstruction_errors, 99)
                
                ae_threshold_data = {
                    "threshold": float(ae_threshold),
                    "sample_size": len(self.X_train_scaled),
                    "calculated_on": datetime.now().isoformat(),
                    "percentile": 99,
                    "model_version": "dns_master"
                }
                
                ae_threshold_path = os.path.join(self.args.output_dir, 'dns_ae_threshold.json')
                with open(ae_threshold_path, 'w') as f:
                    json.dump(ae_threshold_data, f, indent=2)
                self.logger.info(f" Autoencoder threshold saved: {ae_threshold_path}")
                self.logger.info(f"   - 99th percentile threshold: {ae_threshold:.6f}")
                
            except Exception as e:
                self.logger.error(f"Failed to calculate Autoencoder threshold: {e}")

    def save_artifacts(self):
        self.logger.info("\nPHASE 5: SAVING ARTIFACTS")
        output_dir = self.args.output_dir
        
        isolation_path = os.path.join(output_dir, 'dns_tunneling_isolation_forest.pkl')
        autoencoder_path = os.path.join(output_dir, 'dns_tunneling_autoencoder.keras')
        scaler_path = os.path.join(output_dir, 'dns_tunneling_scaler.pkl')

        joblib.dump(self.isolation_model, isolation_path)
        self.autoencoder_model.save(autoencoder_path)
        joblib.dump(self.scaler, scaler_path)
        self.logger.info(f"Models and scaler saved in: {output_dir}")

        # Calculate and save thresholds
        self.calculate_and_save_thresholds()

        metadata = {
            'project': 'DNS Tunneling & Anomaly Detection Pipeline',
            'version': '3.0_REFACTORED',
            'training_parameters': vars(self.args),
            'features': {'total_count': len(self.feature_columns), 'list': self.feature_columns},
            'training_data_summary': {
                'total_samples': len(self.df),
                'train_samples': len(self.X_train_scaled),
                'val_samples': len(self.X_val_scaled),
                'training_date': datetime.now().isoformat()
            }
        }
        metadata_path = os.path.join(output_dir, 'dns_pipeline_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=4)
        self.logger.info(f"Pipeline metadata saved: {metadata_path}")

    def run_pipeline(self):
        """Executes the full training pipeline in sequence."""
        self.logger.info("="*70)
        self.logger.info("Starting DNS Training Pipeline v3.0 (Refactored)")
        self.logger.info(f"Configuration: {vars(self.args)}")
        self.logger.info("="*70)
        try:
            self.load_and_merge_data()
            self.engineer_features()
            self.split_and_preprocess_data()
            self.train_models()
            self.save_artifacts()
            self.logger.info("\n" + "="*70)
            self.logger.info("DNS TRAINING PIPELINE COMPLETED SUCCESSFULLY!")
            self.logger.info("="*70)
            return True
        except (FileNotFoundError, ValueError, Exception) as e:
            self.logger.error(f"PIPELINE FAILED: {e}", exc_info=True)
            return False

def main():
    """Parses command-line arguments and runs the training pipeline."""
    parser = argparse.ArgumentParser(
        description="Sentinel-Core v3.0: DNS Tunneling Detection Training Pipeline",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--input-pattern', type=str, default="./data/final_dns_lab.log", help='Glob pattern for input Zeek DNS log files.')
    parser.add_argument('--output-dir', type=str, default='model_dns_lab', help='Directory to save models and artifacts.')
    parser.add_argument('--iso-estimators', type=int, default=500, help='Number of estimators for Isolation Forest.')
    parser.add_argument('--iso-contamination', type=float, default=0.005, help='Contamination factor for Isolation Forest.')
    parser.add_argument('--ae-epochs', type=int, default=150, help='Number of training epochs for Autoencoder.')
    parser.add_argument('--ae-batch-size', type=int, default=128, help='Batch size for Autoencoder training.')
    parser.add_argument('--random-state', type=int, default=42, help='Random state for reproducibility.')
    args = parser.parse_args()

    pipeline = DNSTrainingPipeline(args)
    success = pipeline.run_pipeline()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 