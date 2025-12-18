#!/usr/bin/env python3
"""
Script to show feature mapping from trained models
"""

import json
import os
import sys

# Try to import joblib, fallback if not available
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False
    print("⚠️ joblib not available - will skip pipeline analysis")

def show_feature_mapping(model_dir="model_final1"):
    """Show feature mapping from trained models"""
    
    print("🔍 FEATURE MAPPING ANALYSIS")
    print("=" * 60)
    
    # Load training metadata
    metadata_path = os.path.join(model_dir, "training_metadata_cic_master.json")
    if os.path.exists(metadata_path):
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        print(f"📊 Model Version: {metadata.get('model_version', 'Unknown')}")
        print(f"📊 Input Dimension: {metadata.get('input_dim_after_preprocessing', 'Unknown')}")
        training_samples = metadata.get('training_samples', 'Unknown')
        if isinstance(training_samples, (int, float)):
            print(f"📊 Training Samples: {training_samples:,}")
        else:
            print(f"📊 Training Samples: {training_samples}")
        print()
    
    # Load feature importance data
    ae_importance_path = os.path.join(model_dir, "training_plots", "autoencoder_feature_importance_data.json")
    if os.path.exists(ae_importance_path):
        with open(ae_importance_path, 'r') as f:
            ae_data = json.load(f)
        
        print("🧠 AUTOENCODER FEATURE IMPORTANCE:")
        print("-" * 40)
        
        # Show top 10 most important features
        top_10_features = ae_data.get('top_20_features', [])[-10:]
        top_10_importance = ae_data.get('top_20_importance', [])[-10:]
        
        for i, (feature, importance) in enumerate(zip(top_10_features, top_10_importance), 1):
            print(f"{i:2d}. {feature:<30} {importance:.6f}")
        
        print()
        
        # Show all feature names
        all_features = ae_data.get('feature_names', [])
        print(f"📋 ALL FEATURES ({len(all_features)} total):")
        print("-" * 40)
        
        for i, feature in enumerate(all_features):
            print(f"{i:2d}: {feature}")
    
    # Try to load pipeline to get actual feature names
    if JOBLIB_AVAILABLE:
        pipeline_path = os.path.join(model_dir, "complete_pipeline_cic_master.joblib")
        if os.path.exists(pipeline_path):
            try:
                pipeline = joblib.load(pipeline_path)
                
                print("\n🔧 PIPELINE FEATURE NAMES:")
                print("-" * 40)
                
                if hasattr(pipeline, 'get_feature_names_out'):
                    pipeline_features = pipeline.get_feature_names_out()
                    print(f"✅ Pipeline provides {len(pipeline_features)} feature names:")
                    for i, feature in enumerate(pipeline_features):
                        print(f"{i:2d}: {feature}")
                else:
                    print("⚠️ Pipeline doesn't provide feature names")
                    
            except Exception as e:
                print(f"❌ Failed to load pipeline: {e}")
    else:
        print("\n⚠️ Skipping pipeline analysis (joblib not available)")
    
    print("\n" + "=" * 60)
    print("💡 INTERPRETATION:")
    print("-" * 40)
    print("• Feature_0 to Feature_27: Numerical features (duration, bytes, etc.)")
    print("• Feature_28+: Categorical features (proto, conn_state, etc.)")
    print("• Higher importance = more critical for anomaly detection")
    print("• Autoencoder importance = reconstruction error increase when feature is permuted")

if __name__ == "__main__":
    model_dir = sys.argv[1] if len(sys.argv) > 1 else "model_final1"
    show_feature_mapping(model_dir) 