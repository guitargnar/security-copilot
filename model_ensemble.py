#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ensemble Model System for Advanced Phishing Detection
Combines multiple ML algorithms for superior accuracy
"""
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
import joblib
from pathlib import Path
import json

from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier,
    VotingClassifier,
    AdaBoostClassifier
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, roc_auc_score, confusion_matrix
)

# Import XGBoost and LightGBM if available
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("XGBoost not installed. Install with: pip install xgboost")

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    print("LightGBM not installed. Install with: pip install lightgbm")


class EnsemblePhishingDetector:
    """
    Advanced ensemble model combining multiple algorithms for phishing detection.
    """
    
    def __init__(self, models_dir: str = "models/ensemble"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Individual models
        self.models = {}
        self.model_weights = {}
        self.ensemble = None
        self.calibrated_ensemble = None
        
        # Feature importance tracking
        self.feature_importance = {}
        
        # Performance metrics
        self.performance_metrics = {}
        
    def create_base_models(self) -> Dict:
        """Create diverse base models for ensemble."""
        models = {
            # Linear models
            'logistic_regression': LogisticRegression(
                random_state=42,
                max_iter=1000,
                class_weight='balanced'
            ),
            
            # Tree-based models
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced',
                n_jobs=-1
            ),
            
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            ),
            
            'adaboost': AdaBoostClassifier(
                n_estimators=50,
                learning_rate=1.0,
                random_state=42
            ),
            
            # Probabilistic models
            'naive_bayes': MultinomialNB(alpha=0.1),
            
            # Neural Network
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(100, 50),
                activation='relu',
                solver='adam',
                alpha=0.001,
                max_iter=500,
                random_state=42,
                early_stopping=True
            ),
            
            # Support Vector Machine
            'svm': SVC(
                kernel='rbf',
                probability=True,
                random_state=42,
                class_weight='balanced'
            )
        }
        
        # Add XGBoost if available
        if HAS_XGBOOST:
            models['xgboost'] = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                objective='binary:logistic',
                random_state=42,
                use_label_encoder=False,
                eval_metric='logloss'
            )
        
        # Add LightGBM if available
        if HAS_LIGHTGBM:
            models['lightgbm'] = lgb.LGBMClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                objective='binary',
                random_state=42,
                verbose=-1
            )
        
        return models
    
    def train_individual_models(self, X_train, y_train, X_val=None, y_val=None):
        """Train individual models and evaluate performance."""
        print("🎯 Training Individual Models...")
        print("-" * 50)
        
        self.models = self.create_base_models()
        
        for name, model in self.models.items():
            print(f"\n📊 Training {name}...")
            
            try:
                # Train model
                model.fit(X_train, y_train)
                
                # Evaluate on validation set if provided
                if X_val is not None and y_val is not None:
                    y_pred = model.predict(X_val)
                    y_pred_proba = model.predict_proba(X_val)[:, 1]
                    
                    # Calculate metrics
                    metrics = {
                        'accuracy': accuracy_score(y_val, y_pred),
                        'precision': precision_score(y_val, y_pred),
                        'recall': recall_score(y_val, y_pred),
                        'f1': f1_score(y_val, y_pred),
                        'auc': roc_auc_score(y_val, y_pred_proba)
                    }
                    
                    self.performance_metrics[name] = metrics
                    
                    print(f"  ✅ Accuracy: {metrics['accuracy']:.3f}")
                    print(f"  ✅ Precision: {metrics['precision']:.3f}")
                    print(f"  ✅ Recall: {metrics['recall']:.3f}")
                    print(f"  ✅ F1: {metrics['f1']:.3f}")
                    print(f"  ✅ AUC: {metrics['auc']:.3f}")
                else:
                    # Use cross-validation if no validation set
                    cv_scores = cross_val_score(
                        model, X_train, y_train, 
                        cv=5, scoring='accuracy'
                    )
                    print(f"  ✅ CV Accuracy: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")
                    self.performance_metrics[name] = {'cv_accuracy': cv_scores.mean()}
                
                # Extract feature importance if available
                if hasattr(model, 'feature_importances_'):
                    self.feature_importance[name] = model.feature_importances_
                elif hasattr(model, 'coef_'):
                    self.feature_importance[name] = np.abs(model.coef_[0])
                    
            except Exception as e:
                print(f"  ❌ Error training {name}: {e}")
                self.performance_metrics[name] = {'error': str(e)}
    
    def create_ensemble(self, voting: str = 'soft', weights: Optional[List[float]] = None):
        """Create ensemble model from trained base models."""
        print("\n🔗 Creating Ensemble Model...")
        print("-" * 50)
        
        # Select best performing models for ensemble
        if self.performance_metrics:
            # Sort models by performance
            sorted_models = sorted(
                self.performance_metrics.items(),
                key=lambda x: x[1].get('accuracy', x[1].get('cv_accuracy', 0)),
                reverse=True
            )
            
            # Select top performers
            top_models = []
            for name, metrics in sorted_models[:7]:  # Use top 7 models
                if 'error' not in metrics:
                    top_models.append((name, self.models[name]))
                    print(f"  ✅ Including {name} (Accuracy: {metrics.get('accuracy', metrics.get('cv_accuracy', 0)):.3f})")
        else:
            # Use all models if no metrics available
            top_models = list(self.models.items())
        
        # Create voting classifier
        self.ensemble = VotingClassifier(
            estimators=top_models,
            voting=voting,
            weights=weights,
            n_jobs=-1
        )
        
        print(f"\n📦 Ensemble created with {len(top_models)} models")
        print(f"  Voting: {voting}")
        if weights:
            print(f"  Weights: {weights}")
        
        return self.ensemble
    
    def train_ensemble(self, X_train, y_train):
        """Train the ensemble model."""
        if self.ensemble is None:
            self.create_ensemble()
        
        print("\n🚀 Training Ensemble...")
        self.ensemble.fit(X_train, y_train)
        print("  ✅ Ensemble trained successfully")
        
        # Calibrate probabilities
        print("\n📏 Calibrating probabilities...")
        self.calibrated_ensemble = CalibratedClassifierCV(
            self.ensemble,
            method='sigmoid',
            cv=3
        )
        self.calibrated_ensemble.fit(X_train, y_train)
        print("  ✅ Calibration complete")
    
    def predict(self, X, use_calibrated: bool = True) -> np.ndarray:
        """Make predictions using ensemble."""
        if use_calibrated and self.calibrated_ensemble is not None:
            return self.calibrated_ensemble.predict(X)
        elif self.ensemble is not None:
            return self.ensemble.predict(X)
        else:
            raise ValueError("No ensemble model trained")
    
    def predict_proba(self, X, use_calibrated: bool = True) -> np.ndarray:
        """Get prediction probabilities using ensemble."""
        if use_calibrated and self.calibrated_ensemble is not None:
            return self.calibrated_ensemble.predict_proba(X)
        elif self.ensemble is not None:
            return self.ensemble.predict_proba(X)
        else:
            raise ValueError("No ensemble model trained")
    
    def predict_with_confidence(self, X) -> List[Dict]:
        """
        Make predictions with detailed confidence analysis.
        Returns predictions from individual models and ensemble.
        """
        results = []
        
        # Get predictions from each model
        individual_predictions = {}
        individual_probabilities = {}
        
        for name, model in self.models.items():
            try:
                pred = model.predict(X)
                proba = model.predict_proba(X)[:, 1]
                individual_predictions[name] = pred
                individual_probabilities[name] = proba
            except:
                pass
        
        # Get ensemble prediction
        ensemble_pred = self.predict(X)
        ensemble_proba = self.predict_proba(X)[:, 1]
        
        # Compile results for each sample
        for i in range(len(X)):
            result = {
                'ensemble_prediction': int(ensemble_pred[i]),
                'ensemble_confidence': float(ensemble_proba[i]),
                'individual_votes': {},
                'agreement_score': 0.0
            }
            
            # Collect individual model votes
            votes_phishing = 0
            votes_legitimate = 0
            
            for name in individual_predictions:
                pred = int(individual_predictions[name][i])
                conf = float(individual_probabilities[name][i])
                
                result['individual_votes'][name] = {
                    'prediction': pred,
                    'confidence': conf
                }
                
                if pred == 1:
                    votes_phishing += 1
                else:
                    votes_legitimate += 1
            
            # Calculate agreement score
            total_votes = votes_phishing + votes_legitimate
            if total_votes > 0:
                result['agreement_score'] = max(votes_phishing, votes_legitimate) / total_votes
            
            result['votes_summary'] = {
                'phishing': votes_phishing,
                'legitimate': votes_legitimate
            }
            
            results.append(result)
        
        return results
    
    def evaluate_ensemble(self, X_test, y_test) -> Dict:
        """Comprehensive evaluation of ensemble performance."""
        print("\n📈 Evaluating Ensemble Performance...")
        print("-" * 50)
        
        # Get predictions
        y_pred = self.predict(X_test)
        y_pred_proba = self.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'auc': roc_auc_score(y_test, y_pred_proba)
        }
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        metrics['confusion_matrix'] = {
            'true_negatives': int(cm[0, 0]),
            'false_positives': int(cm[0, 1]),
            'false_negatives': int(cm[1, 0]),
            'true_positives': int(cm[1, 1])
        }
        
        # Print results
        print(f"  🎯 Accuracy: {metrics['accuracy']:.4f}")
        print(f"  🎯 Precision: {metrics['precision']:.4f}")
        print(f"  🎯 Recall: {metrics['recall']:.4f}")
        print(f"  🎯 F1 Score: {metrics['f1']:.4f}")
        print(f"  🎯 AUC-ROC: {metrics['auc']:.4f}")
        
        print(f"\n  📊 Confusion Matrix:")
        print(f"     True Negatives: {metrics['confusion_matrix']['true_negatives']}")
        print(f"     False Positives: {metrics['confusion_matrix']['false_positives']}")
        print(f"     False Negatives: {metrics['confusion_matrix']['false_negatives']}")
        print(f"     True Positives: {metrics['confusion_matrix']['true_positives']}")
        
        return metrics
    
    def save_ensemble(self, filename: str = "ensemble_model.pkl"):
        """Save the ensemble model and metadata."""
        save_path = self.models_dir / filename
        
        # Save ensemble
        joblib.dump({
            'ensemble': self.ensemble,
            'calibrated_ensemble': self.calibrated_ensemble,
            'performance_metrics': self.performance_metrics,
            'feature_importance': self.feature_importance
        }, save_path)
        
        print(f"\n💾 Ensemble saved to {save_path}")
        
        # Save metadata
        metadata_path = self.models_dir / "ensemble_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump({
                'models': list(self.models.keys()),
                'performance': {
                    k: {mk: float(mv) if isinstance(mv, (int, float, np.number)) else str(mv) 
                         for mk, mv in v.items()}
                    for k, v in self.performance_metrics.items()
                },
                'ensemble_type': 'VotingClassifier',
                'calibrated': self.calibrated_ensemble is not None
            }, f, indent=2)
        
        print(f"📄 Metadata saved to {metadata_path}")
    
    def load_ensemble(self, filename: str = "ensemble_model.pkl"):
        """Load a saved ensemble model."""
        load_path = self.models_dir / filename
        
        if not load_path.exists():
            raise FileNotFoundError(f"Model not found: {load_path}")
        
        data = joblib.load(load_path)
        self.ensemble = data['ensemble']
        self.calibrated_ensemble = data.get('calibrated_ensemble')
        self.performance_metrics = data.get('performance_metrics', {})
        self.feature_importance = data.get('feature_importance', {})
        
        print(f"✅ Ensemble loaded from {load_path}")
    
    def get_feature_importance_summary(self, feature_names: Optional[List[str]] = None) -> pd.DataFrame:
        """Get aggregated feature importance from all models."""
        if not self.feature_importance:
            return None
        
        # Create DataFrame
        importance_df = pd.DataFrame(self.feature_importance)
        
        if feature_names and len(feature_names) == len(importance_df):
            importance_df['feature'] = feature_names
            importance_df = importance_df.set_index('feature')
        
        # Calculate mean importance
        importance_df['mean_importance'] = importance_df.mean(axis=1)
        importance_df = importance_df.sort_values('mean_importance', ascending=False)
        
        return importance_df


def create_and_train_ensemble(X_train, y_train, X_val, y_val, 
                             feature_names: Optional[List[str]] = None) -> EnsemblePhishingDetector:
    """
    Convenience function to create and train ensemble model.
    """
    print("=" * 60)
    print("🚀 ENSEMBLE MODEL TRAINING")
    print("=" * 60)
    
    # Initialize ensemble
    ensemble_detector = EnsemblePhishingDetector()
    
    # Train individual models
    ensemble_detector.train_individual_models(X_train, y_train, X_val, y_val)
    
    # Create and train ensemble
    ensemble_detector.create_ensemble(voting='soft')
    ensemble_detector.train_ensemble(X_train, y_train)
    
    # Evaluate on validation set
    metrics = ensemble_detector.evaluate_ensemble(X_val, y_val)
    
    # Get feature importance
    if feature_names:
        importance_df = ensemble_detector.get_feature_importance_summary(feature_names)
        if importance_df is not None:
            print("\n📊 Top 10 Most Important Features:")
            print(importance_df.head(10))
    
    # Save model
    ensemble_detector.save_ensemble()
    
    print("\n" + "=" * 60)
    print("✅ ENSEMBLE TRAINING COMPLETE")
    print("=" * 60)
    
    return ensemble_detector