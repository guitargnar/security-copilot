#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Train Ensemble Model for Enhanced Phishing Detection
Combines multiple ML algorithms for 98%+ accuracy potential
"""
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path
import json
from datetime import datetime

# Import our modules
from model_ensemble import EnsemblePhishingDetector, create_and_train_ensemble
from advanced_features import AdvancedFeatureExtractor
# We'll use our own enhanced synthetic data generator

def prepare_enhanced_features(texts, feature_extractor, vectorizer=None, fit=False):
    """
    Prepare enhanced features combining TF-IDF and advanced features.
    """
    print("🔧 Extracting enhanced features...")
    
    # Extract advanced features for each text
    advanced_features = []
    for i, text in enumerate(texts):
        if i % 100 == 0:
            print(f"  Processing {i}/{len(texts)} samples...")
        features = feature_extractor.extract_all_features(text)
        advanced_features.append(list(features.values()))
    
    advanced_features = np.array(advanced_features)
    print(f"  ✅ Extracted {advanced_features.shape[1]} advanced features")
    
    # TF-IDF features
    if fit:
        print("  📝 Fitting TF-IDF vectorizer...")
        vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=2
        )
        tfidf_features = vectorizer.fit_transform(texts).toarray()
    else:
        print("  📝 Transforming with TF-IDF...")
        tfidf_features = vectorizer.transform(texts).toarray()
    
    print(f"  ✅ Generated {tfidf_features.shape[1]} TF-IDF features")
    
    # Combine features
    combined_features = np.hstack([tfidf_features, advanced_features])
    print(f"  ✅ Total features: {combined_features.shape[1]}")
    
    return combined_features, vectorizer

def generate_enhanced_synthetic_data(n_samples=2000):
    """
    Generate enhanced synthetic training data with more variety.
    """
    print("🎲 Generating enhanced synthetic data...")
    print(f"  Target: {n_samples} samples")
    
    phishing_templates = [
        # Account security
        "URGENT: Your {company} account has been {action}! Click here to {remedy}: {url}",
        "Security Alert: Suspicious activity on your {company} account. Verify now: {url}",
        "Your {company} password expires in 24 hours. Reset it here: {url}",
        
        # Financial
        "You have received ${amount} from {company}. Claim it here: {url}",
        "IRS Tax Refund ${amount} pending. Submit form at: {url}",
        "Your {bank} account will be closed unless you verify: {url}",
        
        # Prizes/Rewards
        "Congratulations! You won ${amount}! Click to claim: {url}",
        "You're the {number}th visitor! Claim your prize: {url}",
        "{company} Rewards: You have {points} points expiring! Redeem: {url}",
        
        # Delivery
        "Your {company} package couldn't be delivered. Reschedule: {url}",
        "Customs fee required for your package. Pay here: {url}",
        "Track your {company} delivery: {url}",
        
        # Verification
        "Verify your {company} account to avoid suspension: {url}",
        "Complete your {company} profile to continue: {url}",
        "Update your payment method for {company}: {url}"
    ]
    
    legitimate_templates = [
        # Newsletters
        "Thank you for subscribing to our {company} newsletter. Here are this week's updates.",
        "Your {company} monthly statement is now available in your account.",
        "{company} News: Check out our latest blog post about {topic}.",
        
        # Confirmations
        "Your {company} order #{order} has been confirmed and will arrive {date}.",
        "Thank you for your purchase from {company}. Your receipt is attached.",
        "Your appointment with {company} is confirmed for {date}.",
        
        # Updates
        "We've updated our privacy policy at {company}. Learn more on our website.",
        "{company} will be performing maintenance on {date}. Some services may be unavailable.",
        "New features are now available in your {company} account.",
        
        # Support
        "Your {company} support ticket #{ticket} has been resolved.",
        "Thank you for contacting {company} support. We'll respond within 24 hours.",
        "Rate your recent experience with {company} customer service."
    ]
    
    companies = ["PayPal", "Amazon", "Netflix", "Apple", "Microsoft", "Google", "Facebook", 
                 "Bank of America", "Chase", "Wells Fargo", "eBay", "Walmart"]
    
    suspicious_urls = [
        "bit.ly/verify", "tinyurl.com/account", "goo.gl/secure",
        "paypal-verify.tk", "amazon-security.ml", "netflix-update.ga",
        "192.168.1.1/login", "http://123.456.789.0/verify",
        "amaz0n.com/account", "paypaI.com/verify", "goog1e.com/security"
    ]
    
    legitimate_urls = [
        "paypal.com/help", "amazon.com/orders", "netflix.com/account",
        "support.apple.com", "account.microsoft.com", "myaccount.google.com"
    ]
    
    emails = []
    labels = []
    
    # Generate phishing emails
    for _ in range(n_samples // 2):
        template = np.random.choice(phishing_templates)
        email = template.format(
            company=np.random.choice(companies),
            action=np.random.choice(["suspended", "compromised", "locked", "flagged"]),
            remedy=np.random.choice(["verify", "confirm", "update", "restore"]),
            url=np.random.choice(suspicious_urls),
            amount=np.random.choice([100, 500, 1000, 5000]),
            bank=np.random.choice(["Chase", "Bank of America", "Wells Fargo"]),
            number=np.random.choice([1000000, 999999, 1000]),
            points=np.random.choice([1000, 5000, 10000]),
            topic=np.random.choice(["security", "updates", "features"]),
            order=np.random.randint(10000, 99999),
            date=np.random.choice(["tomorrow", "next week", "in 3 days"]),
            ticket=np.random.randint(1000, 9999)
        )
        
        # Add urgency indicators randomly
        if np.random.random() > 0.5:
            email = "URGENT! " + email
        if np.random.random() > 0.7:
            email += " Act NOW!"
        
        emails.append(email)
        labels.append(1)  # Phishing
    
    # Generate legitimate emails
    for _ in range(n_samples // 2):
        template = np.random.choice(legitimate_templates)
        email = template.format(
            company=np.random.choice(companies),
            topic=np.random.choice(["security updates", "new features", "community news"]),
            order=np.random.randint(10000, 99999),
            date=np.random.choice(["March 15", "April 1", "May 30"]),
            ticket=np.random.randint(1000, 9999)
        )
        
        emails.append(email)
        labels.append(0)  # Legitimate
    
    print(f"  ✅ Generated {len(emails)} samples")
    print(f"     - Phishing: {sum(labels)}")
    print(f"     - Legitimate: {len(labels) - sum(labels)}")
    
    return emails, labels

def train_ensemble_model():
    """
    Main training pipeline for ensemble model.
    """
    print("=" * 70)
    print("🚀 ENSEMBLE MODEL TRAINING PIPELINE")
    print("=" * 70)
    print()
    
    # Initialize components
    feature_extractor = AdvancedFeatureExtractor()
    
    # Generate or load training data
    print("📊 Preparing training data...")
    
    # Try to load existing data first
    data_path = Path("data/training_data.pkl")
    if data_path.exists():
        print("  📁 Loading existing training data...")
        data = joblib.load(data_path)
        emails = data['emails']
        labels = data['labels']
        print(f"  ✅ Loaded {len(emails)} samples")
    else:
        print("  🎲 Generating new training data...")
        emails, labels = generate_enhanced_synthetic_data(2000)
        
        # Save for future use
        data_path.parent.mkdir(exist_ok=True)
        joblib.dump({'emails': emails, 'labels': labels}, data_path)
        print(f"  💾 Saved training data to {data_path}")
    
    # Split data
    print("\n📂 Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        emails, labels, test_size=0.2, random_state=42, stratify=labels
    )
    print(f"  Training: {len(X_train)} samples")
    print(f"  Testing: {len(X_test)} samples")
    
    # Extract features
    print("\n🔬 Feature Extraction...")
    X_train_features, vectorizer = prepare_enhanced_features(
        X_train, feature_extractor, fit=True
    )
    X_test_features, _ = prepare_enhanced_features(
        X_test, feature_extractor, vectorizer=vectorizer, fit=False
    )
    
    # Scale features
    print("\n⚖️ Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_features)
    X_test_scaled = scaler.transform(X_test_features)
    print(f"  ✅ Features scaled to zero mean and unit variance")
    
    # Create feature names for importance analysis
    tfidf_feature_names = vectorizer.get_feature_names_out().tolist()
    advanced_feature_names = list(feature_extractor.extract_all_features("test").keys())
    all_feature_names = tfidf_feature_names + advanced_feature_names
    
    # Train ensemble
    print("\n" + "=" * 70)
    print("🎯 TRAINING ENSEMBLE MODEL")
    print("=" * 70)
    
    ensemble_detector = EnsemblePhishingDetector(models_dir="models/ensemble")
    
    # Train individual models
    ensemble_detector.train_individual_models(
        X_train_scaled, y_train, 
        X_test_scaled, y_test
    )
    
    # Create and train ensemble
    ensemble_detector.create_ensemble(voting='soft')
    ensemble_detector.train_ensemble(X_train_scaled, y_train)
    
    # Evaluate ensemble
    print("\n" + "=" * 70)
    print("📊 FINAL EVALUATION")
    print("=" * 70)
    
    metrics = ensemble_detector.evaluate_ensemble(X_test_scaled, y_test)
    
    # Get predictions with confidence
    print("\n🔮 Sample Predictions with Confidence:")
    sample_indices = np.random.choice(len(X_test), 3, replace=False)
    sample_features = X_test_scaled[sample_indices]
    sample_predictions = ensemble_detector.predict_with_confidence(sample_features)
    
    for i, (idx, pred) in enumerate(zip(sample_indices, sample_predictions)):
        print(f"\n  Sample {i+1}:")
        print(f"    Text: {X_test[idx][:100]}...")
        print(f"    True Label: {'Phishing' if y_test[idx] == 1 else 'Legitimate'}")
        print(f"    Ensemble: {'Phishing' if pred['ensemble_prediction'] == 1 else 'Legitimate'}")
        print(f"    Confidence: {pred['ensemble_confidence']:.2%}")
        print(f"    Agreement: {pred['agreement_score']:.2%}")
        print(f"    Votes: {pred['votes_summary']}")
    
    # Feature importance
    print("\n📈 Top 20 Most Important Features:")
    importance_df = ensemble_detector.get_feature_importance_summary(all_feature_names)
    if importance_df is not None:
        print(importance_df.head(20)[['mean_importance']])
    
    # Save everything
    print("\n💾 Saving models and components...")
    
    # Save ensemble
    ensemble_detector.save_ensemble("ensemble_model.pkl")
    
    # Save vectorizer and scaler
    joblib.dump(vectorizer, "models/ensemble/vectorizer.pkl")
    joblib.dump(scaler, "models/ensemble/scaler.pkl")
    joblib.dump(feature_extractor, "models/ensemble/feature_extractor.pkl")
    print("  ✅ Saved vectorizer, scaler, and feature extractor")
    
    # Save training metadata
    metadata = {
        'training_date': datetime.now().isoformat(),
        'n_training_samples': len(X_train),
        'n_test_samples': len(X_test),
        'n_features': X_train_scaled.shape[1],
        'test_metrics': {
            k: float(v) if isinstance(v, (int, float, np.number)) else v
            for k, v in metrics.items()
        },
        'feature_composition': {
            'tfidf_features': len(tfidf_feature_names),
            'advanced_features': len(advanced_feature_names)
        }
    }
    
    with open("models/ensemble/training_metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)
    print("  ✅ Saved training metadata")
    
    # Print summary
    print("\n" + "=" * 70)
    print("🎉 ENSEMBLE TRAINING COMPLETE!")
    print("=" * 70)
    print(f"  ✅ Accuracy: {metrics['accuracy']:.2%}")
    print(f"  ✅ Precision: {metrics['precision']:.2%}")
    print(f"  ✅ Recall: {metrics['recall']:.2%}")
    print(f"  ✅ F1 Score: {metrics['f1']:.2%}")
    print(f"  ✅ AUC-ROC: {metrics['auc']:.3f}")
    print()
    print("  📁 Models saved to: models/ensemble/")
    print("  🚀 Ready for integration with API server!")
    print("=" * 70)
    
    return ensemble_detector, metrics

if __name__ == "__main__":
    # Train the ensemble model
    detector, metrics = train_ensemble_model()
    
    # Optionally test on a real example
    print("\n🧪 Quick Test on Real-World Example:")
    test_email = """
    URGENT: Your PayPal account has been suspended due to suspicious activity!
    
    Click here immediately to verify your identity: http://bit.ly/paypal-verify
    
    If you don't act within 24 hours, your account will be permanently closed
    and you will lose access to your $5,000 balance.
    
    This is not a scam - this is official PayPal security.
    """
    
    # Load components
    vectorizer = joblib.load("models/ensemble/vectorizer.pkl")
    scaler = joblib.load("models/ensemble/scaler.pkl")
    feature_extractor = joblib.load("models/ensemble/feature_extractor.pkl")
    
    # Prepare features
    features, _ = prepare_enhanced_features(
        [test_email], feature_extractor, vectorizer=vectorizer, fit=False
    )
    features_scaled = scaler.transform(features)
    
    # Predict
    prediction = detector.predict(features_scaled)[0]
    confidence = detector.predict_proba(features_scaled)[0, 1]
    
    print(f"  Prediction: {'🚨 PHISHING' if prediction == 1 else '✅ LEGITIMATE'}")
    print(f"  Confidence: {confidence:.2%}")