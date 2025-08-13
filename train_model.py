#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Machine Learning Model Training for Phishing Detection
Generates synthetic dataset and trains a LogisticRegression classifier.
"""

import os
import random
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib


def generate_synthetic_dataset():
    """
    Generate synthetic phishing and legitimate email samples.
    
    Returns:
        DataFrame with email text and labels
    """
    
    # Templates for phishing emails
    phishing_templates = [
        "URGENT: Your {account} account will be suspended! Click here to verify your password immediately.",
        "Congratulations! You've won ${amount}! Click this link to claim your prize: {url}",
        "Security Alert: Suspicious activity on your {account}. Verify your identity now or lose access.",
        "Your {account} password expires in 24 hours. Update it here: {url}",
        "IMPORTANT: Confirm your account details to avoid suspension. Act now!",
        "Limited time offer! Get {discount}% off. Click here before it expires!",
        "Your payment of ${amount} failed. Update your payment method immediately at {url}",
        "Warning: Your {account} has been compromised. Reset password here: {url}",
        "IRS Tax Refund: You're eligible for ${amount}. Claim here: {url}",
        "Your package delivery failed. Reschedule here: {url} within 24 hours.",
        "Verify your email to receive ${amount} transfer. Click: {url}",
        "FINAL NOTICE: Your {account} will be closed. Prevent this now!",
        "You have (1) new voicemail. Listen here: {url}",
        "Account locked due to suspicious activity. Unlock here: {url}",
        "Congratulations! You're our lucky winner! Claim ${amount} now!",
        "Update required for {account}. Install now to maintain access: {url}",
        "Your subscription expires today! Renew here: {url} to keep your data.",
        "Bank notification: Unusual transaction detected. Verify: {url}",
        "Free gift card worth ${amount}! Limited quantity - act fast!",
        "Your {account} storage is full. Upgrade now or lose your files: {url}"
    ]
    
    # Templates for legitimate emails
    legitimate_templates = [
        "Thank you for your recent purchase. Your order #{order} has been shipped and will arrive soon.",
        "Your monthly statement for {account} is now available. You can view it in your account dashboard.",
        "Welcome to our newsletter! We're excited to share updates about our products and services.",
        "Your appointment is confirmed for {date}. Please arrive 15 minutes early.",
        "Thank you for contacting customer support. Your ticket #{ticket} has been received.",
        "Here's your weekly digest of activity on your {account} account.",
        "Your order #{order} has been delivered. We hope you enjoy your purchase!",
        "Reminder: Your next bill of ${amount} is due on {date}. No action needed if autopay is enabled.",
        "Thank you for your feedback. We appreciate your time and insights.",
        "Your reservation is confirmed. Confirmation number: {confirmation}",
        "Meeting reminder: {meeting} scheduled for tomorrow at {time}.",
        "Your monthly report is ready. Key highlights included below.",
        "Thank you for being a valued customer. Enjoy these exclusive member benefits.",
        "Your subscription renewal was successful. Next billing date: {date}",
        "New features are now available in your {account} account. Learn more in our help center.",
        "Your receipt for order #{order}. Total: ${amount}. Thank you for your business.",
        "Quarterly newsletter: Industry insights and company updates inside.",
        "Your data export is complete. Download link valid for 7 days.",
        "Service maintenance scheduled for {date}. Expected downtime: 2 hours.",
        "Thank you for attending our webinar. Recording and resources attached."
    ]
    
    # Variables for template filling
    accounts = ['PayPal', 'Amazon', 'Netflix', 'Apple', 'Google', 'Microsoft', 'Bank of America', 'Chase']
    urls = ['bit.ly/x7k9m', 'tinyurl.com/abc123', 'shorturl.at/zxc456', '192.168.1.1/verify', 'verify-account.com']
    legitimate_urls = ['account.company.com', 'support.service.com', 'help.product.com']
    amounts = [100, 500, 1000, 5000, 10000]
    discounts = [25, 50, 70, 90]
    
    # Generate dataset
    emails = []
    labels = []
    
    # Generate phishing emails
    for _ in range(500):
        template = random.choice(phishing_templates)
        email = template.format(
            account=random.choice(accounts),
            url=random.choice(urls),
            amount=random.choice(amounts),
            discount=random.choice(discounts),
            order=random.randint(10000, 99999),
            ticket=random.randint(1000, 9999),
            date="2024-01-15",
            time="2:00 PM",
            confirmation="CNF" + str(random.randint(100000, 999999)),
            meeting="Team Sync"
        )
        
        # Add variations
        if random.random() > 0.5:
            email = email.upper()  # Some phishing emails use all caps
        if random.random() > 0.7:
            email += "!!!"  # Add urgency markers
            
        emails.append(email)
        labels.append(1)  # 1 for phishing
    
    # Generate legitimate emails  
    for _ in range(500):
        template = random.choice(legitimate_templates)
        email = template.format(
            account=random.choice(accounts),
            url=random.choice(legitimate_urls),
            amount=random.choice(amounts),
            order=random.randint(10000, 99999),
            ticket=random.randint(1000, 9999),
            date="2024-01-15",
            time="2:00 PM",
            confirmation="CNF" + str(random.randint(100000, 999999)),
            meeting="Team Sync"
        )
        
        # Add footer to some legitimate emails
        if random.random() > 0.5:
            email += "\n\nTo unsubscribe from these emails, click here. Privacy Policy | Terms of Service"
            
        emails.append(email)
        labels.append(0)  # 0 for legitimate
    
    # Create DataFrame
    df = pd.DataFrame({
        'email_text': emails,
        'label': labels
    })
    
    # Shuffle the dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return df


def train_model(df):
    """
    Train a LogisticRegression model on the email dataset.
    
    Args:
        df: DataFrame with 'email_text' and 'label' columns
        
    Returns:
        Tuple of (trained_model, vectorizer, metrics_dict)
    """
    
    print("📊 Preparing data for training...")
    
    # Split features and labels
    X = df['email_text']
    y = df['label']
    
    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"  Training samples: {len(X_train)}")
    print(f"  Testing samples: {len(X_test)}")
    
    # Create TF-IDF vectorizer
    print("\n🔤 Creating TF-IDF features...")
    vectorizer = TfidfVectorizer(
        max_features=1000,  # Use top 1000 features
        stop_words='english',  # Remove common English words
        ngram_range=(1, 2),  # Use unigrams and bigrams
        min_df=2,  # Ignore terms that appear in less than 2 documents
        max_df=0.95  # Ignore terms that appear in more than 95% of documents
    )
    
    # Transform text to features
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    print(f"  Feature dimensions: {X_train_tfidf.shape[1]}")
    
    # Train LogisticRegression model
    print("\n🤖 Training LogisticRegression model...")
    model = LogisticRegression(
        random_state=42,
        max_iter=1000,
        class_weight='balanced'  # Handle any class imbalance
    )
    
    model.fit(X_train_tfidf, y_train)
    
    # Make predictions
    y_pred = model.predict(X_test_tfidf)
    y_pred_proba = model.predict_proba(X_test_tfidf)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n✅ Training complete!")
    print(f"  Accuracy: {accuracy:.2%}")
    
    # Generate classification report
    print("\n" + "="*60)
    print("📈 CLASSIFICATION REPORT")
    print("="*60)
    report = classification_report(
        y_test, y_pred,
        target_names=['Legitimate', 'Phishing'],
        digits=3
    )
    print(report)
    
    # Generate confusion matrix
    print("📊 CONFUSION MATRIX")
    print("-"*40)
    cm = confusion_matrix(y_test, y_pred)
    print("             Predicted")
    print("             Legit  Phish")
    print(f"Actual Legit   {cm[0,0]:3d}    {cm[0,1]:3d}")
    print(f"       Phish   {cm[1,0]:3d}    {cm[1,1]:3d}")
    print("="*60)
    
    # Get feature importance (top words for phishing)
    feature_names = vectorizer.get_feature_names_out()
    coef = model.coef_[0]
    top_phishing_indices = coef.argsort()[-20:][::-1]
    top_phishing_words = [feature_names[i] for i in top_phishing_indices]
    
    print("\n🔍 Top 20 Phishing Indicators:")
    print("-"*40)
    for i, (word, score) in enumerate(zip(top_phishing_words, coef[top_phishing_indices]), 1):
        print(f"{i:2d}. {word:20s} (score: {score:.3f})")
    
    metrics = {
        'accuracy': accuracy,
        'report': report,
        'confusion_matrix': cm,
        'top_features': top_phishing_words[:10]
    }
    
    return model, vectorizer, metrics


def save_models(model, vectorizer, model_dir='models'):
    """
    Save the trained model and vectorizer to disk.
    
    Args:
        model: Trained sklearn model
        vectorizer: Fitted TfidfVectorizer
        model_dir: Directory to save models
    """
    
    # Create models directory if it doesn't exist
    os.makedirs(model_dir, exist_ok=True)
    
    # Save model
    model_path = os.path.join(model_dir, 'phishing_clf.pkl')
    joblib.dump(model, model_path)
    print(f"\n💾 Model saved to: {model_path}")
    
    # Save vectorizer
    vectorizer_path = os.path.join(model_dir, 'tfidf_vec.pkl')
    joblib.dump(vectorizer, vectorizer_path)
    print(f"💾 Vectorizer saved to: {vectorizer_path}")
    
    # Save metadata
    metadata = {
        'model_type': 'LogisticRegression',
        'vectorizer_type': 'TfidfVectorizer',
        'training_samples': 1000,
        'features': vectorizer.max_features,
        'ngram_range': vectorizer.ngram_range
    }
    
    metadata_path = os.path.join(model_dir, 'model_metadata.pkl')
    joblib.dump(metadata, metadata_path)
    print(f"💾 Metadata saved to: {metadata_path}")
    
    return model_path, vectorizer_path


def main():
    """Main training pipeline."""
    
    print("🚀 PHISHING DETECTOR MODEL TRAINING")
    print("="*60)
    
    # Generate synthetic dataset
    print("\n📧 Generating synthetic email dataset...")
    df = generate_synthetic_dataset()
    print(f"  Generated {len(df)} email samples")
    print(f"  Phishing emails: {df['label'].sum()}")
    print(f"  Legitimate emails: {len(df) - df['label'].sum()}")
    
    # Train model
    model, vectorizer, metrics = train_model(df)
    
    # Save models
    print("\n💾 Saving trained models...")
    model_path, vec_path = save_models(model, vectorizer)
    
    # Final summary
    print("\n" + "="*60)
    print("🎉 TRAINING COMPLETE!")
    print("="*60)
    print(f"  Model accuracy: {metrics['accuracy']:.2%}")
    print(f"  Model saved: {model_path}")
    print(f"  Vectorizer saved: {vec_path}")
    print("\n  Top phishing indicators detected:")
    for i, word in enumerate(metrics['top_features'][:5], 1):
        print(f"    {i}. {word}")
    print("\n✅ Models are ready for integration!")
    print("="*60)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())