#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for Enhanced Security Copilot features
"""
import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

def test_health():
    """Test enhanced health endpoint"""
    response = requests.get(f"{BASE_URL}/health")
    print("🏥 Enhanced Health Check:")
    data = response.json()
    print(f"  Version: {data.get('version')}")
    print(f"  Features: {json.dumps(data.get('features', {}), indent=4)}")
    print()

def test_enhanced_classification():
    """Test email classification with advanced features"""
    print("📧 ENHANCED EMAIL CLASSIFICATION:")
    print("-" * 40)
    
    email = """
    URGENT: Your PayPal account has been suspended!
    
    Click here to verify: http://bit.ly/paypal-verify
    
    Dear Customer,
    Your account will be closed in 24 hours unless you verify your identity.
    Act now to avoid losing access to your $5,000 balance!
    
    This is not a scam!!!
    """
    
    response = requests.post(
        f"{BASE_URL}/classify",
        json={
            "email_text": email,
            "include_advanced_features": True
        }
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"  Classification: {result['classification']}")
        print(f"  Confidence: {result['confidence']:.2%}")
        
        if result.get('url_analysis'):
            print("\n  URL Analysis:")
            for url_info in result['url_analysis']:
                print(f"    - {url_info['url']}")
                print(f"      Risk Score: {url_info.get('risk_score', 0):.2f}")
                print(f"      Risk Level: {url_info.get('risk_level', 'unknown')}")
                if url_info.get('risk_factors'):
                    print(f"      Factors: {', '.join(url_info['risk_factors'])}")
        
        if result.get('advanced_features'):
            print("\n  Top Features:")
            features = result['advanced_features']
            # Show most important features
            important = ['urgency_score', 'has_shortener', 'suspicious_phrase_count']
            for feat in important:
                if feat in features:
                    print(f"    - {feat}: {features[feat]}")
    print()

def test_url_check():
    """Test URL checking"""
    print("🔗 URL SAFETY CHECKS:")
    print("-" * 40)
    
    test_urls = [
        "http://bit.ly/suspicious",
        "http://192.168.1.1/admin",
        "http://amaz0n.com/account",
        "https://google.com",
        "http://paypal-verify.tk/login"
    ]
    
    for url in test_urls:
        response = requests.post(
            f"{BASE_URL}/check_url",
            json={"url": url}
        )
        
        if response.status_code == 200:
            result = response.json()
            emoji = "🔴" if result['risk_level'] == "high" else "🟡" if result['risk_level'] == "medium" else "🟢"
            print(f"  {emoji} {url}")
            print(f"     Risk: {result['risk_score']:.2f} ({result['risk_level']})")
            if result['risk_factors']:
                print(f"     Factors: {', '.join(result['risk_factors'][:3])}")
    print()

def test_sms_analysis():
    """Test SMS analysis"""
    print("📱 SMS SCAM DETECTION:")
    print("-" * 40)
    
    test_messages = [
        ("Your package is waiting! Track at: http://ups-delivery.tk/123", "SHORTCODE"),
        ("Your verification code is 123456. Do not share with anyone.", "PayPal"),
        ("Congrats! You won $1000! Click here to claim: bit.ly/prize", "9999"),
        ("Reminder: Your appointment is tomorrow at 2pm", "DrOffice")
    ]
    
    for msg, sender in test_messages:
        response = requests.post(
            f"{BASE_URL}/analyze_sms",
            json={
                "message_text": msg,
                "sender": sender
            }
        )
        
        if response.status_code == 200:
            result = response.json()
            emoji = "🚨" if result['is_scam'] else "✅"
            print(f"  {emoji} From: {sender}")
            print(f"     Message: {msg[:50]}...")
            print(f"     Classification: {result['classification']} ({result['confidence']:.1%})")
            if result['risk_indicators']:
                print(f"     Indicators: {', '.join(result['risk_indicators'])}")
    print()

def test_feedback():
    """Test feedback system"""
    print("💬 FEEDBACK SYSTEM TEST:")
    print("-" * 40)
    
    # Submit feedback for a false positive
    response = requests.post(
        f"{BASE_URL}/feedback",
        json={
            "email_text": "Your order from Amazon has shipped",
            "correct_label": "legitimate",
            "predicted_label": "phishing",
            "confidence": 0.75,
            "user_comment": "This was a real Amazon email"
        }
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"  Status: {result['status']}")
        print(f"  Message: {result['message']}")
        print(f"  Was Correct: {result['was_correct']}")
    print()

def test_stats():
    """Get enhanced statistics"""
    response = requests.get(f"{BASE_URL}/stats")
    stats = response.json()
    
    print("📊 ENHANCED STATISTICS:")
    print("-" * 40)
    print(f"  Total Events: {stats['total_events']}")
    
    if 'by_source' in stats:
        print("\n  Events by Source:")
        for source, count in stats['by_source'].items():
            print(f"    - {source}: {count}")
    
    if 'threats_detected' in stats:
        print("\n  Threats Detected:")
        for threat, count in stats['threats_detected'].items():
            print(f"    - {threat}: {count}")
    
    if 'feedback' in stats:
        print("\n  Feedback Stats:")
        fb = stats['feedback']
        print(f"    - Total: {fb['total']}")
        print(f"    - False Positives: {fb['false_positives']}")
        print(f"    - False Negatives: {fb['false_negatives']}")
    
    if 'model_accuracy' in stats:
        print(f"\n  Estimated Accuracy: {stats['model_accuracy']['estimated']:.1%}")
    print()

def main():
    print("=" * 60)
    print("🚀 ENHANCED SECURITY COPILOT TEST SUITE")
    print("=" * 60)
    print()
    
    # Test all features
    test_health()
    test_enhanced_classification()
    test_url_check()
    test_sms_analysis()
    test_feedback()
    test_stats()
    
    print("=" * 60)
    print("✅ Enhanced Security Copilot tests complete!")
    print("🎯 New capabilities: Advanced features, URL analysis, SMS detection")
    print("=" * 60)

if __name__ == "__main__":
    main()