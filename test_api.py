#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for the Phishing Detector API
"""
import requests
import json

# API base URL
BASE_URL = "http://localhost:8000"

def test_health():
    """Test the health endpoint"""
    response = requests.get(f"{BASE_URL}/health")
    print("🏥 Health Check:")
    print(f"  Status: {response.status_code}")
    print(f"  Response: {response.json()}")
    print()

def test_classification(email_text, description):
    """Test email classification"""
    print(f"📧 Testing: {description}")
    print(f"  Email: {email_text[:50]}...")
    
    response = requests.post(
        f"{BASE_URL}/classify",
        json={"email_text": email_text}
    )
    
    if response.status_code == 200:
        result = response.json()
        emoji = "🚨" if result["is_phishing"] else "✅"
        print(f"  {emoji} Classification: {result['classification']}")
        print(f"  📊 Confidence: {result['confidence']:.1%}")
    else:
        print(f"  ❌ Error: {response.status_code}")
        print(f"  Response: {response.text}")
    print()

def main():
    print("=" * 60)
    print("🔍 PHISHING DETECTOR API TEST")
    print("=" * 60)
    print()
    
    # Test health endpoint
    test_health()
    
    # Test various emails
    test_cases = [
        ("URGENT: Your account will be suspended! Click here to verify your password immediately.", "Phishing - Urgent/Suspended"),
        ("Congratulations! You've won $10000! Click this link to claim your prize now!", "Phishing - Prize Scam"),
        ("Thank you for your recent purchase. Your order #12345 has been shipped.", "Legitimate - Order Confirmation"),
        ("Your monthly statement for Amazon is now available in your account dashboard.", "Legitimate - Statement"),
        ("IRS Tax Refund: You're eligible for $5000. Claim here: bit.ly/xyz", "Phishing - Tax Scam"),
        ("Meeting reminder: Team Sync scheduled for tomorrow at 2:00 PM.", "Legitimate - Meeting"),
    ]
    
    for email, description in test_cases:
        test_classification(email, description)
    
    print("=" * 60)
    print("✅ API tests complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()