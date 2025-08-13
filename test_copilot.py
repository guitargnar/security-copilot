#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for Security Copilot features
"""
import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint"""
    response = requests.get(f"{BASE_URL}/health")
    print("🏥 Health Check:")
    print(f"  Status: {response.json()}")
    print()

def test_email(text, description):
    """Test email classification"""
    print(f"📧 {description}")
    response = requests.post(
        f"{BASE_URL}/classify",
        json={"email_text": text}
    )
    
    if response.status_code == 200:
        result = response.json()
        emoji = "🚨" if result["is_phishing"] else "✅"
        print(f"  {emoji} {result['classification']} ({result['confidence']:.1%})")
    else:
        print(f"  ❌ Error: {response.text}")

def test_call(number, name=None):
    """Test call logging"""
    print(f"📞 Call from: {number}")
    payload = {"phone_number": number}
    if name:
        payload["caller_name"] = name
    
    response = requests.post(
        f"{BASE_URL}/call_log",
        json=payload
    )
    
    if response.status_code == 200:
        result = response.json()
        risk_emoji = {
            "high": "🔴",
            "medium": "🟡", 
            "low": "🟢",
            "unknown": "⚪"
        }
        print(f"  {risk_emoji.get(result['risk_level'], '⚪')} Risk: {result['risk_level']}")
    else:
        print(f"  ❌ Error: {response.text}")

def test_stats():
    """Get statistics"""
    response = requests.get(f"{BASE_URL}/stats")
    stats = response.json()
    print("\n📊 Security Statistics:")
    print(f"  Total Events: {stats['total_events']}")
    print(f"  Email Events: {stats['email_events']}")
    print(f"  Call Events: {stats['call_events']}")
    print(f"  Phishing Detected: {stats['phishing_detected']}")
    print()

def main():
    print("=" * 60)
    print("🛡️  SECURITY COPILOT TEST SUITE")
    print("=" * 60)
    print()
    
    # Test health
    test_health()
    
    # Test various emails
    print("📧 EMAIL TESTS:")
    print("-" * 40)
    test_email(
        "URGENT: Your account suspended! Verify now at bit.ly/abc",
        "Phishing - Urgent Account"
    )
    test_email(
        "Your Amazon order #12345 has shipped. Track at amazon.com",
        "Legitimate - Order Update"
    )
    test_email(
        "IRS Refund $5000 waiting! Claim at irs-refund.fake",
        "Phishing - Tax Scam"
    )
    print()
    
    # Test various calls
    print("📞 CALL TESTS:")
    print("-" * 40)
    test_call("900-555-0100", "Premium Rate")
    test_call("876-123-4567", "Jamaica Number")
    test_call("502-555-0123", "Local Number")
    test_call("0000000000", "Spoofed")
    test_call("123456789012345678", "Too Long")
    print()
    
    # Get statistics
    test_stats()
    
    print("=" * 60)
    print("✅ Security Copilot test complete!")
    print("📁 Check logs/security_log.csv for detailed records")
    print("=" * 60)

if __name__ == "__main__":
    main()