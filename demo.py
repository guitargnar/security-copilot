#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Copilot Demo - Real-World Examples
Shows how to use the phishing detection system
"""
import requests
import json
from datetime import datetime
from typing import Dict, Any

# API Configuration
API_BASE = "http://localhost:8000"

class SecurityCopilotDemo:
    """Demo class showing real-world usage"""
    
    def __init__(self):
        self.base_url = API_BASE
        print("=" * 70)
        print("🛡️  SECURITY COPILOT DEMO")
        print("=" * 70)
        print(f"API Server: {self.base_url}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    def check_server(self) -> bool:
        """Verify server is running"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=2)
            if response.status_code == 200:
                print("✅ Server is running")
                return True
        except:
            print("❌ Server not responding. Start with: python3 main_enhanced.py")
            return False
        return False
    
    def demo_email_check(self):
        """Demo: Check various email types"""
        print("\n" + "=" * 70)
        print("📧 EMAIL PHISHING DETECTION DEMO")
        print("=" * 70)
        
        test_emails = [
            {
                "name": "Netflix Phishing",
                "text": """
                URGENT: Your Netflix account has been suspended!
                
                We detected unusual activity on your account. Click here immediately:
                http://netflix-verify.tk/restore-account
                
                You have 24 hours to verify or your account will be deleted.
                
                Netflix Security Team
                """
            },
            {
                "name": "Legitimate Amazon",
                "text": """
                Your order has shipped!
                
                Hi John,
                
                Your recent order #123-4567890 has been shipped and is on its way.
                Track your package at amazon.com/orders
                
                Expected delivery: Tuesday, March 15
                
                Thank you for shopping with Amazon!
                """
            },
            {
                "name": "IRS Scam",
                "text": """
                IRS TAX REFUND NOTIFICATION
                
                You are eligible for a tax refund of $3,458.23
                
                To claim your refund, please verify your identity:
                http://irs-refund.ml/claim?id=TX4589
                
                This offer expires in 48 hours.
                
                Internal Revenue Service
                """
            },
            {
                "name": "PayPal Phishing",
                "text": """
                Your PayPal account has been limited
                
                We noticed unusual activity and need to confirm your identity.
                
                Click here to restore access: http://bit.ly/paypal-secure
                
                If you don't verify within 24 hours, your funds may be frozen.
                
                PayPal Security
                """
            }
        ]
        
        for email in test_emails:
            print(f"\n📨 Testing: {email['name']}")
            print("-" * 40)
            print(f"Email preview: {email['text'][:100].strip()}...")
            
            # Check with API
            response = requests.post(
                f"{self.base_url}/classify",
                json={
                    "email_text": email['text'],
                    "include_advanced_features": True
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Display result with visual indicators
                if result['classification'] == 'phishing':
                    print(f"🚨 PHISHING DETECTED!")
                    print(f"   Confidence: {result['confidence']:.1%}")
                    print(f"   Risk Level: {result.get('risk_level', 'high')}")
                else:
                    print(f"✅ LEGITIMATE EMAIL")
                    print(f"   Confidence: {(1 - result['confidence']):.1%}")
                
                # Show URL analysis if available
                if result.get('url_analysis'):
                    print("   URLs found:")
                    for url_info in result['url_analysis']:
                        risk_emoji = "🔴" if url_info['risk_level'] == 'high' else "🟡"
                        print(f"     {risk_emoji} {url_info['url'][:50]}...")
                        if url_info.get('risk_factors'):
                            print(f"        Risks: {', '.join(url_info['risk_factors'][:2])}")
    
    def demo_url_check(self):
        """Demo: Check suspicious URLs"""
        print("\n" + "=" * 70)
        print("🔗 URL SAFETY CHECK DEMO")
        print("=" * 70)
        
        test_urls = [
            ("http://bit.ly/win-prize", "Shortened URL (prize scam)"),
            ("http://192.168.1.1/admin", "IP address instead of domain"),
            ("http://amaz0n.com/deals", "Typosquatting (fake Amazon)"),
            ("https://paypal.com/help", "Legitimate PayPal"),
            ("http://google-verify.tk", "Suspicious TLD"),
            ("https://www.google.com", "Legitimate Google"),
            ("http://paypaI.com/login", "Homograph attack (fake PayPal)"),
        ]
        
        for url, description in test_urls:
            print(f"\n🔍 Checking: {description}")
            print(f"   URL: {url}")
            
            response = requests.post(
                f"{self.base_url}/check_url",
                json={"url": url}
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Visual risk indicator
                if result['risk_level'] == 'high':
                    print(f"   🔴 HIGH RISK (Score: {result['risk_score']:.2f})")
                elif result['risk_level'] == 'medium':
                    print(f"   🟡 MEDIUM RISK (Score: {result['risk_score']:.2f})")
                else:
                    print(f"   🟢 LOW RISK (Score: {result['risk_score']:.2f})")
                
                if result['risk_factors']:
                    print(f"   Reasons: {', '.join(result['risk_factors'][:3])}")
    
    def demo_sms_check(self):
        """Demo: Check SMS/text messages"""
        print("\n" + "=" * 70)
        print("📱 SMS SCAM DETECTION DEMO")
        print("=" * 70)
        
        test_messages = [
            {
                "text": "Your package is waiting! Track: http://ups-track.tk/PKG123",
                "sender": "28849",
                "description": "Fake package delivery"
            },
            {
                "text": "Your verification code is 123456. Do not share with anyone.",
                "sender": "PayPal",
                "description": "Legitimate 2FA code"
            },
            {
                "text": "Congratulations! You won $1000! Click to claim: bit.ly/prize",
                "sender": "9999",
                "description": "Prize scam"
            },
            {
                "text": "Reminder: Your dentist appointment is tomorrow at 2pm",
                "sender": "DrSmith",
                "description": "Legitimate reminder"
            },
            {
                "text": "URGENT: Your bank account will be closed. Call 1-900-SCAMMER",
                "sender": "UNKNOWN",
                "description": "Bank scam with premium number"
            }
        ]
        
        for msg in test_messages:
            print(f"\n📲 Testing: {msg['description']}")
            print(f"   From: {msg['sender']}")
            print(f"   Message: {msg['text'][:60]}...")
            
            response = requests.post(
                f"{self.base_url}/analyze_sms",
                json={
                    "message_text": msg['text'],
                    "sender": msg['sender']
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if result['is_scam']:
                    print(f"   🚨 SCAM DETECTED!")
                    print(f"      Type: {result['classification']}")
                    print(f"      Confidence: {result['confidence']:.1%}")
                    if result['risk_indicators']:
                        print(f"      Red flags: {', '.join(result['risk_indicators'][:2])}")
                else:
                    print(f"   ✅ LEGITIMATE MESSAGE")
                    print(f"      Confidence: {(1 - result['confidence']):.1%}")
    
    def demo_feedback(self):
        """Demo: Feedback system for continuous improvement"""
        print("\n" + "=" * 70)
        print("💬 FEEDBACK SYSTEM DEMO")
        print("=" * 70)
        
        print("\n📝 Submitting feedback for false positive...")
        
        # Example: Report a false positive
        response = requests.post(
            f"{self.base_url}/feedback",
            json={
                "email_text": "Your Amazon order has shipped. Track at amazon.com/orders",
                "correct_label": "legitimate",
                "predicted_label": "phishing",
                "confidence": 0.65,
                "user_comment": "This was a real Amazon email"
            }
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"   Status: {result['status']}")
            print(f"   {result['message']}")
            print("   ✅ Model will learn from this correction")
    
    def show_statistics(self):
        """Show current system statistics"""
        print("\n" + "=" * 70)
        print("📊 SYSTEM STATISTICS")
        print("=" * 70)
        
        response = requests.get(f"{self.base_url}/stats")
        
        if response.status_code == 200:
            stats = response.json()
            
            print(f"\n📈 Total Events Processed: {stats.get('total_events', 0)}")
            
            if stats.get('by_source'):
                print("\n📋 Events by Type:")
                for source, count in stats['by_source'].items():
                    print(f"   - {source}: {count}")
            
            if stats.get('threats_detected'):
                print("\n⚠️ Threats Detected:")
                for threat, count in stats['threats_detected'].items():
                    print(f"   - {threat}: {count}")
    
    def run_all_demos(self):
        """Run all demonstrations"""
        if not self.check_server():
            return
        
        self.demo_email_check()
        self.demo_url_check()
        self.demo_sms_check()
        self.demo_feedback()
        self.show_statistics()
        
        print("\n" + "=" * 70)
        print("✅ DEMO COMPLETE!")
        print("=" * 70)
        print("\n📚 Next Steps:")
        print("1. Check your own emails: Copy suspicious emails and test them")
        print("2. Verify URLs: Test links before clicking")
        print("3. Analyze SMS: Check text messages for scams")
        print("4. Integrate: Use the API in your own applications")
        print("\n🔗 API Documentation: http://localhost:8000/docs")
        print("📖 Usage Guide: REAL_WORLD_USAGE.md")

def main():
    """Run the demo"""
    demo = SecurityCopilotDemo()
    
    print("\n🤖 Starting Security Copilot Demo...")
    print("This will demonstrate real-world phishing detection scenarios.\n")
    
    try:
        demo.run_all_demos()
    except KeyboardInterrupt:
        print("\n\n⚠️ Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        print("Make sure the server is running: python3 main_enhanced.py")

if __name__ == "__main__":
    main()