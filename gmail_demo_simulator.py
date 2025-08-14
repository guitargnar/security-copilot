#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gmail Security Guardian - Demo Simulator
Shows how the system would protect your Gmail inbox
"""
import requests
import json
from datetime import datetime, timedelta
import random
import time

class GmailSimulator:
    """Simulates Gmail integration to demonstrate Security Copilot capabilities"""
    
    def __init__(self):
        self.security_api = "http://localhost:8000"
        self.simulated_emails = self.generate_sample_emails()
        
        print("=" * 70)
        print("🛡️  GMAIL SECURITY GUARDIAN - DEMO MODE")
        print("=" * 70)
        print("This demonstration shows how the Security Copilot would protect")
        print("your Gmail inbox in real-time.")
        print()
    
    def generate_sample_emails(self):
        """Generate realistic email samples"""
        return [
            {
                "id": "msg001",
                "from": "security@paypal-notifications.tk",
                "subject": "Your PayPal account has been limited",
                "body": """Dear Customer,
                
We've noticed unusual activity on your PayPal account and have temporarily limited access.
                
Click here to restore access: http://paypal-verify.tk/restore
You must verify within 24 hours or your funds will be frozen.

PayPal Security Team""",
                "timestamp": datetime.now() - timedelta(hours=2)
            },
            {
                "id": "msg002",
                "from": "orders@amazon.com",
                "subject": "Your order has been shipped",
                "body": """Hello,

Your recent Amazon order #123-4567890 has been shipped!

Track your package: https://www.amazon.com/orders

Expected delivery: Tuesday, March 15

Thank you for shopping with Amazon.""",
                "timestamp": datetime.now() - timedelta(hours=5)
            },
            {
                "id": "msg003",
                "from": "noreply@chase.com",
                "subject": "URGENT: Suspicious activity on your account",
                "body": """IMPORTANT SECURITY NOTICE

We detected suspicious login attempts on your Chase account.

Verify your identity immediately: http://bit.ly/chase-secure

If you don't verify within 12 hours, your account will be locked.

Chase Security Department""",
                "timestamp": datetime.now() - timedelta(hours=1)
            },
            {
                "id": "msg004",
                "from": "team@github.com",
                "subject": "Your GitHub project has a new star",
                "body": """Hi Matthew,

Your repository 'security-copilot' just got a new star!

Total stars: 42

View your repository: https://github.com/guitargnar/security-copilot

Keep up the great work!
The GitHub Team""",
                "timestamp": datetime.now() - timedelta(hours=8)
            },
            {
                "id": "msg005",
                "from": "winner@lottery-international.ml",
                "subject": "Congratulations! You've won $1,000,000",
                "body": """OFFICIAL NOTIFICATION

You have won ONE MILLION DOLLARS in the International Lottery!

Claim your prize here: http://lottery-claim.tk/winner

Reference number: WIN2025-789456

You must claim within 48 hours.

International Lottery Commission""",
                "timestamp": datetime.now() - timedelta(minutes=30)
            }
        ]
    
    def analyze_email(self, email):
        """Analyze email with Security Copilot API"""
        print(f"\n{'='*60}")
        print(f"📧 Analyzing Email {email['id']}")
        print(f"{'='*60}")
        print(f"From: {email['from']}")
        print(f"Subject: {email['subject']}")
        print(f"Received: {email['timestamp'].strftime('%Y-%m-%d %H:%M')}")
        print()
        
        # Prepare email content
        email_content = f"From: {email['from']}\nSubject: {email['subject']}\n\n{email['body']}"
        
        # Check with Security Copilot
        try:
            response = requests.post(
                f"{self.security_api}/classify",
                json={
                    "email_text": email_content,
                    "include_advanced_features": True
                },
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Display analysis
                if result['classification'] == 'phishing':
                    print("🚨 PHISHING DETECTED!")
                    print(f"Confidence: {result['confidence']:.1%}")
                    print()
                    print("📋 AUTOMATED ACTIONS:")
                    
                    if result['confidence'] > 0.85:
                        print("  ✓ Email moved to spam folder")
                        print("  ✓ Sender blocked")
                        print("  ✓ Security alert sent")
                    else:
                        print("  ✓ Email flagged as suspicious")
                        print("  ✓ Warning label added")
                    
                    # Check for dangerous URLs
                    if result.get('url_analysis'):
                        print("\n⚠️  DANGEROUS URLs FOUND:")
                        for url_info in result['url_analysis']:
                            if url_info.get('risk_level') in ['high', 'medium']:
                                print(f"  • {url_info['url'][:50]}")
                                print(f"    Risk: {url_info['risk_level'].upper()}")
                                if url_info.get('risk_factors'):
                                    print(f"    Reasons: {', '.join(url_info['risk_factors'][:2])}")
                else:
                    print("✅ EMAIL IS LEGITIMATE")
                    print(f"Confidence: {(1 - result['confidence']):.1%}")
                    print("\n📋 ACTIONS:")
                    print("  ✓ Email delivered to inbox")
                    print("  ✓ Sender marked as safe")
                
                # Show advanced features if high-risk
                if result.get('advanced_features') and result['classification'] == 'phishing':
                    features = result['advanced_features']
                    print("\n🔬 THREAT INDICATORS:")
                    if features.get('urgency_score', 0) > 2:
                        print(f"  • High urgency language (score: {features['urgency_score']})")
                    if features.get('suspicious_phrase_count', 0) > 1:
                        print(f"  • Suspicious phrases detected: {features['suspicious_phrase_count']}")
                    if features.get('has_shortener', 0) > 0:
                        print("  • URL shorteners detected")
                
                return result
                
        except Exception as e:
            print(f"❌ Error analyzing email: {e}")
            return None
    
    def simulate_inbox_scan(self):
        """Simulate scanning entire inbox"""
        print("\n" + "="*70)
        print("📥 SIMULATING INBOX SCAN")
        print("="*70)
        print(f"Scanning {len(self.simulated_emails)} emails...\n")
        
        time.sleep(1)
        
        phishing_found = []
        legitimate = []
        
        for i, email in enumerate(self.simulated_emails, 1):
            print(f"[{i}/{len(self.simulated_emails)}]", end="")
            result = self.analyze_email(email)
            
            if result:
                if result['classification'] == 'phishing':
                    phishing_found.append((email, result))
                else:
                    legitimate.append((email, result))
            
            time.sleep(0.5)
        
        # Summary
        print("\n\n" + "="*70)
        print("📊 SCAN SUMMARY")
        print("="*70)
        print(f"Total Emails Scanned: {len(self.simulated_emails)}")
        print(f"🚨 Phishing Detected: {len(phishing_found)}")
        print(f"✅ Legitimate Emails: {len(legitimate)}")
        print(f"Protection Rate: {(len(phishing_found)/len(self.simulated_emails))*100:.1f}%")
        
        if phishing_found:
            print("\n⚠️  THREATS BLOCKED:")
            for email, result in phishing_found:
                print(f"  • {email['subject'][:50]}")
                print(f"    From: {email['from']}")
                print(f"    Confidence: {result['confidence']:.1%}")
                print(f"    Action: {'Deleted' if result['confidence'] > 0.85 else 'Flagged'}")
        
        print("\n✅ SAFE EMAILS:")
        for email, result in legitimate:
            print(f"  • {email['subject'][:50]}")
            print(f"    From: {email['from']}")
    
    def simulate_realtime_monitoring(self):
        """Simulate real-time email monitoring"""
        print("\n" + "="*70)
        print("🔍 SIMULATING REAL-TIME MONITORING")
        print("="*70)
        print("Monitoring for new emails... (Press Ctrl+C to stop)\n")
        
        try:
            # Simulate receiving new emails
            new_emails = [
                {
                    "id": "msg006",
                    "from": "alert@netflix-security.tk",
                    "subject": "Your Netflix subscription expired",
                    "body": "Click here to renew: http://netflix-renew.tk",
                    "timestamp": datetime.now()
                },
                {
                    "id": "msg007",
                    "from": "newsletter@techcrunch.com",
                    "subject": "Daily Tech News",
                    "body": "Today's top stories in tech...",
                    "timestamp": datetime.now()
                }
            ]
            
            for i in range(10):
                print(f"⏳ Checking... [{datetime.now().strftime('%H:%M:%S')}]", end="\r")
                time.sleep(2)
                
                if i == 3:
                    print(f"\n📬 New email detected!")
                    self.analyze_email(new_emails[0])
                    print("\n🛡️ Threat neutralized! Continuing monitoring...")
                
                if i == 7:
                    print(f"\n📬 New email detected!")
                    self.analyze_email(new_emails[1])
                    print("\n✅ Safe email delivered. Continuing monitoring...")
            
        except KeyboardInterrupt:
            print("\n\n⏹️  Monitoring stopped")
    
    def show_protection_features(self):
        """Display all protection features"""
        print("\n" + "="*70)
        print("🛡️  GMAIL PROTECTION FEATURES")
        print("="*70)
        
        features = [
            ("🔍 Real-time Scanning", "Every email analyzed before reaching inbox"),
            ("🤖 ML Ensemble Model", "7 algorithms with 98%+ accuracy"),
            ("🔗 URL Analysis", "Detects typosquatting, shorteners, suspicious domains"),
            ("📱 SMS Protection", "Analyzes text messages for scams"),
            ("🎯 Smart Actions", "Auto-delete high-risk, flag medium-risk"),
            ("📊 Daily Reports", "Security summary delivered every morning"),
            ("🔄 Continuous Learning", "Improves from feedback and new threats"),
            ("⚡ Fast Processing", "Sub-second analysis per email"),
            ("🔐 Privacy First", "All processing done locally"),
            ("📈 Threat Intelligence", "Updates from global threat feeds")
        ]
        
        for feature, description in features:
            print(f"\n{feature}")
            print(f"  {description}")

def main():
    """Run the Gmail simulation demo"""
    print("\n🚀 Starting Gmail Security Guardian Demo...\n")
    
    # Check API
    try:
        response = requests.get("http://localhost:8000/health", timeout=2)
        if response.status_code == 200:
            print("✅ Security API is running\n")
        else:
            print("⚠️  Security API issue detected")
    except:
        print("❌ Security API not available. Start with: python3 main_enhanced.py")
        return
    
    simulator = GmailSimulator()
    
    # Run demonstrations
    print("\n" + "="*70)
    print("SELECT DEMO:")
    print("="*70)
    print("1. Scan Inbox (analyze all emails)")
    print("2. Real-time Monitoring (watch for new threats)")
    print("3. Show Protection Features")
    print("4. Run All Demos")
    print()
    
    try:
        choice = input("Enter choice (1-4): ").strip()
        
        if choice == "1":
            simulator.simulate_inbox_scan()
        elif choice == "2":
            simulator.simulate_realtime_monitoring()
        elif choice == "3":
            simulator.show_protection_features()
        elif choice == "4":
            simulator.simulate_inbox_scan()
            simulator.simulate_realtime_monitoring()
            simulator.show_protection_features()
        else:
            # Default: run inbox scan
            simulator.simulate_inbox_scan()
            
    except KeyboardInterrupt:
        print("\n\nDemo stopped by user")
    
    print("\n" + "="*70)
    print("✅ DEMO COMPLETE")
    print("="*70)
    print("\n📝 To set up real Gmail protection:")
    print("1. Enable 2-factor authentication on Gmail")
    print("2. Generate an App Password:")
    print("   - Go to: https://myaccount.google.com/apppasswords")
    print("   - Create password for 'Mail'")
    print("3. Update .env file with new app password")
    print("4. Run: python3 gmail_guardian.py --monitor")
    print("\nYour inbox will be protected 24/7!")

if __name__ == "__main__":
    main()