#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gmail Security Guardian - Automated Phishing Protection
Uses existing Gmail App Password for immediate protection
"""
import imaplib
import email
from email.header import decode_header
import requests
import json
import time
from datetime import datetime, timedelta
import os
import sys
from pathlib import Path
import csv
import re
from typing import Dict, List, Tuple, Optional
import argparse

class GmailSecurityGuardian:
    """
    Automated Gmail protection using Security Copilot ML models
    """
    
    def __init__(self, email_address: str = None, app_password: str = None):
        """Initialize Gmail Guardian with credentials"""
        # Load credentials
        if not email_address or not app_password:
            self.load_credentials()
        else:
            self.email = email_address
            self.password = app_password
        
        self.imap = None
        self.security_api = "http://localhost:8000"
        self.scan_history = []
        self.threats_blocked = 0
        self.emails_scanned = 0
        
        # Logging
        self.log_file = Path("gmail_security_log.csv")
        self.init_logging()
        
        print("=" * 70)
        print("🛡️  GMAIL SECURITY GUARDIAN INITIALIZED")
        print("=" * 70)
        print(f"Protected Email: {self.email}")
        print(f"Security API: {self.security_api}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    def load_credentials(self):
        """Load credentials from .env file"""
        env_paths = [
            Path(".env"),
            Path("/Users/matthewscott/SURVIVE/career-automation/interview-prep/.env"),
            Path("/Users/matthewscott/Projects/new_phishing_detector/.env")
        ]
        
        for env_path in env_paths:
            if env_path.exists():
                with open(env_path, 'r') as f:
                    for line in f:
                        if line.startswith('EMAIL_ADDRESS='):
                            self.email = line.split('=')[1].strip()
                        elif line.startswith('EMAIL_APP_PASSWORD='):
                            self.password = line.split('=')[1].strip()
                
                if hasattr(self, 'email') and hasattr(self, 'password'):
                    print(f"✅ Credentials loaded from {env_path}")
                    return
        
        raise ValueError("Could not find Gmail credentials in .env files")
    
    def init_logging(self):
        """Initialize CSV logging"""
        if not self.log_file.exists():
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'email_id', 'sender', 'subject',
                    'classification', 'confidence', 'action_taken', 'risk_factors'
                ])
    
    def connect(self) -> bool:
        """Establish IMAP connection to Gmail"""
        try:
            print("📡 Connecting to Gmail...")
            self.imap = imaplib.IMAP4_SSL("imap.gmail.com")
            self.imap.login(self.email, self.password)
            print("✅ Connected successfully!")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def get_email_body(self, msg) -> str:
        """Extract email body from message"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body = part.get_payload(decode=True).decode()
                    except:
                        pass
                elif content_type == "text/html" and not body:
                    try:
                        html_body = part.get_payload(decode=True).decode()
                        # Simple HTML to text
                        body = re.sub('<[^<]+?>', '', html_body)
                    except:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode()
            except:
                body = str(msg.get_payload())
        
        return body[:5000]  # Limit to 5000 chars
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def scan_email(self, email_id: str) -> Dict:
        """Analyze single email for phishing threats"""
        try:
            # Fetch email
            status, data = self.imap.fetch(email_id, "(RFC822)")
            if status != "OK":
                return None
            
            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)
            
            # Extract metadata
            subject = ""
            if msg["Subject"]:
                subject_parts = decode_header(msg["Subject"])
                subject = str(subject_parts[0][0]) if subject_parts[0][0] else ""
                if isinstance(subject, bytes):
                    subject = subject.decode(errors='ignore')
            
            sender = msg.get("From", "Unknown")
            date = msg.get("Date", "")
            body = self.get_email_body(msg)
            
            # Prepare for analysis
            email_content = f"From: {sender}\nSubject: {subject}\nDate: {date}\n\n{body}"
            
            print(f"\n📧 Scanning: {subject[:50]}...")
            print(f"   From: {sender}")
            
            # Check with Security Copilot API
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
                result['email_id'] = email_id.decode() if isinstance(email_id, bytes) else email_id
                result['sender'] = sender
                result['subject'] = subject
                
                # Check URLs in email
                urls = self.extract_urls(body)
                if urls:
                    result['urls_found'] = len(urls)
                    dangerous_urls = []
                    
                    for url in urls[:5]:  # Check first 5 URLs
                        url_response = requests.post(
                            f"{self.security_api}/check_url",
                            json={"url": url},
                            timeout=5
                        )
                        if url_response.status_code == 200:
                            url_result = url_response.json()
                            if url_result['risk_level'] in ['high', 'medium']:
                                dangerous_urls.append({
                                    'url': url[:50],
                                    'risk': url_result['risk_level'],
                                    'score': url_result['risk_score']
                                })
                    
                    if dangerous_urls:
                        result['dangerous_urls'] = dangerous_urls
                
                # Display result
                if result['classification'] == 'phishing':
                    print(f"   🚨 PHISHING DETECTED! (Confidence: {result['confidence']:.1%})")
                    if 'dangerous_urls' in result:
                        print(f"   ⚠️  {len(result['dangerous_urls'])} dangerous URLs found")
                else:
                    print(f"   ✅ Legitimate (Confidence: {(1-result['confidence']):.1%})")
                
                self.emails_scanned += 1
                self.log_scan(result)
                
                return result
            
        except Exception as e:
            print(f"   ❌ Error scanning email: {e}")
            return None
    
    def log_scan(self, result: Dict):
        """Log scan result to CSV"""
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                result.get('email_id', ''),
                result.get('sender', '')[:50],
                result.get('subject', '')[:50],
                result.get('classification', ''),
                result.get('confidence', 0),
                result.get('action_taken', 'scanned'),
                json.dumps(result.get('risk_factors', []))[:100]
            ])
    
    def scan_inbox(self, limit: int = 50) -> Dict:
        """Scan recent emails in inbox"""
        print(f"\n📥 Scanning last {limit} emails in inbox...")
        print("-" * 50)
        
        self.imap.select("INBOX")
        status, data = self.imap.search(None, "ALL")
        
        if status == "OK":
            email_ids = data[0].split()
            # Get last N emails
            email_ids = email_ids[-limit:] if len(email_ids) > limit else email_ids
            
            phishing_found = []
            legitimate_count = 0
            
            for i, email_id in enumerate(email_ids, 1):
                print(f"\n[{i}/{len(email_ids)}]", end="")
                result = self.scan_email(email_id)
                
                if result:
                    if result['classification'] == 'phishing':
                        phishing_found.append(result)
                        self.threats_blocked += 1
                    else:
                        legitimate_count += 1
            
            # Summary
            print("\n" + "=" * 50)
            print("📊 SCAN SUMMARY")
            print("=" * 50)
            print(f"Total Scanned: {len(email_ids)}")
            print(f"Phishing Detected: {len(phishing_found)}")
            print(f"Legitimate: {legitimate_count}")
            
            if phishing_found:
                print("\n⚠️  PHISHING EMAILS FOUND:")
                for p in phishing_found:
                    print(f"  - {p['subject'][:50]} (from: {p['sender'][:30]})")
                    print(f"    Confidence: {p['confidence']:.1%}")
                    if 'dangerous_urls' in p:
                        print(f"    Dangerous URLs: {len(p['dangerous_urls'])}")
            
            return {
                'total_scanned': len(email_ids),
                'phishing_found': len(phishing_found),
                'legitimate': legitimate_count,
                'phishing_details': phishing_found
            }
        
        return {'error': 'Could not access inbox'}
    
    def monitor_new_emails(self, check_interval: int = 60):
        """Continuously monitor for new emails"""
        print("\n🔍 Starting real-time monitoring...")
        print(f"Checking every {check_interval} seconds")
        print("Press Ctrl+C to stop\n")
        
        last_seen = set()
        
        try:
            while True:
                self.imap.select("INBOX")
                status, data = self.imap.search(None, "UNSEEN")
                
                if status == "OK":
                    email_ids = data[0].split()
                    new_emails = [eid for eid in email_ids if eid not in last_seen]
                    
                    if new_emails:
                        print(f"\n📬 {len(new_emails)} new email(s) detected!")
                        
                        for email_id in new_emails:
                            result = self.scan_email(email_id)
                            
                            if result and result['classification'] == 'phishing':
                                self.handle_threat(email_id, result)
                            
                            last_seen.add(email_id)
                    else:
                        print(".", end="", flush=True)
                
                time.sleep(check_interval)
                
        except KeyboardInterrupt:
            print("\n\n⏹️  Monitoring stopped by user")
            self.print_session_stats()
    
    def handle_threat(self, email_id: str, analysis: Dict):
        """Take action on detected phishing email"""
        print(f"\n🚨 THREAT RESPONSE ACTIVATED")
        print(f"   Threat Level: {'HIGH' if analysis['confidence'] > 0.8 else 'MEDIUM'}")
        
        if analysis['confidence'] > 0.8:
            # High confidence - mark as spam
            print("   Action: Moving to spam folder")
            try:
                self.imap.store(email_id, '+FLAGS', '\\Deleted')
                self.imap.expunge()
                print("   ✅ Email deleted")
            except:
                print("   ⚠️  Could not delete email")
        else:
            # Medium confidence - flag it
            print("   Action: Flagging as suspicious")
            try:
                self.imap.store(email_id, '+FLAGS', '\\Flagged')
                print("   ✅ Email flagged")
            except:
                print("   ⚠️  Could not flag email")
        
        # Log the action
        analysis['action_taken'] = 'deleted' if analysis['confidence'] > 0.8 else 'flagged'
        self.log_scan(analysis)
    
    def print_session_stats(self):
        """Print session statistics"""
        print("\n" + "=" * 50)
        print("📊 SESSION STATISTICS")
        print("=" * 50)
        print(f"Emails Scanned: {self.emails_scanned}")
        print(f"Threats Blocked: {self.threats_blocked}")
        print(f"Protection Rate: {(self.threats_blocked/max(self.emails_scanned,1))*100:.1f}%")
        print(f"Log File: {self.log_file}")
    
    def generate_report(self) -> str:
        """Generate security report"""
        report = []
        report.append("=" * 70)
        report.append("GMAIL SECURITY REPORT")
        report.append("=" * 70)
        report.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Protected Email: {self.email}")
        report.append("")
        report.append("STATISTICS:")
        report.append(f"  Total Emails Scanned: {self.emails_scanned}")
        report.append(f"  Phishing Attempts Blocked: {self.threats_blocked}")
        report.append(f"  Detection Rate: {(self.threats_blocked/max(self.emails_scanned,1))*100:.1f}%")
        report.append("")
        
        # Read recent threats from log
        if self.log_file.exists():
            report.append("RECENT THREATS:")
            with open(self.log_file, 'r') as f:
                reader = csv.DictReader(f)
                threats = [row for row in reader if row['classification'] == 'phishing']
                recent_threats = threats[-5:] if len(threats) > 5 else threats
                
                for threat in recent_threats:
                    report.append(f"  - {threat['subject'][:40]}")
                    report.append(f"    From: {threat['sender'][:40]}")
                    report.append(f"    Confidence: {float(threat['confidence'])*100:.1f}%")
                    report.append("")
        
        report.append("=" * 70)
        return "\n".join(report)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Gmail Security Guardian')
    parser.add_argument('--scan', type=int, help='Scan last N emails')
    parser.add_argument('--monitor', action='store_true', help='Monitor for new emails')
    parser.add_argument('--report', action='store_true', help='Generate security report')
    parser.add_argument('--check-api', action='store_true', help='Check if API is running')
    
    args = parser.parse_args()
    
    # Check API availability
    if args.check_api or True:  # Always check
        try:
            response = requests.get("http://localhost:8000/health", timeout=2)
            if response.status_code == 200:
                print("✅ Security API is running")
            else:
                print("⚠️  Security API returned status:", response.status_code)
        except:
            print("❌ Security API not available. Start with: python3 main_enhanced.py")
            print("Continuing anyway...")
    
    # Initialize Guardian
    guardian = GmailSecurityGuardian()
    
    if not guardian.connect():
        print("Failed to connect to Gmail")
        return 1
    
    # Execute requested action
    if args.scan:
        guardian.scan_inbox(limit=args.scan)
    elif args.monitor:
        guardian.monitor_new_emails()
    elif args.report:
        print(guardian.generate_report())
    else:
        # Default: scan last 20 emails
        guardian.scan_inbox(limit=20)
    
    # Cleanup
    if guardian.imap:
        guardian.imap.logout()
    
    guardian.print_session_stats()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())