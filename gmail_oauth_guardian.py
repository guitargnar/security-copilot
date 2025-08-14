#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gmail Security Guardian with OAuth2 - Real Gmail Integration
Uses existing OAuth credentials from ai-talent-optimizer
"""
import pickle
import os
import sys
from pathlib import Path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
import requests
import json
from datetime import datetime, timedelta
import time
import csv
from typing import Dict, List, Optional
import re

# If modifying these scopes, delete the token.pickle file
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.modify']

class GmailOAuthGuardian:
    """Gmail Security Guardian using OAuth2 authentication"""
    
    def __init__(self):
        """Initialize with OAuth2 credentials"""
        self.service = None
        self.security_api = "http://localhost:8000"
        self.creds = None
        self.emails_scanned = 0
        self.threats_blocked = 0
        
        # Paths to credentials
        self.token_path = Path("/Users/matthewscott/AI-ML-Portfolio/ai-talent-optimizer/token.pickle")
        self.client_secret_path = Path("/Users/matthewscott/Google Gmail/client_secret_234263158377-mgju2kfq6aftic7os093vv0lguq5s4gu.apps.googleusercontent.com.json")
        
        # Logging
        self.log_file = Path("gmail_oauth_security_log.csv")
        self.init_logging()
        
        print("=" * 70)
        print("🛡️  GMAIL SECURITY GUARDIAN - OAuth Edition")
        print("=" * 70)
        print(f"Security API: {self.security_api}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    def init_logging(self):
        """Initialize CSV logging"""
        if not self.log_file.exists():
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'message_id', 'sender', 'subject',
                    'classification', 'confidence', 'action_taken', 'urls_found'
                ])
    
    def authenticate(self) -> bool:
        """Authenticate with Gmail API using OAuth2"""
        try:
            print("🔐 Authenticating with Gmail API...")
            
            # Load existing token
            if self.token_path.exists():
                print(f"  Loading token from: {self.token_path}")
                with open(self.token_path, 'rb') as token:
                    self.creds = pickle.load(token)
            
            # If there are no (valid) credentials available, let the user log in
            if not self.creds or not self.creds.valid:
                if self.creds and self.creds.expired and self.creds.refresh_token:
                    print("  Refreshing expired token...")
                    self.creds.refresh(Request())
                else:
                    if not self.client_secret_path.exists():
                        print(f"❌ Client secret not found: {self.client_secret_path}")
                        return False
                    
                    print("  Starting OAuth flow...")
                    flow = InstalledAppFlow.from_client_secrets_file(
                        str(self.client_secret_path), SCOPES)
                    self.creds = flow.run_local_server(port=0)
                
                # Save the credentials for the next run
                with open(self.token_path, 'wb') as token:
                    pickle.dump(self.creds, token)
                print("  ✅ Token saved for future use")
            
            # Build the Gmail service
            self.service = build('gmail', 'v1', credentials=self.creds)
            
            # Test connection
            profile = self.service.users().getProfile(userId='me').execute()
            print(f"✅ Connected to Gmail: {profile['emailAddress']}")
            print(f"   Total messages: {profile['messagesTotal']}")
            
            return True
            
        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            return False
    
    def get_message_content(self, msg_id: str) -> Dict:
        """Get full message content"""
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=msg_id,
                format='full'
            ).execute()
            
            # Extract headers
            headers = message['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            date = next((h['value'] for h in headers if h['name'] == 'Date'), '')
            
            # Extract body
            body = self.extract_body(message['payload'])
            
            return {
                'id': msg_id,
                'subject': subject,
                'sender': sender,
                'date': date,
                'body': body,
                'snippet': message.get('snippet', '')
            }
        except Exception as e:
            print(f"Error getting message {msg_id}: {e}")
            return None
    
    def extract_body(self, payload) -> str:
        """Extract email body from payload"""
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                elif part['mimeType'] == 'text/html' and not body:
                    data = part['body']['data']
                    html = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    # Simple HTML stripping
                    body = re.sub('<[^<]+?>', '', html)
        elif payload['body'].get('data'):
            body = base64.urlsafe_b64decode(
                payload['body']['data']).decode('utf-8', errors='ignore')
        
        return body[:5000]  # Limit to 5000 chars
    
    def scan_message(self, msg_id: str) -> Optional[Dict]:
        """Scan a single message for phishing"""
        msg_content = self.get_message_content(msg_id)
        if not msg_content:
            return None
        
        print(f"\n📧 Scanning: {msg_content['subject'][:50]}...")
        print(f"   From: {msg_content['sender'][:50]}")
        
        # Prepare for analysis
        email_text = f"""From: {msg_content['sender']}
Subject: {msg_content['subject']}
Date: {msg_content['date']}

{msg_content['body']}"""
        
        # Check with Security Copilot
        try:
            response = requests.post(
                f"{self.security_api}/classify",
                json={
                    "email_text": email_text,
                    "include_advanced_features": True
                },
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                result.update({
                    'message_id': msg_id,
                    'sender': msg_content['sender'],
                    'subject': msg_content['subject']
                })
                
                # Extract and check URLs
                urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', msg_content['body'])
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
                                    'risk': url_result['risk_level']
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
            print(f"   ❌ Error scanning: {e}")
            return None
    
    def log_scan(self, result: Dict):
        """Log scan result"""
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                result.get('message_id', ''),
                result.get('sender', '')[:100],
                result.get('subject', '')[:100],
                result.get('classification', ''),
                result.get('confidence', 0),
                result.get('action_taken', 'scanned'),
                result.get('urls_found', 0)
            ])
    
    def scan_inbox(self, max_results: int = 20, query: str = "is:unread") -> Dict:
        """Scan messages matching query"""
        print(f"\n📥 Scanning messages: {query} (max: {max_results})")
        print("-" * 50)
        
        try:
            # Get messages
            results = self.service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            
            if not messages:
                print("No messages found.")
                return {'total': 0, 'phishing': 0, 'legitimate': 0}
            
            phishing_found = []
            legitimate_count = 0
            
            for i, msg in enumerate(messages, 1):
                print(f"\n[{i}/{len(messages)}]", end="")
                result = self.scan_message(msg['id'])
                
                if result:
                    if result['classification'] == 'phishing':
                        phishing_found.append(result)
                        self.threats_blocked += 1
                        self.handle_phishing(msg['id'], result)
                    else:
                        legitimate_count += 1
            
            # Summary
            print("\n" + "=" * 50)
            print("📊 SCAN SUMMARY")
            print("=" * 50)
            print(f"Total Scanned: {len(messages)}")
            print(f"Phishing Detected: {len(phishing_found)}")
            print(f"Legitimate: {legitimate_count}")
            
            if phishing_found:
                print("\n⚠️  PHISHING EMAILS FOUND:")
                for p in phishing_found[:5]:
                    print(f"  - {p['subject'][:50]}")
                    print(f"    From: {p['sender'][:40]}")
                    print(f"    Confidence: {p['confidence']:.1%}")
                    print(f"    Action: {p.get('action_taken', 'Flagged')}")
            
            return {
                'total': len(messages),
                'phishing': len(phishing_found),
                'legitimate': legitimate_count,
                'details': phishing_found
            }
            
        except HttpError as error:
            print(f'An error occurred: {error}')
            return None
    
    def handle_phishing(self, msg_id: str, analysis: Dict):
        """Take action on phishing email"""
        print(f"\n   🛡️ Taking protective action...")
        
        try:
            if analysis['confidence'] > 0.85:
                # High confidence - move to spam
                print("   Action: Moving to SPAM")
                self.service.users().messages().modify(
                    userId='me',
                    id=msg_id,
                    body={'addLabelIds': ['SPAM'], 'removeLabelIds': ['INBOX']}
                ).execute()
                analysis['action_taken'] = 'moved_to_spam'
                print("   ✅ Moved to spam")
            else:
                # Medium confidence - mark as important
                print("   Action: Flagging as suspicious")
                self.service.users().messages().modify(
                    userId='me',
                    id=msg_id,
                    body={'addLabelIds': ['IMPORTANT']}
                ).execute()
                analysis['action_taken'] = 'flagged'
                print("   ✅ Flagged for review")
                
            self.log_scan(analysis)
            
        except Exception as e:
            print(f"   ⚠️  Could not take action: {e}")
    
    def monitor_realtime(self, interval: int = 60):
        """Monitor inbox in real-time"""
        print(f"\n🔍 Starting real-time monitoring (every {interval}s)")
        print("Press Ctrl+C to stop\n")
        
        last_checked = datetime.now()
        
        try:
            while True:
                # Check new messages since last check
                query = f"after:{int(last_checked.timestamp())}"
                print(f"\n⏰ Checking... [{datetime.now().strftime('%H:%M:%S')}]")
                
                result = self.scan_inbox(max_results=10, query=query)
                
                if result and result['total'] > 0:
                    print(f"📬 Found {result['total']} new messages")
                else:
                    print("   No new messages")
                
                last_checked = datetime.now()
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n⏹️  Monitoring stopped")
            self.print_stats()
    
    def print_stats(self):
        """Print session statistics"""
        print("\n" + "=" * 50)
        print("📊 SESSION STATISTICS")
        print("=" * 50)
        print(f"Emails Scanned: {self.emails_scanned}")
        print(f"Threats Blocked: {self.threats_blocked}")
        if self.emails_scanned > 0:
            print(f"Protection Rate: {(self.threats_blocked/self.emails_scanned)*100:.1f}%")
        print(f"Log File: {self.log_file}")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Gmail OAuth Security Guardian')
    parser.add_argument('--scan', type=int, default=20, help='Number of messages to scan')
    parser.add_argument('--query', type=str, default='is:unread', help='Gmail search query')
    parser.add_argument('--monitor', action='store_true', help='Monitor in real-time')
    parser.add_argument('--interval', type=int, default=60, help='Monitor interval in seconds')
    
    args = parser.parse_args()
    
    # Check API
    try:
        response = requests.get("http://localhost:8000/health", timeout=2)
        if response.status_code == 200:
            print("✅ Security API is running")
        else:
            print("⚠️  Security API issue detected")
    except:
        print("❌ Security API not available. Start with: python3 main_enhanced.py")
        return 1
    
    # Initialize Guardian
    guardian = GmailOAuthGuardian()
    
    # Authenticate
    if not guardian.authenticate():
        print("Failed to authenticate with Gmail")
        return 1
    
    # Execute requested action
    if args.monitor:
        guardian.monitor_realtime(interval=args.interval)
    else:
        guardian.scan_inbox(max_results=args.scan, query=args.query)
    
    guardian.print_stats()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())