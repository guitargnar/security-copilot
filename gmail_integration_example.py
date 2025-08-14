#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gmail Integration Example for Security Copilot
Demonstrates how to integrate phishing detection with Gmail API
"""
import os
import base64
import re
from typing import List, Dict, Optional
import requests
from datetime import datetime
import json

# Gmail API imports (install with: pip install google-api-python-client google-auth-oauthlib)
try:
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    GMAIL_AVAILABLE = True
except ImportError:
    print("Gmail API not available. Install with: pip install google-api-python-client google-auth-oauthlib")
    GMAIL_AVAILABLE = False

class GmailPhishingDetector:
    """Integrate Security Copilot with Gmail for automated phishing detection."""
    
    def __init__(self, security_copilot_url: str = "http://localhost:8000"):
        self.copilot_url = security_copilot_url
        self.gmail_service = None
        
        # Gmail API scopes
        self.SCOPES = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.modify'  # For marking/moving emails
        ]
        
        # Results storage
        self.scan_results = []
    
    def authenticate_gmail(self, credentials_file: str = 'credentials.json', 
                          token_file: str = 'token.json') -> bool:
        """Authenticate with Gmail API."""
        if not GMAIL_AVAILABLE:
            print("❌ Gmail API libraries not installed")
            return False
        
        creds = None
        
        # Load existing token
        if os.path.exists(token_file):
            creds = Credentials.from_authorized_user_file(token_file, self.SCOPES)
        
        # If no valid credentials, get new ones
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(credentials_file):
                    print(f"❌ Gmail credentials file not found: {credentials_file}")
                    print("📋 To set up Gmail integration:")
                    print("   1. Go to Google Cloud Console")
                    print("   2. Enable Gmail API")
                    print("   3. Create OAuth 2.0 credentials")
                    print("   4. Download as credentials.json")
                    return False
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_file, self.SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save credentials for next run
            with open(token_file, 'w') as token:
                token.write(creds.to_json())
        
        self.gmail_service = build('gmail', 'v1', credentials=creds)
        print("✅ Gmail authentication successful")
        return True
    
    def check_email_with_copilot(self, email_text: str, 
                                include_advanced: bool = True) -> Dict:
        """Check email with Security Copilot API."""
        try:
            response = requests.post(
                f"{self.copilot_url}/classify",
                json={
                    "email_text": email_text,
                    "include_advanced_features": include_advanced
                },
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except requests.RequestException as e:
            return {"error": f"Connection error: {e}"}
    
    def extract_email_content(self, message_data: Dict) -> str:
        """Extract readable content from Gmail message."""
        payload = message_data.get('payload', {})
        content = ""
        
        # Get subject
        headers = payload.get('headers', [])
        subject = ""
        sender = ""
        
        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
            elif header['name'] == 'From':
                sender = header['value']
        
        content += f"From: {sender}\n"
        content += f"Subject: {subject}\n\n"
        
        # Extract body
        body = self._extract_body_recursive(payload)
        content += body
        
        return content
    
    def _extract_body_recursive(self, payload: Dict) -> str:
        """Recursively extract email body from payload."""
        body = ""
        
        # Check if this part has body data
        if 'body' in payload and 'data' in payload['body']:
            try:
                decoded = base64.urlsafe_b64decode(
                    payload['body']['data'] + '===='
                ).decode('utf-8', errors='ignore')
                body += decoded
            except:
                pass
        
        # Check parts recursively
        if 'parts' in payload:
            for part in payload['parts']:
                body += self._extract_body_recursive(part)
        
        return body
    
    def scan_recent_emails(self, max_results: int = 50, 
                          query: str = "is:unread") -> List[Dict]:
        """Scan recent Gmail messages for phishing."""
        if not self.gmail_service:
            print("❌ Gmail not authenticated")
            return []
        
        print(f"🔍 Scanning {max_results} emails with query: '{query}'")
        
        try:
            # Get list of messages
            results = self.gmail_service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            print(f"📧 Found {len(messages)} messages to scan")
            
            scan_results = []
            
            for i, message in enumerate(messages):
                print(f"  Processing {i+1}/{len(messages)}...")
                
                # Get full message
                msg = self.gmail_service.users().messages().get(
                    userId='me',
                    id=message['id']
                ).execute()
                
                # Extract content
                email_content = self.extract_email_content(msg)
                
                # Check with Security Copilot
                analysis = self.check_email_with_copilot(email_content)
                
                # Store result
                result = {
                    'message_id': message['id'],
                    'timestamp': datetime.now().isoformat(),
                    'analysis': analysis,
                    'content_preview': email_content[:200] + "..." if len(email_content) > 200 else email_content
                }
                
                scan_results.append(result)
                
                # Print immediate result for high-risk emails
                if analysis.get('classification') == 'phishing' and analysis.get('confidence', 0) > 0.8:
                    print(f"    🚨 HIGH RISK PHISHING DETECTED!")
                    print(f"       Confidence: {analysis['confidence']:.1%}")
                    print(f"       Preview: {email_content[:100]}...")
            
            self.scan_results = scan_results
            return scan_results
            
        except Exception as e:
            print(f"❌ Error scanning emails: {e}")
            return []
    
    def generate_report(self, save_to_file: bool = True) -> Dict:
        """Generate a security report from scan results."""
        if not self.scan_results:
            return {"error": "No scan results available"}
        
        total_emails = len(self.scan_results)
        phishing_count = 0
        high_confidence_phishing = 0
        legitimate_count = 0
        errors = 0
        
        threat_details = []
        
        for result in self.scan_results:
            analysis = result.get('analysis', {})
            
            if 'error' in analysis:
                errors += 1
                continue
            
            classification = analysis.get('classification', 'unknown')
            confidence = analysis.get('confidence', 0)
            
            if classification == 'phishing':
                phishing_count += 1
                if confidence > 0.8:
                    high_confidence_phishing += 1
                    threat_details.append({
                        'message_id': result['message_id'],
                        'confidence': confidence,
                        'preview': result['content_preview']
                    })
            elif classification == 'legitimate':
                legitimate_count += 1
        
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'summary': {
                'total_emails_scanned': total_emails,
                'phishing_detected': phishing_count,
                'high_confidence_threats': high_confidence_phishing,
                'legitimate_emails': legitimate_count,
                'scan_errors': errors
            },
            'threat_details': threat_details,
            'recommendations': []
        }
        
        # Add recommendations
        if high_confidence_phishing > 0:
            report['recommendations'].append(
                f"🚨 {high_confidence_phishing} high-confidence phishing emails detected - review immediately"
            )
        
        if phishing_count > total_emails * 0.1:  # More than 10% phishing
            report['recommendations'].append(
                "⚠️ High phishing rate detected - consider additional email security measures"
            )
        
        if errors > 0:
            report['recommendations'].append(
                f"🔧 {errors} emails had scanning errors - check API connectivity"
            )
        
        # Save to file
        if save_to_file:
            filename = f"gmail_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"📄 Report saved to: {filename}")
        
        return report
    
    def mark_phishing_emails(self, confidence_threshold: float = 0.8) -> int:
        """Mark high-confidence phishing emails with labels."""
        if not self.gmail_service or not self.scan_results:
            return 0
        
        marked_count = 0
        
        for result in self.scan_results:
            analysis = result.get('analysis', {})
            
            if (analysis.get('classification') == 'phishing' and 
                analysis.get('confidence', 0) >= confidence_threshold):
                
                try:
                    # Add label or move to spam
                    self.gmail_service.users().messages().modify(
                        userId='me',
                        id=result['message_id'],
                        body={
                            'addLabelIds': ['SPAM'],  # Move to spam
                            'removeLabelIds': ['INBOX']  # Remove from inbox
                        }
                    ).execute()
                    
                    marked_count += 1
                    print(f"🔒 Moved phishing email to spam: {result['message_id']}")
                    
                except Exception as e:
                    print(f"❌ Error marking email {result['message_id']}: {e}")
        
        return marked_count


def main():
    """Example usage of Gmail phishing detection."""
    print("=" * 60)
    print("🛡️ GMAIL PHISHING DETECTOR")
    print("=" * 60)
    print()
    
    # Initialize detector
    detector = GmailPhishingDetector()
    
    # Check if Security Copilot is running
    try:
        response = requests.get(f"{detector.copilot_url}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Security Copilot API is running")
        else:
            print("❌ Security Copilot API not responding")
            return
    except:
        print("❌ Security Copilot API not available at http://localhost:8000")
        print("   Start it with: python3 main_enhanced.py")
        return
    
    # Authenticate with Gmail
    if not detector.authenticate_gmail():
        print("❌ Gmail authentication failed")
        return
    
    # Scan recent emails
    print("\n🔍 Scanning recent unread emails...")
    results = detector.scan_recent_emails(max_results=20, query="is:unread")
    
    if not results:
        print("📭 No emails to scan")
        return
    
    # Generate report
    print("\n📊 Generating security report...")
    report = detector.generate_report()
    
    # Print summary
    summary = report['summary']
    print(f"\n📈 SCAN RESULTS:")
    print(f"   📧 Total emails scanned: {summary['total_emails_scanned']}")
    print(f"   🚨 Phishing detected: {summary['phishing_detected']}")
    print(f"   ⚠️ High confidence threats: {summary['high_confidence_threats']}")
    print(f"   ✅ Legitimate emails: {summary['legitimate_emails']}")
    
    # Show recommendations
    if report['recommendations']:
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"   {rec}")
    
    # Ask about automatic actions
    if summary['high_confidence_threats'] > 0:
        response = input(f"\n🤔 Move {summary['high_confidence_threats']} high-risk emails to spam? (y/N): ")
        if response.lower().startswith('y'):
            moved = detector.mark_phishing_emails()
            print(f"🔒 Moved {moved} emails to spam")
    
    print("\n✅ Gmail security scan complete!")


if __name__ == "__main__":
    main()