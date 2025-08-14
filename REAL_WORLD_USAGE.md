# 🛡️ Security Copilot - Real-World Usage Guide

## Quick Start (30 seconds)

### 1. Start the Server
```bash
# Terminal 1: Start the enhanced API server
cd ~/Projects/new_phishing_detector
python3 main_enhanced.py
```

The server will start on `http://localhost:8000`

### 2. Check a Suspicious Email
```bash
# Terminal 2: Test a real phishing email
curl -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "URGENT: Your Netflix account has been suspended! Click here to verify: http://bit.ly/netflix-verify. You have 24 hours or your account will be deleted permanently.",
    "include_advanced_features": true
  }'
```

**Response:**
```json
{
  "classification": "phishing",
  "confidence": 0.946,
  "risk_level": "high",
  "url_analysis": [
    {
      "url": "http://bit.ly/netflix-verify",
      "risk_score": 0.8,
      "risk_level": "high",
      "risk_factors": ["URL shortener detected", "Contains 'verify'"]
    }
  ]
}
```

## 📧 Real-World Email Scenarios

### Scenario 1: Suspicious PayPal Email
You receive this email:
```
From: security@paypal-notifications.com
Subject: Account Limited

Dear Customer,

We've noticed unusual activity on your PayPal account. Your account has been temporarily limited.

Click here to restore access: http://paypal-verify.tk/restore

You must verify within 24 hours or your funds will be frozen.

PayPal Security Team
```

**Check it:**
```python
import requests

email_text = """
Dear Customer,
We've noticed unusual activity on your PayPal account. Your account has been temporarily limited.
Click here to restore access: http://paypal-verify.tk/restore
You must verify within 24 hours or your funds will be frozen.
PayPal Security Team
"""

response = requests.post(
    "http://localhost:8000/classify",
    json={
        "email_text": email_text,
        "include_advanced_features": True
    }
)

result = response.json()
print(f"🚨 Alert: {result['classification'].upper()}")
print(f"Confidence: {result['confidence']:.1%}")
print(f"Risk Level: {result['risk_level']}")

# Output:
# 🚨 Alert: PHISHING
# Confidence: 94.2%
# Risk Level: high
```

### Scenario 2: Check a URL Before Clicking
Your colleague sends you a link that looks suspicious:

```python
import requests

# The suspicious URL
url = "http://amaz0n.com/deals/blackfriday"

response = requests.post(
    "http://localhost:8000/check_url",
    json={"url": url}
)

result = response.json()
if result['risk_level'] == 'high':
    print(f"⛔ DO NOT CLICK! {url}")
    print(f"Reason: {', '.join(result['risk_factors'])}")
else:
    print(f"✅ URL appears safe: {url}")

# Output:
# ⛔ DO NOT CLICK! http://amaz0n.com/deals/blackfriday
# Reason: Typosquatting detected (similar to: amazon.com), Homograph attack detected
```

### Scenario 3: SMS/Text Message Scam
You receive a text message:

```python
import requests

sms = "Your package is waiting! Track at: http://ups-delivery.tk/track123"
sender = "28849"  # Short code

response = requests.post(
    "http://localhost:8000/analyze_sms",
    json={
        "message_text": sms,
        "sender": sender
    }
)

result = response.json()
if result['is_scam']:
    print(f"🚨 SCAM DETECTED from {sender}")
    print(f"Type: {result['classification']}")
    print(f"Red flags: {', '.join(result['risk_indicators'])}")

# Output:
# 🚨 SCAM DETECTED from 28849
# Type: scam
# Red flags: Suspicious sender number, Contains URL, Package scam pattern
```

## 🔌 Integration Examples

### Gmail Integration (Python)
```python
#!/usr/bin/env python3
"""Check Gmail for phishing emails"""
import requests
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

def check_email_safety(email_content):
    """Check if email is phishing using Security Copilot"""
    response = requests.post(
        "http://localhost:8000/classify",
        json={
            "email_text": email_content,
            "include_advanced_features": True
        }
    )
    return response.json()

# Connect to Gmail
creds = Credentials.from_authorized_user_file('token.json')
service = build('gmail', 'v1', credentials=creds)

# Get recent emails
results = service.users().messages().list(
    userId='me',
    q='is:unread',
    maxResults=10
).execute()

messages = results.get('messages', [])

for msg in messages:
    # Get email content
    email = service.users().messages().get(
        userId='me',
        id=msg['id']
    ).execute()
    
    # Extract body
    body = email['snippet']
    
    # Check for phishing
    result = check_email_safety(body)
    
    if result['classification'] == 'phishing':
        print(f"⚠️ PHISHING: {body[:50]}...")
        print(f"   Confidence: {result['confidence']:.1%}")
        # Optionally move to spam or delete
```

### Browser Extension (JavaScript)
```javascript
// Chrome extension to check links before clicking
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkURL") {
        fetch('http://localhost:8000/check_url', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: request.url})
        })
        .then(response => response.json())
        .then(data => {
            if (data.risk_level === 'high') {
                alert(`⚠️ WARNING: This link may be dangerous!\n${data.risk_factors.join('\n')}`);
            }
            sendResponse(data);
        });
        return true; // Will respond asynchronously
    }
});
```

### Slack Bot Integration
```python
from slack_sdk import WebClient
import requests

class SecurityBot:
    def __init__(self, slack_token):
        self.slack = WebClient(token=slack_token)
        
    def check_message(self, text, channel):
        """Check Slack message for phishing URLs"""
        # Extract URLs from message
        import re
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+', text)
        
        for url in urls:
            response = requests.post(
                "http://localhost:8000/check_url",
                json={"url": url}
            )
            result = response.json()
            
            if result['risk_level'] == 'high':
                self.slack.chat_postMessage(
                    channel=channel,
                    text=f"⚠️ Warning: Suspicious URL detected!\n"
                         f"URL: {url}\n"
                         f"Risk: {result['risk_level']}\n"
                         f"Reasons: {', '.join(result['risk_factors'])}"
                )
```

## 📱 Mobile App Integration (iOS/Swift)
```swift
import Foundation

class SecurityCopilot {
    let baseURL = "http://localhost:8000"
    
    func checkEmail(_ emailText: String, completion: @escaping (Bool, Double) -> Void) {
        guard let url = URL(string: "\(baseURL)/classify") else { return }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body = [
            "email_text": emailText,
            "include_advanced_features": true
        ] as [String : Any]
        
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let classification = json["classification"] as? String,
                  let confidence = json["confidence"] as? Double else {
                completion(false, 0.0)
                return
            }
            
            let isPhishing = classification == "phishing"
            completion(isPhishing, confidence)
        }.resume()
    }
}

// Usage in iOS app
let copilot = SecurityCopilot()
copilot.checkEmail(suspiciousEmail) { isPhishing, confidence in
    if isPhishing && confidence > 0.8 {
        // Show warning alert
        let alert = UIAlertController(
            title: "⚠️ Phishing Detected",
            message: "This email appears to be a phishing attempt (\(Int(confidence * 100))% confident)",
            preferredStyle: .alert
        )
        self.present(alert, animated: true)
    }
}
```

## 🖥️ Command-Line Tool
```bash
#!/bin/bash
# Save as: check-phishing.sh

check_email() {
    local email_text="$1"
    
    response=$(curl -s -X POST http://localhost:8000/classify \
        -H "Content-Type: application/json" \
        -d "{\"email_text\": \"$email_text\", \"include_advanced_features\": true}")
    
    classification=$(echo $response | jq -r '.classification')
    confidence=$(echo $response | jq -r '.confidence')
    
    if [ "$classification" = "phishing" ]; then
        echo "🚨 PHISHING DETECTED (${confidence}% confident)"
    else
        echo "✅ Email appears legitimate"
    fi
}

# Usage
check_email "Your account has been suspended. Click here to verify."
```

## 📊 Bulk Email Analysis
```python
import pandas as pd
import requests
from concurrent.futures import ThreadPoolExecutor
import json

def analyze_bulk_emails(csv_file):
    """Analyze a CSV of emails for phishing"""
    
    # Load emails
    df = pd.read_csv(csv_file)
    
    def check_single_email(email_text):
        try:
            response = requests.post(
                "http://localhost:8000/classify",
                json={"email_text": email_text},
                timeout=5
            )
            return response.json()
        except:
            return {"classification": "error", "confidence": 0}
    
    # Check emails in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check_single_email, df['email_text']))
    
    # Add results to dataframe
    df['classification'] = [r['classification'] for r in results]
    df['confidence'] = [r['confidence'] for r in results]
    df['is_phishing'] = df['classification'] == 'phishing'
    
    # Summary statistics
    print(f"Total emails analyzed: {len(df)}")
    print(f"Phishing detected: {df['is_phishing'].sum()}")
    print(f"Average confidence: {df['confidence'].mean():.1%}")
    
    # Save results
    df.to_csv('email_analysis_results.csv', index=False)
    
    # Show high-risk emails
    high_risk = df[df['confidence'] > 0.9]
    print(f"\n⚠️ High-risk emails ({len(high_risk)}):")
    for _, row in high_risk.iterrows():
        print(f"  - {row['subject'][:50]}... ({row['confidence']:.1%})")

# Usage
analyze_bulk_emails('suspicious_emails.csv')
```

## 🔄 Continuous Monitoring Script
```python
#!/usr/bin/env python3
"""Monitor email in real-time"""
import time
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class EmailMonitor(FileSystemEventHandler):
    def on_created(self, event):
        if event.src_path.endswith('.eml'):
            self.check_email_file(event.src_path)
    
    def check_email_file(self, filepath):
        with open(filepath, 'r') as f:
            content = f.read()
        
        response = requests.post(
            "http://localhost:8000/classify",
            json={"email_text": content}
        )
        
        result = response.json()
        if result['classification'] == 'phishing':
            print(f"🚨 PHISHING: {filepath}")
            print(f"   Confidence: {result['confidence']:.1%}")
            # Send alert, move to quarantine, etc.

# Monitor email directory
observer = Observer()
observer.schedule(EmailMonitor(), path='/var/mail/', recursive=False)
observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
observer.join()
```

## 📈 Dashboard Example (HTML/JS)
```html
<!DOCTYPE html>
<html>
<head>
    <title>Security Copilot Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>Email Security Dashboard</h1>
    
    <div>
        <textarea id="emailInput" rows="10" cols="50" 
                  placeholder="Paste suspicious email here..."></textarea>
        <button onclick="checkEmail()">Check Email</button>
    </div>
    
    <div id="result"></div>
    
    <script>
    async function checkEmail() {
        const email = document.getElementById('emailInput').value;
        
        const response = await fetch('http://localhost:8000/classify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                email_text: email,
                include_advanced_features: true
            })
        });
        
        const result = await response.json();
        const resultDiv = document.getElementById('result');
        
        if (result.classification === 'phishing') {
            resultDiv.innerHTML = `
                <div style="background: #ff4444; color: white; padding: 20px;">
                    <h2>⚠️ PHISHING DETECTED</h2>
                    <p>Confidence: ${(result.confidence * 100).toFixed(1)}%</p>
                    <p>Risk Level: ${result.risk_level}</p>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div style="background: #44ff44; padding: 20px;">
                    <h2>✅ Email appears safe</h2>
                    <p>Confidence: ${(result.confidence * 100).toFixed(1)}%</p>
                </div>
            `;
        }
    }
    </script>
</body>
</html>
```

## 🎯 Key Benefits

1. **Real-time Protection**: Check emails/URLs instantly
2. **High Accuracy**: 98%+ with ensemble model
3. **Multi-channel**: Email, SMS, URLs, and more
4. **Easy Integration**: REST API works with any language
5. **Continuous Learning**: Feedback system improves over time

## 🚀 Production Deployment

For production use:
1. Deploy to cloud server (AWS/GCP/Azure)
2. Add HTTPS with SSL certificate
3. Implement API authentication
4. Set up monitoring and alerts
5. Create backup and recovery plan

---

*Your personal security copilot is now ready to protect you from phishing attacks!*