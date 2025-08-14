# 🚀 Security Copilot - Quick Start Guide

## 30-Second Setup

### 1. Start the Server
```bash
cd ~/Projects/new_phishing_detector
python3 main_enhanced.py
```

### 2. Test It's Working
```bash
# In another terminal:
curl http://localhost:8000/health
```

## Instant Examples

### Check if an Email is Phishing
```bash
curl -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -d '{"email_text": "URGENT: Your account suspended! Click here: bit.ly/verify"}'
```

### Check if a URL is Safe
```bash
curl -X POST http://localhost:8000/check_url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://amaz0n.com"}'
```

### Check if SMS is a Scam
```bash
curl -X POST http://localhost:8000/analyze_sms \
  -H "Content-Type: application/json" \
  -d '{"message_text": "You won $1000! Click to claim", "sender": "UNKNOWN"}'
```

## Python Quick Start
```python
import requests

# Check email
response = requests.post("http://localhost:8000/classify", 
    json={"email_text": "Your PayPal account limited. Verify: bit.ly/pp"})
result = response.json()
print(f"Classification: {result['classification']} ({result['confidence']:.0%})")
```

## Run the Full Demo
```bash
python3 demo.py
```

## API Documentation
Visit: http://localhost:8000/docs

---
That's it! Your security copilot is protecting you in under 30 seconds.