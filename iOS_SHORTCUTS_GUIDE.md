# 📱 iOS Shortcuts Integration Guide

## Prerequisites
- iOS 14 or later
- Shortcuts app installed
- Your Mac running the Security Copilot server (`python3 main.py`)
- Both devices on the same network

## 🔍 Finding Your Server IP
1. On your Mac, open Terminal
2. Run: `ifconfig | grep "inet " | grep -v 127.0.0.1`
3. Look for something like `192.168.1.100`
4. Use this IP instead of `localhost` in shortcuts

---

## 📧 Gmail Copilot Shortcut

### What It Does
Analyzes emails shared from Gmail app to detect phishing attempts instantly.

### Step-by-Step Setup

#### 1. Create New Shortcut
- Open Shortcuts app
- Tap the **+** button
- Name it "Check Email Security"

#### 2. Configure Share Sheet Trigger
- Tap the three dots (•••) at the top
- Toggle ON "Use with Share Sheet"
- Toggle ON "Show in Share Sheet"
- Under "Share Sheet Types" select:
  - ✅ Text
  - ✅ URLs

#### 3. Build the Shortcut Actions

**Action 1: Get Shared Input**
- Add action: "Get Item from Share Sheet"
- This captures the email content

**Action 2: Set Server URL**
- Add action: "Text"
- Enter: `http://YOUR_IP:8000/classify`
- Replace YOUR_IP with your Mac's IP (e.g., `192.168.1.100`)

**Action 3: Create JSON Payload**
- Add action: "Get Dictionary Value"
- Add these fields:
  - Key: `email_text`
  - Value: (Select "Shortcut Input" from variables)

**Action 4: Send to API**
- Add action: "Get Contents of URL"
- Method: POST
- Headers:
  - Key: `Content-Type`
  - Value: `application/json`
- Request Body: Select the Dictionary from Action 3

**Action 5: Parse Response**
- Add action: "Get Dictionary Value"
- Get: `classification`
- From: "Contents of URL"

**Action 6: Get Confidence**
- Add action: "Get Dictionary Value"
- Get: `confidence`
- From: "Contents of URL"

**Action 7: Format Confidence**
- Add action: "Calculate"
- Input: (Confidence from Action 6) × 100
- Round to 1 decimal place

**Action 8: Show Result**
- Add action: "Show Notification"
- Title: Use IF statement:
  - If classification contains "phishing": "⚠️ PHISHING DETECTED"
  - Otherwise: "✅ Email Appears Safe"
- Body: "Confidence: [Formatted percentage]%"

#### 4. How to Use
1. Open Gmail app
2. Open any email
3. Tap the three dots menu
4. Select "Share"
5. Choose "Check Email Security"
6. See instant notification with results

---

## 📞 Call Copilot Shortcut

### What It Does
Automatically logs unknown incoming calls and assesses risk level.

### Step-by-Step Setup

#### 1. Create New Automation
- Open Shortcuts app
- Go to "Automation" tab
- Tap **+** → "Create Personal Automation"
- Select trigger: **"Phone Call"**
- Choose: "When call from Anyone"

#### 2. Add Contact Filter
- Add action: "Get My Contacts"
- Add action: "If"
- Condition: "If Shortcut Input is not in Contacts"
- This ensures only unknown numbers are logged

#### 3. Inside the IF Block

**Action 1: Get Phone Number**
- The phone number is in "Shortcut Input"
- Store it in a variable called "PhoneNumber"

**Action 2: Get Current Date**
- Add action: "Current Date"
- Format: ISO 8601
- Store as "CallTime"

**Action 3: Set Server URL**
- Add action: "Text"
- Enter: `http://YOUR_IP:8000/call_log`

**Action 4: Create JSON Payload**
- Add action: "Dictionary"
- Add fields:
  - `phone_number`: PhoneNumber variable
  - `timestamp`: CallTime variable

**Action 5: Send to API**
- Add action: "Get Contents of URL"
- URL: Server URL from Action 3
- Method: POST
- Headers:
  - `Content-Type`: `application/json`
- Body: Dictionary from Action 4

**Action 6: Parse Risk Level**
- Add action: "Get Dictionary Value"
- Get: `risk_level`
- From: "Contents of URL"

**Action 7: Show Alert (Optional)**
- Add action: "Show Notification"
- Only if risk_level equals "high":
  - Title: "⚠️ High Risk Call"
  - Body: "From: [PhoneNumber]"

#### 4. Enable Automation
- Save the automation
- Toggle OFF "Ask Before Running"
- Confirm you want it to run automatically

---

## 🔧 Testing Your Shortcuts

### Test Email Classification
1. Start server: `python3 main.py`
2. Share this test email from any app:
   ```
   URGENT: Your account will be suspended! 
   Click here to verify immediately.
   ```
3. Should show "⚠️ PHISHING DETECTED"

### Test Call Logging
1. Have a friend (not in contacts) call you
2. Check `logs/security_log.csv` for the entry
3. Or visit `http://YOUR_IP:8000/stats` to see counts

---

## 📊 Viewing Your Security Log

### From Terminal
```bash
cat logs/security_log.csv
```

### From Browser
Visit: `http://YOUR_IP:8000/stats`

### Log Format
```csv
timestamp,source,content,classification,confidence,metadata
2024-01-15T10:30:00,email,"Urgent account...",phishing,0.938,API classification
2024-01-15T10:31:00,call,"Phone: 876-555-0100",risk_medium,N/A,caller:unknown|indicators:international_risk
```

---

## 🚨 Troubleshooting

### "Could not connect to server"
- Ensure server is running: `python3 main.py`
- Check both devices are on same WiFi
- Try using IP address instead of localhost
- Check firewall settings

### "Invalid response"
- Check server logs for errors
- Ensure you're using POST method
- Verify JSON formatting

### Automation not triggering
- Go to Settings → Shortcuts
- Enable "Allow Untrusted Shortcuts"
- Make sure automation is enabled
- Check notification permissions

---

## 🔒 Security Notes

1. **Local Only**: This runs on your local network only
2. **No Cloud**: Your data never leaves your devices
3. **Privacy**: Only email previews (200 chars) are logged
4. **Control**: You can delete logs anytime

---

## 📈 Advanced Features

### Custom Risk Rules
Edit `main.py` to add your own phone number patterns:
```python
elif phone.startswith("YOUR_AREA_CODE"):
    risk_indicators.append("local_spam")
    risk_level = "medium"
```

### Email Whitelist
Add trusted senders to skip classification:
```python
if "trusted-company.com" in req.email_text:
    return ClassificationResponse(
        classification="legitimate",
        confidence=1.0,
        is_phishing=False
    )
```

---

## 📞 Support

Server running? Check: `http://YOUR_IP:8000/health`
View stats: `http://YOUR_IP:8000/stats`
Test classification: Use `test_api.py`

Remember: The server must be running for shortcuts to work!