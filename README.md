# 🔍 Simple Phishing Email Detector

A lightweight Python tool for detecting potential phishing emails using keyword analysis and pattern matching.

## Features

- **Keyword-based detection**: Checks for suspicious words and phrases
- **Pattern matching**: Identifies suspicious URL patterns and formatting
- **Risk scoring**: Calculates risk level based on multiple factors
- **Clear recommendations**: Provides actionable advice for each classification

## Installation

No external dependencies required! Uses only Python standard library.

```bash
# Clone or navigate to the project
cd ~/Projects/new_phishing_detector

# Make the script executable (optional)
chmod +x main.py
```

## Usage

### Method 1: Pass email as argument
```bash
python3 main.py "Dear user, URGENT! Your account will be suspended. Click here to verify your password immediately!"
```

### Method 2: Interactive mode
```bash
python3 main.py
# Then paste your email content and press Ctrl+D when done
```

### Method 3: Pipe email content
```bash
echo "Congratulations! You've won $1000. Click this link to claim." | python3 main.py
```

### Method 4: Read from file
```bash
cat suspicious_email.txt | python3 main.py
```

## Classification Levels

- **🚨 PHISHING** (High Risk): Score ≥ 10
- **⚠️ SUSPICIOUS** (Medium Risk): Score 5-9  
- **⚠️ SUSPICIOUS** (Low Risk): Score 3-4
- **✅ SAFE**: Score < 3

## Exit Codes

- `0`: Email classified as SAFE
- `1`: Email classified as SUSPICIOUS
- `2`: Email classified as PHISHING

## How It Works

1. **Keyword Analysis**: Searches for suspicious words with weighted scoring
   - High risk (3 points): "urgent", "verify", "suspended"
   - Medium risk (2 points): "password", "account", "security"
   - Low risk (1 point): "free", "offer", "discount"

2. **Pattern Detection**: Identifies suspicious patterns
   - Shortened URLs (bit.ly, tinyurl)
   - IP addresses instead of domains
   - Excessive capitalization
   - Multiple exclamation marks

3. **Legitimate Indicators**: Reduces score for legitimate email features
   - Common email providers
   - Unsubscribe links
   - Privacy policy mentions

## Examples

### Phishing Email
```bash
python3 main.py "URGENT! Your account has been suspended. Verify your password at bit.ly/abc123 NOW!"
# Result: 🚨 PHISHING (High confidence)
```

### Legitimate Email  
```bash
python3 main.py "Thank you for your purchase. You can unsubscribe from our newsletter below."
# Result: ✅ SAFE (High confidence)
```

## Future Enhancements

- Machine learning models for improved accuracy
- URL reputation checking
- Sender verification
- HTML email parsing
- Integration with email clients

## License

MIT License - Feel free to use and modify!

## Author

Created with Claude Code's sustainable project management system.
