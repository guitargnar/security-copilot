# Phishing Detector API

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Train the Model (if not already done)
```bash
python3 train_model.py
```

### 3. Start the API Server
```bash
python3 main.py
# Or with uvicorn directly:
# uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## 📡 API Endpoints

### Health Check
```bash
GET http://localhost:8000/health
```

Response:
```json
{
  "status": "healthy",
  "model_loaded": true
}
```

### Classify Email
```bash
POST http://localhost:8000/classify
Content-Type: application/json

{
  "email_text": "Your email content here..."
}
```

Response:
```json
{
  "classification": "phishing",
  "confidence": 0.891,
  "is_phishing": true
}
```

## 🍎 iOS Shortcuts Integration

1. Create a new Shortcut
2. Add "Get Contents of URL" action
3. Set URL to `http://YOUR_IP:8000/classify`
4. Method: POST
5. Headers: `Content-Type: application/json`
6. Request Body (JSON):
```json
{
  "email_text": "Email from clipboard or input"
}
```
7. Parse the response and show alert based on `is_phishing`

## 📊 Logging

All classifications are logged to `logs/classifications.csv` with:
- Timestamp
- Email preview (first 200 chars)
- Classification result
- Confidence score
- Client IP

## 🧪 Testing

Run the test suite:
```bash
python3 test_api.py
```

## 🔧 Configuration

- Default port: 8000
- CORS: Enabled for all origins (adjust for production)
- Model directory: `models/`
- Log directory: `logs/`

## 📈 Model Performance

- Training accuracy: ~100% on synthetic dataset
- Uses TF-IDF vectorization with LogisticRegression
- 1000 training samples (500 phishing, 500 legitimate)