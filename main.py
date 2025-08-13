#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py – FastAPI Security Copilot Server
------------------------------------------
Run:  uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""
import os
import csv
import time
import joblib
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ------------------------------------------------------------------ #
# 1. Load ML assets once at startup
# ------------------------------------------------------------------ #
MODEL_DIR = Path("models")
CLF_PATH = MODEL_DIR / "phishing_clf.pkl"
VEC_PATH = MODEL_DIR / "tfidf_vec.pkl"

if not CLF_PATH.exists() or not VEC_PATH.exists():
    raise RuntimeError(
        "Models not found. Run `python train_model.py` first."
    )

clf = joblib.load(CLF_PATH)
vec = joblib.load(VEC_PATH)

# ------------------------------------------------------------------ #
# 2. FastAPI app & CORS (for iOS Shortcuts)
# ------------------------------------------------------------------ #
app = FastAPI(
    title="Security Copilot API",
    version="3.0",
    description="AI-powered security analysis for emails and calls"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------ #
# 3. Request / Response models
# ------------------------------------------------------------------ #
class ClassificationRequest(BaseModel):
    email_text: str

class ClassificationResponse(BaseModel):
    classification: str
    confidence: float
    is_phishing: bool

class CallLogRequest(BaseModel):
    phone_number: str
    timestamp: Optional[str] = None
    caller_name: Optional[str] = None

class CallLogResponse(BaseModel):
    logged: bool
    phone_number: str
    timestamp: str
    risk_level: str

# ------------------------------------------------------------------ #
# 4. Unified security logger
# ------------------------------------------------------------------ #
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
SECURITY_LOG = LOG_DIR / "security_log.csv"

def init_security_log():
    """Initialize the security log with headers if it doesn't exist."""
    if not SECURITY_LOG.exists():
        with SECURITY_LOG.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "source", "content", 
                "classification", "confidence", "metadata"
            ])

def log_security_event(
    source: str,  # "email" or "call"
    content: str,
    classification: str,
    confidence: float = 0.0,
    metadata: str = "",
    client_ip: str = "localhost"
):
    """Log any security event to the unified log."""
    with SECURITY_LOG.open("a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            source,
            content[:200],  # Truncate for privacy
            classification,
            f"{confidence:.3f}" if confidence > 0 else "N/A",
            metadata
        ])

# Initialize log on startup
init_security_log()

# ------------------------------------------------------------------ #
# 5. Email classification endpoint
# ------------------------------------------------------------------ #
@app.post("/classify", response_model=ClassificationResponse)
async def classify_email(req: ClassificationRequest):
    """Classify an email as phishing or legitimate."""
    if not req.email_text.strip():
        raise HTTPException(status_code=400, detail="Empty text")

    # Get prediction (0 or 1)
    prediction = clf.predict(vec.transform([req.email_text]))[0]
    proba = clf.predict_proba(vec.transform([req.email_text]))[0]
    
    # Convert to string labels
    label = "phishing" if prediction == 1 else "legitimate"
    conf = float(proba[1] if prediction == 1 else proba[0])
    
    # Log to unified security log
    log_security_event(
        source="email",
        content=req.email_text,
        classification=label,
        confidence=conf,
        metadata="API classification"
    )

    return ClassificationResponse(
        classification=label,
        confidence=conf,
        is_phishing=(prediction == 1)
    )

# ------------------------------------------------------------------ #
# 6. Call logging endpoint
# ------------------------------------------------------------------ #
@app.post("/call_log", response_model=CallLogResponse)
async def log_call(req: CallLogRequest):
    """Log an incoming call for security tracking."""
    
    # Use provided timestamp or create one
    timestamp = req.timestamp or datetime.now().isoformat()
    
    # Basic risk assessment based on common patterns
    risk_level = "unknown"
    risk_indicators = []
    
    # Check for suspicious patterns
    phone = req.phone_number.replace("-", "").replace(" ", "").replace("(", "").replace(")", "")
    
    # Common scam area codes and patterns
    if phone.startswith("900") or phone.startswith("976"):
        risk_indicators.append("premium_rate")
        risk_level = "high"
    elif phone.startswith("876"):  # Jamaica (common scam origin)
        risk_indicators.append("international_risk")
        risk_level = "medium"
    elif len(phone) > 15:  # Unusually long number
        risk_indicators.append("unusual_format")
        risk_level = "medium"
    elif phone == "0000000000" or phone == "1111111111":
        risk_indicators.append("spoofed")
        risk_level = "high"
    
    if not risk_indicators:
        risk_level = "low"
    
    # Log to unified security log
    metadata = f"caller:{req.caller_name or 'unknown'}|indicators:{','.join(risk_indicators)}"
    log_security_event(
        source="call",
        content=f"Phone: {req.phone_number}",
        classification=f"risk_{risk_level}",
        confidence=0.0,  # No ML confidence for calls yet
        metadata=metadata
    )
    
    return CallLogResponse(
        logged=True,
        phone_number=req.phone_number,
        timestamp=timestamp,
        risk_level=risk_level
    )

# ------------------------------------------------------------------ #
# 7. Health & stats endpoints
# ------------------------------------------------------------------ #
@app.get("/health")
async def health_check():
    """Check if the API is healthy and models are loaded."""
    return {
        "status": "healthy",
        "model_loaded": True,
        "endpoints": ["/classify", "/call_log", "/stats"]
    }

@app.get("/stats")
async def get_stats():
    """Get basic statistics about logged security events."""
    if not SECURITY_LOG.exists():
        return {"total_events": 0}
    
    with SECURITY_LOG.open("r") as f:
        reader = csv.DictReader(f)
        events = list(reader)
    
    email_count = sum(1 for e in events if e["source"] == "email")
    call_count = sum(1 for e in events if e["source"] == "call")
    phishing_count = sum(1 for e in events if e["classification"] == "phishing")
    
    return {
        "total_events": len(events),
        "email_events": email_count,
        "call_events": call_count,
        "phishing_detected": phishing_count,
        "log_file": str(SECURITY_LOG)
    }

# ------------------------------------------------------------------ #
# 8. CLI fallback (uvicorn entry-point)
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Security Copilot Server...")
    print("📡 API will be available at http://localhost:8000")
    print("📱 Ready for iOS Shortcuts integration")
    print("-" * 50)
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)