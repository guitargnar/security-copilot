#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Security Copilot Server with Advanced Features
--------------------------------------------------------
Run:  uvicorn main_enhanced:app --reload --host 0.0.0.0 --port 8000
"""
import os
import csv
import json
import time
import joblib
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import our new modules
from advanced_features import AdvancedFeatureExtractor
from url_analyzer import URLAnalyzer

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

# Initialize advanced analyzers
feature_extractor = AdvancedFeatureExtractor()
url_analyzer = URLAnalyzer()

# ------------------------------------------------------------------ #
# 2. FastAPI app & CORS (for iOS Shortcuts)
# ------------------------------------------------------------------ #
app = FastAPI(
    title="Security Copilot API - Enhanced",
    version="4.0",
    description="Advanced AI-powered security analysis with URL checking and feedback"
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
    include_advanced_features: bool = False

class ClassificationResponse(BaseModel):
    classification: str
    confidence: float
    is_phishing: bool
    advanced_features: Optional[Dict] = None
    url_analysis: Optional[List[Dict]] = None

class FeedbackRequest(BaseModel):
    email_text: str
    correct_label: str  # "phishing" or "legitimate"
    predicted_label: str
    confidence: float
    user_comment: Optional[str] = None

class URLCheckRequest(BaseModel):
    url: str

class URLCheckResponse(BaseModel):
    url: str
    risk_score: float
    risk_level: str
    risk_factors: List[str]
    is_blacklisted: bool
    is_whitelisted: bool

class SMSAnalysisRequest(BaseModel):
    message_text: str
    sender: Optional[str] = None

class SMSAnalysisResponse(BaseModel):
    classification: str
    confidence: float
    is_scam: bool
    risk_indicators: List[str]

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
FEEDBACK_LOG = LOG_DIR / "feedback_log.csv"

def init_logs():
    """Initialize all log files with headers."""
    if not SECURITY_LOG.exists():
        with SECURITY_LOG.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "source", "content", 
                "classification", "confidence", "metadata"
            ])
    
    if not FEEDBACK_LOG.exists():
        with FEEDBACK_LOG.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "email_text", "correct_label",
                "predicted_label", "confidence", "user_comment"
            ])

def log_security_event(
    source: str,
    content: str,
    classification: str,
    confidence: float = 0.0,
    metadata: str = "",
):
    """Log any security event to the unified log."""
    with SECURITY_LOG.open("a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            source,
            content[:200],
            classification,
            f"{confidence:.3f}" if confidence > 0 else "N/A",
            metadata
        ])

def log_feedback(feedback: FeedbackRequest):
    """Log user feedback for model improvement."""
    with FEEDBACK_LOG.open("a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            feedback.email_text[:500],
            feedback.correct_label,
            feedback.predicted_label,
            feedback.confidence,
            feedback.user_comment or ""
        ])
    
    # If it was a false positive/negative, save for retraining
    if feedback.correct_label != feedback.predicted_label:
        save_for_retraining(feedback)

def save_for_retraining(feedback: FeedbackRequest):
    """Save misclassified emails for model retraining."""
    retrain_dir = Path("data") / "retrain"
    retrain_dir.mkdir(parents=True, exist_ok=True)
    
    retrain_file = retrain_dir / "misclassified.jsonl"
    
    with retrain_file.open("a") as f:
        json.dump({
            "text": feedback.email_text,
            "true_label": feedback.correct_label,
            "predicted_label": feedback.predicted_label,
            "confidence": feedback.confidence,
            "timestamp": datetime.now().isoformat()
        }, f)
        f.write("\n")

# Initialize logs on startup
init_logs()

# ------------------------------------------------------------------ #
# 5. Enhanced email classification endpoint
# ------------------------------------------------------------------ #
@app.post("/classify", response_model=ClassificationResponse)
async def classify_email(req: ClassificationRequest):
    """Enhanced email classification with advanced features."""
    if not req.email_text.strip():
        raise HTTPException(status_code=400, detail="Empty text")

    # Get basic prediction
    prediction = clf.predict(vec.transform([req.email_text]))[0]
    proba = clf.predict_proba(vec.transform([req.email_text]))[0]
    
    # Convert to string labels
    label = "phishing" if prediction == 1 else "legitimate"
    conf = float(proba[1] if prediction == 1 else proba[0])
    
    response_data = {
        "classification": label,
        "confidence": conf,
        "is_phishing": (prediction == 1)
    }
    
    # Add advanced features if requested
    if req.include_advanced_features:
        advanced_features = feature_extractor.extract_all_features(req.email_text)
        response_data["advanced_features"] = advanced_features
        
        # Extract and analyze URLs
        import re
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, req.email_text)
        
        if urls:
            url_analyses = []
            for url in urls[:5]:  # Limit to 5 URLs
                analysis = url_analyzer.analyze_url(url)
                url_analyses.append(analysis)
                
                # If high-risk URL found, adjust confidence
                if analysis.get('risk_score', 0) > 0.7:
                    conf = min(conf + 0.1, 1.0)
                    response_data["confidence"] = conf
            
            response_data["url_analysis"] = url_analyses
    
    # Log to unified security log
    log_security_event(
        source="email",
        content=req.email_text,
        classification=label,
        confidence=conf,
        metadata="Enhanced analysis"
    )

    return ClassificationResponse(**response_data)

# ------------------------------------------------------------------ #
# 6. Feedback endpoint for model improvement
# ------------------------------------------------------------------ #
@app.post("/feedback")
async def submit_feedback(req: FeedbackRequest, background_tasks: BackgroundTasks):
    """Accept user feedback on classifications."""
    
    # Validate feedback
    if req.correct_label not in ["phishing", "legitimate"]:
        raise HTTPException(status_code=400, detail="Invalid correct_label")
    
    # Log feedback
    background_tasks.add_task(log_feedback, req)
    
    # Update URL blacklist/whitelist if applicable
    import re
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, req.email_text)
    
    for url in urls:
        if req.correct_label == "phishing":
            url_analyzer.add_to_blacklist(url)
        else:
            url_analyzer.add_to_whitelist(url)
    
    return {
        "status": "success",
        "message": "Feedback recorded for model improvement",
        "was_correct": req.correct_label == req.predicted_label
    }

# ------------------------------------------------------------------ #
# 7. URL checking endpoint
# ------------------------------------------------------------------ #
@app.post("/check_url", response_model=URLCheckResponse)
async def check_url(req: URLCheckRequest):
    """Check if a URL is potentially malicious."""
    
    analysis = url_analyzer.analyze_url(req.url)
    
    # Log URL check
    log_security_event(
        source="url_check",
        content=req.url,
        classification=f"risk_{analysis.get('risk_level', 'unknown')}",
        confidence=analysis.get('risk_score', 0),
        metadata=json.dumps(analysis.get('indicators', {}))
    )
    
    return URLCheckResponse(
        url=req.url,
        risk_score=analysis.get('risk_score', 0),
        risk_level=analysis.get('risk_level', 'unknown'),
        risk_factors=analysis.get('risk_factors', []),
        is_blacklisted=analysis.get('is_blacklisted', False),
        is_whitelisted=analysis.get('is_whitelisted', False)
    )

# ------------------------------------------------------------------ #
# 8. SMS analysis endpoint
# ------------------------------------------------------------------ #
@app.post("/analyze_sms", response_model=SMSAnalysisResponse)
async def analyze_sms(req: SMSAnalysisRequest):
    """Analyze SMS messages for scams (smishing)."""
    
    # Use the same model but with SMS-specific preprocessing
    text = req.message_text.strip()
    
    if not text:
        raise HTTPException(status_code=400, detail="Empty message")
    
    # SMS-specific indicators
    risk_indicators = []
    
    # Check for common SMS scam patterns
    sms_scam_patterns = [
        "package delivery",
        "tax refund",
        "prize winner",
        "verification code",
        "suspend account",
        "click link",
        "free gift",
        "act now"
    ]
    
    for pattern in sms_scam_patterns:
        if pattern.lower() in text.lower():
            risk_indicators.append(f"Contains '{pattern}'")
    
    # Check for URLs in SMS (often suspicious)
    import re
    if re.search(r'https?://', text):
        risk_indicators.append("Contains URL")
    
    # Check for short codes or premium numbers
    if req.sender and (len(req.sender) < 6 or req.sender.startswith("9")):
        risk_indicators.append("Suspicious sender number")
    
    # Get ML prediction
    prediction = clf.predict(vec.transform([text]))[0]
    proba = clf.predict_proba(vec.transform([text]))[0]
    
    label = "scam" if prediction == 1 else "legitimate"
    conf = float(proba[1] if prediction == 1 else proba[0])
    
    # Adjust confidence based on SMS-specific indicators
    if len(risk_indicators) >= 2:
        conf = min(conf + 0.2, 1.0)
        label = "scam"
    
    # Log SMS analysis
    log_security_event(
        source="sms",
        content=text,
        classification=label,
        confidence=conf,
        metadata=f"sender:{req.sender}|indicators:{','.join(risk_indicators)}"
    )
    
    return SMSAnalysisResponse(
        classification=label,
        confidence=conf,
        is_scam=(label == "scam"),
        risk_indicators=risk_indicators
    )

# ------------------------------------------------------------------ #
# 9. Enhanced call logging with pattern detection
# ------------------------------------------------------------------ #
@app.post("/call_log", response_model=CallLogResponse)
async def log_call(req: CallLogRequest):
    """Enhanced call logging with advanced risk assessment."""
    
    timestamp = req.timestamp or datetime.now().isoformat()
    
    # Enhanced risk assessment
    risk_level = "unknown"
    risk_indicators = []
    
    phone = req.phone_number.replace("-", "").replace(" ", "").replace("(", "").replace(")", "")
    
    # Premium rate numbers
    if phone.startswith("900") or phone.startswith("976"):
        risk_indicators.append("premium_rate")
        risk_level = "high"
    # International high-risk
    elif phone.startswith(("876", "284", "473", "664", "649")):  # Caribbean
        risk_indicators.append("international_risk")
        risk_level = "medium"
    # Spoofed numbers
    elif phone in ["0000000000", "1111111111", "1234567890"]:
        risk_indicators.append("spoofed")
        risk_level = "high"
    # Too short or too long
    elif len(phone) < 10 or len(phone) > 15:
        risk_indicators.append("unusual_format")
        risk_level = "medium"
    # Neighbor spoofing (same area code and prefix as your number)
    elif phone.startswith("502") and len(phone) == 10:  # Adjust to your area
        risk_indicators.append("possible_neighbor_spoofing")
        risk_level = "low"
    else:
        risk_level = "low"
    
    # Log call
    metadata = f"caller:{req.caller_name or 'unknown'}|indicators:{','.join(risk_indicators)}"
    log_security_event(
        source="call",
        content=f"Phone: {req.phone_number}",
        classification=f"risk_{risk_level}",
        confidence=0.0,
        metadata=metadata
    )
    
    return CallLogResponse(
        logged=True,
        phone_number=req.phone_number,
        timestamp=timestamp,
        risk_level=risk_level
    )

# ------------------------------------------------------------------ #
# 10. Health & enhanced stats endpoints
# ------------------------------------------------------------------ #
@app.get("/health")
async def health_check():
    """Check if the API is healthy and models are loaded."""
    return {
        "status": "healthy",
        "version": "4.0-enhanced",
        "model_loaded": True,
        "features": {
            "advanced_features": True,
            "url_analysis": True,
            "sms_analysis": True,
            "feedback_system": True
        },
        "endpoints": [
            "/classify", "/feedback", "/check_url",
            "/analyze_sms", "/call_log", "/stats"
        ]
    }

@app.get("/stats")
async def get_stats():
    """Get enhanced statistics about logged security events."""
    if not SECURITY_LOG.exists():
        return {"total_events": 0}
    
    with SECURITY_LOG.open("r") as f:
        reader = csv.DictReader(f)
        events = list(reader)
    
    # Basic counts
    email_count = sum(1 for e in events if e["source"] == "email")
    call_count = sum(1 for e in events if e["source"] == "call")
    sms_count = sum(1 for e in events if e["source"] == "sms")
    url_count = sum(1 for e in events if e["source"] == "url_check")
    
    # Threat counts
    phishing_count = sum(1 for e in events if "phishing" in e.get("classification", ""))
    scam_count = sum(1 for e in events if "scam" in e.get("classification", ""))
    high_risk_count = sum(1 for e in events if "high" in e.get("classification", ""))
    
    # Feedback stats
    feedback_count = 0
    false_positives = 0
    false_negatives = 0
    
    if FEEDBACK_LOG.exists():
        with FEEDBACK_LOG.open("r") as f:
            reader = csv.DictReader(f)
            feedback_events = list(reader)
            feedback_count = len(feedback_events)
            
            for fb in feedback_events:
                if fb["predicted_label"] == "phishing" and fb["correct_label"] == "legitimate":
                    false_positives += 1
                elif fb["predicted_label"] == "legitimate" and fb["correct_label"] == "phishing":
                    false_negatives += 1
    
    return {
        "total_events": len(events),
        "by_source": {
            "email": email_count,
            "sms": sms_count,
            "call": call_count,
            "url_check": url_count
        },
        "threats_detected": {
            "phishing": phishing_count,
            "scams": scam_count,
            "high_risk_calls": high_risk_count
        },
        "feedback": {
            "total": feedback_count,
            "false_positives": false_positives,
            "false_negatives": false_negatives
        },
        "model_accuracy": {
            "estimated": 1 - ((false_positives + false_negatives) / max(feedback_count, 1))
        },
        "log_files": {
            "security": str(SECURITY_LOG),
            "feedback": str(FEEDBACK_LOG)
        }
    }

# ------------------------------------------------------------------ #
# 11. CLI fallback (uvicorn entry-point)
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Enhanced Security Copilot Server v4.0...")
    print("✨ New Features: Advanced analysis, URL checking, SMS scanning, Feedback system")
    print("📡 API will be available at http://localhost:8000")
    print("📱 Ready for iOS Shortcuts integration")
    print("-" * 50)
    uvicorn.run("main_enhanced:app", host="0.0.0.0", port=8000, reload=True)