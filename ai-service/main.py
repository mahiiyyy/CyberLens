from fastapi import FastAPI
from pydantic import BaseModel, Field
import re
import math
from collections import Counter

app = FastAPI(title="CyberLens Local AI Service", version="1.0")

PHISHING_TERMS = {
    "verify": 2.0, "verification": 2.0, "urgent": 2.5, "immediately": 2.5,
    "suspend": 2.2, "suspended": 2.2, "locked": 2.0, "unlock": 1.8,
    "password": 2.0, "credential": 2.4, "login": 1.5, "sign in": 1.5,
    "confirm your account": 2.8, "click here": 1.4, "security alert": 1.5,
    "unusual activity": 1.8, "expire": 1.6, "limited time": 1.8,
    "payment": 1.0, "invoice": 0.8, "wire transfer": 2.2, "gift card": 2.0,
}
LEGIT_TERMS = {
    "newsletter": 1.0, "receipt": 1.2, "order confirmation": 1.5,
    "meeting": 0.7, "calendar": 0.7, "thank you": 0.5, "unsubscribe": 0.8,
    "privacy policy": 0.6, "support ticket": 0.8, "no action required": 1.0,
}

class Evidence(BaseModel):
    subject: str = ""
    body: str = ""
    sender: str = ""
    reply_to: str = ""
    return_path: str = ""
    urls: list[str] = Field(default_factory=list)
    authentication: dict = Field(default_factory=dict)
    header_mismatches: list[str] = Field(default_factory=list)
    deterministic_score: int = 0

def text_features(text: str):
    t = text.lower()
    phishing = 0.0
    legit = 0.0
    hits = []
    for term, weight in PHISHING_TERMS.items():
        if term in t:
            phishing += weight
            hits.append(term)
    for term, weight in LEGIT_TERMS.items():
        if term in t:
            legit += weight
    exclamations = min(t.count("!"), 5)
    phishing += exclamations * 0.35
    caps = len(re.findall(r"\b[A-Z]{4,}\b", text))
    phishing += min(caps, 6) * 0.25
    return phishing, legit, hits

def sigmoid(x):
    return 1 / (1 + math.exp(-max(-12, min(12, x))))

@app.get("/health")
def health():
    return {"ok": True, "model": "CyberLens Local Evidence NLP v1", "mode": "local"}

@app.post("/analyze")
def analyze(evidence: Evidence):
    text = " ".join([evidence.subject, evidence.body, evidence.sender, evidence.reply_to])
    phishing, legit, hits = text_features(text)

    auth_failures = sum(1 for k in ("spf", "dkim", "dmarc") if str(evidence.authentication.get(k, "")).upper() in {"FAIL", "FAILED"})
    mismatch_count = len(evidence.header_mismatches)
    url_count = len(evidence.urls)
    suspicious_url = any(re.search(r"/(login|verify|signin|password|account|secure)", u.lower()) for u in evidence.urls)

    # The AI score is semantic/contextual evidence. It never pretends to be SPF/DKIM/DMARC.
    signal = phishing - (legit * 0.8) + auth_failures * 0.7 + mismatch_count * 0.8 + (1.0 if suspicious_url else 0)
    semantic_probability = sigmoid(signal - 3.0)
    ai_score = round(semantic_probability * 100)

    if ai_score >= 75:
        verdict = "PHISHING / IMPERSONATION"
        label = "malicious"
    elif ai_score >= 50:
        verdict = "SUSPICIOUS"
        label = "suspicious"
    elif ai_score >= 25:
        verdict = "NEEDS REVIEW"
        label = "review"
    else:
        verdict = "BENIGN / LEGITIMATE"
        label = "benign"

    findings = []
    if hits:
        findings.append({
            "title": "Social-engineering language",
            "severity": "HIGH" if len(hits) >= 3 else "MEDIUM",
            "confidence": min(99, 65 + len(hits) * 5),
            "evidence": ", ".join(hits[:8]),
            "explanation": "The local NLP model detected language commonly associated with urgency, account verification, credential collection, or pressure tactics."
        })
    if suspicious_url:
        findings.append({
            "title": "Credential-oriented URL context",
            "severity": "HIGH",
            "confidence": 88,
            "evidence": next((u for u in evidence.urls if re.search(r"/(login|verify|signin|password|account|secure)", u.lower())), evidence.urls[0] if evidence.urls else "URL"),
            "explanation": "The URL path contains an account or authentication action. This is contextual evidence, not proof by itself."
        })
    if mismatch_count:
        findings.append({
            "title": "Sender/header mismatch context",
            "severity": "MEDIUM",
            "confidence": 86,
            "evidence": "; ".join(evidence.header_mismatches),
            "explanation": "The AI incorporated a detected identity mismatch as supporting evidence. The underlying header check remains deterministic."
        })
    if auth_failures:
        findings.append({
            "title": "Authentication failures considered",
            "severity": "HIGH",
            "confidence": 91,
            "evidence": f"{auth_failures} of SPF/DKIM/DMARC checks reported FAIL",
            "explanation": "Authentication failures increase the contextual risk, but the AI does not perform or replace those cryptographic checks."
        })

    if not findings:
        findings.append({
            "title": "No strong phishing language detected",
            "severity": "LOW",
            "confidence": 82,
            "evidence": "No high-weight phishing phrases or credential-oriented URL patterns",
            "explanation": "The local NLP model did not find strong semantic indicators of phishing in the supplied content."
        })

    return {
        "model": "CyberLens Local Evidence NLP v1",
        "mode": "local-ai",
        "verdict": verdict,
        "label": label,
        "confidence": max(55, round(abs(ai_score - 50) * 0.8 + 55)),
        "ai_score": ai_score,
        "findings": findings,
        "explanation": f"The AI interpreted the email text and supplied security evidence. Semantic indicators: {', '.join(hits[:6]) if hits else 'none detected'}. AI score: {ai_score}/100."
    }
