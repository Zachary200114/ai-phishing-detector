from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

import hashlib
import json
import re
from difflib import SequenceMatcher

from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# =========================
# Database setup (SQLite)
# =========================

SQLALCHECHEMY_DATABASE_URL = "sqlite:///./phish.db"

# NOTE: there's a small typo in the variable name above (SQLALCHECHEMY_...),
# but we only use it once below, so it's okay as long as it's consistent.
engine = create_engine(
    SQLALCHECHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    subject = Column(String, index=True)
    body_hash = Column(String, index=True)
    risk_score = Column(Integer)
    verdict = Column(String)
    reasons_json = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
# Pydantic models
# =========================

class EmailAnalysisRequest(BaseModel):
    subject: str
    body: str
    raw_headers: Optional[str] = None


class HeaderAnalysis(BaseModel):
    spf_pass: Optional[bool] = None
    dkim_pass: Optional[bool] = None
    dmarc_pass: Optional[bool] = None
    from_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    suspicious_flags: List[str] = []


class EmailAnalysisResponse(BaseModel):
    risk_score: int          # 0-100
    verdict: str             # SAFE / SUSPICIOUS / PHISHING
    reasons: List[str]
    header_analysis: HeaderAnalysis
    model_name: str
    created_at: str
    id: int                  # database id


class AnalysisHistoryItem(BaseModel):
    id: int
    subject: str
    risk_score: int
    verdict: str
    created_at: str
    reasons: List[str]


class RewriteRequest(BaseModel):
    subject: str
    body: str


class RewriteResponse(BaseModel):
    safe_subject: str
    safe_body: str
    diff_html: str


# =========================
# FastAPI app setup
# =========================

app = FastAPI()

origins = [
    "http://localhost:5173",  # frontend dev server
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# Simple heuristic analysis
# =========================

def simple_heuristic_score(subject, body):
    text = (subject + " " + body).lower()

    score = 10
    reasons: List[str] = []

    phishing_keywords = ["password", "verify", "account", "login", "click", "reset", "urgent"]
    for word in phishing_keywords:
        if word in text:
            score = score + 15
            reasons.append("Contains keyword: " + word)

    if "http://" in text or "https://" in text:
        score = score + 20
        reasons.append("Contains a link")

    if "bank" in text or "paypal" in text or "crypto" in text:
        score = score + 15
        reasons.append("Mentions financial service or money")

    if score > 100:
        score = 100

    return score, reasons


def score_to_verdict(score):
    if score <= 30:
        return "SAFE"
    if score <= 69:
        return "SUSPICIOUS"
    return "PHISHING"


def fake_header_analysis(raw_headers):
    if not raw_headers:
        return HeaderAnalysis(
            spf_pass=None,
            dkim_pass=None,
            dmarc_pass=None,
            from_domain=None,
            return_path_domain=None,
            reply_to_domain=None,
            suspicious_flags=["No headers provided"]
        )

    lower = raw_headers.lower()
    flags: List[str] = []

    spf_pass = "spf=pass" in lower
    dkim_pass = "dkim=pass" in lower
    dmarc_pass = "dmarc=pass" in lower

    if "spf=fail" in lower:
        flags.append("SPF fail found in Authentication-Results")
    if "dkim=fail" in lower:
        flags.append("DKIM fail found in Authentication-Results")
    if "dmarc=fail" in lower:
        flags.append("DMARC fail found in Authentication-Results")

    return HeaderAnalysis(
        spf_pass=spf_pass,
        dkim_pass=dkim_pass,
        dmarc_pass=dmarc_pass,
        from_domain=None,
        return_path_domain=None,
        reply_to_domain=None,
        suspicious_flags=flags
    )


# =========================
# Rewrite + diff helpers
# =========================

def rewrite_to_safe(subject: str, body: str) -> (str, str):
    """
    Simple rule-based "safe" rewrite.
    This is where you could later plug in a real LLM.
    """

    safe_subject = subject

    # Tone down scary/urgent words in subject
    subject_replacements = {
        "suspended": "updated",
        "suspension": "update",
        "urgent": "important",
        "immediately": "",
        "immediate": "",
    }
    for bad, good in subject_replacements.items():
        safe_subject = re.sub(bad, good, safe_subject, flags=re.IGNORECASE)

    safe_body = body

    # Remove login / password requests
    patterns_to_remove = [
        r"(?i)click.*link.*(login|log in|verify|reset)",
        r"(?i)enter.*password",
        r"(?i)provide.*credentials",
    ]
    for pat in patterns_to_remove:
        safe_body = re.sub(pat, "[removed sensitive instructions]", safe_body)

    # Remove URLs
    safe_body = re.sub(r"https?://\S+", "[link removed]", safe_body)

    # Soften threatening language
    body_replacements = {
        "will be closed": "may require your attention",
        "will be disabled": "may be temporarily limited",
        "within 24 hours": "in the near future",
        "immediately": "soon",
        "urgent": "important",
    }
    for bad, good in body_replacements.items():
        safe_body = re.sub(bad, good, safe_body, flags=re.IGNORECASE)

    # Add a generic safe closing if none exists
    if "thank you" not in safe_body.lower():
        safe_body = safe_body.strip() + "\n\nThank you,\nCustomer Support Team"

    return safe_subject, safe_body


def diff_words_html(original: str, safe: str) -> str:
    """
    Simple word-level diff as HTML.
    - unchanged: plain text
    - removed: <del> with red background
    - added: <ins> with green background
    """
    orig_words = original.split()
    safe_words = safe.split()

    sm = SequenceMatcher(None, orig_words, safe_words)
    out_parts: List[str] = []

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            out_parts.extend(orig_words[i1:i2])
        elif tag == "delete":
            for w in orig_words[i1:i2]:
                out_parts.append(
                    f'<del style="background-color:#8b0000;color:white;padding:0 2px;">{w}</del>'
                )
        elif tag == "insert":
            for w in safe_words[j1:j2]:
                out_parts.append(
                    f'<ins style="background-color:#006400;color:white;padding:0 2px;">{w}</ins>'
                )
        elif tag == "replace":
            for w in orig_words[i1:i2]:
                out_parts.append(
                    f'<del style="background-color:#8b0000;color:white;padding:0 2px;">{w}</del>'
                )
            for w in safe_words[j1:j2]:
                out_parts.append(
                    f'<ins style="background-color:#006400;color:white;padding:0 2px;">{w}</ins>'
                )

    return " ".join(out_parts)


# =========================
# Routes
# =========================

@app.get("/")
def read_root():
    return {"status": "ok"}


@app.post("/analyze", response_model=EmailAnalysisResponse)
def analyze_email(req: EmailAnalysisRequest, db: Session = Depends(get_db)):
    # 1) Heuristic scoring
    score, heuristic_reasons = simple_heuristic_score(req.subject, req.body)
    verdict = score_to_verdict(score)

    # 2) Header analysis
    header_info = fake_header_analysis(req.raw_headers)

    # 3) Combine reasons (heuristics + header flags)
    reasons: List[str] = []

    if len(heuristic_reasons) == 0:
        reasons.append("No obvious phishing keywords found.")
    else:
        for r in heuristic_reasons:
            reasons.append(r)

    if len(header_info.suspicious_flags) > 0:
        for f in header_info.suspicious_flags:
            reasons.append("Header flag: " + f)

    # 4) Compute body hash (for privacy)
    body_hash = hashlib.sha256(req.body.encode("utf-8")).hexdigest()

    # 5) Save to database
    db_item = Analysis(
        subject=req.subject,
        body_hash=body_hash,
        risk_score=score,
        verdict=verdict,
        reasons_json=json.dumps(reasons),
        created_at=datetime.utcnow(),
    )
    db.add(db_item)
    db.commit()
    db.refresh(db_item)

    # 6) Build response for frontend
    response = EmailAnalysisResponse(
        risk_score=score,
        verdict=verdict,
        reasons=reasons,
        header_analysis=header_info,
        model_name="simple_heuristic_v1",
        created_at=db_item.created_at.isoformat(),
        id=db_item.id,
    )

    return response


@app.get("/history", response_model=List[AnalysisHistoryItem])
def get_history(limit: int = 20, db: Session = Depends(get_db)):
    # Get most recent analyses, newest first
    items = (
        db.query(Analysis)
        .order_by(Analysis.created_at.desc())
        .limit(limit)
        .all()
    )

    history: List[AnalysisHistoryItem] = []

    for item in items:
        reasons = []
        if item.reasons_json:
            try:
                reasons = json.loads(item.reasons_json)
            except Exception:
                reasons = []

        history.append(
            AnalysisHistoryItem(
                id=item.id,
                subject=item.subject,
                risk_score=item.risk_score,
                verdict=item.verdict,
                created_at=item.created_at.isoformat(),
                reasons=reasons,
            )
        )

    return history


@app.post("/rewrite-safe", response_model=RewriteResponse)
def rewrite_safe_email(req: RewriteRequest):
    """
    Rewrite a potentially malicious email into a safe, legitimate version
    and return HTML highlighting the differences.
    """
    safe_subject, safe_body = rewrite_to_safe(req.subject, req.body)
    diff_html = diff_words_html(req.body, safe_body)

    return RewriteResponse(
        safe_subject=safe_subject,
        safe_body=safe_body,
        diff_html=diff_html,
    )

