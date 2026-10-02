from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .features import extract_features
from .ml import model_name, predict_proba
from .models import Scan, ScanSignal
from .risk import compute_risk
from .schemas import HistoryPage, ScanRequest, ScanResponse, SignalOut

Base.metadata.create_all(bind=engine)

app = FastAPI(title="PhishGuard API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],   # add your production URL on Day 4
    allow_methods=["*"],
    allow_headers=["*"],
)

FALLBACK_RECOMMENDATIONS = {
    "SAFE": "No significant risk indicators found. Normal caution still applies.",
    "LOW RISK": "No strong red flags, but verify the sender before trusting this link.",
    "MEDIUM RISK": "Several suspicious indicators detected. Avoid entering credentials or personal data.",
    "HIGH RISK": "Strong phishing indicators. Do not enter any information on this site.",
    "CRITICAL": "Multiple critical phishing indicators. Do not visit or share this URL.",
}


def _jsonable(d: dict) -> dict:
    """numpy scalars aren't JSON serialisable — convert them."""
    return {k: (v.item() if hasattr(v, "item") else v) for k, v in d.items()}


@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    db_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "model": model_name,
        "database": "up" if db_ok else "down",
        "time": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan", response_model=ScanResponse)
def scan(req: ScanRequest, db: Session = Depends(get_db)):
    url = req.url.strip()
    if not url:
        raise HTTPException(400, "URL must not be empty")
    if len(url) > 2048:
        raise HTTPException(400, "URL exceeds 2048 characters")
    if "://" not in url:
        url = "http://" + url

    host = urlparse(url).hostname or ""
    features = _jsonable(extract_features(url))
    p_phish = predict_proba(features)
    result = compute_risk(url, p_phish)

    row = Scan(
        url=url,
        host=host,
        risk_score=result["risk_score"],
        threat_level=result["threat_level"],
        classification=result["classification"],
        confidence=result["confidence"],
        ml_probability=p_phish,
        recommendation=result.get("recommendation", ""),
        features=features,
        breakdown=result.get("risk_breakdown", {}),
    )
    db.add(row)
    db.flush()
    for s in result["signals"]:
        db.add(ScanSignal(
            scan_id=row.id,
            signal=s["id"],
            title=s.get("title", s["id"]),
            severity=s["severity"],
            description=s.get("description", ""),
            points=int(s.get("points", 0)),
        ))
    db.commit()
    db.refresh(row)

    return ScanResponse(
        id=row.id,
        url=row.url,
        host=row.host,
        timestamp=row.timestamp,
        risk_score=row.risk_score,
        threat_level=row.threat_level,
        classification=row.classification,
        confidence=row.confidence,
        ml_probability=row.ml_probability,
        recommendation=row.recommendation,
        signals=[SignalOut(
            id=s.signal, title=s.title, severity=s.severity,
            description=s.description, points=s.points,
        ) for s in row.signals],
        features=row.features or {},
        breakdown=row.breakdown or {},
    )


@app.get("/api/history", response_model=HistoryPage)
def history(
    search: str | None = None,
    level: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(Scan)
    if search:
        q = q.filter(Scan.url.ilike(f"%{search}%"))
    if level:
        q = q.filter(Scan.threat_level == level)
    return {
        "total": q.count(),
        "items": q.order_by(Scan.timestamp.desc()).offset(offset).limit(limit).all(),
    }


@app.get("/api/history/{scan_id}", response_model=ScanResponse)
def scan_detail(scan_id: int, db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    if row is None:
        raise HTTPException(404, "Scan not found")
    return ScanResponse(
        id=row.id,
        url=row.url,
        host=row.host,
        timestamp=row.timestamp,
        risk_score=row.risk_score,
        threat_level=row.threat_level,
        classification=row.classification,
        confidence=row.confidence,
        ml_probability=row.ml_probability,
        recommendation=row.recommendation or FALLBACK_RECOMMENDATIONS.get(row.threat_level, ""),
        signals=[SignalOut(
            id=s.signal, title=s.title, severity=s.severity,
            description=s.description, points=s.points,
        ) for s in row.signals],
        features=row.features or {},
        breakdown=row.breakdown or {},
    )


@app.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Scan.id)).scalar() or 0
    by_level = dict(db.query(Scan.threat_level, func.count()).group_by(Scan.threat_level).all())
    by_class = dict(db.query(Scan.classification, func.count()).group_by(Scan.classification).all())
    avg_score = float(db.query(func.avg(Scan.risk_score)).scalar() or 0)
    top_signals = [
        {"signal": s, "count": c}
        for s, c in db.query(ScanSignal.signal, func.count())
        .group_by(ScanSignal.signal)
        .order_by(func.count().desc())
        .limit(8)
        .all()
    ]
    per_day = [
        {"date": str(d), "scans": c}
        for d, c in db.query(func.date(Scan.timestamp), func.count())
        .group_by(func.date(Scan.timestamp))
        .order_by(func.date(Scan.timestamp))
        .all()
    ]
    return {
        "total_scans": total,
        "by_threat_level": by_level,
        "by_classification": by_class,
        "average_risk_score": round(avg_score, 1),
        "top_signals": top_signals,
        "scans_per_day": per_day,
    }
