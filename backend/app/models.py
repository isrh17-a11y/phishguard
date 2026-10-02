from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(String(255), index=True, default="")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    risk_score: Mapped[int] = mapped_column(Integer)
    threat_level: Mapped[str] = mapped_column(String(20), index=True)
    classification: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    ml_probability: Mapped[float] = mapped_column(Float)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    breakdown: Mapped[dict] = mapped_column(JSON, default=dict)

    signals: Mapped[list["ScanSignal"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanSignal(Base):
    __tablename__ = "scan_signals"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    signal: Mapped[str] = mapped_column(String(80), index=True)   # stable id, e.g. "brand_impersonation" — used for stats grouping
    title: Mapped[str] = mapped_column(String(200))               # human-readable, e.g. "Possible paypal impersonation"
    severity: Mapped[str] = mapped_column(String(10), index=True)
    description: Mapped[str] = mapped_column(Text)
    points: Mapped[int] = mapped_column(Integer, default=0)

    scan: Mapped["Scan"] = relationship(back_populates="signals")