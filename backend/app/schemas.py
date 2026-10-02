from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScanRequest(BaseModel):
    url: str


class SignalOut(BaseModel):
    id: str
    title: str
    severity: str
    description: str
    points: int = 0


class ScanResponse(BaseModel):
    id: int
    url: str
    host: str = ""
    timestamp: datetime
    risk_score: int
    threat_level: str
    classification: str
    confidence: float
    ml_probability: float
    recommendation: str = ""
    signals: list[SignalOut] = []
    features: dict = {}
    breakdown: dict = {}


class HistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    url: str
    host: str
    timestamp: datetime
    risk_score: int
    threat_level: str
    classification: str
    confidence: float


class HistoryPage(BaseModel):
    total: int
    items: list[HistoryItem]
    