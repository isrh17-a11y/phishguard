from pathlib import Path
import joblib
import pandas as pd

ARTIFACT_PATH = Path(__file__).resolve().parents[2] / "ml" / "artifacts" / "model.pkl"

_bundle = joblib.load(ARTIFACT_PATH)
if isinstance(_bundle, dict):                     # your model.pkl is {'model', 'features', 'name'}
    model = _bundle["model"]
    _order = _bundle.get("features")
    model_name = _bundle.get("name", "unknown")
else:
    model = _bundle
    _order = list(getattr(model, "feature_names_in_", []))
    model_name = type(model).__name__

def predict_proba(features: dict) -> float:
    X = pd.DataFrame([features])
    order = _order or list(getattr(model, "feature_names_in_", []))
    if order:
        X = X.reindex(columns=order, fill_value=0)
    return float(model.predict_proba(X)[0][1])