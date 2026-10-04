"""Instance-level explanations: per-scan SHAP feature attributions.

The TreeExplainer is built lazily on first use — app startup stays fast and
SHAP can never prevent the API from serving scans. Any failure degrades to
an empty attribution list; explainability must never break a scan.
"""
import logging
import threading

import numpy as np
import pandas as pd

from .ml import model, _order

logger = logging.getLogger(__name__)

_explainer = None          # built on first use
_failed = False            # sentinel: SHAP unavailable — stop retrying
_lock = threading.Lock()


def _get_explainer():
    global _explainer, _failed
    if _explainer is not None or _failed:
        return _explainer
    with _lock:
        if _explainer is None and not _failed:
            try:
                import shap
                _explainer = shap.TreeExplainer(model)
            except Exception as e:
                logger.warning("SHAP explainer unavailable: %s", e)
                _failed = True
    return _explainer


def explain(features: dict, top_n: int = 5) -> list[dict]:
    """Top features pushing THIS prediction, signed toward phishing.

    contribution > 0 → pushes toward PHISHING, < 0 → toward LEGITIMATE.
    """
    if not features:
        return []
    explainer = _get_explainer()
    if explainer is None:
        return []
    try:
        X = pd.DataFrame([features])
        order = _order or list(getattr(model, "feature_names_in_", []) or [])
        if order:
            X = X.reindex(columns=order, fill_value=0)

        vals = np.asarray(explainer.shap_values(X))[0]
        top = np.argsort(-np.abs(vals))[:top_n]
        return [
            {
                "feature": str(X.columns[i]),
                "value": float(X.iloc[0, i]),
                "contribution": round(float(vals[i]), 4),
            }
            for i in top
        ]
    except Exception as e:
        logger.warning("SHAP explanation failed: %s", e)
        return []