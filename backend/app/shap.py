"""Instance-level explanations: per-scan SHAP feature attributions.

The TreeExplainer is built once at import time; explaining a single URL
afterwards costs milliseconds, so it runs inline on every scan. Any SHAP
failure degrades to an empty list — explainability must never break a scan.
"""
import logging

import numpy as np
import pandas as pd

from .ml import model, _order

logger = logging.getLogger(__name__)

try:
    import shap

    _explainer = shap.TreeExplainer(model)
except Exception as e:  # pragma: no cover
    logger.warning("SHAP explainer unavailable: %s", e)
    _explainer = None


def explain(features: dict, top_n: int = 5) -> list[dict]:
    """Top features pushing THIS prediction, signed toward phishing.

    contribution > 0  → pushes the model toward PHISHING
    contribution < 0  → pushes toward LEGITIMATE
    """
    if _explainer is None or not features:
        return []
    try:
        X = pd.DataFrame([features])
        order = _order or list(getattr(model, "feature_names_in_", []) or [])
        if order:
            X = X.reindex(columns=order, fill_value=0)

        vals = np.asarray(_explainer.shap_values(X))[0]
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