"""Train and compare Logistic Regression, Random Forest and XGBoost.

Usage (from the project root):
    python ml/train.py --data data/raw.csv --url-col url --label-col label --phishing-values 1

--phishing-values: comma-separated label values that mean PHISHING.
   * Kaggle "Phishing Site URLs":  --phishing-values bad
   * PhiUSIIL (UCI):               --phishing-values 0   (!! in PhiUSIIL, 1 = legitimate)
   * Many others:                  --phishing-values 1,phishing,malicious,bad
CHECK your dataset's label meaning before training. Getting this backwards
gives a model that looks great and is completely inverted.

Split: 70% train / 15% validation / 15% test (stratified).
Model selection uses VALIDATION F1; the final numbers you report come from TEST.
"""
import argparse
import json
import sys
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (ConfusionMatrixDisplay, accuracy_score, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score,
                             roc_curve)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.features import FEATURE_NAMES, extract_features  # noqa: E402

SEED = 42
OUT = ROOT / "ml" / "artifacts"
OUT.mkdir(parents=True, exist_ok=True)


def load_data(path, url_col, label_col, phishing_values, limit):
    df = pd.read_csv(path)
    df = df[[url_col, label_col]].rename(columns={url_col: "url", label_col: "raw_label"})
    df = df.dropna()
    df["url"] = df["url"].astype(str).str.strip()

    pv = {v.strip().lower() for v in phishing_values.split(",")}
    df["label"] = df["raw_label"].astype(str).str.strip().str.lower().isin(pv).astype(int)

    # remove duplicate URLs, and URLs that appear with conflicting labels
    conflict = df.groupby("url")["label"].nunique()
    conflict = conflict[conflict > 1].index
    df = df[~df["url"].isin(conflict)].drop_duplicates(subset="url")

    if limit and len(df) > limit:
        parts = [g.sample(min(len(g), limit // 2), random_state=SEED)
                 for _, g in df.groupby("label")]
        df = pd.concat(parts)
    print(f"Rows after cleaning: {len(df)} | phishing share: {df['label'].mean():.2%}")
    return df.reset_index(drop=True)


def build_features(df, cache):
    if cache.exists():
        cached = pd.read_csv(cache)
        if len(cached) == len(df) and (cached["url"].values == df["url"].values).all():
            print("Using cached features:", cache)
            return cached
    print("Extracting features (this can take a few minutes)...")
    feats = pd.DataFrame([extract_features(u) for u in df["url"]])
    out = pd.concat([df[["url", "label"]], feats], axis=1)
    out.to_csv(cache, index=False)
    return out


def metrics(y, pred, proba):
    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "roc_auc": roc_auc_score(y, proba),
    }


def shap_summary(model, X_sample, name):
    try:
        import shap
        explainer = shap.TreeExplainer(model)
        sv = explainer.shap_values(X_sample)
        if isinstance(sv, list):          # older shap: list per class
            sv = sv[1]
        elif getattr(sv, "ndim", 2) == 3:  # newer shap: (n, features, classes)
            sv = sv[:, :, 1]
        shap.summary_plot(sv, X_sample, show=False)
        plt.tight_layout()
        plt.savefig(OUT / f"shap_summary_{name}.png", dpi=150)
        plt.close()
        print("Saved SHAP summary plot.")
    except Exception as e:  # SHAP is a nice-to-have; never fail training over it
        print("SHAP skipped:", e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--url-col", default="url")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--phishing-values", default="1")
    ap.add_argument("--limit", type=int, default=0, help="optional cap on rows for quick tests")
    args = ap.parse_args()

    df = load_data(args.data, args.url_col, args.label_col, args.phishing_values, args.limit)
    data = build_features(df, ROOT / "data" / "features.csv")

    X, y = data[FEATURE_NAMES], data["label"]
    X_train, X_tmp, y_train, y_tmp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=SEED)
    X_val, X_test, y_val, y_test = train_test_split(
        X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=SEED)
    print(f"train={len(X_train)} val={len(X_val)} test={len(X_test)}")

    spw = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    models = {
        "LogisticRegression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
        "RandomForest": RandomForestClassifier(
            n_estimators=200, n_jobs=-1, class_weight="balanced", random_state=SEED),
        "XGBoost": XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.9,
            colsample_bytree=0.9, scale_pos_weight=spw, eval_metric="logloss",
            n_jobs=-1, random_state=SEED),
    }

    rows, fitted = [], {}
    fig_roc, ax_roc = plt.subplots(figsize=(6, 5))
    for name, model in models.items():
        print(f"Training {name}...")
        model.fit(X_train, y_train)
        fitted[name] = model

        v_proba = model.predict_proba(X_val)[:, 1]
        v = metrics(y_val, (v_proba >= 0.5).astype(int), v_proba)

        t_proba = model.predict_proba(X_test)[:, 1]
        t_pred = (t_proba >= 0.5).astype(int)
        t = metrics(y_test, t_pred, t_proba)

        rows.append({"model": name,
                     **{f"val_{k}": round(x, 4) for k, x in v.items()},
                     **{f"test_{k}": round(x, 4) for k, x in t.items()}})

        ConfusionMatrixDisplay(confusion_matrix(y_test, t_pred),
                               display_labels=["Legit", "Phishing"]).plot(cmap="Blues")
        plt.title(f"{name} - test confusion matrix")
        plt.savefig(OUT / f"confusion_{name}.png", dpi=150)
        plt.close()

        fpr, tpr, _ = roc_curve(y_test, t_proba)
        ax_roc.plot(fpr, tpr, label=f"{name} (AUC={t['roc_auc']:.3f})")

    ax_roc.plot([0, 1], [0, 1], "k--", alpha=0.4)
    ax_roc.set_xlabel("False positive rate")
    ax_roc.set_ylabel("True positive rate")
    ax_roc.set_title("ROC curves (test set)")
    ax_roc.legend()
    fig_roc.savefig(OUT / "roc_curves.png", dpi=150)
    plt.close(fig_roc)

    comp = pd.DataFrame(rows)
    comp.to_csv(OUT / "model_comparison.csv", index=False)
    print("\n", comp.to_string(index=False))

    # select on VALIDATION F1 (ties broken by validation ROC-AUC)
    best_row = comp.sort_values(["val_f1", "val_roc_auc"], ascending=False).iloc[0]
    best_name = best_row["model"]
    best = fitted[best_name]
    print(f"\nSelected model: {best_name} (val F1={best_row['val_f1']})")

    joblib.dump({"model": best, "features": FEATURE_NAMES, "name": best_name},
                OUT / "model.pkl")
    (OUT / "selection.json").write_text(json.dumps(
        {"selected": best_name, "criterion": "validation F1", "seed": SEED,
         "n_train": len(X_train), "n_val": len(X_val), "n_test": len(X_test)}, indent=2))

    if best_name in ("RandomForest", "XGBoost"):
        shap_summary(best, X_test.sample(min(500, len(X_test)), random_state=SEED), best_name)

    print("Artifacts saved in", OUT)


if __name__ == "__main__":
    main()
