"""Feature preparation and XGBoost GPU pipeline for IoT-23 binary classification."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import polars as pl
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier

LABEL_COL = "label"
DETAILED_LABEL_COL = "detailed-label"

NUMERIC_FEATURES = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "missed_bytes",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "id.orig_p",
    "id.resp_p",
]

CATEGORICAL_FEATURES = ["proto", "service", "conn_state"]

DROP_COLUMNS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.resp_h",
    "history",
    "tunnel_parents",
    "local_orig",
    "local_resp",
    LABEL_COL,
    DETAILED_LABEL_COL,
]


def to_binary_labels(series: pl.Series) -> np.ndarray:
    values = series.cast(pl.Utf8).str.strip_chars().str.to_lowercase().to_list()
    return np.array([1 if value == "malicious" else 0 for value in values], dtype=np.int8)


def prepare_frame(df: pl.DataFrame) -> tuple[pl.DataFrame, np.ndarray | None]:
    if df.is_empty():
        return df, None

    frame = df.drop(
        [col for col in DROP_COLUMNS if col in df.columns],
        strict=False,
    )

    labels = None
    if LABEL_COL in df.columns:
        labels = to_binary_labels(df[LABEL_COL])

    for col in NUMERIC_FEATURES:
        if col in frame.columns:
            frame = frame.with_columns(pl.col(col).cast(pl.Float64, strict=False))

    for col in CATEGORICAL_FEATURES:
        if col in frame.columns:
            frame = frame.with_columns(pl.col(col).cast(pl.Utf8, strict=False).fill_null("unknown"))

    return frame, labels


def imbalance_weight(y: np.ndarray) -> float:
    negatives = int((y == 0).sum())
    positives = int((y == 1).sum())
    return negatives / max(positives, 1)


def build_pipeline(
    numeric_cols: list[str],
    categorical_cols: list[str],
    *,
    n_estimators: int = 300,
    max_depth: int = 8,
    learning_rate: float = 0.1,
    device: str = "cuda",
    scale_pos_weight: float = 1.0,
    random_state: int = 42,
) -> Pipeline:
    transformers = []
    if numeric_cols:
        transformers.append(
            (
                "num",
                SimpleImputer(strategy="median"),
                numeric_cols,
            )
        )
    if categorical_cols:
        transformers.append(
            (
                "cat",
                Pipeline(
                    [
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        (
                            "onehot",
                            OneHotEncoder(
                                handle_unknown="ignore",
                                max_categories=50,
                                sparse_output=False,
                            ),
                        ),
                    ]
                ),
                categorical_cols,
            )
        )

    preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")
    classifier = XGBClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        tree_method="hist",
        device=device,
        scale_pos_weight=scale_pos_weight,
        random_state=random_state,
        eval_metric="logloss",
        n_jobs=1,
    )
    return Pipeline(
        [
            ("preprocess", preprocessor),
            ("clf", classifier),
        ]
    )


def save_model(pipeline: Pipeline, feature_columns: list[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": pipeline, "feature_columns": feature_columns}, path)


def load_model(path: Path) -> tuple[Pipeline, list[str]]:
    payload = joblib.load(path)
    return payload["pipeline"], payload["feature_columns"]
