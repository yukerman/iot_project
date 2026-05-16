"""Load trained model and run inference on network flows."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pandas as pd
import polars as pl

from model import CATEGORICAL_FEATURES, NUMERIC_FEATURES, load_model, prepare_frame

FEATURE_COLUMNS = NUMERIC_FEATURES + CATEGORICAL_FEATURES


def resolve_model_path(path: Path | None = None) -> Path:
    if path is not None and path.exists():
        return path
    root = Path(__file__).resolve().parents[1]
    candidates = [
        root / "artifacts" / "iot23_xgb_gpu.joblib",
        root / "src" / "artifacts" / "iot23_xgb_gpu.joblib",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Trained model not found. Run train.py first or pass --model-path."
    )


class FlowClassifier:
    def __init__(self, model_path: Path | None = None) -> None:
        resolved = resolve_model_path(model_path)
        self.pipeline, saved_columns = load_model(resolved)
        self.feature_columns = saved_columns or FEATURE_COLUMNS
        self.model_path = resolved

    def flows_to_frame(self, flows: list[dict]) -> pd.DataFrame:
        rows = []
        for flow in flows:
            row = {col: flow.get(col) for col in self.feature_columns}
            rows.append(row)
        return pd.DataFrame(rows, columns=self.feature_columns)

    def predict(self, flows: list[dict]) -> list[dict]:
        if not flows:
            return []

        frame = pl.DataFrame(flows)
        features, _ = prepare_frame(frame)
        missing = [col for col in self.feature_columns if col not in features.columns]
        if missing:
            raise ValueError(f"Missing required flow fields: {missing}")

        features = features.select(self.feature_columns)
        matrix = features.to_pandas()

        probabilities = self.pipeline.predict_proba(matrix)[:, 1]
        labels = self.pipeline.predict(matrix)

        results = []
        now = datetime.now(timezone.utc).isoformat()
        for index, flow in enumerate(flows):
            malicious = int(labels[index]) == 1
            results.append(
                {
                    "id": flow.get("id") or str(uuid4()),
                    "device_id": flow.get("device_id", "unknown"),
                    "ts": flow.get("ts"),
                    "prediction": "malicious" if malicious else "benign",
                    "label_code": int(labels[index]),
                    "probability_malicious": round(float(probabilities[index]), 4),
                    "probability_benign": round(float(1 - probabilities[index]), 4),
                    "received_at": now,
                    "proto": flow.get("proto"),
                    "id.resp_h": flow.get("id.resp_h"),
                    "id.resp_p": flow.get("id.resp_p"),
                }
            )
        return results
