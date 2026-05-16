"""
Train XGBoost (GPU) for binary IoT-23 classification: Benign vs Malicious.

Train/test split is by capture scenario (no rows from the same capture in both sets).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupKFold, train_test_split

from model import (
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    build_pipeline,
    imbalance_weight,
    prepare_frame,
    save_model,
)
from read_dataset import (
    capture_id,
    find_labeled_logs,
    group_files_by_capture,
    iter_batches,
    parse_fields_line,
    project_data_dir,
)


def capture_majority_malicious(path: Path, batch_size: int = 10_000) -> float:
    for batch in iter_batches(path, batch_size=batch_size):
        _, labels = prepare_frame(batch)
        if labels is not None and len(labels) > 0:
            return float(labels.mean())
    return 0.5


def split_captures(
    files: list[Path],
    data_dir: Path,
    *,
    test_size: float,
    random_state: int,
) -> tuple[list[str], list[str]]:
    groups = group_files_by_capture(files, data_dir)
    captures = sorted(groups)

    majority_malicious = []
    for capture in captures:
        sample_file = groups[capture][0]
        majority_malicious.append(int(capture_majority_malicious(sample_file) >= 0.5))

    train_captures, test_captures = train_test_split(
        captures,
        test_size=test_size,
        random_state=random_state,
        stratify=majority_malicious,
    )
    return sorted(train_captures), sorted(test_captures)


def files_for_captures(files: list[Path], data_dir: Path, captures: list[str]) -> list[Path]:
    allowed = set(captures)
    return [path for path in files if capture_id(path, data_dir) in allowed]


def collect_training_data(
    files: list[Path],
    *,
    batch_size: int,
    max_rows_per_file: int | None,
    max_total_rows: int | None,
) -> tuple[pd.DataFrame, np.ndarray, list[str], list[str]]:
    feature_names: list[str] | None = None
    numeric_cols: list[str] = []
    categorical_cols: list[str] = []
    x_parts: list[pd.DataFrame] = []
    y_parts: list[np.ndarray] = []
    total_rows = 0

    for path in files:
        file_rows = 0
        columns = parse_fields_line(path)
        for batch in iter_batches(path, batch_size=batch_size, columns=columns):
            features, labels = prepare_frame(batch)
            if labels is None or features.is_empty():
                continue

            batch_numeric = [col for col in NUMERIC_FEATURES if col in features.columns]
            batch_categorical = [col for col in CATEGORICAL_FEATURES if col in features.columns]
            ordered = batch_numeric + batch_categorical

            if feature_names is None:
                feature_names = ordered
                numeric_cols = batch_numeric
                categorical_cols = batch_categorical
            else:
                features = features.select(feature_names)

            x_parts.append(features.to_pandas())
            y_parts.append(labels)
            batch_len = len(labels)
            file_rows += batch_len
            total_rows += batch_len

            if max_rows_per_file is not None and file_rows >= max_rows_per_file:
                break
            if max_total_rows is not None and total_rows >= max_total_rows:
                break

        if max_total_rows is not None and total_rows >= max_total_rows:
            break

    if not x_parts:
        raise RuntimeError("No training rows were loaded. Check the data directory.")

    return (
        pd.concat(x_parts, ignore_index=True),
        np.concatenate(y_parts),
        numeric_cols,
        categorical_cols,
    )


def print_class_balance(name: str, y: np.ndarray) -> None:
    print(
        f"{name}: {len(y):,} rows | "
        f"benign={int((y == 0).sum()):,}, malicious={int((y == 1).sum()):,}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train IoT-23 binary classifier (XGBoost GPU)")
    parser.add_argument("--data-dir", type=Path, default=project_data_dir())
    parser.add_argument("--batch-size", type=int, default=50_000)
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=100_000,
        help="Cap rows per capture file (None = read entire file)",
    )
    parser.add_argument(
        "--max-total-rows",
        type=int,
        default=2_000_000,
        help="Max rows per split (train and test each)",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of capture scenarios held out for test",
    )
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=0.1)
    parser.add_argument(
        "--device",
        type=str,
        default="cuda",
        choices=["cuda", "cpu"],
        help="XGBoost device: cuda for GPU, cpu for fallback",
    )
    parser.add_argument("--model-out", type=Path, default=Path("artifacts/iot23_xgb_gpu.joblib"))
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument(
        "--cv-folds",
        type=int,
        default=0,
        help="If >1, run GroupKFold CV on captures instead of a single train/test split",
    )
    args = parser.parse_args()

    files = find_labeled_logs(args.data_dir)
    print(f"Found {len(files)} labeled log files under {args.data_dir}")
    print(f"Model: XGBoost | device={args.device}")
    print("Split: by capture scenario (GroupKFold-style, no row leakage across captures)")

    train_captures, test_captures = split_captures(
        files,
        args.data_dir,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    print(f"\nTrain captures ({len(train_captures)}): {', '.join(train_captures)}")
    print(f"Test captures  ({len(test_captures)}): {', '.join(test_captures)}")

    train_files = files_for_captures(files, args.data_dir, train_captures)
    test_files = files_for_captures(files, args.data_dir, test_captures)

    x_train, y_train, numeric_cols, categorical_cols = collect_training_data(
        train_files,
        batch_size=args.batch_size,
        max_rows_per_file=args.max_rows_per_file,
        max_total_rows=args.max_total_rows,
    )
    x_test, y_test, _, _ = collect_training_data(
        test_files,
        batch_size=args.batch_size,
        max_rows_per_file=args.max_rows_per_file,
        max_total_rows=args.max_total_rows,
    )

    print()
    print_class_balance("Train", y_train)
    print_class_balance("Test ", y_test)

    scale_pos_weight = imbalance_weight(y_train)
    print(f"scale_pos_weight={scale_pos_weight:.2f}")

    pipeline = build_pipeline(
        numeric_cols,
        categorical_cols,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        device=args.device,
        scale_pos_weight=scale_pos_weight,
        random_state=args.random_state,
    )
    pipeline.fit(x_train, y_train)

    y_pred = pipeline.predict(x_test)
    print("\nConfusion matrix (held-out captures):\n", confusion_matrix(y_test, y_pred))
    print(
        "\nClassification report (held-out captures):\n",
        classification_report(y_test, y_pred, target_names=["benign", "malicious"]),
    )

    if args.cv_folds > 1:
        groups_map = group_files_by_capture(files, args.data_dir)
        captures = sorted(groups_map)
        group_ids = np.array([captures.index(capture_id(path, args.data_dir)) for path in files])
        gkf = GroupKFold(n_splits=args.cv_folds)
        print(f"\n--- GroupKFold CV ({args.cv_folds} folds, by capture) ---")
        for fold, (train_idx, test_idx) in enumerate(gkf.split(files, groups=group_ids), start=1):
            fold_train_files = [files[i] for i in train_idx]
            fold_test_files = [files[i] for i in test_idx]
            fold_train_caps = sorted({capture_id(path, args.data_dir) for path in fold_train_files})
            fold_test_caps = sorted({capture_id(path, args.data_dir) for path in fold_test_files})
            print(f"\nFold {fold}: train={fold_train_caps} | test={fold_test_caps}")

            x_tr, y_tr, _, _ = collect_training_data(
                fold_train_files,
                batch_size=args.batch_size,
                max_rows_per_file=args.max_rows_per_file,
                max_total_rows=args.max_total_rows,
            )
            x_te, y_te, _, _ = collect_training_data(
                fold_test_files,
                batch_size=args.batch_size,
                max_rows_per_file=args.max_rows_per_file,
                max_total_rows=args.max_total_rows,
            )
            fold_pipeline = build_pipeline(
                numeric_cols,
                categorical_cols,
                n_estimators=args.n_estimators,
                max_depth=args.max_depth,
                learning_rate=args.learning_rate,
                device=args.device,
                scale_pos_weight=imbalance_weight(y_tr),
                random_state=args.random_state,
            )
            fold_pipeline.fit(x_tr, y_tr)
            y_fold_pred = fold_pipeline.predict(x_te)
            print(classification_report(y_te, y_fold_pred, target_names=["benign", "malicious"]))

    feature_columns = numeric_cols + categorical_cols
    save_model(pipeline, feature_columns, args.model_out)
    print(f"\nModel saved to {args.model_out.resolve()}")


if __name__ == "__main__":
    main()
