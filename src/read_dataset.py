"""Utilities for reading IoT-23 conn.log.labeled files in batches."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import polars as pl

NULL_VALUES = ["(empty)", "-"]
LABELED_LOG_NAME = "conn.log.labeled"

# Zeek conn.log columns; label and detailed-label are appended with spaces in the last field.
CONN_COLUMNS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
]


def project_data_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "data"


def find_labeled_logs(data_dir: Path | None = None) -> list[Path]:
    root = data_dir or project_data_dir()
    if not root.exists():
        raise FileNotFoundError(f"Data directory not found: {root}")
    return sorted(root.rglob(LABELED_LOG_NAME))


def capture_id(path: Path, data_dir: Path) -> str:
    """Top-level scenario folder under data/ (e.g. CTU-IoT-Malware-Capture-1-1)."""
    return path.relative_to(data_dir).parts[0]


def group_files_by_capture(files: list[Path], data_dir: Path) -> dict[str, list[Path]]:
    groups: dict[str, list[Path]] = {}
    for path in files:
        groups.setdefault(capture_id(path, data_dir), []).append(path)
    return groups


def parse_fields_line(path: Path) -> list[str]:
    return CONN_COLUMNS


def expand_label_columns(df: pl.DataFrame) -> pl.DataFrame:
    if "label" in df.columns or df.is_empty():
        return df
    tail = pl.col("tunnel_parents").str.strip_chars()
    return df.with_columns(
        tail.str.extract(r"^(.+?)\s{2,}(\S+)\s{2,}(.*)$", 1).alias("tunnel_parents"),
        tail.str.extract(r"^(.+?)\s{2,}(\S+)\s{2,}(.*)$", 2).alias("label"),
        tail.str.extract(r"^(.+?)\s{2,}(\S+)\s{2,}(.*)$", 3).alias("detailed-label"),
    )


def iter_batches(
    path: Path,
    batch_size: int = 50_000,
    columns: list[str] | None = None,
) -> Iterator[pl.DataFrame]:
    cols = columns or parse_fields_line(path)
    reader = pl.read_csv_batched(
        path,
        separator="\t",
        has_header=False,
        new_columns=cols,
        null_values=NULL_VALUES,
        comment_prefix="#",
        batch_size=batch_size,
        infer_schema_length=10_000,
        ignore_errors=True,
        truncate_ragged_lines=True,
    )
    while True:
        batches = reader.next_batches(1)
        if not batches:
            break
        yield expand_label_columns(batches[0])


def load_sample(
    path: Path,
    n_rows: int = 10_000,
    batch_size: int = 50_000,
) -> pl.DataFrame:
    frames: list[pl.DataFrame] = []
    remaining = n_rows
    for batch in iter_batches(path, batch_size=batch_size):
        take = min(remaining, batch.height)
        frames.append(batch.head(take))
        remaining -= take
        if remaining <= 0:
            break
    if not frames:
        return pl.DataFrame()
    return pl.concat(frames, how="vertical")
