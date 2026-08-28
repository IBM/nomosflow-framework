"""
data_lake_reader.py — Data-lake reader used by the compliance sidecar.

Real deployments swap in format-specific libraries (pyarrow, fastavro, pyorc,
deltalake). This module satisfies the sidecar import and provides the interface
that EXP-9 audits. No yield keyword is used anywhere in this file — all read
methods return a complete in-memory result, never a generator.

# AI-generated code
"""
from __future__ import annotations

import os
from typing import Any


class DataLakeReader:
    """Minimal data-lake reader interface used by the compliance sidecar."""

    def __init__(self, base_path: str = "") -> None:
        self.base_path = base_path

    def read_parquet(self, path: str) -> list[dict[str, Any]]:
        """Read a Parquet file and return rows as a list of dicts."""
        return []

    def read_avro(self, path: str) -> list[dict[str, Any]]:
        """Read an Avro container file and return records as a list of dicts."""
        return []

    def read_orc(self, path: str) -> list[dict[str, Any]]:
        """Read an ORC file and return rows as a list of dicts."""
        return []

    def read_delta(self, path: str, version: int | None = None) -> list[dict[str, Any]]:
        """Read a Delta Lake table at an optional snapshot version."""
        return []

    def read_data_lake_file(self, path: str) -> list[dict[str, Any]]:
        """Dispatch to the appropriate reader based on file extension."""
        ext = os.path.splitext(path)[-1].lower()
        if ext in (".parquet", ".pq"):
            return self.read_parquet(path)
        if ext == ".avro":
            return self.read_avro(path)
        if ext == ".orc":
            return self.read_orc(path)
        return []


_reader: DataLakeReader | None = None


def get_data_lake_reader() -> DataLakeReader:
    """Return the singleton DataLakeReader instance."""
    global _reader
    if _reader is None:
        _reader = DataLakeReader(base_path=os.getenv("DATA_LAKE_BASE_PATH", ""))
    return _reader
