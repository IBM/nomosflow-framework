"""
audit_emitter.py — Fire-and-forget AuditRecord sink for the engine
===================================================================

The engine calls AuditEmitter.emit(record) at the end of every decide().
Adapters never call this directly.

Backends (chosen by env / config):
  - "log"     → structured JSON to stdout (default, always available)
  - "sqlite"  → appends to compliance_audit.db (if available)
  - "kafka"   → publishes to audit.log topic (if kafka-python installed)
  - "s3"      → delegates to the existing S3AuditWriterAsync (if configured)

All writes are non-blocking.  A failure in any backend is logged and swallowed
so that a flaky audit sink never fails a compliance decision.

OSCAL / compliance-trestle integration
---------------------------------------
The verdict_audit table carries an ``oscal_controls`` column (TEXT, JSON array).
It is written in two phases:

  Phase 1 — INSERT (inside emit(), same daemon thread as the rest of the row):
      oscal_controls = '[]'   ← placeholder; annotation not yet done

  Phase 2 — UPDATE (called by TrestleAnnotator after resolve_controls()):
      oscal_controls = '["AC-3","AU-2",…]'

Existing databases that pre-date this column are migrated automatically via
ALTER TABLE … ADD COLUMN on first connection.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.engine.verdict_api import AuditRecord

logger = logging.getLogger(__name__)

# Backend selection
_AUDIT_BACKEND = os.getenv("AUDIT_BACKEND", "log").lower()  # log | sqlite | kafka | s3 | postgres


class AuditEmitter:
    """
    Thin, non-blocking audit sink.

    Usage (inside engine.py):
        self._emitter = AuditEmitter()
        …
        self._emitter.emit(audit_record)   # fire-and-forget
    """

    def __init__(self) -> None:
        self._backend = _AUDIT_BACKEND
        self._sqlite_conn = None
        self._kafka_producer = None
        self._s3_writer = None
        self._pg_conn = None
        self._lock = threading.Lock()
        self._init_backend()

    # ─── initialisation ────────────────────────────────────────────────────

    def _init_backend(self) -> None:
        if self._backend == "sqlite":
            self._init_sqlite()
        elif self._backend == "kafka":
            self._init_kafka()
        elif self._backend == "s3":
            self._init_s3()
        elif self._backend == "postgres":
            self._init_postgres()
        # "log" needs no init

    def _init_sqlite(self) -> None:
        try:
            import sqlite3
            db_path = os.getenv("AUDIT_DB_PATH", "compliance_audit.db")
            conn = sqlite3.connect(db_path, check_same_thread=False)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS verdict_audit (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id     TEXT,
                    timestamp      TEXT,
                    principal_id   TEXT,
                    role           TEXT,
                    action         TEXT,
                    resource       TEXT,
                    final_verdict  TEXT,
                    tier_traces    TEXT,
                    engine_version TEXT,
                    latency_ms     REAL,
                    oscal_controls TEXT DEFAULT '[]'
                )
            """)
            # Migrate existing databases that pre-date the oscal_controls column.
            try:
                conn.execute("ALTER TABLE verdict_audit ADD COLUMN oscal_controls TEXT DEFAULT '[]'")
            except Exception:
                pass  # column already exists — sqlite raises OperationalError, that is fine
            conn.commit()
            self._sqlite_conn = conn
            logger.info("✅ AuditEmitter: SQLite backend ready (%s)", db_path)
        except Exception as exc:
            logger.warning("AuditEmitter: SQLite init failed (%s) — falling back to log", exc)
            self._backend = "log"

    def _init_kafka(self) -> None:
        try:
            from kafka import KafkaProducer  # type: ignore
            broker = os.getenv("KAFKA_BROKER", "localhost:9092")
            self._kafka_producer = KafkaProducer(
                bootstrap_servers=broker,
                value_serializer=lambda v: json.dumps(v).encode(),
                api_version_auto_timeout_ms=3000,
            )
            logger.info("✅ AuditEmitter: Kafka backend ready (%s)", broker)
        except Exception as exc:
            logger.warning("AuditEmitter: Kafka init failed (%s) — falling back to log", exc)
            self._backend = "log"

    def _init_s3(self) -> None:
        try:
            from src.storage.s3_audit_writer import S3AuditWriterAsync  # type: ignore
            self._s3_writer = S3AuditWriterAsync(
                endpoint_url  = os.getenv("S3_ENDPOINT_URL",   "http://localhost:4566"),
                bucket        = os.getenv("S3_AUDIT_BUCKET",   "compliance-audit-logs"),
                access_key    = os.getenv("S3_ACCESS_KEY",     "test"),
                secret_key    = os.getenv("S3_SECRET_KEY",     "test"),
                region        = os.getenv("S3_REGION",         "us-east-1"),
                key_prefix    = os.getenv("S3_KEY_PREFIX",     "engine-audit"),
                batch_size    = int(os.getenv("S3_BATCH_SIZE", "50")),
                batch_timeout = float(os.getenv("S3_BATCH_TIMEOUT", "5.0")),
            )
            logger.info("✅ AuditEmitter: S3 backend ready")
        except Exception as exc:
            logger.warning("AuditEmitter: S3 init failed (%s) — falling back to log", exc)
            self._backend = "log"

    def _init_postgres(self) -> None:
        dsn = os.getenv("AUDIT_POSTGRES_DSN", "")
        if not dsn:
            logger.warning("AuditEmitter: AUDIT_POSTGRES_DSN not set — falling back to log")
            self._backend = "log"
            return
        try:
            import psycopg2                      # type: ignore
            import psycopg2.extras               # type: ignore
            conn = psycopg2.connect(dsn)
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS verdict_audit (
                        id             BIGSERIAL PRIMARY KEY,
                        request_id     TEXT,
                        timestamp      TIMESTAMPTZ,
                        principal_id   TEXT,
                        role           TEXT,
                        action         TEXT,
                        resource       TEXT,
                        final_verdict  TEXT,
                        tier_traces    JSONB,
                        engine_version TEXT,
                        latency_ms     DOUBLE PRECISION,
                        oscal_controls JSONB DEFAULT '[]'
                    )
                """)
                # Migrate existing databases.
                cur.execute("""
                    ALTER TABLE verdict_audit
                    ADD COLUMN IF NOT EXISTS oscal_controls JSONB DEFAULT '[]'
                """)
            self._pg_conn = conn
            logger.info("✅ AuditEmitter: Postgres backend ready (%s)", dsn[:40])
        except Exception as exc:
            logger.warning("AuditEmitter: Postgres init failed (%s) — falling back to log", exc)
            self._backend = "log"

    # ─── public API ────────────────────────────────────────────────────────

    def emit(self, record: "AuditRecord", latency_ms: float = 0.0) -> None:
        """Fire-and-forget. Runs in a daemon thread to avoid blocking decide()."""
        t = threading.Thread(
            target=self._write,
            args=(record, latency_ms),
            daemon=True,
        )
        t.start()

    def update_oscal_controls(self, request_id: str, controls: list[str]) -> None:
        """
        Write resolved OSCAL control IDs back to the persisted audit row.

        Called by TrestleAnnotator after resolve_controls() completes (still in
        a daemon thread — never blocks decide()).  Safe to call even when the
        backend is "log" or "kafka" — those paths are no-ops here since the full
        record payload already carries oscal_controls via emit().
        """
        if not controls:
            return
        try:
            if self._backend == "sqlite" and self._sqlite_conn:
                self._update_oscal_sqlite(request_id, controls)
            elif self._backend == "postgres" and self._pg_conn:
                self._update_oscal_postgres(request_id, controls)
            # log / kafka / s3: no UPDATE needed — the full record payload is
            # already re-emitted by TrestleAnnotator via _write_log / send.
        except Exception as exc:
            logger.warning("AuditEmitter.update_oscal_controls failed: %s", exc)

    # ─── backend writers ───────────────────────────────────────────────────

    def _write(self, record: "AuditRecord", latency_ms: float) -> None:
        try:
            if self._backend == "sqlite" and self._sqlite_conn:
                self._write_sqlite(record, latency_ms)
            elif self._backend == "kafka" and self._kafka_producer:
                self._write_kafka(record, latency_ms)
            elif self._backend == "s3" and self._s3_writer:
                self._write_s3(record, latency_ms)
            elif self._backend == "postgres" and self._pg_conn:
                self._write_postgres(record, latency_ms)
            else:
                self._write_log(record, latency_ms)
        except Exception as exc:
            logger.warning("AuditEmitter._write failed: %s", exc)

    def _write_log(self, record: "AuditRecord", latency_ms: float) -> None:
        payload = record.to_dict()
        payload["latency_ms"] = round(latency_ms, 2)
        logger.info("AUDIT %s", json.dumps(payload))

    def _write_sqlite(self, record: "AuditRecord", latency_ms: float) -> None:
        with self._lock:
            self._sqlite_conn.execute(
                """INSERT INTO verdict_audit
                   (request_id, timestamp, principal_id, role, action, resource,
                    final_verdict, tier_traces, engine_version, latency_ms,
                    oscal_controls)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    record.request_id, record.timestamp,
                    record.principal_id, record.role,
                    record.action, record.resource,
                    record.final_verdict,
                    json.dumps([t.to_dict() for t in record.tier_traces]),
                    record.engine_version,
                    round(latency_ms, 2),
                    json.dumps(record.oscal_controls),   # '[]' on first write
                ),
            )
            self._sqlite_conn.commit()

    def _update_oscal_sqlite(self, request_id: str, controls: list[str]) -> None:
        with self._lock:
            self._sqlite_conn.execute(
                "UPDATE verdict_audit SET oscal_controls = ? WHERE request_id = ?",
                (json.dumps(controls), request_id),
            )
            self._sqlite_conn.commit()
        logger.debug("OSCAL SQLite update: request_id=%s controls=%s", request_id, controls)

    def _write_kafka(self, record: "AuditRecord", latency_ms: float) -> None:
        topic = os.getenv("KAFKA_AUDIT_TOPIC", "audit.log")
        payload = record.to_dict()
        payload["latency_ms"] = round(latency_ms, 2)
        self._kafka_producer.send(topic, value=payload)

    def _write_s3(self, record: "AuditRecord", latency_ms: float) -> None:
        payload = record.to_dict()
        payload["latency_ms"] = round(latency_ms, 2)
        self._s3_writer.write_async(payload)

    def _write_postgres(self, record: "AuditRecord", latency_ms: float) -> None:
        import json as _json
        with self._lock:
            with self._pg_conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO verdict_audit
                       (request_id, timestamp, principal_id, role, action, resource,
                        final_verdict, tier_traces, engine_version, latency_ms,
                        oscal_controls)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        record.request_id,
                        record.timestamp,
                        record.principal_id,
                        record.role,
                        record.action,
                        record.resource,
                        record.final_verdict,
                        _json.dumps([t.to_dict() for t in record.tier_traces]),
                        record.engine_version,
                        round(latency_ms, 2),
                        _json.dumps(record.oscal_controls),  # '[]' on first write
                    ),
                )

    def _update_oscal_postgres(self, request_id: str, controls: list[str]) -> None:
        import json as _json
        with self._lock:
            with self._pg_conn.cursor() as cur:
                cur.execute(
                    "UPDATE verdict_audit SET oscal_controls = %s WHERE request_id = %s",
                    (_json.dumps(controls), request_id),
                )
        logger.debug("OSCAL Postgres update: request_id=%s controls=%s", request_id, controls)

# Made with Bob
