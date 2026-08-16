"""
S3 Audit Writer Module for Compliance Pipeline

This module provides optimized S3 writing capabilities for audit logs with:
- Batch processing to reduce S3 API calls
- Connection pooling via boto3 session management
- Automatic bucket creation
- JSON and JSONL format support
- Prometheus metrics integration
- Hash-chain (prev_hash) for tamper evidence on every appended record
"""

import hashlib
import json
import time
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
from typing import List, Dict, Any, Optional
from prometheus_client import Counter, Histogram, Gauge
import threading
import queue

# Prometheus Metrics for S3 operations
s3_writes_total = Counter(
    's3_audit_writes_total',
    'Total number of audit logs written to S3',
    ['bucket', 'status']
)

s3_batch_size = Histogram(
    's3_audit_batch_size',
    'Size of audit log batches written to S3'
)

s3_write_duration_seconds = Histogram(
    's3_audit_write_duration_seconds',
    'Time spent writing audit logs to S3',
    ['operation']
)

s3_queue_size = Gauge(
    's3_audit_queue_size',
    'Current size of S3 audit write queue'
)


class S3AuditWriter:
    """
    Optimized S3 writer for compliance audit logs.
    
    Features:
    - Batch processing to minimize S3 API calls
    - Automatic bucket creation and validation
    - Support for JSON and JSONL formats
    - Thread-safe queue-based architecture
    - Prometheus metrics integration
    """
    
    def __init__(
        self,
        bucket: str,
        endpoint_url: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        region_name: str = "us-east-1",
        batch_size: int = 50,
        batch_timeout: float = 5.0,
        key_prefix: str = "compliance-audit",
        format: str = "jsonl",
        create_bucket_if_missing: bool = True
    ):
        """
        Initialize S3 Audit Writer.
        
        Args:
            bucket: S3 bucket name
            endpoint_url: S3 endpoint URL (e.g., LocalStack)
            aws_access_key_id: AWS access key
            aws_secret_access_key: AWS secret key
            region_name: AWS region
            batch_size: Number of records to batch before writing
            batch_timeout: Maximum seconds to wait before flushing batch
            key_prefix: Prefix for S3 keys (e.g., "compliance-audit")
            format: Output format ("json" or "jsonl")
            create_bucket_if_missing: Auto-create bucket if it doesn't exist
        """
        self.bucket = bucket
        self.key_prefix = key_prefix
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.format = format.lower()
        
        # Initialize boto3 client with connection pooling
        self.s3_client = boto3.client(
            's3',
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
            config=boto3.session.Config(
                max_pool_connections=20,
                retries={'max_attempts': 3, 'mode': 'standard'}
            )
        )
        
        # Batch management
        self.audit_batch: List[Dict[str, Any]] = []
        self.last_batch_flush = time.time()
        self.batch_lock = threading.Lock()
        # Hash-chain state: SHA-256 of the last successfully serialised record.
        # Stored under "prev_hash" in each new record so the append-only stream
        # is tamper-evident: any removed or reordered record breaks the chain.
        self._last_hash: str = "0" * 64  # genesis sentinel
        
        # Ensure bucket exists
        if create_bucket_if_missing:
            self._ensure_bucket_exists()
    
    def _ensure_bucket_exists(self):
        """Create S3 bucket if it doesn't exist."""
        start_time = time.time()
        try:
            self.s3_client.head_bucket(Bucket=self.bucket)
            print(f"✅ S3 bucket '{self.bucket}' exists")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                try:
                    self.s3_client.create_bucket(Bucket=self.bucket)
                    print(f"✅ Created S3 bucket '{self.bucket}'")
                    s3_writes_total.labels(bucket=self.bucket, status='bucket_created').inc()
                except Exception as create_error:
                    print(f"❌ Failed to create bucket '{self.bucket}': {create_error}")
                    raise
            else:
                print(f"❌ Error checking bucket '{self.bucket}': {e}")
                raise
        finally:
            s3_write_duration_seconds.labels(operation='bucket_check').observe(time.time() - start_time)
    
    def add_audit_record(self, record: Dict[str, Any], upstream_chain: Optional[List] = None):
        """
        Add an audit record to the batch queue.

        Args:
            record: Audit record dictionary
            upstream_chain: Optional list of AuditChainEntry-like objects from an upstream
                gateway (Demo 4 hybrid mode).  When provided, their dicts are merged into
                the record under the key "gateway_tiers".  All existing callers omit this
                parameter and are unaffected.
        """
        with self.batch_lock:
            # Add timestamp if not present
            if 'timestamp' not in record:
                record['timestamp'] = datetime.utcnow().isoformat() + 'Z'

            # Merge gateway audit chain when running in hybrid mode
            if upstream_chain:
                try:
                    record['gateway_tiers'] = [
                        e.to_dict() if hasattr(e, 'to_dict') else e
                        for e in upstream_chain
                    ]
                except Exception:
                    pass  # Never let audit-chain merging break the write path

            # Hash-chain: stamp this record with the hash of its predecessor.
            # Use deterministic JSON serialisation (sort_keys) so the hash is
            # reproducible by any verifier replaying the stream.
            record['prev_hash'] = self._last_hash
            self._last_hash = hashlib.sha256(
                json.dumps(record, sort_keys=True, default=str).encode()
            ).hexdigest()

            self.audit_batch.append(record)
            s3_queue_size.set(len(self.audit_batch))
            
            # Flush if batch is full or timeout reached
            if len(self.audit_batch) >= self.batch_size or \
               (time.time() - self.last_batch_flush) >= self.batch_timeout:
                self._flush_batch()
    
    def _flush_batch(self):
        """Flush accumulated audit records to S3."""
        if not self.audit_batch:
            return
        
        start_time = time.time()
        batch_count = len(self.audit_batch)
        
        try:
            # Generate S3 key with timestamp
            timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H%M%S')
            key = f"{self.key_prefix}/{timestamp}-batch-{batch_count}.{self.format}"
            
            # Prepare content based on format
            if self.format == 'jsonl':
                # JSONL: one JSON object per line
                content = '\n'.join(json.dumps(record) for record in self.audit_batch)
            else:
                # JSON: array of objects
                content = json.dumps(self.audit_batch, indent=2)
            
            # Write to S3
            self.s3_client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=content.encode('utf-8'),
                ContentType='application/json'
            )
            
            # Metrics
            s3_writes_total.labels(bucket=self.bucket, status='success').inc(batch_count)
            s3_batch_size.observe(batch_count)
            s3_write_duration_seconds.labels(operation='batch_write').observe(time.time() - start_time)
            
            print(f"✅ Flushed {batch_count} audit records to S3: s3://{self.bucket}/{key} "
                  f"({(time.time() - start_time)*1000:.1f}ms)")
            
            # Clear batch
            self.audit_batch = []
            self.last_batch_flush = time.time()
            s3_queue_size.set(0)
            
        except Exception as e:
            print(f"❌ S3 Batch Write Error: {e}")
            s3_writes_total.labels(bucket=self.bucket, status='error').inc()
            s3_write_duration_seconds.labels(operation='batch_write_error').observe(time.time() - start_time)
            # Clear batch to prevent memory leak
            self.audit_batch = []
            s3_queue_size.set(0)
    
    def flush(self):
        """Manually flush any pending audit records."""
        with self.batch_lock:
            self._flush_batch()
    
    def close(self):
        """Flush remaining records and cleanup."""
        self.flush()
        print(f"✅ S3 Audit Writer closed for bucket '{self.bucket}'")


class S3AuditWriterAsync:
    """
    Asynchronous S3 writer with background thread for non-blocking writes.
    
    This version uses a queue and background worker thread to ensure
    audit logging doesn't block the main compliance processing flow.
    """
    
    def __init__(
        self,
        bucket: str,
        endpoint_url: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        region_name: str = "us-east-1",
        batch_size: int = 50,
        batch_timeout: float = 5.0,
        key_prefix: str = "compliance-audit",
        format: str = "jsonl",
        create_bucket_if_missing: bool = True,
        queue_maxsize: int = 1000
    ):
        """Initialize async S3 writer with background worker."""
        self.writer = S3AuditWriter(
            bucket=bucket,
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
            batch_size=batch_size,
            batch_timeout=batch_timeout,
            key_prefix=key_prefix,
            format=format,
            create_bucket_if_missing=create_bucket_if_missing
        )
        
        self.queue = queue.Queue(maxsize=queue_maxsize)
        self.running = True
        
        # Start background worker thread
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        print(f"✅ S3 Async Audit Writer started for bucket '{bucket}'")
    
    def _worker(self):
        """Background worker that processes queue and flushes batches."""
        while self.running:
            try:
                # Wait for records with timeout to allow periodic flushing
                try:
                    record = self.queue.get(timeout=self.writer.batch_timeout)
                    self.writer.add_audit_record(record)
                    self.queue.task_done()
                except queue.Empty:
                    # Timeout reached, flush if needed
                    self.writer.flush()
            except Exception as e:
                print(f"❌ S3 Worker Error: {e}")
    
    def add_audit_record(self, record: Dict[str, Any], upstream_chain: Optional[List] = None):
        """
        Add audit record to async queue (non-blocking).

        Args:
            record: Audit record dictionary
            upstream_chain: Optional list of AuditChainEntry-like objects from an upstream
                gateway (Demo 4 hybrid mode).  Merged into the record before queuing so
                the full causal chain is preserved in S3.
        """
        if upstream_chain:
            try:
                record = dict(record)  # avoid mutating the caller's dict
                record['gateway_tiers'] = [
                    e.to_dict() if hasattr(e, 'to_dict') else e
                    for e in upstream_chain
                ]
            except Exception:
                pass  # Never let audit-chain merging break the write path
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            print(f"⚠️  S3 audit queue full, dropping record")
            s3_writes_total.labels(bucket=self.writer.bucket, status='queue_full').inc()
    
    def close(self):
        """Stop worker and flush remaining records."""
        self.running = False
        self.worker_thread.join(timeout=10)
        self.writer.close()


# Made with Bob