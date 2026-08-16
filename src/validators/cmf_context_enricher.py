"""
CMF (ContextForge) - Context Enrichment Module
Implements CDM v2 specification for message context enrichment
"""

import json
import time
import re
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone


class CDMContext:
    """Common Data Model v2 Context"""
    
    def __init__(self):
        self.cdm_version = "2.0"
        self.user = {}
        self.topic = {}
        self.message = {}
        self.environment = {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "cdm_version": self.cdm_version,
            "context": {
                "user": self.user,
                "topic": self.topic,
                "message": self.message,
                "environment": self.environment
            }
        }


class UserContextProvider:
    """Extracts user identity, roles, and clearance level"""
    
    def enrich(self, message: Dict[str, Any], context: CDMContext) -> None:
        metadata = message.get("metadata", {})
        
        context.user = {
            "id": metadata.get("user_id", "unknown"),
            "roles": metadata.get("user_roles", []),
            "clearance_level": metadata.get("user_clearance", "public"),
            "attributes": {
                "department": metadata.get("department", ""),
                "location": metadata.get("location", "")
            }
        }


class TopicContextProvider:
    """Provides topic metadata and classification"""
    
    def __init__(self):
        # Topic classification mapping
        self.topic_classifications = {
            "sensitive-data": {
                "classification": "confidential",
                "compliance_required": True,
                "retention_policy": "30d"
            },
            "public-data": {
                "classification": "public",
                "compliance_required": False,
                "retention_policy": "90d"
            },
            "financial-data": {
                "classification": "restricted",
                "compliance_required": True,
                "retention_policy": "7y"
            }
        }
    
    def enrich(self, message: Dict[str, Any], context: CDMContext) -> None:
        topic_name = message.get("topic", "unknown")
        metadata = message.get("metadata", {})
        
        # Get topic classification
        topic_config = self.topic_classifications.get(
            topic_name,
            {
                "classification": metadata.get("data_classification", "public"),
                "compliance_required": False,
                "retention_policy": "30d"
            }
        )
        
        context.topic = {
            "name": topic_name,
            "classification": topic_config["classification"],
            "compliance_required": topic_config["compliance_required"],
            "retention_policy": topic_config["retention_policy"]
        }


class MessageContextProvider:
    """Analyzes message content for PII, size, and other attributes"""
    
    # PII detection patterns
    PII_PATTERNS = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
    }
    
    def __init__(self, pii_detection: bool = True, max_inspection_size: int = 1048576):
        self.pii_detection = pii_detection
        self.max_inspection_size = max_inspection_size
    
    def detect_pii(self, content: str) -> Dict[str, bool]:
        """Detect PII in message content"""
        if not self.pii_detection:
            return {}
        
        # Limit inspection size
        content = content[:self.max_inspection_size]
        
        pii_found = {}
        for pii_type, pattern in self.PII_PATTERNS.items():
            pii_found[pii_type] = bool(re.search(pattern, content))
        
        return pii_found
    
    def enrich(self, message: Dict[str, Any], context: CDMContext) -> None:
        data = message.get("data", {})
        content = json.dumps(data) if isinstance(data, dict) else str(data)
        
        # Detect PII
        pii_detected = self.detect_pii(content)
        contains_pii = any(pii_detected.values())
        
        context.message = {
            "size_bytes": len(content.encode('utf-8')),
            "content_type": "application/json",
            "contains_pii": contains_pii,
            "pii_types": [k for k, v in pii_detected.items() if v],
            "encryption_required": contains_pii or message.get("metadata", {}).get("data_classification") == "confidential"
        }


class EnvironmentContextProvider:
    """Adds environment metadata (timestamp, IP, request ID)"""
    
    def enrich(self, message: Dict[str, Any], context: CDMContext) -> None:
        metadata = message.get("metadata", {})
        
        context.environment = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": metadata.get("source_ip", "unknown"),
            "request_id": message.get("request_id", "unknown"),
            "kafka_partition": metadata.get("partition", -1),
            "kafka_offset": metadata.get("offset", -1)
        }


class CMFContextEnricher:
    """
    Main CMF Context Enricher
    Orchestrates all context providers to enrich messages with CDM v2 context
    """
    
    def __init__(self, 
                 pii_detection: bool = True,
                 max_inspection_size: int = 1048576):
        """
        Initialize CMF Context Enricher
        
        Args:
            pii_detection: Enable PII detection in messages
            max_inspection_size: Maximum message size to inspect for PII
        """
        self.user_provider = UserContextProvider()
        self.topic_provider = TopicContextProvider()
        self.message_provider = MessageContextProvider(pii_detection, max_inspection_size)
        self.environment_provider = EnvironmentContextProvider()
    
    def enrich_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a message with CDM v2 context
        
        Args:
            message: Original message with metadata
            
        Returns:
            Enriched message with CDM context
        """
        start_time = time.perf_counter()
        
        # Create CDM context
        context = CDMContext()
        
        # Run all context providers
        self.user_provider.enrich(message, context)
        self.topic_provider.enrich(message, context)
        self.message_provider.enrich(message, context)
        self.environment_provider.enrich(message, context)
        
        # Add context to message
        enriched_message = message.copy()
        enriched_message["cdm_context"] = context.to_dict()
        
        # Add enrichment metadata
        enriched_message["cmf_metadata"] = {
            "enrichment_time_ms": (time.perf_counter() - start_time) * 1000,
            "enrichment_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return enriched_message
    
    def benchmark_enrichment(self, num_iterations: int = 1000) -> Dict[str, Any]:
        """
        Benchmark CMF context enrichment performance
        
        Args:
            num_iterations: Number of iterations to run
            
        Returns:
            Benchmark results with latency statistics
        """
        # Sample test message
        test_message = {
            "request_id": "test-123",
            "topic": "sensitive-data",
            "data": {
                "customer_id": "C12345",
                "email": "john.doe@example.com",
                "transaction_amount": 1500.00
            },
            "metadata": {
                "user_id": "user123",
                "user_roles": ["producer"],
                "user_clearance": "confidential",
                "data_classification": "confidential",
                "source_ip": "10.0.0.1"
            }
        }
        
        latencies = []
        
        for _ in range(num_iterations):
            start = time.perf_counter()
            self.enrich_message(test_message)
            end = time.perf_counter()
            latencies.append((end - start) * 1_000_000)  # Convert to microseconds
        
        # Calculate statistics
        latencies.sort()
        mean_latency = sum(latencies) / len(latencies)
        p50 = latencies[len(latencies) // 2]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]
        
        return {
            "iterations": num_iterations,
            "mean_latency_us": mean_latency,
            "p50_latency_us": p50,
            "p95_latency_us": p95,
            "p99_latency_us": p99,
            "throughput_ops_per_sec": 1_000_000 / mean_latency
        }


# Convenience function for quick enrichment
def enrich_message(message: Dict[str, Any], 
                   pii_detection: bool = True) -> Dict[str, Any]:
    """
    Quick function to enrich a message with CMF context
    
    Args:
        message: Message to enrich
        pii_detection: Enable PII detection
        
    Returns:
        Enriched message with CDM v2 context
    """
    enricher = CMFContextEnricher(pii_detection=pii_detection)
    return enricher.enrich_message(message)

# Made with Bob
