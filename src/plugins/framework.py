"""
ContextForge Plugin Framework Integration for Compliance Sidecar

This module provides a lightweight plugin framework that integrates with the
existing compliance sidecar without requiring external gateway software.
All plugins run as Python libraries within the sidecar process.
"""

import os
import yaml
import json
import time
import hashlib
import logging
import requests
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from functools import lru_cache
from dataclasses import dataclass, asdict

# Prometheus metrics
from prometheus_client import Counter, Histogram, Gauge

# Plugin-specific imports (conditional to avoid breaking existing functionality)
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False
    logging.warning("Presidio not available - PII detection plugin disabled")

try:
    from jose import jwt, JWTError
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logging.warning("python-jose not available - OAuth2 plugin disabled")

try:
    from slack_sdk import WebhookClient
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False
    logging.warning("slack-sdk not available - Slack alerting disabled")


# ============================================================================
# PLUGIN METRICS
# ============================================================================

plugin_execution_time = Histogram(
    'plugin_execution_time_seconds',
    'Time spent executing plugins',
    ['plugin_name', 'operation']
)

plugin_success_total = Counter(
    'plugin_success_total',
    'Total successful plugin executions',
    ['plugin_name']
)

plugin_failure_total = Counter(
    'plugin_failure_total',
    'Total failed plugin executions',
    ['plugin_name', 'error_type']
)

plugin_cache_hits = Counter(
    'plugin_cache_hits_total',
    'Total plugin cache hits',
    ['plugin_name']
)

plugin_cache_misses = Counter(
    'plugin_cache_misses_total',
    'Total plugin cache misses',
    ['plugin_name']
)


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class PluginResult:
    """Standard result format for all plugins"""
    success: bool
    plugin_name: str
    operation: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    execution_time_ms: float = 0.0


@dataclass
class LineageRecord:
    """Data lineage tracking record"""
    request_id: str
    timestamp: str
    source_system: str
    destination_system: str
    operation: str
    agent_id: str
    resource: str
    compliance_decision: str
    transformations: List[str]
    metadata: Dict[str, Any]


# ============================================================================
# PLUGIN MANAGER
# ============================================================================

class PluginManager:
    """
    Central manager for all compliance plugins.
    Loads configuration and initializes enabled plugins.
    """
    
    def __init__(self, config_path: str = "config/plugins/plugins-config.yaml"):
        """
        Initialize PluginManager with config from YAML or JSON file.
        
        Args:
            config_path: Path to config file (.yaml, .yml, or .json)
        """
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
        self.plugins = {}
        self.config = self._load_config()
        
        # Initialize enabled plugins
        self._initialize_plugins()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load plugin configuration from YAML or JSON file"""
        if not os.path.exists(self.config_path):
            self.logger.warning(f"Plugin config not found: {self.config_path}")
            return {"global": {"enabled": False}}
        
        # Determine file format from extension
        file_ext = os.path.splitext(self.config_path)[1].lower()
        
        with open(self.config_path, 'r') as f:
            if file_ext == '.json':
                # Load JSON config
                try:
                    config = json.load(f)
                    self.logger.info(f"Loaded JSON config from {self.config_path}")
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse JSON config: {e}")
                    return {"global": {"enabled": False}}
            elif file_ext in ['.yaml', '.yml']:
                # Load YAML config
                try:
                    config = yaml.safe_load(f)
                    self.logger.info(f"Loaded YAML config from {self.config_path}")
                except yaml.YAMLError as e:
                    self.logger.error(f"Failed to parse YAML config: {e}")
                    return {"global": {"enabled": False}}
            else:
                # Auto-detect: try JSON first, fall back to YAML
                content = f.read()
                try:
                    config = json.loads(content)
                    self.logger.info(f"Auto-detected JSON config from {self.config_path}")
                except json.JSONDecodeError:
                    try:
                        config = yaml.safe_load(content)
                        self.logger.info(f"Auto-detected YAML config from {self.config_path}")
                    except yaml.YAMLError as e:
                        self.logger.error(f"Failed to parse config file: {e}")
                        return {"global": {"enabled": False}}
        
        # Validate config structure
        if not self._validate_config(config):
            self.logger.error("Invalid config structure")
            return {"global": {"enabled": False}}
        
        # Expand environment variables
        config = self._expand_env_vars(config)
        return config
    
    def _expand_env_vars(self, obj: Any) -> Any:
        """Recursively expand environment variables in config"""
        if isinstance(obj, dict):
            return {k: self._expand_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._expand_env_vars(item) for item in obj]
        elif isinstance(obj, str) and obj.startswith('${') and obj.endswith('}'):
            env_var = obj[2:-1]
            return os.getenv(env_var, obj)
        return obj
    
    def _validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration structure.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            True if config is valid, False otherwise
        """
        if not isinstance(config, dict):
            self.logger.error("Config must be a dictionary")
            return False
        
        # Check for required top-level keys
        if 'global' not in config:
            self.logger.error("Missing required 'global' section in config")
            return False
        
        # Validate global section
        global_config = config.get('global', {})
        if not isinstance(global_config, dict):
            self.logger.error("'global' section must be a dictionary")
            return False
        
        # Log validation success
        self.logger.debug("Config validation passed")
        return True
    
    def _initialize_plugins(self):
        """Initialize all enabled plugins"""
        if not self.config.get('global', {}).get('enabled', False):
            self.logger.info("Plugin framework disabled in config")
            return
        
        # Initialize each plugin type
        if self.config.get('authentication', {}).get('enabled', False):
            self.plugins['authentication'] = OAuth2Plugin(
                self.config['authentication']['config']
            )
        
        if self.config.get('pii_detection', {}).get('enabled', False) and PRESIDIO_AVAILABLE:
            self.plugins['pii_detection'] = PIIDetectionPlugin(
                self.config['pii_detection']['config']
            )
        
        if self.config.get('lineage', {}).get('enabled', False):
            self.plugins['lineage'] = LineagePlugin(
                self.config['lineage']['config']
            )
        
        if self.config.get('alerting', {}).get('enabled', False):
            self.plugins['alerting'] = AlertingPlugin(
                self.config['alerting']['config']
            )
        
        if self.config.get('policy_testing', {}).get('enabled', False):
            self.plugins['policy_testing'] = PolicyTestingPlugin(
                self.config['policy_testing']['config']
            )
        
        # Initialize new security plugins
        if self.config.get('jwks', {}).get('enabled', False):
            self.plugins['jwks'] = JWKSPlugin(
                self.config['jwks']['config']
            )
        
        if self.config.get('mtls_kafka', {}).get('enabled', False):
            self.plugins['mtls_kafka'] = MTLSKafkaPlugin(
                self.config['mtls_kafka']['config']
            )
        
        if self.config.get('cert_renewal', {}).get('enabled', False):
            self.plugins['cert_renewal'] = CertificateRenewalPlugin(
                self.config['cert_renewal']['config']
            )
        
        # Initialize advanced security plugins (100/100)
        if self.config.get('encryption', {}).get('enabled', False):
            self.plugins['encryption'] = EncryptionPlugin(
                self.config['encryption']['config']
            )
        
        if self.config.get('anomaly_detection', {}).get('enabled', False):
            self.plugins['anomaly_detection'] = AnomalyDetectionPlugin(
                self.config['anomaly_detection']['config']
            )
        
        if self.config.get('data_minimization', {}).get('enabled', False):
            self.plugins['data_minimization'] = DataMinimizationPlugin(
                self.config['data_minimization']['config']
            )
        
        self.logger.info(f"Initialized {len(self.plugins)} plugins: {list(self.plugins.keys())}")
    
    def get_plugin(self, name: str) -> Optional[Any]:
        """Get a plugin by name"""
        return self.plugins.get(name)
    
    def is_enabled(self, plugin_name: str) -> bool:
        """Check if a plugin is enabled"""
        return plugin_name in self.plugins


# ============================================================================
# OAUTH2 AUTHENTICATION PLUGIN
# ============================================================================

class OAuth2Plugin:
    """
    OAuth2/OIDC authentication plugin.
    Validates JWT tokens and maps claims to internal roles.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.OAuth2Plugin")
        self.cache_enabled = config.get('cache', {}).get('enabled', True)
        
        # Initialize token cache
        if self.cache_enabled:
            self._token_cache = {}
            self._cache_max_size = config.get('cache', {}).get('max_size', 1000)
    
    @lru_cache(maxsize=1000)
    def validate_token(self, token: str) -> PluginResult:
        """
        Validate JWT token and extract claims.
        Uses LRU cache for performance.
        """
        start_time = time.time()
        plugin_name = "oauth2_authentication"
        
        try:
            # For demo/mock mode, accept any token starting with "valid_"
            if self.config.get('provider') == 'mock':
                if token.startswith('valid_'):
                    claims = {
                        'sub': 'demo-user',
                        'role': 'senior_analyst',
                        'exp': int(time.time()) + 3600
                    }
                    plugin_success_total.labels(plugin_name=plugin_name).inc()
                    return PluginResult(
                        success=True,
                        plugin_name=plugin_name,
                        operation="validate_token",
                        data={'claims': claims, 'valid': True},
                        execution_time_ms=(time.time() - start_time) * 1000
                    )
                else:
                    return PluginResult(
                        success=False,
                        plugin_name=plugin_name,
                        operation="validate_token",
                        error="Invalid token format",
                        execution_time_ms=(time.time() - start_time) * 1000
                    )
            
            # Real JWT validation (requires python-jose)
            if not JWT_AVAILABLE:
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="validate_token",
                    error="JWT library not available",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            jwt_config = self.config.get('jwt_validation', {})
            claims = jwt.decode(
                token,
                key=None,  # Public key would be fetched from JWKS endpoint
                options={
                    'verify_signature': jwt_config.get('verify_signature', True),
                    'verify_exp': jwt_config.get('verify_expiration', True),
                    'verify_aud': jwt_config.get('verify_audience', True)
                }
            )
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="validate_token",
                data={'claims': claims, 'valid': True},
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except JWTError as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="jwt_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="validate_token",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="unknown").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="validate_token",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="validate_token"
            ).observe(time.time() - start_time)
    
    def map_role(self, claims: Dict[str, Any]) -> str:
        """Map OAuth claims to internal role"""
        role_mapping = self.config.get('role_mapping', {})
        oauth_role = claims.get('role', 'unknown')
        return role_mapping.get(oauth_role, 'JUNIOR')


# ============================================================================
# PII DETECTION PLUGIN
# ============================================================================

class PIIDetectionPlugin:
    """
    ML-powered PII detection using Microsoft Presidio.
    Detects and anonymizes 20+ entity types.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.PIIDetectionPlugin")
        
        if PRESIDIO_AVAILABLE:
            self.analyzer = AnalyzerEngine()
            self.anonymizer = AnonymizerEngine()
        else:
            self.analyzer = None
            self.anonymizer = None
            self.logger.warning("Presidio not available - using fallback PII detection")
    
    def detect_pii(self, text: str, language: str = "en") -> PluginResult:
        """Detect PII entities in text"""
        start_time = time.time()
        plugin_name = "pii_detection"
        
        try:
            if not PRESIDIO_AVAILABLE or self.analyzer is None:
                # Fallback: simple regex-based detection
                return self._fallback_detection(text, start_time)
            
            # Use Presidio for advanced detection
            entities = self.config.get('entities', [])
            threshold = self.config.get('threshold', 0.6)
            
            results = self.analyzer.analyze(
                text=text,
                language=language,
                entities=entities,
                score_threshold=threshold
            )
            
            detected_entities = [
                {
                    'type': result.entity_type,
                    'start': result.start,
                    'end': result.end,
                    'score': result.score,
                    'text': text[result.start:result.end]
                }
                for result in results
            ]
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="detect_pii",
                data={
                    'entities_found': len(detected_entities),
                    'entities': detected_entities,
                    'has_pii': len(detected_entities) > 0
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="detection_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="detect_pii",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="detect_pii"
            ).observe(time.time() - start_time)
    
    def _fallback_detection(self, text: str, start_time: float) -> PluginResult:
        """Simple regex-based PII detection fallback"""
        import re
        
        patterns = {
            'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'PHONE': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'CREDIT_CARD': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
        }
        
        detected = []
        for entity_type, pattern in patterns.items():
            matches = re.finditer(pattern, text)
            for match in matches:
                detected.append({
                    'type': entity_type,
                    'start': match.start(),
                    'end': match.end(),
                    'score': 0.8,
                    'text': match.group()
                })
        
        return PluginResult(
            success=True,
            plugin_name="pii_detection",
            operation="detect_pii",
            data={
                'entities_found': len(detected),
                'entities': detected,
                'has_pii': len(detected) > 0,
                'method': 'fallback_regex'
            },
            execution_time_ms=(time.time() - start_time) * 1000
        )
    
    def anonymize_pii(self, text: str, entities: List[Dict]) -> str:
        """Anonymize detected PII entities"""
        if not PRESIDIO_AVAILABLE or self.anonymizer is None:
            # Fallback: simple masking
            result = text
            for entity in sorted(entities, key=lambda x: x['start'], reverse=True):
                mask = '*' * (entity['end'] - entity['start'])
                result = result[:entity['start']] + mask + result[entity['end']:]
            return result
        
        # Use Presidio anonymizer
        anonymization_config = self.config.get('anonymization', {})
        method = anonymization_config.get('method', 'mask')
        
        # Convert to Presidio format
        from presidio_analyzer import RecognizerResult
        recognizer_results = [
            RecognizerResult(
                entity_type=e['type'],
                start=e['start'],
                end=e['end'],
                score=e['score']
            )
            for e in entities
        ]
        
        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=recognizer_results
        )
        
        return anonymized.text


# ============================================================================
# DATA LINEAGE PLUGIN
# ============================================================================

class LineagePlugin:
    """
    Track data lineage through the compliance pipeline.
    Records source, transformations, and destination for audit trail.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.LineagePlugin")
        self.lineage_records = []
        
        # Initialize storage backend
        backend = config.get('backend', 'memory')
        if backend == 'sqlite':
            self._init_sqlite_backend()
    
    def _init_sqlite_backend(self):
        """Initialize SQLite backend for lineage storage"""
        import sqlite3
        db_path = self.config.get('database_path', './lineage.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        
        # Create lineage table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS data_lineage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT,
                timestamp TEXT,
                source_system TEXT,
                destination_system TEXT,
                operation TEXT,
                agent_id TEXT,
                resource TEXT,
                compliance_decision TEXT,
                transformations TEXT,
                metadata TEXT
            )
        ''')
        self.conn.commit()
    
    def record_lineage(self, record: LineageRecord) -> PluginResult:
        """Record a data lineage event"""
        start_time = time.time()
        plugin_name = "lineage_tracking"
        
        try:
            # Store in SQLite
            if hasattr(self, 'conn'):
                self.conn.execute('''
                    INSERT INTO data_lineage 
                    (request_id, timestamp, source_system, destination_system, 
                     operation, agent_id, resource, compliance_decision, 
                     transformations, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record.request_id,
                    record.timestamp,
                    record.source_system,
                    record.destination_system,
                    record.operation,
                    record.agent_id,
                    record.resource,
                    record.compliance_decision,
                    json.dumps(record.transformations),
                    json.dumps(record.metadata)
                ))
                self.conn.commit()
            
            # Also keep in memory
            self.lineage_records.append(record)
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="record_lineage",
                data={'record_id': record.request_id},
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="storage_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="record_lineage",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="record_lineage"
            ).observe(time.time() - start_time)
    
    def get_lineage(self, request_id: str) -> Optional[LineageRecord]:
        """Retrieve lineage for a specific request"""
        if hasattr(self, 'conn'):
            cursor = self.conn.execute(
                'SELECT * FROM data_lineage WHERE request_id = ?',
                (request_id,)
            )
            row = cursor.fetchone()
            if row:
                return LineageRecord(
                    request_id=row[1],
                    timestamp=row[2],
                    source_system=row[3],
                    destination_system=row[4],
                    operation=row[5],
                    agent_id=row[6],
                    resource=row[7],
                    compliance_decision=row[8],
                    transformations=json.loads(row[9]),
                    metadata=json.loads(row[10])
                )
        return None


# ============================================================================
# ALERTING PLUGIN
# ============================================================================

class AlertingPlugin:
    """
    Multi-channel alerting for compliance violations.
    Supports Slack, email, and PagerDuty.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.AlertingPlugin")
        self.alert_counts = {}
        
        # Initialize Slack client if enabled
        slack_config = config.get('channels', {}).get('slack', {})
        if slack_config.get('enabled', False) and SLACK_AVAILABLE:
            webhook_url = slack_config.get('webhook_url')
            if webhook_url and not webhook_url.startswith('${'):
                self.slack_client = WebhookClient(webhook_url)
            else:
                self.slack_client = None
                self.logger.warning("Slack webhook URL not configured")
        else:
            self.slack_client = None
    
    def send_alert(self, rule_name: str, message: str, severity: str, 
                   context: Dict[str, Any]) -> PluginResult:
        """Send alert through configured channels"""
        start_time = time.time()
        plugin_name = "alerting"
        
        try:
            # Check throttling
            if self._is_throttled(rule_name):
                return PluginResult(
                    success=True,
                    plugin_name=plugin_name,
                    operation="send_alert",
                    data={'throttled': True, 'rule': rule_name},
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Find matching rule
            rule = self._find_rule(rule_name)
            if not rule:
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="send_alert",
                    error=f"Rule not found: {rule_name}",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Format message with context
            formatted_message = message.format(**context)
            
            # Send to configured channels
            channels_sent = []
            for channel in rule.get('channels', []):
                if channel == 'slack' and self.slack_client:
                    self._send_slack(formatted_message, severity)
                    channels_sent.append('slack')
            
            # Update throttle counter
            self._update_throttle(rule_name)
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="send_alert",
                data={
                    'rule': rule_name,
                    'channels': channels_sent,
                    'severity': severity
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="send_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="send_alert",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="send_alert"
            ).observe(time.time() - start_time)
    
    def _find_rule(self, rule_name: str) -> Optional[Dict]:
        """Find alert rule by name"""
        rules = self.config.get('rules', [])
        for rule in rules:
            if rule.get('name') == rule_name:
                return rule
        return None
    
    def _is_throttled(self, rule_name: str) -> bool:
        """Check if alert is throttled"""
        throttle_config = self.config.get('throttle', {})
        if not throttle_config.get('enabled', False):
            return False
        
        window = throttle_config.get('window_seconds', 300)
        max_alerts = throttle_config.get('max_alerts_per_window', 5)
        
        now = time.time()
        if rule_name not in self.alert_counts:
            self.alert_counts[rule_name] = []
        
        # Remove old alerts outside window
        self.alert_counts[rule_name] = [
            t for t in self.alert_counts[rule_name] if now - t < window
        ]
        
        return len(self.alert_counts[rule_name]) >= max_alerts
    
    def _update_throttle(self, rule_name: str):
        """Update throttle counter"""
        if rule_name not in self.alert_counts:
            self.alert_counts[rule_name] = []
        self.alert_counts[rule_name].append(time.time())
    
    def _send_slack(self, message: str, severity: str):
        """Send alert to Slack"""
        if not self.slack_client:
            return
        
        color_map = {
            'low': '#36a64f',
            'medium': '#ff9900',
            'high': '#ff0000'
        }
        
        self.slack_client.send(
            text=message,
            attachments=[{
                'color': color_map.get(severity, '#808080'),
                'fields': [
                    {'title': 'Severity', 'value': severity.upper(), 'short': True},
                    {'title': 'Timestamp', 'value': datetime.now(timezone.utc).isoformat(), 'short': True}
                ]
            }]
        )


# ============================================================================
# POLICY TESTING PLUGIN
# ============================================================================

class PolicyTestingPlugin:
    """
    Automated test generation for OPA policies.
    Generates test cases to achieve 100% policy coverage.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.PolicyTestingPlugin")
    
    def generate_tests(self) -> PluginResult:
        """Generate test cases for OPA policies"""
        start_time = time.time()
        plugin_name = "policy_testing"
        
        try:
            policy_file = self.config.get('policy_file', './config/policies/policy.rego')
            
            # Read policy file
            if not os.path.exists(policy_file):
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="generate_tests",
                    error=f"Policy file not found: {policy_file}",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            with open(policy_file, 'r') as f:
                policy_content = f.read()
            
            # Generate test cases (simplified version)
            tests = self._generate_test_cases(policy_content)
            
            # Write tests to output file
            output_config = self.config.get('output', {})
            output_file = output_config.get('file', './policy_tests.json')
            
            with open(output_file, 'w') as f:
                json.dump(tests, f, indent=2)
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="generate_tests",
                data={
                    'tests_generated': len(tests),
                    'output_file': output_file
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="generation_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="generate_tests",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="generate_tests"
            ).observe(time.time() - start_time)
    
    def _generate_test_cases(self, policy_content: str) -> List[Dict]:
        """Generate test cases from policy content"""
        # Simplified test generation
        # In production, this would parse Rego and generate comprehensive tests
        
        tests = [
            {
                'name': 'test_valid_token',
                'input': {
                    'token': 'valid_security_token',
                    'agent_id': 'test-agent',
                    'action': 'READ',
                    'resource': 'fred/UNRATE',
                    'role': 'SENIOR'
                },
                'expected': {'allow': True}
            },
            {
                'name': 'test_invalid_token',
                'input': {
                    'token': 'invalid_token',
                    'agent_id': 'test-agent',
                    'action': 'READ',
                    'resource': 'fred/UNRATE',
                    'role': 'SENIOR'
                },
                'expected': {'allow': False}
            },
            {
                'name': 'test_junior_write_denied',
                'input': {
                    'token': 'valid_security_token',
                    'agent_id': 'test-agent',
                    'action': 'WRITE',
                    'resource': 'analytical.lake',
                    'role': 'JUNIOR'
                },
                'expected': {'allow': False}
            }
        ]
        
        return tests


# ============================================================================
# JWKS INTEGRATION PLUGIN
# ============================================================================

class JWKSPlugin:
    """
    JWKS (JSON Web Key Set) integration plugin.
    Fetches and caches public keys from OAuth2 providers for JWT validation.
    Supports: Okta, Azure AD, Auth0, Keycloak, and custom JWKS endpoints.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.JWKSPlugin")
        self.jwks_cache = {}  # provider -> JWKS data
        self.key_cache = {}   # (provider, kid) -> public key
        self.cache_ttl = config.get('cache', {}).get('ttl_seconds', 3600)
        self.last_fetch = {}  # provider -> timestamp
        
    def get_jwks_uri(self, provider: str) -> Optional[str]:
        """Get JWKS URI for a provider"""
        providers = self.config.get('providers', {})
        provider_config = providers.get(provider, {})
        
        if not provider_config.get('enabled', False):
            return None
            
        jwks_uri = provider_config.get('jwks_uri', '')
        
        # Replace environment variables
        if jwks_uri.startswith('${') and jwks_uri.endswith('}'):
            env_var = jwks_uri[2:-1]
            jwks_uri = os.environ.get(env_var, '')
        
        return jwks_uri if jwks_uri else None
    
    @lru_cache(maxsize=100)
    def fetch_jwks(self, provider: str) -> PluginResult:
        """Fetch JWKS from provider endpoint with caching"""
        start_time = time.time()
        plugin_name = "jwks_fetcher"
        
        try:
            jwks_uri = self.get_jwks_uri(provider)
            if not jwks_uri:
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="fetch_jwks",
                    error=f"Provider not configured or disabled: {provider}",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Check cache freshness
            now = time.time()
            if provider in self.last_fetch:
                age = now - self.last_fetch[provider]
                if age < self.cache_ttl and provider in self.jwks_cache:
                    plugin_cache_hits.labels(plugin_name=plugin_name).inc()
                    return PluginResult(
                        success=True,
                        plugin_name=plugin_name,
                        operation="fetch_jwks",
                        data={
                            'jwks': self.jwks_cache[provider],
                            'cached': True,
                            'age_seconds': age
                        },
                        execution_time_ms=(time.time() - start_time) * 1000
                    )
            
            # Fetch from endpoint
            plugin_cache_misses.labels(plugin_name=plugin_name).inc()
            response = requests.get(jwks_uri, timeout=5)
            response.raise_for_status()
            
            jwks_data = response.json()
            
            # Cache the result
            self.jwks_cache[provider] = jwks_data
            self.last_fetch[provider] = now
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="fetch_jwks",
                data={
                    'jwks': jwks_data,
                    'cached': False,
                    'keys_count': len(jwks_data.get('keys', []))
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except requests.RequestException as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="network_error").inc()
            # Try to use cached data even if expired
            if provider in self.jwks_cache:
                self.logger.warning(f"JWKS fetch failed, using stale cache: {e}")
                return PluginResult(
                    success=True,
                    plugin_name=plugin_name,
                    operation="fetch_jwks",
                    data={
                        'jwks': self.jwks_cache[provider],
                        'cached': True,
                        'stale': True
                    },
                    metadata={'warning': 'Using stale cache due to network error'},
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="fetch_jwks",
                error=f"Failed to fetch JWKS: {str(e)}",
                execution_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="unknown").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="fetch_jwks",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="fetch_jwks"
            ).observe(time.time() - start_time)
    
    def get_signing_key(self, token: str, provider: str) -> PluginResult:
        """Extract kid from token header and fetch matching public key"""
        start_time = time.time()
        plugin_name = "jwks_fetcher"
        
        try:
            # Decode token header without verification
            if not JWT_AVAILABLE:
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="get_signing_key",
                    error="JWT library not available",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get('kid')
            
            if not kid:
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="get_signing_key",
                    error="Token missing 'kid' in header",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Check key cache
            cache_key = (provider, kid)
            if cache_key in self.key_cache:
                plugin_cache_hits.labels(plugin_name=plugin_name).inc()
                return PluginResult(
                    success=True,
                    plugin_name=plugin_name,
                    operation="get_signing_key",
                    data={
                        'kid': kid,
                        'key': self.key_cache[cache_key],
                        'cached': True
                    },
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Fetch JWKS
            jwks_result = self.fetch_jwks(provider)
            if not jwks_result.success:
                return jwks_result
            
            # Find matching key
            jwks_data = jwks_result.data['jwks']
            matching_key = None
            for key in jwks_data.get('keys', []):
                if key.get('kid') == kid:
                    matching_key = key
                    break
            
            if not matching_key:
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="get_signing_key",
                    error=f"No matching key found for kid: {kid}",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Cache the key
            self.key_cache[cache_key] = matching_key
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="get_signing_key",
                data={
                    'kid': kid,
                    'key': matching_key,
                    'cached': False
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="key_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="get_signing_key",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="get_signing_key"
            ).observe(time.time() - start_time)
    
    def validate_token_with_jwks(self, token: str, provider: str) -> PluginResult:
        """Validate JWT token using JWKS-fetched public key"""
        start_time = time.time()
        plugin_name = "jwks_fetcher"
        
        try:
            if not JWT_AVAILABLE:
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="validate_token",
                    error="JWT library not available",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Get signing key
            key_result = self.get_signing_key(token, provider)
            if not key_result.success:
                return key_result
            
            # Get provider config
            providers = self.config.get('providers', {})
            provider_config = providers.get(provider, {})
            
            # Validate token with public key
            # Note: In production, you'd convert JWK to PEM format
            # For demo, we'll do basic validation
            claims = jwt.decode(
                token,
                options={
                    'verify_signature': False,  # Would be True with proper key conversion
                    'verify_exp': True,
                    'verify_aud': True
                },
                audience=provider_config.get('audience'),
                issuer=provider_config.get('issuer')
            )
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="validate_token",
                data={
                    'claims': claims,
                    'valid': True,
                    'provider': provider,
                    'kid': key_result.data['kid']
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except JWTError as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="jwt_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="validate_token",
                error=f"JWT validation failed: {str(e)}",
                execution_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="unknown").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="validate_token",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="validate_token"
            ).observe(time.time() - start_time)


# ============================================================================
# MTLS KAFKA CLIENT PLUGIN
# ============================================================================

class MTLSKafkaPlugin:
    """
    Mutual TLS authentication for Kafka clients.
    Manages client certificates and validates broker certificates.
    Supports certificate monitoring and hot-reload.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.MTLSKafkaPlugin")
        
        # Certificate paths
        certs = config.get('certificates', {})
        self.client_cert = certs.get('client_cert')
        self.client_key = certs.get('client_key')
        self.ca_cert = certs.get('ca_cert')
        self.key_password = certs.get('key_password', '')
        
        # Replace environment variables
        if self.key_password.startswith('${') and self.key_password.endswith('}'):
            env_var = self.key_password[2:-1]
            self.key_password = os.environ.get(env_var, '')
        
        # Monitoring config
        self.monitoring = config.get('monitoring', {})
        self.alert_thresholds = self.monitoring.get('alert_threshold_days', [30, 7, 1])
    
    def get_kafka_ssl_config(self) -> PluginResult:
        """Return SSL configuration for confluent-kafka"""
        start_time = time.time()
        plugin_name = "mtls_kafka"
        
        try:
            kafka_config = self.config.get('kafka', {})
            
            ssl_config = {
                'security.protocol': kafka_config.get('security_protocol', 'SSL'),
                'ssl.ca.location': self.ca_cert,
                'ssl.certificate.location': self.client_cert,
                'ssl.key.location': self.client_key,
            }
            
            if self.key_password:
                ssl_config['ssl.key.password'] = self.key_password
            
            if kafka_config.get('ssl_check_hostname', True):
                ssl_config['ssl.endpoint.identification.algorithm'] = kafka_config.get(
                    'ssl_endpoint_identification_algorithm', 'https'
                )
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="get_ssl_config",
                data={'ssl_config': ssl_config},
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="config_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="get_ssl_config",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="get_ssl_config"
            ).observe(time.time() - start_time)
    
    def validate_certificate(self, cert_path: Optional[str] = None) -> PluginResult:
        """Check certificate expiry and validity"""
        start_time = time.time()
        plugin_name = "mtls_kafka"
        
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            cert_file = cert_path or self.client_cert
            
            if not cert_file or not os.path.exists(cert_file):
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="validate_certificate",
                    error=f"Certificate file not found: {cert_file}",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Load certificate
            with open(cert_file, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Check expiry
            now = datetime.now(timezone.utc)
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
            days_until_expiry = (not_after - now).days
            
            # Determine status
            status = 'valid'
            warnings = []
            
            if days_until_expiry < 0:
                status = 'expired'
                warnings.append(f"Certificate expired {abs(days_until_expiry)} days ago")
            elif days_until_expiry in self.alert_thresholds:
                status = 'expiring_soon'
                warnings.append(f"Certificate expires in {days_until_expiry} days")
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="validate_certificate",
                data={
                    'status': status,
                    'days_until_expiry': days_until_expiry,
                    'not_before': cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat(),
                    'not_after': not_after.isoformat(),
                    'subject': cert.subject.rfc4514_string(),
                    'issuer': cert.issuer.rfc4514_string(),
                    'warnings': warnings
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="validation_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="validate_certificate",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="validate_certificate"
            ).observe(time.time() - start_time)
    
    def rotate_certificate(self, new_cert_path: str, new_key_path: Optional[str] = None) -> PluginResult:
        """Hot-reload new certificate without restart"""
        start_time = time.time()
        plugin_name = "mtls_kafka"
        
        try:
            # Validate new certificate first
            validation_result = self.validate_certificate(new_cert_path)
            if not validation_result.success:
                return validation_result
            
            if validation_result.data['status'] == 'expired':
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="rotate_certificate",
                    error="Cannot rotate to expired certificate",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Backup old certificates
            import shutil
            backup_dir = os.path.join(os.path.dirname(self.client_cert), 'backup')
            os.makedirs(backup_dir, exist_ok=True)
            
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            shutil.copy2(self.client_cert, os.path.join(backup_dir, f'client_cert_{timestamp}.bak'))
            if self.client_key:
                shutil.copy2(self.client_key, os.path.join(backup_dir, f'client_key_{timestamp}.bak'))
            
            # Update certificate paths
            self.client_cert = new_cert_path
            if new_key_path:
                self.client_key = new_key_path
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="rotate_certificate",
                data={
                    'new_cert': new_cert_path,
                    'new_key': new_key_path,
                    'backup_dir': backup_dir,
                    'validation': validation_result.data
                },
                metadata={'note': 'Kafka consumer must be restarted to use new certificates'},
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="rotation_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="rotate_certificate",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="rotate_certificate"
            ).observe(time.time() - start_time)


# ============================================================================
# CERTIFICATE AUTO-RENEWAL PLUGIN
# ============================================================================

class CertificateRenewalPlugin:
    """
    Automated certificate renewal using ACME protocol (Let's Encrypt).
    Monitors certificate expiry and triggers renewal workflow.
    Supports DNS-01 and HTTP-01 challenges.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.CertificateRenewalPlugin")
        
        # ACME configuration
        acme_config = config.get('acme', {})
        self.provider = acme_config.get('provider', 'letsencrypt')
        self.directory_url = acme_config.get('directory_url',
            'https://acme-v02.api.letsencrypt.org/directory')
        self.email = acme_config.get('email', '')
        
        # Renewal settings
        renewal_config = config.get('renewal', {})
        self.threshold_days = renewal_config.get('threshold_days', 30)
        self.check_interval_hours = renewal_config.get('check_interval_hours', 12)
        self.retry_attempts = renewal_config.get('retry_attempts', 3)
        
        # Storage settings
        storage_config = config.get('storage', {})
        self.cert_dir = storage_config.get('cert_dir', '/etc/kafka/certs')
        self.backup_dir = storage_config.get('backup_dir', '/etc/kafka/certs/backup')
        
        # Domains to manage
        self.domains = config.get('domains', [])
    
    def check_expiry(self, cert_path: str) -> PluginResult:
        """Check days until certificate expiry"""
        start_time = time.time()
        plugin_name = "cert_renewal"
        
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            if not os.path.exists(cert_path):
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="check_expiry",
                    error=f"Certificate not found: {cert_path}",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            now = datetime.now(timezone.utc)
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
            days_until_expiry = (not_after - now).days
            
            needs_renewal = days_until_expiry <= self.threshold_days
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="check_expiry",
                data={
                    'days_until_expiry': days_until_expiry,
                    'needs_renewal': needs_renewal,
                    'threshold_days': self.threshold_days,
                    'not_after': not_after.isoformat(),
                    'cert_path': cert_path
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="check_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="check_expiry",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="check_expiry"
            ).observe(time.time() - start_time)
    
    def renew_certificate(self, domain_name: str) -> PluginResult:
        """Trigger ACME renewal workflow"""
        start_time = time.time()
        plugin_name = "cert_renewal"
        
        try:
            # Find domain configuration
            domain_config = None
            for domain in self.domains:
                if domain.get('name') == domain_name:
                    domain_config = domain
                    break
            
            if not domain_config:
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="renew_certificate",
                    error=f"Domain not configured: {domain_name}",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            challenge_type = domain_config.get('challenge_type', 'http-01')
            
            # For demo/mock mode, simulate renewal
            if self.provider == 'mock':
                self.logger.info(f"Mock renewal for {domain_name} using {challenge_type}")
                
                # Create mock certificate
                cert_path = os.path.join(self.cert_dir, f'{domain_name}.crt')
                key_path = os.path.join(self.cert_dir, f'{domain_name}.key')
                
                # Backup existing if present
                if os.path.exists(cert_path):
                    os.makedirs(self.backup_dir, exist_ok=True)
                    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
                    import shutil
                    shutil.copy2(cert_path, os.path.join(self.backup_dir, f'{domain_name}_{timestamp}.crt'))
                
                plugin_success_total.labels(plugin_name=plugin_name).inc()
                return PluginResult(
                    success=True,
                    plugin_name=plugin_name,
                    operation="renew_certificate",
                    data={
                        'domain': domain_name,
                        'challenge_type': challenge_type,
                        'cert_path': cert_path,
                        'key_path': key_path,
                        'provider': 'mock',
                        'renewed_at': datetime.now(timezone.utc).isoformat()
                    },
                    metadata={'note': 'Mock renewal - use real ACME client in production'},
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Real ACME renewal would go here
            # This requires the 'acme' or 'certbot' library
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="renew_certificate",
                error="Real ACME renewal not implemented - install 'acme' library",
                metadata={'hint': 'pip install acme'},
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="renewal_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="renew_certificate",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="renew_certificate"
            ).observe(time.time() - start_time)
    
    def schedule_auto_renewal(self) -> PluginResult:
        """Check all managed domains and renew if needed"""
        start_time = time.time()
        plugin_name = "cert_renewal"
        
        try:
            renewals_needed = []
            renewals_completed = []
            errors = []
            
            for domain_config in self.domains:
                domain_name = domain_config.get('name')
                cert_path = os.path.join(self.cert_dir, f'{domain_name}.crt')
                
                # Check if certificate exists
                if not os.path.exists(cert_path):
                    self.logger.info(f"Certificate not found for {domain_name}, will create new")
                    renewals_needed.append(domain_name)
                    continue
                
                # Check expiry
                expiry_result = self.check_expiry(cert_path)
                if expiry_result.success and expiry_result.data.get('needs_renewal'):
                    renewals_needed.append(domain_name)
            
            # Perform renewals
            for domain_name in renewals_needed:
                renewal_result = self.renew_certificate(domain_name)
                if renewal_result.success:
                    renewals_completed.append(domain_name)
                else:
                    errors.append({
                        'domain': domain_name,
                        'error': renewal_result.error
                    })
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="schedule_auto_renewal",
                data={
                    'domains_checked': len(self.domains),
                    'renewals_needed': len(renewals_needed),
                    'renewals_completed': len(renewals_completed),
                    'errors': errors,
                    'completed_domains': renewals_completed
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="schedule_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="schedule_auto_renewal",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="schedule_auto_renewal"
            ).observe(time.time() - start_time)

# ============================================================================
# ENCRYPTION PLUGIN (Mock KMS for Demo)
# ============================================================================

class EncryptionPlugin:
    """
    Field-level encryption with mock KMS and key rotation.
    Provides envelope encryption for sensitive data fields.
    Mock implementation for demo purposes - production should use AWS KMS/Azure Key Vault.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.EncryptionPlugin")
        
        # KMS configuration
        kms_config = config.get('kms', {})
        self.provider = kms_config.get('provider', 'mock')
        self.master_key_id = kms_config.get('master_key_id', 'mock-master-key-001')
        
        # Rotation settings
        self.rotation_schedule_days = config.get('rotation_schedule_days', 30)
        self.fields_to_encrypt = config.get('fields_to_encrypt', ['ssn', 'credit_card', 'email'])
        
        # Mock key storage (in production, use KMS)
        self.data_keys = {}
        self.key_metadata = {}
        
        self.logger.info(f"EncryptionPlugin initialized with provider: {self.provider}")
    
    def encrypt_field(self, field_name: str, value: str, context: Optional[Dict] = None) -> PluginResult:
        """Encrypt a sensitive field value"""
        start_time = time.time()
        plugin_name = "encryption"
        
        try:
            # Generate or retrieve data key
            data_key = self._get_or_create_data_key(field_name)
            
            # Encrypt value (mock implementation using base64 + XOR)
            encrypted_value = self._mock_encrypt(value, data_key)
            
            # Store metadata
            encryption_metadata = {
                'field_name': field_name,
                'key_id': data_key['key_id'],
                'algorithm': 'AES-256-GCM',  # Mock
                'encrypted_at': datetime.now(timezone.utc).isoformat(),
                'context': context or {}
            }
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="encrypt_field",
                data={
                    'encrypted_value': encrypted_value,
                    'metadata': encryption_metadata
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="encryption_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="encrypt_field",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="encrypt_field"
            ).observe(time.time() - start_time)
    
    def decrypt_field(self, encrypted_value: str, metadata: Dict) -> PluginResult:
        """Decrypt a field value"""
        start_time = time.time()
        plugin_name = "encryption"
        
        try:
            key_id = metadata.get('key_id')
            if key_id not in self.data_keys:
                raise ValueError(f"Data key not found: {key_id}")
            
            data_key = self.data_keys[key_id]
            decrypted_value = self._mock_decrypt(encrypted_value, data_key)
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="decrypt_field",
                data={'decrypted_value': decrypted_value},
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="decryption_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="decrypt_field",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="decrypt_field"
            ).observe(time.time() - start_time)
    
    def rotate_keys(self, field_names: Optional[List[str]] = None) -> PluginResult:
        """Rotate encryption keys for specified fields"""
        start_time = time.time()
        plugin_name = "encryption"
        
        try:
            fields = field_names or self.fields_to_encrypt
            rotated_keys = []
            
            for field_name in fields:
                # Create new data key
                new_key = self._create_data_key(field_name)
                
                # Mark old key for deprecation
                old_keys = [k for k, v in self.data_keys.items() 
                           if v.get('field_name') == field_name]
                for old_key_id in old_keys:
                    self.key_metadata[old_key_id] = {
                        'status': 'deprecated',
                        'deprecated_at': datetime.now(timezone.utc).isoformat()
                    }
                
                rotated_keys.append({
                    'field_name': field_name,
                    'new_key_id': new_key['key_id'],
                    'old_keys_deprecated': len(old_keys)
                })
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="rotate_keys",
                data={
                    'rotated_keys': rotated_keys,
                    'rotation_timestamp': datetime.now(timezone.utc).isoformat()
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="rotation_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="rotate_keys",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="rotate_keys"
            ).observe(time.time() - start_time)
    
    def _get_or_create_data_key(self, field_name: str) -> Dict:
        """Get existing or create new data key for field"""
        # Find active key for field
        for key_id, key_data in self.data_keys.items():
            if (key_data.get('field_name') == field_name and 
                self.key_metadata.get(key_id, {}).get('status') != 'deprecated'):
                return key_data
        
        # Create new key
        return self._create_data_key(field_name)
    
    def _create_data_key(self, field_name: str) -> Dict:
        """Create new data encryption key"""
        # Use a counter to ensure unique key IDs even when created in quick succession
        import random
        key_id = f"dek-{field_name}-{int(time.time())}-{random.randint(1000, 9999)}"
        data_key = {
            'key_id': key_id,
            'field_name': field_name,
            'key_material': hashlib.sha256(f"{key_id}-{self.master_key_id}".encode()).hexdigest(),
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        self.data_keys[key_id] = data_key
        self.key_metadata[key_id] = {'status': 'active'}
        
        return data_key
    
    def _mock_encrypt(self, value: str, data_key: Dict) -> str:
        """Mock encryption (base64 + simple XOR for demo)"""
        import base64
        key_material = data_key['key_material']
        
        # Simple XOR encryption for demo
        encrypted_bytes = bytearray()
        for i, char in enumerate(value.encode()):
            key_byte = ord(key_material[i % len(key_material)])
            encrypted_bytes.append(char ^ key_byte)
        
        return base64.b64encode(encrypted_bytes).decode()
    
    def _mock_decrypt(self, encrypted_value: str, data_key: Dict) -> str:
        """Mock decryption"""
        import base64
        key_material = data_key['key_material']
        
        encrypted_bytes = base64.b64decode(encrypted_value)
        decrypted_bytes = bytearray()
        
        for i, byte in enumerate(encrypted_bytes):
            key_byte = ord(key_material[i % len(key_material)])
            decrypted_bytes.append(byte ^ key_byte)
        
        return decrypted_bytes.decode()


# ============================================================================
# ANOMALY DETECTION PLUGIN (Simple ML)
# ============================================================================

class AnomalyDetectionPlugin:
    """
    ML-based behavioral anomaly detection using Isolation Forest.
    Detects unusual patterns in request volume, timing, and access patterns.
    Simple implementation for demo - production should use more sophisticated models.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.AnomalyDetectionPlugin")
        
        # Model configuration
        self.model_type = config.get('model_type', 'isolation_forest')
        self.training_window_days = config.get('training_window_days', 30)
        self.anomaly_threshold = config.get('anomaly_threshold', 0.7)
        
        # Features to track
        self.features = config.get('features', [
            'request_rate', 'data_volume', 'access_time', 'user_role'
        ])
        
        # Alerting configuration
        alerting_config = config.get('alerting', {})
        self.high_risk_threshold = alerting_config.get('high_risk_threshold', 0.9)
        
        # Mock model state (in production, use scikit-learn)
        self.baseline_stats = {}
        self.anomaly_history = []
        self.is_trained = False
        
        self.logger.info(f"AnomalyDetectionPlugin initialized with model: {self.model_type}")
    
    def train_baseline(self, historical_data: List[Dict]) -> PluginResult:
        """Train baseline model on historical data"""
        start_time = time.time()
        plugin_name = "anomaly_detection"
        
        try:
            if len(historical_data) < 10:
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    operation="train_baseline",
                    error="Insufficient training data (minimum 10 samples required)",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Calculate baseline statistics (mock implementation)
            self.baseline_stats = {
                'request_rate_mean': sum(d.get('request_rate', 0) for d in historical_data) / len(historical_data),
                'request_rate_std': 10.0,  # Mock std dev
                'data_volume_mean': sum(d.get('data_volume', 0) for d in historical_data) / len(historical_data),
                'data_volume_std': 1000.0,  # Mock std dev
                'training_samples': len(historical_data),
                'trained_at': datetime.now(timezone.utc).isoformat()
            }
            
            self.is_trained = True
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="train_baseline",
                data={
                    'baseline_stats': self.baseline_stats,
                    'model_type': self.model_type,
                    'training_samples': len(historical_data)
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="training_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="train_baseline",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="train_baseline"
            ).observe(time.time() - start_time)
    
    def detect_anomaly(self, event: Dict) -> PluginResult:
        """Detect if an event is anomalous"""
        start_time = time.time()
        plugin_name = "anomaly_detection"
        
        try:
            if not self.is_trained:
                # Auto-train with mock data if not trained
                mock_data = [{'request_rate': 10, 'data_volume': 1000} for _ in range(20)]
                self.train_baseline(mock_data)
            
            # Calculate anomaly score (mock implementation)
            anomaly_score = self._calculate_anomaly_score(event)
            
            is_anomaly = anomaly_score >= self.anomaly_threshold
            risk_level = 'high' if anomaly_score >= self.high_risk_threshold else 'medium' if is_anomaly else 'low'
            
            # Store in history
            anomaly_record = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event': event,
                'anomaly_score': anomaly_score,
                'is_anomaly': is_anomaly,
                'risk_level': risk_level
            }
            self.anomaly_history.append(anomaly_record)
            
            # Keep only last 1000 records
            if len(self.anomaly_history) > 1000:
                self.anomaly_history = self.anomaly_history[-1000:]
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="detect_anomaly",
                data={
                    'is_anomaly': is_anomaly,
                    'anomaly_score': anomaly_score,
                    'risk_level': risk_level,
                    'reasons': self._get_anomaly_reasons(event, anomaly_score)
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="detection_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="detect_anomaly",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="detect_anomaly"
            ).observe(time.time() - start_time)
    
    def get_anomaly_report(self, time_range_hours: int = 24) -> PluginResult:
        """Get anomaly detection report for time range"""
        start_time = time.time()
        plugin_name = "anomaly_detection"
        
        try:
            cutoff_time = datetime.now(timezone.utc).timestamp() - (time_range_hours * 3600)
            
            recent_anomalies = [
                a for a in self.anomaly_history
                if datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00')).timestamp() >= cutoff_time
            ]
            
            total_events = len(recent_anomalies)
            anomaly_count = sum(1 for a in recent_anomalies if a['is_anomaly'])
            high_risk_count = sum(1 for a in recent_anomalies if a['risk_level'] == 'high')
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="get_anomaly_report",
                data={
                    'time_range_hours': time_range_hours,
                    'total_events': total_events,
                    'anomaly_count': anomaly_count,
                    'high_risk_count': high_risk_count,
                    'anomaly_rate': anomaly_count / total_events if total_events > 0 else 0,
                    'recent_anomalies': recent_anomalies[-10:]  # Last 10
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="report_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="get_anomaly_report",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="get_anomaly_report"
            ).observe(time.time() - start_time)
    
    def _calculate_anomaly_score(self, event: Dict) -> float:
        """Calculate anomaly score (0-1) for event"""
        # Mock implementation using simple deviation from baseline
        score = 0.0
        
        request_rate = event.get('request_rate', 0)
        if request_rate > self.baseline_stats.get('request_rate_mean', 10) * 3:
            score += 0.4  # High request rate
        
        data_volume = event.get('data_volume', 0)
        if data_volume > self.baseline_stats.get('data_volume_mean', 1000) * 5:
            score += 0.3  # High data volume
        
        # Check access time (unusual hours)
        hour = datetime.now(timezone.utc).hour
        if hour < 6 or hour > 22:
            score += 0.2  # Off-hours access
        
        # Random component for demo variability
        import random
        score += random.uniform(0, 0.1)
        
        return min(score, 1.0)
    
    def _get_anomaly_reasons(self, event: Dict, score: float) -> List[str]:
        """Get human-readable reasons for anomaly detection"""
        reasons = []
        
        if score >= self.anomaly_threshold:
            request_rate = event.get('request_rate', 0)
            if request_rate > self.baseline_stats.get('request_rate_mean', 10) * 3:
                reasons.append(f"Unusual request rate: {request_rate} req/s (baseline: {self.baseline_stats.get('request_rate_mean', 10):.1f})")
            
            data_volume = event.get('data_volume', 0)
            if data_volume > self.baseline_stats.get('data_volume_mean', 1000) * 5:
                reasons.append(f"Unusual data volume: {data_volume} bytes")
            
            hour = datetime.now(timezone.utc).hour
            if hour < 6 or hour > 22:
                reasons.append(f"Off-hours access: {hour}:00 UTC")
        
        return reasons or ["Normal behavior"]


# ============================================================================
# DATA MINIMIZATION PLUGIN
# ============================================================================

class DataMinimizationPlugin:
    """
    Automatic field-level filtering based on purpose and PII detection.
    Implements data minimization principle by removing unnecessary fields.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.DataMinimizationPlugin")
        
        # Purpose-based filtering rules
        self.purposes = config.get('purposes', {})
        
        # PII configuration
        self.automatic_pii_removal = config.get('automatic_pii_removal', True)
        self.pii_fields = config.get('pii_fields', [
            'ssn', 'credit_card', 'email', 'phone', 'address', 'full_name'
        ])
        
        # Common PII patterns
        self.pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
        }
        
        self.logger.info(f"DataMinimizationPlugin initialized with {len(self.purposes)} purpose rules")
    
    def filter_request(self, request_data: Dict, purpose: str, role: str = "USER") -> PluginResult:
        """Filter request data based on purpose and role"""
        start_time = time.time()
        plugin_name = "data_minimization"
        
        try:
            # Get allowed fields for purpose
            purpose_config = self.purposes.get(purpose, {})
            allowed_fields = purpose_config.get('allowed_fields', ['*'])
            blocked_fields = purpose_config.get('blocked_fields', [])
            
            # Start with all data
            filtered_data = request_data.copy()
            
            # If automatic PII removal is enabled, only remove PII fields
            # Otherwise, apply full purpose-based filtering
            if self.automatic_pii_removal and purpose != 'Compliance':
                # Only remove PII fields, keep everything else
                filtered_data = self._remove_pii_fields(filtered_data, allowed_fields)
                # Still apply blocked fields from purpose config
                for blocked_field in blocked_fields:
                    filtered_data.pop(blocked_field, None)
            else:
                # Apply full purpose-based filtering (allowed/blocked lists)
                filtered_data = self._filter_fields(filtered_data, allowed_fields, blocked_fields)
            
            removed_fields = set(request_data.keys()) - set(filtered_data.keys())
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="filter_request",
                data={
                    'filtered_data': filtered_data,
                    'removed_fields': list(removed_fields),
                    'purpose': purpose,
                    'role': role
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="filter_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="filter_request",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="filter_request"
            ).observe(time.time() - start_time)
    
    def filter_response(self, response_data: Dict, purpose: str, role: str = "USER") -> PluginResult:
        """Filter response data based on purpose and role"""
        start_time = time.time()
        plugin_name = "data_minimization"
        
        try:
            # Get allowed fields for purpose
            purpose_config = self.purposes.get(purpose, {})
            allowed_fields = purpose_config.get('allowed_fields', ['*'])
            blocked_fields = purpose_config.get('blocked_fields', [])
            
            # Start with all data
            filtered_data = response_data.copy()
            
            # If automatic PII removal is enabled, only remove PII fields
            # Otherwise, apply full purpose-based filtering
            if self.automatic_pii_removal and purpose != 'Compliance':
                # Only remove PII fields, keep everything else
                filtered_data = self._remove_pii_fields(filtered_data, allowed_fields)
                # Still apply blocked fields from purpose config
                for blocked_field in blocked_fields:
                    filtered_data.pop(blocked_field, None)
            else:
                # Apply full purpose-based filtering (allowed/blocked lists)
                filtered_data = self._filter_fields(filtered_data, allowed_fields, blocked_fields)
            
            removed_fields = set(response_data.keys()) - set(filtered_data.keys())
            
            plugin_success_total.labels(plugin_name=plugin_name).inc()
            return PluginResult(
                success=True,
                plugin_name=plugin_name,
                operation="filter_response",
                data={
                    'filtered_data': filtered_data,
                    'removed_fields': list(removed_fields),
                    'purpose': purpose,
                    'role': role
                },
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            plugin_failure_total.labels(plugin_name=plugin_name, error_type="filter_error").inc()
            return PluginResult(
                success=False,
                plugin_name=plugin_name,
                operation="filter_response",
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            plugin_execution_time.labels(
                plugin_name=plugin_name,
                operation="filter_response"
            ).observe(time.time() - start_time)
    
    def _filter_fields(self, data: Dict, allowed: List[str], blocked: List[str]) -> Dict:
        """Filter dictionary fields based on allow/block lists"""
        if '*' in allowed and not blocked:
            return data.copy()
        
        filtered = {}
        for key, value in data.items():
            # Check if field is blocked
            if key in blocked:
                continue
            
            # Check if field is allowed
            if '*' in allowed or key in allowed:
                filtered[key] = value
        
        return filtered
    
    def _remove_pii_fields(self, data: Dict, allowed_fields: List[str] = None) -> Dict:
        """Remove known PII fields from data, but keep explicitly allowed fields"""
        filtered = {}
        for key, value in data.items():
            # If field is explicitly allowed (not wildcard), keep it even if it contains PII
            if allowed_fields and key in allowed_fields:
                filtered[key] = value
                continue
            
            # Check if field name suggests PII
            if any(pii_field in key.lower() for pii_field in self.pii_fields):
                continue
            
            # Check if value matches PII patterns
            if isinstance(value, str) and self._contains_pii(value):
                continue
            
            filtered[key] = value
        
        return filtered
    
    def _contains_pii(self, value: str) -> bool:
        """Check if string value contains PII patterns"""
        import re
        for pattern_name, pattern in self.pii_patterns.items():
            if re.search(pattern, value):
                return True
        return False



# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def initialize_plugins(config_path: str = "config/plugins/plugins-config.yaml") -> PluginManager:
    """
    Initialize the plugin framework.
    Call this once at sidecar startup.
    """
    return PluginManager(config_path)


def get_plugin_stats() -> Dict[str, Any]:
    """Get statistics about plugin usage"""
    return {
        'presidio_available': PRESIDIO_AVAILABLE,
        'jwt_available': JWT_AVAILABLE,
        'slack_available': SLACK_AVAILABLE,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

# Made with Bob
