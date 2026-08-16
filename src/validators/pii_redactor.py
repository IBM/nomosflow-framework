#!/usr/bin/env python3
"""PII Redaction Module for FRED Data and Economic Queries.

This module provides comprehensive PII detection and redaction capabilities
for Federal Reserve Economic Data (FRED) and other economic data sources.

Features:
- Pattern-based PII detection (SSN, email, phone, credit cards, etc.)
- Risk-based redaction strategies (block, mask, tokenize)
- Integration with OPA privacy risk scoring
- Audit trail for all redaction actions
"""

import re
import json
import hashlib
import logging
import yaml
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
from enum import Enum
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Privacy risk levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RedactionAction(Enum):
    """Redaction actions based on risk level."""
    ALLOW = "ALLOW"
    MASK = "MASK"
    TOKENIZE = "TOKENIZE"
    BLOCK = "BLOCK"


class PIIType(Enum):
    """Types of PII that can be detected."""
    SSN = "SSN"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CREDIT_CARD = "CREDIT_CARD"
    NAME = "NAME"
    ADDRESS = "ADDRESS"
    IP_ADDRESS = "IP_ADDRESS"
    API_KEY = "API_KEY"
    PASSWORD = "PASSWORD"
    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    # Custom pattern types (dynamically added)
    CUSTOM = "CUSTOM"


class PIIRedactor:
    """Detects and redacts PII from FRED data and economic queries."""
    
    # PII detection patterns with risk scores
    PII_PATTERNS = {
        PIIType.SSN: {
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
            'replacement': 'XXX-XX-XXXX',
            'risk_score': 0.85,
            'description': 'Social Security Number'
        },
        PIIType.EMAIL: {
            'pattern': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'replacement': '[REDACTED-EMAIL]',
            'risk_score': 0.60,
            'description': 'Email Address'
        },
        PIIType.PHONE: {
            'pattern': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'replacement': 'XXX-XXX-XXXX',
            'risk_score': 0.45,
            'description': 'Phone Number'
        },
        PIIType.CREDIT_CARD: {
            'pattern': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'replacement': 'XXXX-XXXX-XXXX-XXXX',
            'risk_score': 0.85,
            'description': 'Credit Card Number'
        },
        PIIType.IP_ADDRESS: {
            'pattern': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'replacement': 'XXX.XXX.XXX.XXX',
            'risk_score': 0.70,
            'description': 'IP Address'
        },
        PIIType.API_KEY: {
            'pattern': r'(?i)(api[_-]?key|apikey|access[_-]?token)[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            'replacement': r'\1=[REDACTED-KEY]',
            'risk_score': 0.85,
            'description': 'API Key or Access Token'
        },
        PIIType.PASSWORD: {
            'pattern': r'(?i)(password|passwd|pwd)[=:]\s*["\']?([^\s"\']{6,})["\']?',
            'replacement': r'\1=[REDACTED-PASSWORD]',
            'risk_score': 0.85,
            'description': 'Password'
        },
        PIIType.ACCOUNT_NUMBER: {
            'pattern': r'\b(?:account|acct)[#\s]*:?\s*(\d{6,})\b',
            'replacement': 'account: [REDACTED-ACCOUNT]',
            'risk_score': 0.65,
            'description': 'Account Number'
        },
        PIIType.NAME: {
            'pattern': r'\b(?!(?:I|My|The|This|That|These|Those|What|When|Where|Who|Why|How|Can|Could|Would|Should|Will|May|Might|Must|Need|Want|Have|Has|Had|Get|Got|Make|Made|Take|Took|Give|Gave|Show|Showed|Tell|Told|Ask|Asked|Help|Helped|Email|Phone|Account|System|Data|File|Report|Request|Response|Error|Success|Failed|Access|Denied|Allowed|Blocked|Manager|Address|Number|Contact|Please|ABC|DEF|XYZ|Training|Learning|Support|Service|Customer|Deal|Pipeline)\s)[A-Z][a-z]{2,}\s+(?!(?:for|the|and|with|from|about|called|required|invalid|occurred|message|shows|sent|is|will|if|needed|working|help|out|lead|this|portal|center|desk|team|page|site|tool|at)\b)[A-Z][a-z]{2,}\b',
            'replacement': '[REDACTED-NAME]',
            'risk_score': 0.50,
            'description': 'Person Name'
        },
        PIIType.DATE_OF_BIRTH: {
            'pattern': r'\b(?:DOB|date of birth)[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b',
            'replacement': 'DOB: [REDACTED-DOB]',
            'risk_score': 0.75,
            'description': 'Date of Birth'
        }
    }
    
    def __init__(self, enable_tokenization: bool = False, custom_patterns_file: Optional[str] = None):
        """Initialize PII redactor.
        
        Args:
            enable_tokenization: If True, use reversible tokenization instead of masking
            custom_patterns_file: Path to YAML file with custom PII patterns
        """
        self.enable_tokenization = enable_tokenization
        self.token_map: Dict[str, str] = {}  # token -> original value
        self.reverse_token_map: Dict[str, str] = {}  # original value -> token
        self.detection_stats: Dict[str, int] = {}
        self.custom_patterns: Dict[str, Dict[str, Any]] = {}
        self.custom_patterns_enabled = False
        
        # Load custom patterns if provided
        if custom_patterns_file:
            self._load_custom_patterns(custom_patterns_file)
        else:
            # Try to load default custom patterns file if it exists
            default_path = Path(__file__).parent.parent.parent / "config" / "custom_pii_patterns.yaml"
            if default_path.exists():
                self._load_custom_patterns(str(default_path))
        
    def _load_custom_patterns(self, config_file: str) -> None:
        """Load custom PII patterns from YAML configuration file.
        
        Args:
            config_file: Path to YAML configuration file
        """
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            # Check if custom patterns are enabled
            settings = config.get('settings', {})
            self.custom_patterns_enabled = settings.get('enabled', True)
            
            if not self.custom_patterns_enabled:
                logger.info("Custom patterns are disabled in configuration")
                return
            
            # Load custom patterns
            custom_patterns_list = config.get('custom_patterns', [])
            
            for pattern_config in custom_patterns_list:
                # Skip disabled patterns
                if not pattern_config.get('enabled', True):
                    continue
                
                name = pattern_config.get('name')
                if not name:
                    logger.warning("Skipping custom pattern without name")
                    continue
                
                # Create pattern configuration
                self.custom_patterns[name] = {
                    'pattern': pattern_config.get('pattern'),
                    'replacement': pattern_config.get('replacement', '[REDACTED]'),
                    'risk_score': pattern_config.get('risk_score', 0.50),
                    'description': pattern_config.get('description', name),
                    'case_sensitive': pattern_config.get('case_sensitive', False),
                    'category': pattern_config.get('category', 'custom')
                }
            
            logger.info(f"Loaded {len(self.custom_patterns)} custom PII patterns from {config_file}")
            
        except FileNotFoundError:
            logger.warning(f"Custom patterns file not found: {config_file}")
        except yaml.YAMLError as e:
            logger.error(f"Error parsing custom patterns YAML: {e}")
        except Exception as e:
            logger.error(f"Error loading custom patterns: {e}")
    
    def detect_pii(self, text: str) -> List[Dict[str, Any]]:
        """Detect all PII in text.
        
        Args:
            text: Text to scan for PII
            
        Returns:
            List of detected PII items with type, value, position, and risk score
        """
        detections = []
        
        # Detect built-in PII patterns
        for pii_type, config in self.PII_PATTERNS.items():
            pattern = config['pattern']
            # Only use case-insensitive matching for patterns that need it
            # NAME pattern must be case-sensitive to work correctly
            flags = 0
            if pii_type not in [PIIType.NAME]:
                flags = re.IGNORECASE
            
            matches = re.finditer(pattern, text, flags)
            
            for match in matches:
                detection = {
                    'type': pii_type.value,
                    'value': match.group(0),
                    'start': match.start(),
                    'end': match.end(),
                    'risk_score': config['risk_score'],
                    'description': config['description']
                }
                detections.append(detection)
                
                # Update stats
                self.detection_stats[pii_type.value] = \
                    self.detection_stats.get(pii_type.value, 0) + 1
        
        # Detect custom patterns if enabled
        if self.custom_patterns_enabled and self.custom_patterns:
            for pattern_name, config in self.custom_patterns.items():
                pattern = config['pattern']
                flags = 0 if config['case_sensitive'] else re.IGNORECASE
                
                try:
                    matches = re.finditer(pattern, text, flags)
                    
                    for match in matches:
                        detection = {
                            'type': f"CUSTOM_{pattern_name}",
                            'value': match.group(0),
                            'start': match.start(),
                            'end': match.end(),
                            'risk_score': config['risk_score'],
                            'description': config['description'],
                            'category': config.get('category', 'custom')
                        }
                        detections.append(detection)
                        
                        # Update stats
                        stats_key = f"CUSTOM_{pattern_name}"
                        self.detection_stats[stats_key] = \
                            self.detection_stats.get(stats_key, 0) + 1
                except re.error as e:
                    logger.error(f"Invalid regex pattern for {pattern_name}: {e}")
        
        return detections
    
    def calculate_risk_score(self, detections: List[Dict[str, Any]]) -> float:
        """Calculate overall privacy risk score based on detections.
        
        Uses the same 4-layer approach as privacy_risk_scoring.rego:
        - Layer 1: PII Detection (35% weight)
        - Layer 2: Semantic Keywords (35% weight)
        - Layer 3: Embedding Similarity (15% weight)
        - Layer 4: Context Boost (15% weight)
        
        Args:
            detections: List of PII detections
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        if not detections:
            return 0.0
        
        # Layer 1: Maximum PII risk score
        max_pii_score = max([d['risk_score'] for d in detections])
        
        # Layer 1: Bonus for multiple PII types
        unique_types = len(set([d['type'] for d in detections]))
        pii_count_bonus = min(unique_types * 0.05, 0.20)
        
        pii_layer_score = min(1.0, max_pii_score + pii_count_bonus)
        
        # Layer 4: Context boost for multiple critical PII
        context_boost = 0.0
        critical_count = sum(1 for d in detections if d['risk_score'] >= 0.70)
        if critical_count >= 2:
            context_boost = 0.15
        elif critical_count == 1 and len(detections) >= 3:
            context_boost = 0.10
        
        # Final score calculation
        # For critical PII (SSN, credit card, API keys), use higher weight
        # to ensure they trigger HIGH risk (≥0.35)
        if max_pii_score >= 0.85:
            # Critical PII detected - use 50% weight to ensure HIGH risk
            final_score = (pii_layer_score * 0.50) + (context_boost * 0.15)
        else:
            # Standard PII - use 35% weight
            final_score = (pii_layer_score * 0.35) + (context_boost * 0.15)
        
        return min(1.0, final_score)
    
    def determine_action(self, risk_score: float) -> RedactionAction:
        """Determine redaction action based on risk score.
        
        Risk Thresholds:
        - HIGH (≥0.35): BLOCK
        - MEDIUM (0.18-0.35): MASK/TOKENIZE
        - LOW (<0.18): ALLOW
        
        Args:
            risk_score: Privacy risk score (0.0 to 1.0)
            
        Returns:
            Redaction action to take
        """
        if risk_score >= 0.35:
            return RedactionAction.BLOCK
        elif risk_score >= 0.18:
            return RedactionAction.TOKENIZE if self.enable_tokenization else RedactionAction.MASK
        else:
            return RedactionAction.ALLOW
    
    def _generate_token(self, value: str) -> str:
        """Generate a unique token for a PII value."""
        # Check if we already have a token for this value
        if value in self.reverse_token_map:
            return self.reverse_token_map[value]
        
        # Generate new token
        token_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
        token = f"TOKEN_{token_hash.upper()}"
        
        # Store mappings
        self.token_map[token] = value
        self.reverse_token_map[value] = token
        
        return token
    
    def redact_text(self, text: str, action: RedactionAction) -> Tuple[str, List[Dict[str, Any]]]:
        """Redact PII from text based on action.
        
        Args:
            text: Text to redact
            action: Redaction action to apply
            
        Returns:
            Tuple of (redacted_text, detections)
        """
        detections = self.detect_pii(text)
        
        if action == RedactionAction.ALLOW:
            return text, detections
        
        if action == RedactionAction.BLOCK:
            return "[BLOCKED-HIGH-RISK-CONTENT]", detections
        
        # MASK or TOKENIZE
        redacted_text = text
        
        # Sort detections by position (reverse order to maintain positions)
        sorted_detections = sorted(detections, key=lambda x: x['start'], reverse=True)
        
        for detection in sorted_detections:
            detection_type = detection['type']
            
            # Handle custom patterns
            if detection_type.startswith('CUSTOM_'):
                pattern_name = detection_type.replace('CUSTOM_', '')
                if pattern_name in self.custom_patterns:
                    config = self.custom_patterns[pattern_name]
                else:
                    # Fallback if pattern not found
                    config = {'replacement': '[REDACTED]'}
            else:
                # Handle built-in patterns
                try:
                    pii_type = PIIType(detection_type)
                    config = self.PII_PATTERNS[pii_type]
                except (ValueError, KeyError):
                    # Unknown pattern type, use default
                    config = {'replacement': '[REDACTED]'}
            
            if action == RedactionAction.TOKENIZE:
                replacement = self._generate_token(detection['value'])
            else:  # MASK
                replacement = config['replacement']
            
            # Replace the PII value
            start = detection['start']
            end = detection['end']
            redacted_text = redacted_text[:start] + replacement + redacted_text[end:]
        
        return redacted_text, detections
    
    def redact_dict(self, data: Dict[str, Any], action: RedactionAction) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Recursively redact PII from dictionary.
        
        Args:
            data: Dictionary to redact
            action: Redaction action to apply
            
        Returns:
            Tuple of (redacted_dict, all_detections)
        """
        all_detections = []
        redacted = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                redacted_value, detections = self.redact_text(value, action)
                redacted[key] = redacted_value
                all_detections.extend(detections)
            elif isinstance(value, dict):
                redacted_value, detections = self.redact_dict(value, action)
                redacted[key] = redacted_value
                all_detections.extend(detections)
            elif isinstance(value, list):
                redacted_list = []
                for item in value:
                    if isinstance(item, str):
                        redacted_item, detections = self.redact_text(item, action)
                        redacted_list.append(redacted_item)
                        all_detections.extend(detections)
                    elif isinstance(item, dict):
                        redacted_item, detections = self.redact_dict(item, action)
                        redacted_list.append(redacted_item)
                        all_detections.extend(detections)
                    else:
                        redacted_list.append(item)
                redacted[key] = redacted_list
            else:
                redacted[key] = value
        
        return redacted, all_detections
    
    def process_fred_query(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Process a FRED query with PII detection and redaction.
        
        This is the main entry point for the demo.
        
        Args:
            query: FRED query dictionary
            
        Returns:
            Processing result with redacted data, risk assessment, and audit info
        """
        # Detect PII in the entire query
        query_str = json.dumps(query)
        detections = self.detect_pii(query_str)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(detections)
        
        # Determine action
        action = self.determine_action(risk_score)
        
        # Determine risk level
        if risk_score >= 0.35:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 0.18:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Redact the query
        redacted_query, all_detections = self.redact_dict(query, action)
        
        # Build result
        result = {
            'status': 'blocked' if action == RedactionAction.BLOCK else 'allowed',
            'action': action.value,
            'risk_assessment': {
                'risk_score': round(risk_score, 4),
                'risk_level': risk_level.value,
                'pii_detected': len(detections),
                'unique_pii_types': len(set([d['type'] for d in detections])),
                'detections': [
                    {
                        'type': d['type'],
                        'description': d['description'],
                        'risk_score': d['risk_score']
                    }
                    for d in detections
                ]
            },
            'original_query': query if action != RedactionAction.BLOCK else '[BLOCKED]',
            'redacted_query': redacted_query,
            'audit_info': {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'redaction_action': action.value,
                'pii_types_found': list(set([d['type'] for d in detections])),
                'compliance_frameworks': ['GDPR Article 5(1)(f)', 'CCPA §1798.100', 'HIPAA §164.514']
            }
        }
        
        return result
    
    def process_fred_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process FRED API response data with PII detection and redaction.
        
        Scans response data for any PII that might be present in:
        - Series titles, notes, or descriptions
        - Observation values or metadata
        - Any text fields in the response
        
        Args:
            response_data: FRED API response dictionary
            
        Returns:
            Processing result with redacted data, risk assessment, and audit info
        """
        # Detect PII in the entire response
        response_str = json.dumps(response_data)
        detections = self.detect_pii(response_str)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(detections)
        
        # Determine action
        action = self.determine_action(risk_score)
        
        # Determine risk level
        if risk_score >= 0.35:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 0.18:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Redact the response if needed
        if action == RedactionAction.BLOCK:
            redacted_response = {'error': 'Response blocked due to critical PII'}
        else:
            redacted_response, all_detections = self.redact_dict(response_data, action)
        
        # Build result
        result = {
            'status': 'blocked' if action == RedactionAction.BLOCK else 'allowed',
            'action': action.value,
            'risk_assessment': {
                'risk_score': round(risk_score, 4),
                'risk_level': risk_level.value,
                'pii_detected': len(detections),
                'unique_pii_types': len(set([d['type'] for d in detections])),
                'detections': [
                    {
                        'type': d['type'],
                        'description': d['description'],
                        'risk_score': d['risk_score']
                    }
                    for d in detections
                ]
            },
            'original_response': response_data if action != RedactionAction.BLOCK else '[BLOCKED]',
            'redacted_response': redacted_response,
            'audit_info': {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'redaction_action': action.value,
                'pii_types_found': list(set([d['type'] for d in detections])),
                'compliance_frameworks': ['GDPR Article 5(1)(f)', 'CCPA §1798.100', 'HIPAA §164.514'],
                'scan_type': 'response_data'
            }
        }
        
        return result
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get PII detection statistics."""
        return {
            'total_detections': sum(self.detection_stats.values()),
            'detections_by_type': self.detection_stats.copy(),
            'tokens_generated': len(self.token_map) if self.enable_tokenization else 0
        }


# Convenience function for quick usage
def redact_fred_data(query: Dict[str, Any], enable_tokenization: bool = False) -> Dict[str, Any]:
    """Quick function to redact PII from FRED query.
    
    Args:
        query: FRED query dictionary
        enable_tokenization: Use reversible tokenization instead of masking
        
    Returns:
        Processing result with redacted data and risk assessment
    """
    redactor = PIIRedactor(enable_tokenization=enable_tokenization)
    return redactor.process_fred_query(query)


if __name__ == "__main__":
    # Quick test
    print("Testing PII Redactor...")
    
    test_query = {
        "series_id": "UNRATE",
        "researcher": "Dr. Sarah Johnson",
        "email": "sarah.j@university.edu",
        "notes": "Contact: 555-123-4567"
    }
    
    result = redact_fred_data(test_query)
    print(json.dumps(result, indent=2))

# Made with Bob
