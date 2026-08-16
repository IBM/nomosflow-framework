#!/usr/bin/env python3
"""LLM-based validation module for hallucination detection and output validation.

This module uses LiteLLM to validate:
1. Request parameters for fabricated/hallucinated identifiers
2. External API responses for data quality and consistency
3. Compliance with enterprise data governance rules

Integrates with the compliance sidecar to provide AI-powered validation
alongside rule-based OPA policy checks.
"""

import json
import time
import os
import logging
from typing import Dict, Tuple, Optional
from functools import lru_cache
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import litellm
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False
    logger.warning("⚠️  LiteLLM not available. Install with: pip install litellm")


class LLMValidator:
    """Validates requests and responses using LiteLLM for hallucination detection."""
    
    def __init__(
        self,
        model: str = "gpt-3.5-turbo",
        temperature: float = 0.0,
        timeout: float = 5.0,
        enabled: bool = True,
        cache_enabled: bool = True
    ):
        """Initialize LLM validator.
        
        Args:
            model: LiteLLM model identifier (e.g., 'gpt-3.5-turbo', 'claude-3-sonnet')
            temperature: Sampling temperature (0.0 for deterministic)
            timeout: Request timeout in seconds
            enabled: Whether validation is enabled
            cache_enabled: Whether to cache validation results
        """
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.enabled = enabled and LITELLM_AVAILABLE
        self.cache_enabled = cache_enabled
        
        if not LITELLM_AVAILABLE:
            logger.warning("⚠️  LLM validation disabled: litellm not installed")
            self.enabled = False
        
        if self.enabled:
            # Configure LiteLLM
            litellm.set_verbose = False
            litellm.drop_params = True  # Drop unsupported params
            
            # Set API key from environment if available
            # Support multiple LLM providers: OpenAI, Anthropic, etc.
            api_key = os.getenv('LLM_API_KEY') or os.getenv('OPENAI_API_KEY')
            anthropic_key = os.getenv('ANTHROPIC_API_KEY')
            
            if api_key:
                os.environ['OPENAI_API_KEY'] = api_key
            if anthropic_key:
                os.environ['ANTHROPIC_API_KEY'] = anthropic_key
            
            logger.info(f"✅ LLM Validator initialized: model={model}, cache={cache_enabled}")
        else:
            logger.info("ℹ️  LLM validation disabled")
    
    def _create_cache_key(self, data: Dict, validation_type: str) -> str:
        """Create deterministic cache key for validation results."""
        # Remove timestamp and request_id for caching
        cache_data = {k: v for k, v in data.items() 
                     if k not in ['timestamp', 'request_id']}
        data_str = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(f"{validation_type}:{data_str}".encode()).hexdigest()
    
    @lru_cache(maxsize=500)
    def _cached_validation(self, cache_key: str, prompt: str) -> Tuple[bool, str, float]:
        """Cached LLM validation call."""
        return self._call_llm(prompt)
    
    def _call_llm(self, prompt: str) -> Tuple[bool, str, float]:
        """Make LLM API call with error handling.
        
        Updated for LiteLLM >= 1.60.1 compatibility with improved error handling.
        """
        start_time = time.time()
        
        try:
            # Get LiteLLM proxy URL if configured
            api_base = os.getenv('LITELLM_BASE_URL')
            api_key = os.getenv('LLM_API_KEY') or os.getenv('OPENAI_API_KEY') or os.getenv('ANTHROPIC_API_KEY')
            
            # Model name handling based on configuration
            model_name = self.model

            if api_base:
                # IBM LiteLLM proxy (OpenAI-compatible transport).
                #
                # LiteLLM's *client-side* provider router parses the model string
                # before sending anything.  It does not recognise "aws/" or
                # "anthropic/" as valid provider prefixes — those only have meaning
                # on the *proxy server*.  We must therefore present the model as
                # "openai/<model>" so the client uses the OpenAI provider shim and
                # forwards the request to api_base.  The proxy receives the full
                # model name in the request body and uses its own routing table.
                #
                # Always prefix with "openai/" so LiteLLM's client-side router
                # uses the OpenAI shim and forwards to api_base.  The full original
                # model name (e.g. "aws/claude-sonnet-4-6") is preserved after the
                # prefix and reaches the proxy in the request body, where it is used
                # for server-side routing.  This produces "openai/aws/claude-sonnet-4-6"
                # which LiteLLM correctly resolves to provider=openai, model=aws/claude-sonnet-4-6.
                if not model_name.startswith("openai/"):
                    model_name = f"openai/{model_name}"
                logger.info(f"Using LiteLLM proxy: {api_base} → model in body: {model_name.split('/', 1)[-1]}")
            else:
                # Direct API calls: bare names default to OpenAI provider.
                if '/' not in model_name:
                    model_name = f"openai/{model_name}"
                logger.info(f"Using direct API with model: {model_name}")
            
            # Build completion parameters.
            # num_retries=0 disables the litellm/openai SDK automatic retry-with-backoff.
            # Without this, a single rate-limit response causes a 60 s sleep before the
            # next attempt.  Transient errors are handled as fail-open (valid=True) by
            # the caller, so no retry is needed here.
            completion_params = {
                "model": model_name,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.temperature,
                "timeout": self.timeout,
                "num_retries": 0,
            }

            # Add proxy parameters if using LiteLLM proxy
            if api_base:
                completion_params["api_base"] = api_base
                if api_key:
                    completion_params["api_key"] = api_key

            # LiteLLM 1.60.1+ API call with proper error handling
            # Try with response_format first (OpenAI models)
            try:
                response = litellm.completion(
                    **completion_params,
                    response_format={"type": "json_object"}
                )
            except Exception as format_error:
                # Fallback: Some models don't support response_format
                logger.debug(f"response_format not supported, retrying without it: {format_error}")
                response = litellm.completion(**completion_params)
            
            duration = time.time() - start_time
            
            # Extract content from response
            content = response.choices[0].message.content
            if not content:
                logger.error("LLM returned empty content")
                return True, "LLM validation error: Empty response", duration
            
            # Parse JSON response
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code blocks
                logger.warning(f"Failed to parse JSON, attempting to extract from markdown: {content[:200]}")
                import re
                json_match = re.search(r'```json\s*(\{.*?\})\s*```', content, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group(1))
                else:
                    # Last resort: try to find any JSON object
                    json_match = re.search(r'\{.*\}', content, re.DOTALL)
                    if json_match:
                        result = json.loads(json_match.group(0))
                    else:
                        logger.error(f"Could not extract JSON from response: {content[:200]}")
                        return True, f"LLM response parsing error: No valid JSON found", duration
            
            is_valid = result.get("is_valid", True)
            reason = result.get("reason", "No reason provided")
            confidence = result.get("confidence", 0.0)
            
            logger.debug(f"LLM validation result: valid={is_valid}, reason={reason}, confidence={confidence}, duration={duration:.3f}s")
            return is_valid, reason, duration
            
        except json.JSONDecodeError as e:
            duration = time.time() - start_time
            logger.error(f"LLM response JSON parsing error: {e}")
            # Fail open - don't block on parsing errors
            return True, f"LLM response parsing error: {e}", duration
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"LLM validation error: {type(e).__name__}: {e}")
            # Fail open - don't block on LLM errors
            return True, f"LLM validation error: {type(e).__name__}: {str(e)}", duration
    
    def validate_request(self, event: Dict) -> Tuple[bool, str, float]:
        """Validate if a request contains hallucinated or suspicious parameters.
        
        Args:
            event: Request event dictionary
            
        Returns:
            Tuple of (is_valid, reason, duration_seconds)
        """
        if not self.enabled:
            return True, "LLM validation disabled", 0.0
        
        # Create validation prompt
        prompt = f"""Analyze this data access request for potential hallucinations or fabricated identifiers.

Request Details:
{json.dumps(event, indent=2)}

IMPORTANT: Only check for hallucinations and fabricated data. Do NOT validate compliance rules.

Validation Criteria (Hallucination Detection Only):
1. Resource Identifiers: Check if identifiers appear realistic and properly formatted
   - SEC CIK numbers should be exactly 10 digits (e.g., 0000051143 for IBM)
   - FRED series IDs should follow known patterns (e.g., UNRATE, GDP, DFF)
   - Reject obvious test/fake/dummy/mock patterns in resource names

2. Temporal Consistency: Verify timestamps are realistic
   - Timestamp should not be in the future
   - Timestamp should be reasonably recent (within last few years)

3. Data Patterns: Check for obviously fabricated patterns
   - No clearly fake identifiers (e.g., "fake_company", "test_data")
   - No nonsensical combinations

NOTE: Do NOT validate:
- User roles or permissions (handled by policy engine)
- Purpose codes (handled by policy engine)
- Security tokens (handled by policy engine)
- Regional restrictions (handled by policy engine)

Respond with JSON format:
{{
  "is_valid": true or false,
  "reason": "Brief explanation focusing ONLY on hallucination/fabrication issues",
  "confidence": 0.0 to 1.0,
  "violations": ["list of specific hallucination/fabrication issues found"]
}}

If the identifiers appear legitimate and realistic, set is_valid=true.
If you detect fabricated/hallucinated data, set is_valid=false.
"""
        
        # Use cache if enabled
        if self.cache_enabled:
            cache_key = self._create_cache_key(event, "request")
            return self._cached_validation(cache_key, prompt)
        else:
            return self._call_llm(prompt)
    
    def validate_semantic_pii(self, event: Dict) -> Tuple[bool, str, float]:
        """Detect indirect PII and re-identification risk in a data access request.

        This is the T5 semantic tier's core task: catching violations that
        T1 (regex/APL) and T3 (OPA policy rules) cannot express, including:
          - Indirect / quasi-identifier combinations that enable re-identification
          - Shadow PII (derived identifiers, inferred sensitive attributes)
          - Context leakage (merging public + private cohorts)
          - Sensitive-category inference (health, religion, political affiliation)
          - Free-text queries describing prohibited data operations

        Fields owned by T1/T3 (token, role, action, purpose, region, timestamp)
        have already been enforced upstream and are excluded from the prompt so
        the model is not distracted by them.

        Args:
            event: Request event dictionary (pre-filtered to semantic fields)

        Returns:
            Tuple of (is_compliant, reason, duration_seconds).
            is_compliant=False means a semantic privacy violation was detected.
        """
        if not self.enabled:
            return True, "LLM validation disabled", 0.0

        prompt = f"""You are a data-governance compliance auditor evaluating whether a
data-access request contains indirect PII, re-identification risk, or
semantic privacy violations that rule-based policy engines cannot detect.

The upstream policy engine has already enforced:
  - authentication (token validity)
  - RBAC (role/action rules)
  - purpose limitation (allowed purpose codes)
  - geo-sovereignty restrictions
  - timestamp validity

Your ONLY job is to evaluate the REQUEST CONTENT for the following
semantic privacy risks:

1. RE-IDENTIFICATION RISK
   Quasi-identifier combinations (e.g. zip + age + gender, IP + health outcome,
   postal code + birth-date) that together could uniquely identify an individual.

2. INDIRECT / SHADOW PII
   Derived identifiers (derived_id, shadow_id, shadow_pii), inferred attributes,
   or linkage across datasets that reconstructs a personal profile.

3. SENSITIVE-CATEGORY INFERENCE
   Queries that infer health/medical status, genomic data, religion, political
   affiliation, sexual orientation, or financial distress from non-sensitive
   proxies.

4. PROHIBITED DATA OPERATIONS
   Requests that describe de-anonymisation, re-identification, trajectory
   correlation, cross-hospital patient linkage, or cohort merging that
   leaks individual identity.

5. CONTEXT LEAKAGE
   Joining or correlating a public dataset with a private cohort in a way
   that transfers individual-level sensitive attributes.

Data access request to evaluate:
{json.dumps(event, indent=2)}

Respond with JSON only — no markdown fences, no prose outside the JSON:
{{
  "is_compliant": true or false,
  "violation_type": "NONE | RE_IDENTIFICATION | INDIRECT_PII | SENSITIVE_INFERENCE | PROHIBITED_OPERATION | CONTEXT_LEAK",
  "reason": "One sentence explaining the finding.",
  "confidence": 0.0 to 1.0
}}

Set is_compliant=true if you find no semantic privacy risk.
Set is_compliant=false only if you are confident (confidence >= 0.7) a
semantic privacy violation is present.  Do NOT flag requests that look
benign just because they touch sensitive-sounding resources — only flag
actual re-identification or indirect-PII operations described in the content.
"""
        start = time.time()
        try:
            # Build completion params directly (bypass _call_llm to use
            # our own JSON parse logic for the is_compliant key).
            api_base = os.getenv('LITELLM_BASE_URL')
            api_key  = os.getenv('LLM_API_KEY') or os.getenv('OPENAI_API_KEY') or os.getenv('ANTHROPIC_API_KEY')
            model_name = self.model
            if api_base and not model_name.startswith('openai/'):
                model_name = f'openai/{model_name}'
            elif '/' not in model_name:
                model_name = f'openai/{model_name}'

            params: Dict = {
                'model': model_name,
                'messages': [{'role': 'user', 'content': prompt}],
                'temperature': self.temperature,
                'timeout': self.timeout,
                'num_retries': 0,
            }
            if api_base:
                params['api_base'] = api_base
            if api_key:
                params['api_key'] = api_key

            try:
                resp = litellm.completion(**params, response_format={'type': 'json_object'})
            except Exception:
                resp = litellm.completion(**params)

            duration = time.time() - start
            content = resp.choices[0].message.content or ''

            # Parse JSON — strip markdown fences if present
            import re as _re
            content_clean = _re.sub(r'^```[a-z]*\s*|\s*```$', '', content.strip(), flags=_re.M)
            try:
                result = json.loads(content_clean)
            except json.JSONDecodeError:
                m = _re.search(r'\{.*\}', content_clean, _re.DOTALL)
                result = json.loads(m.group(0)) if m else {}

            is_compliant = bool(result.get('is_compliant', True))
            reason       = result.get('reason', 'no reason provided')
            confidence   = float(result.get('confidence', 0.0))
            vtype        = result.get('violation_type', 'NONE')

            # Honour the confidence gate stated in the prompt
            if not is_compliant and confidence < 0.7:
                is_compliant = True
                reason = f'low-confidence flag suppressed ({confidence:.2f}): {reason}'

            tag = f'[{vtype}]' if vtype and vtype != 'NONE' else ''
            return is_compliant, f'{tag} {reason}'.strip(), duration

        except Exception as exc:
            duration = time.time() - start
            logger.error(f'validate_semantic_pii error: {type(exc).__name__}: {exc}')
            return True, f'LLM semantic validation error: {type(exc).__name__}', duration

    def validate_response(
        self,
        resource: str,
        data: Dict,
        max_data_length: int = 2000
    ) -> Tuple[bool, str, float]:
        """Validate if external API response contains hallucinated data.
        
        Args:
            resource: Resource identifier (e.g., 'fred/UNRATE', 'edgar/0000051143')
            data: Response data dictionary
            max_data_length: Maximum data length to send to LLM
            
        Returns:
            Tuple of (is_valid, reason, duration_seconds)
        """
        if not self.enabled:
            return True, "LLM validation disabled", 0.0
        
        # Truncate large responses for LLM processing
        data_str = json.dumps(data, indent=2)
        if len(data_str) > max_data_length:
            data_str = data_str[:max_data_length] + "\n... [TRUNCATED]"
        
        # Create validation prompt
        prompt = f"""Analyze this external API response for data quality and potential hallucinations.

Resource: {resource}
Response Data:
{data_str}

Validation Criteria:
1. Data Structure: Verify response structure is consistent with expected format
   - FRED responses should have 'source', 'series', 'data' fields
   - SEC EDGAR responses should have 'source', 'cik', 'data' fields
   - No missing critical fields

2. Data Quality: Check for realistic values and patterns
   - Numerical values in reasonable ranges
   - Dates are properly formatted and realistic
   - No obvious placeholder or test data

3. Consistency: Verify internal data consistency
   - Temporal ordering makes sense
   - Related fields are consistent
   - No contradictory information

4. Error Indicators: Check for error conditions
   - No error messages in data fields
   - No null/missing critical values
   - No truncation artifacts (unless expected)

5. Hallucination Patterns: Detect fabricated data
   - No suspiciously perfect patterns
   - No unrealistic precision
   - No obvious AI-generated artifacts

Respond with JSON format:
{{
  "is_valid": true or false,
  "reason": "Brief explanation of validation result",
  "confidence": 0.0 to 1.0,
  "data_quality_score": 0.0 to 1.0
}}

If data appears legitimate and high quality, set is_valid=true.
If any hallucination, fabrication, or quality issues detected, set is_valid=false.
"""
        
        # Use cache if enabled
        if self.cache_enabled:
            cache_key = self._create_cache_key(
                {"resource": resource, "data": data_str[:500]},
                "response"
            )
            return self._cached_validation(cache_key, prompt)
        else:
            return self._call_llm(prompt)
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics."""
        if not self.cache_enabled:
            return {"enabled": False}
        
        cache_info = self._cached_validation.cache_info()
        return {
            "enabled": True,
            "hits": cache_info.hits,
            "misses": cache_info.misses,
            "size": cache_info.currsize,
            "maxsize": cache_info.maxsize,
            "hit_rate": cache_info.hits / (cache_info.hits + cache_info.misses)
                       if (cache_info.hits + cache_info.misses) > 0 else 0.0
        }
    
    def clear_cache(self):
        """Clear validation cache."""
        if self.cache_enabled:
            self._cached_validation.cache_clear()


# Singleton instance for global use
_validator_instance: Optional[LLMValidator] = None


def get_validator(
    model: Optional[str] = None,
    enabled: Optional[bool] = None
) -> LLMValidator:
    """Get or create singleton LLM validator instance.
    
    Args:
        model: Override model (uses env var or default if None)
        enabled: Override enabled status (uses env var or default if None)
        
    Returns:
        LLMValidator instance
    """
    global _validator_instance
    
    if _validator_instance is None:
        # Get configuration from environment
        model = model or os.getenv('LLM_MODEL', 'gpt-3.5-turbo')
        enabled = enabled if enabled is not None else \
                 os.getenv('LLM_VALIDATION_ENABLED', 'true').lower() == 'true'
        temperature = float(os.getenv('LLM_TEMPERATURE', '0.0'))
        timeout = float(os.getenv('LLM_VALIDATION_TIMEOUT', '5.0'))
        cache_enabled = os.getenv('LLM_CACHE_ENABLED', 'true').lower() == 'true'
        
        _validator_instance = LLMValidator(
            model=model,
            temperature=temperature,
            timeout=timeout,
            enabled=enabled,
            cache_enabled=cache_enabled
        )
    
    return _validator_instance


def reset_validator():
    """Reset the singleton validator instance.
    
    Useful for testing or when configuration changes require a fresh instance.
    """
    global _validator_instance
    _validator_instance = None


if __name__ == "__main__":
    # Test the validator
    print("Testing LLM Validator...")
    
    validator = get_validator()
    
    # Test request validation
    test_request = {
        "request_id": "test123",
        "agent_id": "AI_Agent_007",
        "token": "valid_security_token",
        "action": "READ",
        "resource": "edgar/0000051143",
        "role": "SENIOR",
        "purpose": "MarketResearch",
        "region": "US",
        "timestamp": int(time.time())
    }
    
    print("\n1. Testing Request Validation (Valid IBM CIK):")
    is_valid, reason, duration = validator.validate_request(test_request)
    print(f"   Valid: {is_valid}")
    print(f"   Reason: {reason}")
    print(f"   Duration: {duration:.3f}s")
    
    # Test with invalid request
    test_request["resource"] = "edgar/FAKE123"
    print("\n2. Testing Request Validation (Invalid CIK):")
    is_valid, reason, duration = validator.validate_request(test_request)
    print(f"   Valid: {is_valid}")
    print(f"   Reason: {reason}")
    print(f"   Duration: {duration:.3f}s")
    
    # Test response validation
    test_response = {
        "source": "FRED",
        "series": "UNRATE",
        "data": {"2024-01": "3.7", "2024-02": "3.9"}
    }
    
    print("\n3. Testing Response Validation (Valid FRED data):")
    is_valid, reason, duration = validator.validate_response("fred/UNRATE", test_response)
    print(f"   Valid: {is_valid}")
    print(f"   Reason: {reason}")
    print(f"   Duration: {duration:.3f}s")
    
    # Cache stats
    print("\n4. Cache Statistics:")
    stats = validator.get_cache_stats()
    print(f"   {json.dumps(stats, indent=2)}")

# Made with Bob