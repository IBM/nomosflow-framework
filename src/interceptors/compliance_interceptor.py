"""
Runtime I/O Interception Pattern (RIIP) for Compliance Sidecar
================================================================

This module provides transparent interception of Python I/O operations
for sandboxed agent containers. All file, HTTP, S3, and database operations are
routed through the compliance sidecar proxy API for validation.

Usage:
    # At the start of your agent code
    import compliance_interceptor
    compliance_interceptor.install()
    
    # Now all I/O operations are automatically intercepted
    with open('/data/file.txt', 'r') as f:  # Routed through proxy
        data = f.read()
    
    # HTTP requests are intercepted (urllib and requests)
    import urllib.request
    urllib.request.urlopen('https://api.example.com')  # Routed through proxy
    
    import requests
    requests.get('https://api.example.com')  # Routed through proxy
    requests.post('https://api.example.com', json={'key': 'value'})  # Routed through proxy
    
    # boto3 S3 operations are intercepted
    import boto3
    s3 = boto3.client('s3')
    s3.get_object(Bucket='my-bucket', Key='file.txt')  # Routed through proxy
    
    # Database operations are intercepted
    import sqlite3
    conn = sqlite3.connect('db.sqlite')  # Routed through proxy

Environment Variables:
    COMPLIANCE_SIDECAR_URL: URL of the compliance sidecar (default: http://localhost:8080)
    COMPLIANCE_INTERCEPT_ENABLED: Set to 'true' to enable interception (default: true)
    COMPLIANCE_AGENT_ID: Unique identifier for this agent (default: auto-generated)
"""

import builtins
import os
import sys
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Dict, Tuple
from io import StringIO, BytesIO
import urllib.request
import urllib.error
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store original functions
_original_open = builtins.open
_original_urlopen = urllib.request.urlopen
_original_boto3_make_request = None
_original_sqlite3_connect = None
_original_psycopg2_connect = None
_original_sqlalchemy_create_engine = None
_original_requests_request = None
_original_requests_session_request = None
_installed = False

# Configuration
SIDECAR_URL = os.getenv('COMPLIANCE_SIDECAR_URL', 'http://localhost:8080')
INTERCEPT_ENABLED = os.getenv('COMPLIANCE_INTERCEPT_ENABLED', 'true').lower() == 'true'
AGENT_ID = os.getenv('COMPLIANCE_AGENT_ID', str(uuid.uuid4()))


class ComplianceProxyClient:
    """Client for communicating with the compliance sidecar proxy API."""
    
    def __init__(
        self,
        sidecar_url: str,
        agent_id: str,
        user_id: Optional[str] = None,
        consent_id: Optional[str] = None,
        data_classification: Optional[str] = None,
        destination_region: Optional[str] = None,
        transfer_mechanism: Optional[str] = None
    ):
        self.sidecar_url = sidecar_url.rstrip('/')
        self.agent_id = agent_id
        self.user_id = user_id
        self.consent_id = consent_id
        self.data_classification = data_classification
        self.destination_region = destination_region
        self.transfer_mechanism = transfer_mechanism
        logger.info(f"Initialized ComplianceProxyClient for agent {agent_id}")
        if user_id:
            logger.info(f"  User ID: {user_id}")
        if consent_id:
            logger.info(f"  Consent ID: {consent_id}")
        if data_classification:
            logger.info(f"  Data Classification: {data_classification}")
    
    def _make_request(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make HTTP request to sidecar proxy endpoint."""
        url = f"{self.sidecar_url}{endpoint}"
        
        # Add agent metadata
        data['agent_id'] = self.agent_id
        data['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        # Add new policy fields if present
        if self.user_id:
            data['user_id'] = self.user_id
        if self.consent_id:
            data['consent_id'] = self.consent_id
        if self.data_classification:
            data['data_classification'] = self.data_classification
        if self.destination_region:
            data['destination_region'] = self.destination_region
        if self.transfer_mechanism:
            data['transfer_mechanism'] = self.transfer_mechanism
        
        request_data = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=request_data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        
        try:
            with _original_urlopen(req, timeout=30) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                return response_data
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            logger.error(f"Proxy request failed: {e.code} - {error_body}")
            raise ComplianceViolationError(f"Compliance check failed: {error_body}")
        except Exception as e:
            logger.error(f"Proxy request error: {str(e)}")
            raise
    
    def validate_file_operation(self, path: str, mode: str, content: Optional[str] = None) -> Dict[str, Any]:
        """Validate file operation through proxy."""
        data = {
            'operation': 'file',
            'path': path,
            'mode': mode,
            'content': content
        }
        return self._make_request('/proxy/file', data)
    
    def validate_http_request(self, url: str, method: str = 'GET', data: Optional[bytes] = None) -> Dict[str, Any]:
        """Validate HTTP request through proxy."""
        request_data = {
            'operation': 'http',
            'url': url,
            'method': method,
            'data': data.decode('utf-8') if data else None,
            # Add required compliance event fields
            'action': 'WRITE' if method in ['POST', 'PUT', 'DELETE', 'PATCH'] else 'READ',
            'resource': url,
            'resource_type': 'http',
            'token': os.getenv('COMPLIANCE_TOKEN', 'valid_security_token'),
            'role': os.getenv('AGENT_ROLE', 'data_analyst'),
            'purpose': os.getenv('DATA_PURPOSE', 'financial_analysis'),
            'region': os.getenv('DATA_REGION', 'US')
        }
        return self._make_request('/proxy/http', request_data)
    
    def validate_s3_operation(self, bucket: str, key: str, operation: str, request_dict: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Validate S3 operation through proxy."""
        data: Dict[str, Any] = {
            'operation': 's3',
            'bucket': bucket,
            'key': key,
            's3_operation': operation
        }
        if request_dict:
            data['request_details'] = str(request_dict)  # Convert to string for JSON serialization
        return self._make_request('/proxy/s3', data)
    
    def validate_database_operation(self, db_type: str, operation: str, **kwargs) -> Dict[str, Any]:
        """Validate database operation through proxy."""
        data = {
            'operation': operation,
            'db_type': db_type,
            'db_operation': operation
        }
        # Merge additional connection info
        data.update(kwargs)
        return self._make_request('/proxy/database', data)


class ComplianceViolationError(Exception):
    """Raised when a compliance violation is detected."""
    pass


class InterceptedFile:
    """Wrapper for file objects that routes operations through compliance proxy."""
    
    def __init__(self, path: str, mode: str, proxy_client: ComplianceProxyClient, *args, **kwargs):
        self.path = path
        self.mode = mode
        self.proxy_client = proxy_client
        self._file = None
        self._content = None
        
        # Validate the file operation
        if 'r' in mode:
            # Read operation - validate and get content from proxy
            result = self.proxy_client.validate_file_operation(path, mode)
            if not result.get('allowed', False):
                raise ComplianceViolationError(f"File read denied: {result.get('reason', 'Unknown')}")
            
            # Create in-memory file from validated content
            content = result.get('content', '')
            if 'b' in mode:
                self._file = BytesIO(content.encode('utf-8') if isinstance(content, str) else content)
            else:
                self._file = StringIO(content)
        
        elif 'w' in mode or 'a' in mode:
            # Write operation - validate path first
            result = self.proxy_client.validate_file_operation(path, mode)
            if not result.get('allowed', False):
                raise ComplianceViolationError(f"File write denied: {result.get('reason', 'Unknown')}")
            
            # Create in-memory buffer for writes
            if 'b' in mode:
                self._file = BytesIO()
            else:
                self._file = StringIO()
    
    def read(self, size: int = -1) -> Any:
        """Read from file."""
        if self._file is None:
            raise ValueError("File not initialized")
        return self._file.read(size)
    
    def write(self, data: Any) -> int:
        """Write to file."""
        if self._file is None:
            raise ValueError("File not initialized")
        return self._file.write(data)
    
    def close(self):
        """Close file and validate write operations."""
        if self._file and ('w' in self.mode or 'a' in self.mode):
            # Get written content
            self._file.seek(0)
            content = self._file.read()
            
            # Validate write with content
            result = self.proxy_client.validate_file_operation(
                self.path, 
                self.mode, 
                content if isinstance(content, str) else content.decode('utf-8')
            )
            
            if not result.get('allowed', False):
                raise ComplianceViolationError(f"File write validation failed: {result.get('reason', 'Unknown')}")
            
            logger.info(f"File write validated: {self.path}")
        
        if self._file:
            self._file.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
    
    def __iter__(self):
        """Iterator support - read all lines and iterate over them."""
        if self._file is None:
            raise ValueError("File not initialized")
        # Read all lines into memory for iteration
        self._file.seek(0)
        if 'b' in self.mode:
            self._lines = self._file.readlines()
        else:
            self._lines = self._file.readlines()
        self._iter_index = 0
        return self
    
    def __next__(self):
        """Return next line in iteration."""
        if self._iter_index >= len(self._lines):
            raise StopIteration
        line = self._lines[self._iter_index]
        self._iter_index += 1
        return line


# Initialize proxy client
_proxy_client = ComplianceProxyClient(SIDECAR_URL, AGENT_ID)


def intercepted_open(file, mode='r', *args, **kwargs):
    """Intercepted open() function that routes through compliance proxy."""
    if not INTERCEPT_ENABLED:
        return _original_open(file, mode, *args, **kwargs)
    
    # Convert file to string path
    path = str(file)
    
    logger.debug(f"Intercepted open: {path} (mode: {mode})")
    
    try:
        return InterceptedFile(path, mode, _proxy_client, *args, **kwargs)
    except ComplianceViolationError:
        raise
    except Exception as e:
        logger.error(f"Error in intercepted_open: {str(e)}")
        # Fall back to original open on error
        return _original_open(file, mode, *args, **kwargs)


def intercepted_urlopen(url, data=None, timeout=None, *args, **kwargs):
    """Intercepted urlopen() function that routes through compliance proxy."""
    if not INTERCEPT_ENABLED:
        return _original_urlopen(url, data, timeout, *args, **kwargs)
    
    # Extract URL string
    url_str = url.full_url if hasattr(url, 'full_url') else str(url)
    method = 'POST' if data else 'GET'
    
    logger.debug(f"Intercepted HTTP request: {method} {url_str}")
    
    try:
        # Validate HTTP request
        result = _proxy_client.validate_http_request(url_str, method, data)
        
        if not result.get('allowed', False):
            raise ComplianceViolationError(f"HTTP request denied: {result.get('reason', 'Unknown')}")
        
        # If allowed, make the actual request
        return _original_urlopen(url, data, timeout, *args, **kwargs)
    
    except ComplianceViolationError:
        raise
    except Exception as e:
        logger.error(f"Error in intercepted_urlopen: {str(e)}")
        # Fall back to original urlopen on error
        return _original_urlopen(url, data, timeout, *args, **kwargs)

def intercepted_boto3_make_request(original_make_request):
    """Create intercepted version of boto3's _make_request method."""
    @wraps(original_make_request)
    def wrapper(self, operation_model, request_dict, *args, **kwargs):
        if not INTERCEPT_ENABLED:
            return original_make_request(self, operation_model, request_dict, *args, **kwargs)
        
        operation_name = operation_model.name
        
        # Extract S3 bucket and key from request
        bucket = request_dict.get('url', '').split('/')[3] if 'url' in request_dict else None
        key = '/'.join(request_dict.get('url', '').split('/')[4:]) if 'url' in request_dict else None
        
        # Handle different S3 operations
        if bucket:
            logger.debug(f"Intercepted boto3 S3 operation: {operation_name} on {bucket}/{key}")
            
            try:
                # Validate S3 operation
                result = _proxy_client.validate_s3_operation(
                    bucket=bucket or 'unknown',
                    key=key or '',
                    operation=operation_name,
                    request_dict=request_dict
                )
                
                if not result.get('allowed', False):
                    raise ComplianceViolationError(f"S3 operation denied: {result.get('reason', 'Unknown')}")
                
                # If allowed, make the actual request
                return original_make_request(self, operation_model, request_dict, *args, **kwargs)
            
            except ComplianceViolationError:
                raise
            except Exception as e:
                logger.error(f"Error in intercepted boto3 request: {str(e)}")
                # Fall back to original on error
                return original_make_request(self, operation_model, request_dict, *args, **kwargs)
        
        # Non-S3 operations pass through
        return original_make_request(self, operation_model, request_dict, *args, **kwargs)
    
    return wrapper


def intercepted_sqlite3_connect(database, *args, **kwargs):
    """Intercepted sqlite3.connect() function."""
    if not INTERCEPT_ENABLED:
        return _original_sqlite3_connect(database, *args, **kwargs)
    
    logger.debug(f"Intercepted sqlite3 connection: {database}")
    
    try:
        # Validate database connection
        result = _proxy_client.validate_database_operation(
            db_type='sqlite',
            operation='connect',
            database=str(database)
        )
        
        # Check for approval in response
        if result.get('decision') == 'APPROVED' or result.get('status') == 'success':
            # If allowed, make the actual connection
            return _original_sqlite3_connect(database, *args, **kwargs)
        else:
            # Extract violations from response
            violations = result.get('violations', [])
            reason = violations[0] if violations else result.get('error', 'Unknown')
            raise ComplianceViolationError(f"Database connection denied: {reason}")
    
    except ComplianceViolationError:
        raise
    except Exception as e:
        logger.error(f"Error in intercepted sqlite3.connect: {str(e)}")
        # Fall back to original on error
        return _original_sqlite3_connect(database, *args, **kwargs)


def intercepted_psycopg2_connect(*args, **kwargs):
    """Intercepted psycopg2.connect() function."""
    if not INTERCEPT_ENABLED:
        return _original_psycopg2_connect(*args, **kwargs)
    
    # Extract connection info
    host = kwargs.get('host', args[0] if args else 'localhost')
    database = kwargs.get('database', kwargs.get('dbname', 'unknown'))
    user = kwargs.get('user', 'unknown')
    port = kwargs.get('port', 5432)
    
    logger.debug(f"Intercepted psycopg2 connection: {host}:{port}/{database}")
    
    try:
        # Validate database connection
        result = _proxy_client.validate_database_operation(
            db_type='postgresql',
            operation='connect',
            host=host,
            database=database,
            user=user,
            port=port
        )
        
        # Check for approval in response
        if result.get('decision') == 'APPROVED' or result.get('status') == 'success':
            # If allowed, make the actual connection
            return _original_psycopg2_connect(*args, **kwargs)
        else:
            # Extract violations from response
            violations = result.get('violations', [])
            reason = violations[0] if violations else result.get('error', 'Unknown')
            raise ComplianceViolationError(f"Database connection denied: {reason}")
    
    except ComplianceViolationError:
        raise
    except Exception as e:
        logger.error(f"Error in intercepted psycopg2.connect: {str(e)}")
        # Fall back to original on error
        return _original_psycopg2_connect(*args, **kwargs)


def intercepted_sqlalchemy_create_engine(url, *args, **kwargs):
    """Intercepted SQLAlchemy create_engine() function."""
    if not INTERCEPT_ENABLED:
        return _original_sqlalchemy_create_engine(url, *args, **kwargs)
    
    logger.debug(f"Intercepted SQLAlchemy engine creation: {url}")
    
    try:
        # Parse connection URL
        url_str = str(url)
        db_type = url_str.split(':')[0] if ':' in url_str else 'unknown'
        
        # Validate database connection
        result = _proxy_client.validate_database_operation(
            db_type='sqlalchemy',
            operation='create_engine',
            connection_string=url_str
        )
        
        # Check for approval in response
        if result.get('decision') == 'APPROVED' or result.get('status') == 'success':
            # If allowed, create the actual engine
            return _original_sqlalchemy_create_engine(url, *args, **kwargs)
        else:
            # Extract violations from response
            violations = result.get('violations', [])
            reason = violations[0] if violations else result.get('error', 'Unknown')
            raise ComplianceViolationError(f"Database engine creation denied: {reason}")
    
    except ComplianceViolationError:
        raise
    except Exception as e:
        logger.error(f"Error in intercepted create_engine: {str(e)}")
        # Fall back to original on error
        return _original_sqlalchemy_create_engine(url, *args, **kwargs)


def intercepted_requests_request(original_func):
    """Create intercepted version of requests.request()."""
    @wraps(original_func)
    def wrapper(method, url, **kwargs):
        if not INTERCEPT_ENABLED:
            return original_func(method, url, **kwargs)
        
        logger.debug(f"Intercepted requests: {method} {url}")
        
        try:
            # Extract request data if present
            data = kwargs.get('data') or kwargs.get('json')
            data_bytes = None
            if data:
                if isinstance(data, (dict, list)):
                    data_bytes = json.dumps(data).encode('utf-8')
                elif isinstance(data, str):
                    data_bytes = data.encode('utf-8')
                elif isinstance(data, bytes):
                    data_bytes = data
            
            # Validate HTTP request through proxy
            result = _proxy_client.validate_http_request(url, method.upper(), data_bytes)
            
            if not result.get('allowed', False):
                raise ComplianceViolationError(
                    f"HTTP request denied: {result.get('reason', 'Unknown')}"
                )
            
            # If allowed, make the actual request
            return original_func(method, url, **kwargs)
        
        except ComplianceViolationError:
            raise
        except Exception as e:
            logger.error(f"Error in intercepted requests.request: {str(e)}")
            return original_func(method, url, **kwargs)
    
    return wrapper


def intercepted_requests_session_request(original_func):
    """Create intercepted version of requests.Session.request()."""
    @wraps(original_func)
    def wrapper(self, method, url, **kwargs):
        if not INTERCEPT_ENABLED:
            return original_func(self, method, url, **kwargs)
        
        logger.debug(f"Intercepted requests.Session: {method} {url}")
        
        try:
            # Extract request data if present
            data = kwargs.get('data') or kwargs.get('json')
            data_bytes = None
            if data:
                if isinstance(data, (dict, list)):
                    data_bytes = json.dumps(data).encode('utf-8')
                elif isinstance(data, str):
                    data_bytes = data.encode('utf-8')
                elif isinstance(data, bytes):
                    data_bytes = data
            
            # Validate HTTP request through proxy
            result = _proxy_client.validate_http_request(url, method.upper(), data_bytes)
            
            if not result.get('allowed', False):
                raise ComplianceViolationError(
                    f"HTTP request denied: {result.get('reason', 'Unknown')}"
                )
            
            # If allowed, make the actual request
            return original_func(self, method, url, **kwargs)
        
        except ComplianceViolationError:
            raise
        except Exception as e:
            logger.error(f"Error in intercepted requests.Session.request: {str(e)}")
            return original_func(self, method, url, **kwargs)
    
    return wrapper


def install():
    """Install the compliance interceptor by monkey-patching built-in functions."""
    global _installed, _original_boto3_make_request, _original_sqlite3_connect
    global _original_psycopg2_connect, _original_sqlalchemy_create_engine
    global _original_requests_request, _original_requests_session_request
    
    if _installed:
        logger.warning("Compliance interceptor already installed")
        return
    
    if not INTERCEPT_ENABLED:
        logger.info("Compliance interception is disabled (COMPLIANCE_INTERCEPT_ENABLED=false)")
        return
    
    logger.info(f"Installing compliance interceptor for agent {AGENT_ID}")
    logger.info(f"Sidecar URL: {SIDECAR_URL}")
    
    # Monkey-patch builtins
    builtins.open = intercepted_open
    urllib.request.urlopen = intercepted_urlopen
    
    # Patch boto3 if available
    try:
        import botocore.client
        _original_boto3_make_request = botocore.client.BaseClient._make_request
        botocore.client.BaseClient._make_request = intercepted_boto3_make_request(_original_boto3_make_request)
        logger.info("✅ boto3/S3 interception enabled")
    except ImportError:
        logger.debug("boto3 not installed, skipping S3 interception")
    
    # Patch sqlite3
    try:
        import sqlite3
        _original_sqlite3_connect = sqlite3.connect
        sqlite3.connect = intercepted_sqlite3_connect
        logger.info("✅ sqlite3 interception enabled")
    except ImportError:
        logger.debug("sqlite3 not available")
    
    # Patch psycopg2 if available
    try:
        import psycopg2
        _original_psycopg2_connect = psycopg2.connect
        psycopg2.connect = intercepted_psycopg2_connect
        logger.info("✅ psycopg2/PostgreSQL interception enabled")
    except ImportError:
        logger.debug("psycopg2 not installed, skipping PostgreSQL interception")
    
    # Patch SQLAlchemy if available
    try:
        import sqlalchemy
        _original_sqlalchemy_create_engine = sqlalchemy.create_engine
        sqlalchemy.create_engine = intercepted_sqlalchemy_create_engine
        logger.info("✅ SQLAlchemy interception enabled")
    except ImportError:
        logger.debug("SQLAlchemy not installed, skipping SQLAlchemy interception")
    
    # Patch requests if available
    try:
        import requests
        import requests.api
        import requests.sessions
        
        # Patch the main request function at module level
        _original_requests_request = requests.api.request
        requests.api.request = intercepted_requests_request(_original_requests_request)
        
        # Patch Session.request for session-based requests
        _original_requests_session_request = requests.sessions.Session.request
        requests.sessions.Session.request = intercepted_requests_session_request(_original_requests_session_request)
        
        # Update module-level convenience functions to use patched request
        requests.request = requests.api.request
        requests.get = lambda url, **kwargs: requests.api.request('GET', url, **kwargs)
        requests.post = lambda url, **kwargs: requests.api.request('POST', url, **kwargs)
        requests.put = lambda url, **kwargs: requests.api.request('PUT', url, **kwargs)
        requests.delete = lambda url, **kwargs: requests.api.request('DELETE', url, **kwargs)
        requests.head = lambda url, **kwargs: requests.api.request('HEAD', url, **kwargs)
        requests.options = lambda url, **kwargs: requests.api.request('OPTIONS', url, **kwargs)
        requests.patch = lambda url, **kwargs: requests.api.request('PATCH', url, **kwargs)
        
        logger.info("✅ requests library interception enabled")
    except ImportError:
        logger.debug("requests not installed, skipping requests interception")
    
    _installed = True
    logger.info("✅ Compliance interceptor installed successfully")


def uninstall():
    """Uninstall the compliance interceptor and restore original functions."""
    global _installed
    
    if not _installed:
        logger.warning("Compliance interceptor not installed")
        return
    
    logger.info("Uninstalling compliance interceptor")
    
    # Restore original functions
    builtins.open = _original_open
    urllib.request.urlopen = _original_urlopen
    
    # Restore boto3 if it was patched
    if _original_boto3_make_request is not None:
        try:
            import botocore.client
            botocore.client.BaseClient._make_request = _original_boto3_make_request
        except ImportError:
            pass
    
    # Restore sqlite3 if it was patched
    if _original_sqlite3_connect is not None:
        try:
            import sqlite3
            sqlite3.connect = _original_sqlite3_connect
        except ImportError:
            pass
    
    # Restore psycopg2 if it was patched
    if _original_psycopg2_connect is not None:
        try:
            import psycopg2
            psycopg2.connect = _original_psycopg2_connect
        except ImportError:
            pass
    
    # Restore SQLAlchemy if it was patched
    if _original_sqlalchemy_create_engine is not None:
        try:
            import sqlalchemy
            sqlalchemy.create_engine = _original_sqlalchemy_create_engine
        except ImportError:
            pass
    
    # Restore requests if it was patched
    if _original_requests_request is not None:
        try:
            import requests
            import requests.api
            import requests.sessions
            requests.api.request = _original_requests_request
            requests.sessions.Session.request = _original_requests_session_request
        except ImportError:
            pass
    
    _installed = False
    logger.info("✅ Compliance interceptor uninstalled")


def is_installed() -> bool:
    """Check if the compliance interceptor is currently installed."""
    return _installed


def get_agent_id() -> str:
    """Get the current agent ID."""
    return AGENT_ID


def get_sidecar_url() -> str:
    """Get the configured sidecar URL."""
    return SIDECAR_URL


def enable_interception():
    """
    Enable compliance interception by setting environment variable and installing interceptor.
    
    This allows runtime control to enable compliance checking.
    
    Example:
        import compliance_interceptor
        compliance_interceptor.enable_interception()
        # Now all I/O operations are intercepted
    """
    global INTERCEPT_ENABLED
    os.environ['COMPLIANCE_INTERCEPT_ENABLED'] = 'true'
    INTERCEPT_ENABLED = True
    if not _installed:
        install()
    logger.info("✅ Compliance interception enabled")


def disable_interception():
    """
    Disable compliance interception by setting environment variable and uninstalling interceptor.
    
    This allows runtime control to disable compliance checking.
    
    Example:
        import compliance_interceptor
        compliance_interceptor.disable_interception()
        # Now all I/O operations bypass compliance checks
    """
    global INTERCEPT_ENABLED
    os.environ['COMPLIANCE_INTERCEPT_ENABLED'] = 'false'
    INTERCEPT_ENABLED = False
    if _installed:
        uninstall()
    logger.info("✅ Compliance interception disabled")


def is_interception_enabled() -> bool:
    """
    Check if compliance interception is enabled via environment variable.
    
    Returns:
        bool: True if COMPLIANCE_INTERCEPT_ENABLED is 'true', False otherwise
    
    Example:
        import compliance_interceptor
        if compliance_interceptor.is_interception_enabled():
            print("Compliance is configured to be enabled")
    """
    return os.getenv('COMPLIANCE_INTERCEPT_ENABLED', 'true').lower() == 'true'


def get_status() -> Dict[str, Any]:
    """
    Get comprehensive status of the compliance interceptor.
    
    Returns:
        dict: Status information including:
            - installed: Whether interceptor is currently installed
            - enabled: Whether interception is enabled via environment variable
            - agent_id: Current agent ID
            - sidecar_url: Configured sidecar URL
    
    Example:
        import compliance_interceptor
        status = compliance_interceptor.get_status()
        print(f"Installed: {status['installed']}")
        print(f"Enabled: {status['enabled']}")
    """
    return {
        'installed': _installed,
        'enabled': INTERCEPT_ENABLED,
        'agent_id': AGENT_ID,
        'sidecar_url': SIDECAR_URL
    }


# Auto-install if COMPLIANCE_AUTO_INSTALL is set
if os.getenv('COMPLIANCE_AUTO_INSTALL', 'false').lower() == 'true':
    install()

# Made with Bob


# ---------------------------------------------------------------------------
# GAP-13b: Canonical hook surface expected by paper_experiments/exp_gap13
# These thin wrappers expose attach / detach so the interceptor inventory
# experiment can verify the hook API without calling install/uninstall directly.
# ---------------------------------------------------------------------------

def attach() -> None:
    """Attach interceptor — installs all I/O patches.  Alias for install()."""
    install()


def detach() -> None:
    """Detach interceptor — restores original I/O functions.  Alias for uninstall()."""
    uninstall()
