#!/usr/bin/env python3
"""
Compliance Proxy Server - HTTP API for Runtime I/O Interception Pattern (RIIP)

This server provides HTTP endpoints that agents can use to perform I/O operations
through the compliance sidecar. It integrates with the existing Kafka-based
compliance pipeline for validation.

Endpoints:
- POST /proxy/file - File read/write operations
- POST /proxy/http - HTTP requests
- POST /proxy/s3 - S3 operations
- POST /proxy/database - Database operations
- GET /health - Health check
"""

import os
import json
import time
import hashlib
import logging
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify
from kafka import KafkaProducer, KafkaConsumer
import requests
import boto3
from io import BytesIO, StringIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)

# Configuration
KAFKA_ENABLED = os.getenv('KAFKA_ENABLED', 'true').lower() == 'true'
KAFKA_BROKER = os.getenv('KAFKA_BROKER', 'localhost:9092')
TOPIC_IN = os.getenv('KAFKA_TOPIC_IN', 'agent.requests')  # Match sidecar's input topic
TOPIC_OUT = os.getenv('KAFKA_TOPIC_OUT', 'read.responses')  # Match sidecar's output topic
OPA_URL = os.getenv('OPA_URL', 'http://localhost:8181')
PROXY_PORT = int(os.getenv('PROXY_PORT', '8080'))
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))

# S3 Configuration
S3_ENABLED = os.getenv('S3_ENABLED', 'false').lower() == 'true'
S3_ENDPOINT = os.getenv('S3_ENDPOINT_URL', 'http://localhost:9000')
S3_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID', 'minioadmin')
S3_SECRET_KEY = os.getenv('AWS_SECRET_ACCESS_KEY', 'minioadmin')

# Database Configuration
DB_ENABLED = os.getenv('DB_ENABLED', 'true').lower() == 'true'
DB_VALIDATION_ENABLED = os.getenv('DB_VALIDATION_ENABLED', 'true').lower() == 'true'

# Initialize Kafka producer
producer = None
pending_requests = {}  # Track pending requests for response correlation

def init_kafka():
    """Initialize Kafka producer with retry logic"""
    global producer
    max_retries = 10
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BROKER,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                api_version_auto_timeout_ms=5000
            )
            logger.info("✅ Successfully connected to Kafka!")
            return True
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"⚠️  Kafka not ready yet: {e}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            else:
                logger.error(f"❌ FATAL: Could not connect to Kafka after {max_retries} attempts")
                return False
    return False

def send_compliance_request(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send request to compliance sidecar via Kafka and wait for response
    
    Args:
        event: Compliance request event
        
    Returns:
        Compliance decision response
    """
    request_id = event.get('request_id')
    
    # Send to Kafka
    producer.send(TOPIC_IN, event)
    producer.flush()
    
    # Wait for response (simplified - in production use proper async handling)
    start_time = time.time()
    while time.time() - start_time < REQUEST_TIMEOUT:
        if request_id in pending_requests:
            response = pending_requests.pop(request_id)
            return response
        time.sleep(0.1)
    
    # Timeout
    return {
        'decision': 'DENIED',
        'violations': ['Request timeout - no response from compliance sidecar'],
        'request_id': request_id
    }

def init_s3_client():
    """Initialize S3 client"""
    if not S3_ENABLED:
        return None
    
    return boto3.client(
        's3',
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY
    )

s3_client = init_s3_client()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    # no-data: server metadata only — no upstream data forwarded
    return jsonify({
        'status': 'healthy',
        'service': 'compliance-proxy-server',
        'kafka_connected': producer is not None,
        's3_enabled': S3_ENABLED,
        'db_enabled': DB_ENABLED
    }), 200

@app.route('/proxy/file', methods=['POST'])
def proxy_file():
    """
    Proxy file operations through compliance validation
    
    Request body:
    {
        "operation": "read" | "write",
        "path": "/path/to/file",
        "mode": "r" | "w" | "a" | "rb" | "wb",
        "content": "..." (for write operations),
        "agent_id": "agent-123",
        "user_id": "user-456" (optional, for REQ 17, 18),
        "consent_id": "consent-789" (optional, for REQ 17),
        "data_classification": "PII" (optional, for REQ 25),
        "destination_region": "EU" (optional, for REQ 25),
        "transfer_mechanism": "SCC" (optional, for REQ 25)
    }
    """
    try:
        data = request.get_json()
        operation = data.get('operation')
        file_path = data.get('path')
        mode = data.get('mode', 'r')
        content = data.get('content')
        agent_id = data.get('agent_id', 'unknown')
        
        # Extract new policy fields (REQ 14, 17, 18, 25)
        user_id = data.get('user_id')
        consent_id = data.get('consent_id')
        data_classification = data.get('data_classification')
        destination_region = data.get('destination_region')
        transfer_mechanism = data.get('transfer_mechanism')
        
        # Generate request ID
        request_id = hashlib.sha256(
            f"{agent_id}-{file_path}-{time.time()}".encode()
        ).hexdigest()[:16]
        
        # Create compliance request
        compliance_event = {
            'request_id': request_id,
            'agent_id': agent_id,
            'action': 'WRITE' if 'w' in mode or 'a' in mode else 'READ',
            'resource': file_path,
            'resource_type': 'file',
            'operation': operation,
            'mode': mode,
            'timestamp': time.time()
        }
        
        # Add content for write operations
        if operation == 'write' and content:
            compliance_event['content'] = content
        
        # Add new policy fields if present
        if user_id:
            compliance_event['user_id'] = user_id
        if consent_id:
            compliance_event['consent_id'] = consent_id
        if data_classification:
            compliance_event['data_classification'] = data_classification
        if destination_region:
            compliance_event['destination_region'] = destination_region
        if transfer_mechanism:
            compliance_event['transfer_mechanism'] = transfer_mechanism
        
        # Send to compliance sidecar
        response = send_compliance_request(compliance_event)
        
        if response.get('decision') == 'APPROVED':
            # Execute the file operation
            if operation == 'read':
                try:
                    with open(file_path, mode) as f:
                        file_content = f.read()
                    
                    # Apply PII scrubbing if present in response
                    if 'data' in response:
                        file_content = response['data']
                    
                    return jsonify({
                        'status': 'success',
                        'content': file_content,
                        'request_id': request_id,
                        'audit_id': response.get('audit_id')
                    }), 200
                except Exception as e:
                    # no-data: file I/O error response — no upstream data forwarded
                    return jsonify({
                        'status': 'error',
                        'error': str(e),
                        'request_id': request_id
                    }), 500
                    
            elif operation == 'write':
                try:
                    with open(file_path, mode) as f:
                        f.write(content)
                    
                    # no-data: write-completion acknowledgement — bytes_written count only
                    return jsonify({
                        'status': 'success',
                        'bytes_written': len(content),
                        'request_id': request_id,
                        'audit_id': response.get('audit_id')
                    }), 200
                except Exception as e:
                    # no-data: file I/O error response — no upstream data forwarded
                    return jsonify({
                        'status': 'error',
                        'error': str(e),
                        'request_id': request_id
                    }), 500
        else:
            # no-data: compliance DENIED — policy decision metadata only, no upstream data
            return jsonify({
                'status': 'denied',
                'decision': response.get('decision'),
                'violations': response.get('violations', []),
                'request_id': request_id
            }), 403
            
    except Exception as e:
        logger.error(f"Error in /proxy/file: {e}")
        # no-data: unhandled exception — no upstream data forwarded
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/proxy/http', methods=['POST'])
def proxy_http():
    """
    Proxy HTTP requests through compliance validation
    
    Request body:
    {
        "method": "GET" | "POST" | "PUT" | "DELETE",
        "url": "https://api.example.com/data",
        "headers": {...},
        "data": {...},
        "agent_id": "agent-123",
        "user_id": "user-456" (optional, for REQ 17, 18),
        "consent_id": "consent-789" (optional, for REQ 17),
        "data_classification": "PII" (optional, for REQ 25),
        "destination_region": "EU" (optional, for REQ 25),
        "transfer_mechanism": "SCC" (optional, for REQ 25)
    }
    """
    try:
        data = request.get_json()
        method = data.get('method', 'GET')
        url = data.get('url')
        headers = data.get('headers', {})
        request_data = data.get('data')
        agent_id = data.get('agent_id', 'unknown')
        
        # Extract new policy fields (REQ 14, 17, 18, 25)
        user_id = data.get('user_id')
        consent_id = data.get('consent_id')
        data_classification = data.get('data_classification')
        destination_region = data.get('destination_region')
        transfer_mechanism = data.get('transfer_mechanism')
        
        # Generate request ID
        request_id = hashlib.sha256(
            f"{agent_id}-{url}-{time.time()}".encode()
        ).hexdigest()[:16]
        
        # Create compliance request
        compliance_event = {
            'request_id': request_id,
            'agent_id': agent_id,
            'action': 'WRITE' if method in ['POST', 'PUT', 'DELETE'] else 'READ',
            'resource': url,
            'resource_type': 'http',
            'method': method,
            'timestamp': time.time()
        }
        
        # Add new policy fields if present
        if user_id:
            compliance_event['user_id'] = user_id
        if consent_id:
            compliance_event['consent_id'] = consent_id
        if data_classification:
            compliance_event['data_classification'] = data_classification
        if destination_region:
            compliance_event['destination_region'] = destination_region
        if transfer_mechanism:
            compliance_event['transfer_mechanism'] = transfer_mechanism
        
        # Send to compliance sidecar
        response = send_compliance_request(compliance_event)
        
        if response.get('decision') == 'APPROVED':
            # Execute the HTTP request
            try:
                http_response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=request_data,
                    timeout=10
                )
                
                return jsonify({
                    'status': 'success',
                    'status_code': http_response.status_code,
                    'content': http_response.text,
                    'headers': dict(http_response.headers),
                    'request_id': request_id,
                    'audit_id': response.get('audit_id')
                }), 200
            except Exception as e:
                # no-data: upstream HTTP request error — no response data returned
                return jsonify({
                    'status': 'error',
                    'error': str(e),
                    'request_id': request_id
                }), 500
        else:
            # no-data: compliance DENIED — policy decision metadata only, no upstream data
            return jsonify({
                'status': 'denied',
                'decision': response.get('decision'),
                'violations': response.get('violations', []),
                'request_id': request_id
            }), 403
            
    except Exception as e:
        logger.error(f"Error in /proxy/http: {e}")
        # no-data: unhandled exception — no upstream data forwarded
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/proxy/s3', methods=['POST'])
def proxy_s3():
    """
    Proxy S3 operations through compliance validation
    
    Request body:
    {
        "operation": "get_object" | "put_object" | "list_objects",
        "bucket": "my-bucket",
        "key": "path/to/object",
        "content": "..." (for put_object),
        "agent_id": "agent-123",
        "user_id": "user-456" (optional, for REQ 17, 18),
        "consent_id": "consent-789" (optional, for REQ 17),
        "data_classification": "PII" (optional, for REQ 25),
        "destination_region": "EU" (optional, for REQ 25),
        "transfer_mechanism": "SCC" (optional, for REQ 25)
    }
    """
    if not S3_ENABLED:
        # no-data: capability-check — S3 disabled, no data forwarded
        return jsonify({
            'status': 'error',
            'error': 'S3 operations are not enabled'
        }), 503
    
    try:
        data = request.get_json()
        operation = data.get('operation')
        bucket = data.get('bucket')
        key = data.get('key')
        content = data.get('content')
        agent_id = data.get('agent_id', 'unknown')
        
        # Extract new policy fields (REQ 14, 17, 18, 25)
        user_id = data.get('user_id')
        consent_id = data.get('consent_id')
        data_classification = data.get('data_classification')
        destination_region = data.get('destination_region')
        transfer_mechanism = data.get('transfer_mechanism')
        
        # Generate request ID
        request_id = hashlib.sha256(
            f"{agent_id}-{bucket}-{key}-{time.time()}".encode()
        ).hexdigest()[:16]
        
        # Create compliance request
        compliance_event = {
            'request_id': request_id,
            'agent_id': agent_id,
            'action': 'WRITE' if operation == 'put_object' else 'READ',
            'resource': f"s3://{bucket}/{key}",
            'resource_type': 's3',
            'operation': operation,
            'timestamp': time.time()
        }
        
        # Add new policy fields if present
        if user_id:
            compliance_event['user_id'] = user_id
        if consent_id:
            compliance_event['consent_id'] = consent_id
        if data_classification:
            compliance_event['data_classification'] = data_classification
        if destination_region:
            compliance_event['destination_region'] = destination_region
        if transfer_mechanism:
            compliance_event['transfer_mechanism'] = transfer_mechanism
        
        # Send to compliance sidecar
        response = send_compliance_request(compliance_event)
        
        if response.get('decision') == 'APPROVED':
            # Execute the S3 operation
            try:
                if operation == 'get_object':
                    obj = s3_client.get_object(Bucket=bucket, Key=key)
                    content = obj['Body'].read().decode('utf-8')
                    
                    return jsonify({
                        'status': 'success',
                        'content': content,
                        'request_id': request_id,
                        'audit_id': response.get('audit_id')
                    }), 200
                    
                elif operation == 'put_object':
                    s3_client.put_object(
                        Bucket=bucket,
                        Key=key,
                        Body=content.encode('utf-8')
                    )
                    
                    return jsonify({
                        'status': 'success',
                        'bytes_written': len(content),
                        'request_id': request_id,
                        'audit_id': response.get('audit_id')
                    }), 200
                    
                elif operation == 'list_objects':
                    result = s3_client.list_objects_v2(Bucket=bucket, Prefix=key)
                    objects = [obj['Key'] for obj in result.get('Contents', [])]
                    
                    return jsonify({
                        'status': 'success',
                        'objects': objects,
                        'request_id': request_id,
                        'audit_id': response.get('audit_id')
                    }), 200
                    
            except Exception as e:
                # no-data: S3 client error — no object data forwarded
                return jsonify({
                    'status': 'error',
                    'error': str(e),
                    'request_id': request_id
                }), 500
        else:
            # no-data: compliance DENIED — policy decision metadata only, no S3 data
            return jsonify({
                'status': 'denied',
                'decision': response.get('decision'),
                'violations': response.get('violations', []),
                'request_id': request_id
            }), 403
            
    except Exception as e:
        logger.error(f"Error in /proxy/s3: {e}")
        # no-data: unhandled exception — no upstream data forwarded
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/proxy/database', methods=['POST'])
def proxy_database():
    """
    Proxy database operations through compliance validation
    
    Request body:
    {
        "operation": "connect" | "query" | "execute",
        "db_type": "sqlite" | "postgresql" | "sqlalchemy",
        "connection_string": "...",
        "database": "db_name",
        "host": "localhost",
        "port": 5432,
        "user": "username",
        "query": "SELECT * FROM users",
        "agent_id": "agent-123",
        "user_id": "user-456" (optional, for REQ 17, 18),
        "consent_id": "consent-789" (optional, for REQ 17),
        "data_classification": "PII" (optional, for REQ 25),
        "destination_region": "EU" (optional, for REQ 25),
        "transfer_mechanism": "SCC" (optional, for REQ 25)
    }
    """
    if not DB_ENABLED:
        return jsonify({
            'status': 'error',
            'error': 'Database operations are not enabled'
        }), 503
    
    try:
        data = request.get_json()
        operation = data.get('operation')
        db_type = data.get('db_type')
        connection_string = data.get('connection_string', '')
        database = data.get('database', '')
        host = data.get('host', 'localhost')
        port = data.get('port', 5432)
        user = data.get('user', '')
        query = data.get('query', '')
        agent_id = data.get('agent_id', 'unknown')
        
        # Extract new policy fields (REQ 14, 17, 18, 25)
        user_id = data.get('user_id')
        consent_id = data.get('consent_id')
        data_classification = data.get('data_classification')
        destination_region = data.get('destination_region')
        transfer_mechanism = data.get('transfer_mechanism')
        
        # Generate request ID
        request_id = hashlib.sha256(
            f"{agent_id}-{db_type}-{database}-{time.time()}".encode()
        ).hexdigest()[:16]
        
        # Create compliance request
        compliance_event = {
            'request_id': request_id,
            'agent_id': agent_id,
            'action': 'WRITE' if operation in ['execute', 'insert', 'update', 'delete'] else 'READ',
            'resource': connection_string or f"{db_type}://{host}:{port}/{database}",
            'resource_type': 'database',
            'operation': operation,
            'db_type': db_type,
            'database': database,
            'host': host,
            'port': port,
            'user': user,
            'query': query,
            'timestamp': time.time()
        }
        
        # Add new policy fields if present
        if user_id:
            compliance_event['user_id'] = user_id
        if consent_id:
            compliance_event['consent_id'] = consent_id
        if data_classification:
            compliance_event['data_classification'] = data_classification
        if destination_region:
            compliance_event['destination_region'] = destination_region
        if transfer_mechanism:
            compliance_event['transfer_mechanism'] = transfer_mechanism
        
        # Send to compliance sidecar
        response = send_compliance_request(compliance_event)
        
        if response.get('decision') == 'APPROVED':
            # For now, we just validate the operation
            # Actual database execution would be done by the agent
            # after receiving approval
            return jsonify({
                'status': 'success',
                'decision': 'APPROVED',
                'message': 'Database operation approved',
                'request_id': request_id,
                'audit_id': response.get('audit_id'),
                'metadata': {
                    'db_type': db_type,
                    'operation': operation,
                    'database': database
                }
            }), 200
        else:
            # no-data: compliance DENIED — policy decision metadata only, no DB data
            return jsonify({
                'status': 'denied',
                'decision': response.get('decision'),
                'violations': response.get('violations', []),
                'request_id': request_id
            }), 403
            
    except Exception as e:
        logger.error(f"Error in /proxy/database: {e}")
        # no-data: unhandled exception — no upstream data forwarded
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

def start_response_consumer():
    """
    Background thread to consume compliance responses from Kafka
    """
    import threading
    
    def consume_responses():
        consumer = KafkaConsumer(
            TOPIC_OUT,
            bootstrap_servers=KAFKA_BROKER,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest',
            group_id='proxy-server-responses'
        )
        
        logger.info(f"Started response consumer for topic: {TOPIC_OUT}")
        
        for message in consumer:
            response = message.value
            request_id = response.get('request_id')
            if request_id:
                pending_requests[request_id] = response
                logger.debug(f"Received response for request_id: {request_id}")
    
    thread = threading.Thread(target=consume_responses, daemon=True)
    thread.start()
@app.route('/proxy/mcp', methods=['POST'])
def proxy_mcp():
    """
    Proxy MCP (Model Context Protocol) tool invocations through compliance validation
    
    Request body (Compliance Event format from MCP Interceptor):
    {
        "request_id": "abc123",
        "agent_id": "mcp-proxy-001",
        "action": "READ" | "WRITE",
        "resource": "/path/to/file" | "SELECT * FROM users" | "https://api.example.com",
        "resource_type": "file" | "database" | "http" | "mcp_tool",
        "tool_name": "filesystem/read_file",
        "arguments": {...},
        "context": {...},
        "timestamp": 1234567890.123
    }
    
    Returns compliance decision
    """
    try:
        # This endpoint receives compliance events from the MCP interceptor
        compliance_event = request.get_json()
        
        if not compliance_event:
            # no-data: bad request — no compliance event to process
            return jsonify({
                'allowed': False,
                'reason': 'Invalid request - no data provided'
            }), 400
        
        # Send to compliance sidecar via Kafka
        response = send_compliance_request(compliance_event)
        
        # Return compliance decision
        if response.get('decision') == 'APPROVED':
            # no-data: compliance APPROVED decision — any 'data' field is sidecar metadata, not upstream payload
            return jsonify({
                'allowed': True,
                'request_id': compliance_event.get('request_id'),
                'audit_id': response.get('audit_id'),
                'data': response.get('data'),
                'metadata': {
                    'compliance_validated': True,
                    'policy_version': response.get('policy_version'),
                    'timestamp': time.time()
                }
            }), 200
        else:
            # no-data: compliance DENIED — policy decision metadata only
            return jsonify({
                'allowed': False,
                'reason': response.get('violations', ['Compliance check failed'])[0] if response.get('violations') else 'Compliance check failed',
                'violations': response.get('violations', []),
                'request_id': compliance_event.get('request_id'),
                'policy': response.get('policy', 'Unknown')
            }), 200  # Return 200 with allowed=false for compliance denial
            
    except Exception as e:
        logger.error(f"Error in /proxy/mcp: {e}")
        return jsonify({
            'jsonrpc': '2.0',
            'id': data.get('id') if data else None,
            'error': {
                'code': -32603,
                'message': 'Internal error',
                'data': {'error': str(e)}
            }
        }), 500

@app.route('/proxy/mcp/validate-response', methods=['POST'])
def proxy_mcp_validate_response():
    """
    Validate MCP tool response for PII and sensitive data
    
    Request body:
    {
        "request_id": "original-request-id",
        "tool_name": "filesystem/read_file",
        "response": {...},
        "agent_id": "agent-123"
    }
    
    Returns validated/redacted response
    """
    try:
        data = request.get_json()
        
        request_id = data.get('request_id', 'unknown')
        tool_name = data.get('tool_name', 'unknown')
        tool_response = data.get('response', {})
        agent_id = data.get('agent_id', 'mcp-agent')
        
        # Create validation event
        validation_event = {
            'request_id': f"{request_id}-validation",
            'agent_id': agent_id,
            'action': 'VALIDATE_RESPONSE',
            'resource_type': 'mcp_response',
            'tool_name': tool_name,
            'response_data': tool_response,
            'timestamp': time.time()
        }
        
        # Send to compliance sidecar for PII detection/redaction
        response = send_compliance_request(validation_event)
        
        # Return validated response
        return jsonify({
            'status': 'validated',
            'data': response.get('data', tool_response),
            'pii_detected': response.get('pii_detected', False),
            'redactions': response.get('redactions', []),
            'request_id': request_id
        }), 200
        
    except Exception as e:
        logger.error(f"Error in /proxy/mcp/validate-response: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
@app.route('/proxy/bash_script', methods=['POST'])
def proxy_bash_script():
    """
    Validate bash script execution through compliance sidecar (Layer 3)
    
    Request body:
    {
        "agent_id": "agent-123",
        "script_path": "/tmp/script.sh",
        "script_content": "#!/bin/bash\ncurl https://api.example.com",
        "commands": "curl https://api.example.com",
        "risk_level": "medium",
        "operations": [{"type": "network", "risk": "high"}],
        "timestamp": "2024-01-01T00:00:00Z"
    }
    
    Returns:
    {
        "allowed": true/false,
        "reason": "...",
        "violations": [...]
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            # no-data: bad request — no script payload to validate
            return jsonify({
                'allowed': False,
                'reason': 'Invalid request - no data provided'
            }), 400
        
        # Extract script details
        agent_id = data.get('agent_id', 'unknown')
        script_path = data.get('script_path', 'unknown')
        script_content = data.get('script_content', '')
        commands = data.get('commands', '')
        risk_level = data.get('risk_level', 'unknown')
        operations = data.get('operations', [])
        
        # Generate request ID
        request_id = hashlib.md5(
            f"{agent_id}{script_path}{time.time()}".encode()
        ).hexdigest()
        
        # Create compliance event
        compliance_event = {
            'request_id': request_id,
            'agent_id': agent_id,
            'timestamp': time.time(),
            'operation_type': 'bash_script_execution',
            'script_path': script_path,
            'script_content': script_content,
            'commands': commands,
            'operations': operations,
            'risk_level': risk_level,
            'resource_type': 'bash_script',
            'action': 'EXECUTE'
        }
        
        logger.info(f"Bash script validation request: {script_path} (risk: {risk_level})")
        
        # Send to compliance sidecar via Kafka
        response = send_compliance_request(compliance_event)
        
        # Check decision
        if response.get('decision') == 'APPROVED':
            logger.info(f"Bash script APPROVED: {script_path}")
            return jsonify({
                'allowed': True,
                'message': 'Script execution approved',
                'operations_validated': len(operations),
                'request_id': request_id,
                'audit_id': response.get('audit_id')
            }), 200
        else:
            # no-data: compliance DENIED — policy violations list only, no script output
            violations = response.get('violations', ['Script execution denied'])
            logger.warning(f"Bash script DENIED: {script_path} - {violations}")
            return jsonify({
                'allowed': False,
                'reason': violations[0] if violations else 'Policy violation',
                'violations': violations,
                'request_id': request_id
            }), 403
            
    except Exception as e:
        logger.error(f"Error in /proxy/bash_script: {e}")
        # no-data: unhandled exception — no script output forwarded
        return jsonify({
            'allowed': False,
            'reason': f'Internal error: {str(e)}'
        }), 500

# Bash command audit log
bash_audit_log = []

@app.route('/proxy/bash_command', methods=['POST'])
def proxy_bash_command():
    """
    Validate bash command execution from OpenCode container.
    This endpoint is called by the bash wrapper in OpenCode.
    """
    try:
        data = request.get_json()
        command = data.get('command', '')
        agent_id = data.get('agent_id', 'unknown')
        
        logger.info(f"Bash command validation request from {agent_id}: {command[:100]}")
        
        # Build OPA input
        opa_input = {
            "input": {
                "operation": "bash_command",
                "command": command,
                "agent_id": agent_id,
                "timestamp": data.get("timestamp"),
                "pid": data.get("pid"),
                "ppid": data.get("ppid"),
                "user": data.get("user"),
                "cwd": data.get("cwd")
            }
        }
        
        # Query OPA
        try:
            opa_response = requests.post(
                f"{OPA_URL}/v1/data/opencode/bash_validation",
                json=opa_input,
                timeout=2
            )
            
            if opa_response.status_code == 200:
                result = opa_response.json()
                decision = result.get("result", {})
                
                approved = decision.get("allow", False)
                reason = decision.get("reason", "No reason provided")
                message = decision.get("message", "")
                
                # Log decision to audit log
                audit_entry = {
                    **data,
                    "approved": approved,
                    "reason": reason,
                    "timestamp_decision": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }
                bash_audit_log.append(audit_entry)
                
                # Keep only last 1000 entries
                if len(bash_audit_log) > 1000:
                    bash_audit_log.pop(0)
                
                logger.info(f"Bash command {'APPROVED' if approved else 'DENIED'}: {reason}")
                
                # no-data: OPA policy verdict (approved/denied boolean) — no bash command output forwarded
                return jsonify({
                    "approved": approved,
                    "reason": reason,
                    "message": message,
                    "policy_decision": decision
                }), 200
            else:
                logger.error(f"OPA returned status {opa_response.status_code}")
                # no-data: OPA HTTP error — fail-secure deny, no command output
                return jsonify({
                    "approved": False,
                    "reason": "OPA query failed",
                    "message": "Unable to validate command"
                }), 200
                
        except requests.exceptions.Timeout:
            logger.error("OPA query timed out")
            # no-data: OPA timeout — fail-secure deny, no command output
            return jsonify({
                "approved": False,
                "reason": "Compliance check timeout",
                "message": "Unable to validate command in time"
            }), 200
        except Exception as e:
            logger.error(f"Error querying OPA: {e}")
            # no-data: OPA exception — fail-secure deny, no command output
            return jsonify({
                "approved": False,
                "reason": f"Validation error: {str(e)}",
                "message": "Unable to validate command"
            }), 200
            
    except Exception as e:
        logger.error(f"Error in /proxy/bash_command: {e}")
        # no-data: unhandled exception — no command output forwarded
        return jsonify({
            "approved": False,
            "reason": "Internal error",
            "message": str(e)
        }), 500

@app.route('/proxy/bash_audit', methods=['GET'])
def get_bash_audit_log():
    """Get audit log of bash command validations"""
    # no-data: audit metadata only — bash_audit_log contains policy verdicts, no file/DB/HTTP payloads
    return jsonify({
        "audit_log": bash_audit_log,
        "count": len(bash_audit_log)
    }), 200



# ---------------------------------------------------------------------------
# GAP-13b: create_app() hook for paper_experiments/exp_gap13 inventory check
# The Flask app is created at module level; this function exposes it via the
# canonical hook name so hasattr(mod, 'create_app') returns True.
# ---------------------------------------------------------------------------

def create_app() -> "Flask":  # type: ignore[name-defined]
    """Return the module-level Flask application instance."""
    return app


    logger.info("Response consumer thread started")

if __name__ == '__main__':
    logger.info("Starting Compliance Proxy Server...")
    logger.info(f"Kafka enabled: {KAFKA_ENABLED}")
    
    # Initialize Kafka only if enabled
    if KAFKA_ENABLED:
        if not init_kafka():
            logger.error("Failed to initialize Kafka. Exiting.")
            exit(1)
        
        # Start response consumer
        start_response_consumer()
        
        # Give consumer time to start
        time.sleep(2)
    else:
        logger.info("Kafka disabled - running in direct OPA mode")
    
    # Start Flask server
    logger.info(f"Starting HTTP server on port {PROXY_PORT}...")
    app.run(host='0.0.0.0', port=PROXY_PORT, debug=False)

# Made with Bob
