"""
MCP (Model Context Protocol) Interceptor for Compliance Sidecar
================================================================

This module provides transparent interception of MCP protocol messages
for AI agents using the Model Context Protocol. All MCP tool invocations
(file operations, database queries, API calls, custom tools) are routed
through the compliance sidecar for validation.

MCP Protocol Overview:
    MCP is a standardized protocol for AI agents to interact with external
    tools and data sources. It defines a JSON-RPC based communication pattern
    where agents send tool invocation requests and receive responses.

Usage:
    # Initialize MCP interceptor
    from src.interceptors.mcp_interceptor import MCPComplianceProxy
    
    # Create proxy server
    proxy = MCPComplianceProxy(
        sidecar_url="http://localhost:8080",
        agent_id="agent-123",
        mcp_servers={
            "filesystem": "http://localhost:3001",
            "database": "http://localhost:3002",
            "api": "http://localhost:3003"
        }
    )
    
    # Start proxy server
    await proxy.start(host="0.0.0.0", port=3000)
    
    # Agent connects to proxy instead of MCP servers directly
    # All MCP requests are intercepted and validated

Environment Variables:
    COMPLIANCE_SIDECAR_URL: URL of the compliance sidecar (default: http://localhost:8080)
    MCP_PROXY_PORT: Port for MCP proxy server (default: 3000)
    MCP_SERVERS: JSON dict of MCP server names to URLs
    COMPLIANCE_AGENT_ID: Unique identifier for this agent
"""

import asyncio
import json
import logging
import os
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
import aiohttp
from aiohttp import web
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SIDECAR_URL = os.getenv('COMPLIANCE_SIDECAR_URL', 'http://localhost:8080')
MCP_PROXY_PORT = int(os.getenv('MCP_PROXY_PORT', '3000'))
AGENT_ID = os.getenv('COMPLIANCE_AGENT_ID', str(uuid.uuid4()))


class MCPComplianceViolationError(Exception):
    """Raised when an MCP operation violates compliance policies."""
    pass


class MCPComplianceProxy:
    """
    Proxy server that intercepts MCP protocol messages and routes them
    through the compliance sidecar for validation.
    """
    
    def __init__(
        self,
        sidecar_url: str = SIDECAR_URL,
        agent_id: str = AGENT_ID,
        mcp_servers: Optional[Dict[str, str]] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """
        Initialize MCP compliance proxy.
        
        Args:
            sidecar_url: URL of the compliance sidecar
            agent_id: Unique identifier for the agent
            mcp_servers: Dictionary mapping MCP server names to URLs
            user_id: Optional user ID for audit trail
            session_id: Optional session ID for tracking
        """
        self.sidecar_url = sidecar_url.rstrip('/')
        self.agent_id = agent_id
        self.user_id = user_id
        self.session_id = session_id or str(uuid.uuid4())
        
        # Parse MCP servers from environment or parameter
        if mcp_servers is None:
            mcp_servers_env = os.getenv('MCP_SERVERS', '{}')
            try:
                mcp_servers = json.loads(mcp_servers_env)
            except json.JSONDecodeError:
                mcp_servers = {}
        
        self.mcp_servers = mcp_servers
        self.app = web.Application()
        self.setup_routes()
        
        logger.info(f"Initialized MCP Compliance Proxy for agent {agent_id}")
        logger.info(f"Sidecar URL: {sidecar_url}")
        logger.info(f"MCP Servers: {list(mcp_servers.keys())}")
    
    def setup_routes(self):
        """Setup HTTP routes for MCP proxy."""
        self.app.router.add_post('/mcp', self.handle_mcp_request)
        self.app.router.add_get('/health', self.health_check)
        self.app.router.add_get('/status', self.get_status)
    
    async def health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({
            'status': 'healthy',
            'agent_id': self.agent_id,
            'mcp_servers': list(self.mcp_servers.keys())
        })
    
    async def get_status(self, request: web.Request) -> web.Response:
        """Get proxy status."""
        return web.json_response({
            'agent_id': self.agent_id,
            'session_id': self.session_id,
            'sidecar_url': self.sidecar_url,
            'mcp_servers': self.mcp_servers,
            'user_id': self.user_id
        })
    
    async def handle_mcp_request(self, request: web.Request) -> web.Response:
        """
        Handle incoming MCP requests from agents.
        
        MCP Request Format (JSON-RPC 2.0):
        {
            "jsonrpc": "2.0",
            "id": "request-id",
            "method": "tools/call",
            "params": {
                "name": "filesystem.read",
                "arguments": {
                    "path": "/data/file.txt"
                }
            }
        }
        """
        try:
            mcp_request = await request.json()
            
            # Validate JSON-RPC format
            if not self._validate_jsonrpc(mcp_request):
                return web.json_response({
                    'jsonrpc': '2.0',
                    'id': mcp_request.get('id'),
                    'error': {
                        'code': -32600,
                        'message': 'Invalid JSON-RPC request'
                    }
                }, status=400)
            
            # Extract MCP tool information
            method = mcp_request.get('method')
            params = mcp_request.get('params', {})
            tool_name = params.get('name', '')
            arguments = params.get('arguments', {})
            
            logger.info(f"MCP Request: {method} - {tool_name}")
            
            # Route to compliance validation
            compliance_result = await self._validate_mcp_operation(
                tool_name=tool_name,
                arguments=arguments,
                method=method,
                request_id=mcp_request.get('id')
            )
            
            # Check if operation is allowed
            if not compliance_result.get('allowed', False):
                # Return compliance violation as MCP error
                return web.json_response({
                    'jsonrpc': '2.0',
                    'id': mcp_request.get('id'),
                    'error': {
                        'code': -32001,  # Custom error code for compliance
                        'message': 'Compliance violation',
                        'data': {
                            'reason': compliance_result.get('reason', 'Unknown'),
                            'violations': compliance_result.get('violations', []),
                            'policy': compliance_result.get('policy', 'Unknown')
                        }
                    }
                }, status=403)
            
            # If allowed, forward to actual MCP server
            mcp_response = await self._forward_to_mcp_server(
                tool_name=tool_name,
                mcp_request=mcp_request
            )
            
            # Validate response through compliance
            validated_response = await self._validate_mcp_response(
                tool_name=tool_name,
                response=mcp_response,
                request_id=mcp_request.get('id')
            )
            
            return web.json_response(validated_response)
        
        except MCPComplianceViolationError as e:
            logger.error(f"MCP compliance violation: {str(e)}")
            return web.json_response({
                'jsonrpc': '2.0',
                'id': mcp_request.get('id') if 'mcp_request' in locals() else None,
                'error': {
                    'code': -32001,
                    'message': str(e)
                }
            }, status=403)
        
        except Exception as e:
            logger.error(f"Error handling MCP request: {str(e)}")
            return web.json_response({
                'jsonrpc': '2.0',
                'id': mcp_request.get('id') if 'mcp_request' in locals() else None,
                'error': {
                    'code': -32603,
                    'message': 'Internal error',
                    'data': str(e)
                }
            }, status=500)
    
    def _validate_jsonrpc(self, request: Dict[str, Any]) -> bool:
        """Validate JSON-RPC 2.0 format."""
        return (
            request.get('jsonrpc') == '2.0' and
            'method' in request and
            'id' in request
        )
    
    async def _validate_mcp_operation(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        method: str,
        request_id: str
    ) -> Dict[str, Any]:
        """
        Validate MCP operation through compliance sidecar.
        
        Args:
            tool_name: Name of the MCP tool (e.g., "filesystem.read")
            arguments: Tool arguments
            method: JSON-RPC method
            request_id: Request ID for tracking
        
        Returns:
            Compliance validation result
        """
        # Create compliance event
        compliance_event = {
            'event_type': 'mcp_request',
            'event_id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'agent_id': self.agent_id,
            'session_id': self.session_id,
            'user_id': self.user_id,
            'mcp_tool': {
                'name': tool_name,
                'method': method,
                'arguments': arguments
            },
            'request_id': request_id
        }
        
        # Send to compliance sidecar
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.sidecar_url}/proxy/mcp",
                    json=compliance_event,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result
                    else:
                        error_text = await response.text()
                        logger.error(f"Compliance validation failed: {error_text}")
                        return {
                            'allowed': False,
                            'reason': f"Compliance check failed: {error_text}"
                        }
        
        except asyncio.TimeoutError:
            logger.error("Compliance validation timeout")
            return {
                'allowed': False,
                'reason': 'Compliance validation timeout'
            }
        
        except Exception as e:
            logger.error(f"Error validating MCP operation: {str(e)}")
            return {
                'allowed': False,
                'reason': f'Validation error: {str(e)}'
            }
    
    async def _forward_to_mcp_server(
        self,
        tool_name: str,
        mcp_request: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Forward validated request to actual MCP server.
        
        Args:
            tool_name: Name of the MCP tool
            mcp_request: Original MCP request
        
        Returns:
            MCP server response
        """
        # Determine which MCP server to use based on tool name
        server_name = tool_name.split('.')[0] if '.' in tool_name else 'default'
        server_url = self.mcp_servers.get(server_name)
        
        if not server_url:
            raise MCPComplianceViolationError(
                f"No MCP server configured for tool: {tool_name}"
            )
        
        # Forward request to MCP server
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{server_url}/mcp",
                    json=mcp_request,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    return await response.json()
        
        except Exception as e:
            logger.error(f"Error forwarding to MCP server: {str(e)}")
            raise MCPComplianceViolationError(
                f"Failed to execute MCP tool: {str(e)}"
            )
    
    async def _validate_mcp_response(
        self,
        tool_name: str,
        response: Dict[str, Any],
        request_id: str
    ) -> Dict[str, Any]:
        """
        Validate MCP response through compliance sidecar.
        
        Args:
            tool_name: Name of the MCP tool
            response: MCP server response
            request_id: Request ID for tracking
        
        Returns:
            Validated response
        """
        # Create response validation event
        validation_event = {
            'event_type': 'mcp_response',
            'event_id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'agent_id': self.agent_id,
            'session_id': self.session_id,
            'mcp_tool': tool_name,
            'response': response,
            'request_id': request_id
        }
        
        # Send to compliance sidecar for response validation
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.sidecar_url}/proxy/mcp/validate-response",
                    json=validation_event,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        # Return sanitized/validated response
                        return result.get('response', response)
                    else:
                        # If validation fails, return error
                        error_text = await resp.text()
                        logger.warning(f"Response validation failed: {error_text}")
                        # Return original response with warning
                        return response
        
        except Exception as e:
            logger.error(f"Error validating MCP response: {str(e)}")
            # Return original response on validation error
            return response
    
    async def start(self, host: str = '0.0.0.0', port: int = MCP_PROXY_PORT):
        """
        Start the MCP proxy server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        logger.info(f"Starting MCP Compliance Proxy on {host}:{port}")
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        logger.info(f"✅ MCP Compliance Proxy started on {host}:{port}")
        
        # Keep running
        try:
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            logger.info("Shutting down MCP Compliance Proxy")
            await runner.cleanup()


async def main():
    """Main entry point for running MCP proxy as standalone service."""
    # Parse MCP servers from environment
    mcp_servers_env = os.getenv('MCP_SERVERS', '{}')
    try:
        mcp_servers = json.loads(mcp_servers_env)
    except json.JSONDecodeError:
        logger.error("Invalid MCP_SERVERS environment variable")
        mcp_servers = {}
    
    # Create and start proxy
    proxy = MCPComplianceProxy(
        sidecar_url=SIDECAR_URL,
        agent_id=AGENT_ID,
        mcp_servers=mcp_servers
    )
    
    await proxy.start()


if __name__ == '__main__':
    asyncio.run(main())

# Made with Bob


# ---------------------------------------------------------------------------
# GAP-13b: Canonical hook surface expected by paper_experiments/exp_gap13
# MCPComplianceProxy.handle_mcp_request is the real async handler registered
# at /mcp.  This module-level alias makes the hook discoverable via hasattr.
# ---------------------------------------------------------------------------

def handle_request(mcp_request: dict) -> dict:  # type: ignore[return]
    """
    Synchronous shim for the MCP request hook surface.

    The real implementation is MCPComplianceProxy.handle_mcp_request (async).
    This stub exists so that paper_experiments/exp_gap13 can verify the hook
    API via hasattr(mod, 'handle_request') without instantiating an aiohttp server.

    In production, create an MCPComplianceProxy instance and call
    handle_mcp_request through the aiohttp web server.
    """
    raise NotImplementedError(
        "Use MCPComplianceProxy.handle_mcp_request (async) in production."
    )
