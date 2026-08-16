"""
Dual Database Adapter for Compliance Sidecar
Supports both SQLite and PostgreSQL with seamless switching via configuration
"""

import os
import sqlite3
import logging
from typing import Dict, List, Any, Optional, Tuple
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger(__name__)

# Try to import PostgreSQL support
try:
    import psycopg2
    import psycopg2.extras
    from psycopg2.pool import ThreadedConnectionPool
    from psycopg2.extras import Json, RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    logger.warning("psycopg2 not available - PostgreSQL support disabled")


class DatabaseAdapter:
    """
    Unified database adapter supporting both SQLite and PostgreSQL.
    
    Features:
    - Automatic connection pooling for PostgreSQL
    - Consistent API regardless of backend
    - Graceful fallback to SQLite if PostgreSQL unavailable
    - Thread-safe operations
    """
    
    def __init__(self, use_postgres: bool = False, config: Optional[Dict[str, Any]] = None):
        """
        Initialize database adapter.
        
        Args:
            use_postgres: If True, use PostgreSQL; otherwise use SQLite
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.use_postgres = use_postgres and POSTGRES_AVAILABLE
        
        if self.use_postgres and not POSTGRES_AVAILABLE:
            logger.warning("PostgreSQL requested but psycopg2 not available - falling back to SQLite")
            self.use_postgres = False
        
        if self.use_postgres:
            self._init_postgres()
        else:
            self._init_sqlite()
        
        logger.info(f"Database adapter initialized: {'PostgreSQL' if self.use_postgres else 'SQLite'}")
    
    def _init_postgres(self):
        """Initialize PostgreSQL connection pool."""
        self.pg_config = {
            'host': os.getenv('POSTGRES_HOST', self.config.get('host', 'localhost')),
            'port': int(os.getenv('POSTGRES_PORT', self.config.get('port', 5432))),
            'database': os.getenv('POSTGRES_DB', self.config.get('database', 'compliance_audit')),
            'user': os.getenv('POSTGRES_USER', self.config.get('user', 'compliance_user')),
            'password': os.getenv('POSTGRES_PASSWORD', self.config.get('password', 'compliance_pass_2024'))
        }
        
        try:
            self.pool = ThreadedConnectionPool(
                minconn=self.config.get('min_connections', 2),
                maxconn=self.config.get('max_connections', 10),
                **self.pg_config
            )
            logger.info(f"PostgreSQL connection pool created: {self.pg_config['host']}:{self.pg_config['port']}/{self.pg_config['database']}")
        except Exception as e:
            logger.error(f"Failed to create PostgreSQL pool: {e}")
            raise
    
    def _init_sqlite(self):
        """Initialize SQLite connection."""
        self.sqlite_path = self.config.get('sqlite_path', 'compliance.db')
        self.conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        logger.info(f"SQLite connection created: {self.sqlite_path}")
        
        # Create tables if they don't exist
        self._create_sqlite_tables()
    
    def _create_sqlite_tables(self):
        """Create SQLite tables if they don't exist."""
        cursor = self.conn.cursor()
        
        # Audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                decision TEXT NOT NULL,
                violations TEXT DEFAULT '[]',
                timestamp INTEGER NOT NULL,
                metadata TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Data lineage table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS data_lineage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                transformations TEXT DEFAULT '[]',
                security_metadata TEXT DEFAULT '{}',
                timestamps TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_log(request_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_agent_id ON audit_log(agent_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_lineage_request_id ON data_lineage(request_id)")
        
        self.conn.commit()
        logger.info("SQLite tables and indexes created")
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        
        Yields:
            Database connection (psycopg2 or sqlite3)
        """
        if self.use_postgres:
            conn = self.pool.getconn()
            try:
                yield conn
            finally:
                self.pool.putconn(conn)
        else:
            yield self.conn
    
    def insert_audit_log(self, data: Dict[str, Any]) -> bool:
        """
        Insert audit log record.
        
        Args:
            data: Dictionary containing audit log fields
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.get_connection() as conn:
                if self.use_postgres:
                    return self._insert_audit_postgres(conn, data)
                else:
                    return self._insert_audit_sqlite(conn, data)
        except Exception as e:
            logger.error(f"Failed to insert audit log: {e}")
            return False
    
    def _insert_audit_postgres(self, conn, data: Dict[str, Any]) -> bool:
        """Insert audit log into PostgreSQL."""
        import json
        
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO audit_log 
                (request_id, agent_id, resource, action, decision, violations, timestamp, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                data['request_id'],
                data['agent_id'],
                data['resource'],
                data['action'],
                data['decision'],
                Json(data.get('violations', [])),
                data['timestamp'],
                Json(data.get('metadata', {}))
            ))
        conn.commit()
        return True
    
    def _insert_audit_sqlite(self, conn, data: Dict[str, Any]) -> bool:
        """Insert audit log into SQLite."""
        import json
        
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log 
            (request_id, agent_id, resource, action, decision, violations, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data['request_id'],
            data['agent_id'],
            data['resource'],
            data['action'],
            data['decision'],
            json.dumps(data.get('violations', [])),
            data['timestamp'],
            json.dumps(data.get('metadata', {}))
        ))
        conn.commit()
        return True
    
    def insert_lineage(self, data: Dict[str, Any]) -> bool:
        """
        Insert data lineage record.
        
        Args:
            data: Dictionary containing lineage fields
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.get_connection() as conn:
                if self.use_postgres:
                    return self._insert_lineage_postgres(conn, data)
                else:
                    return self._insert_lineage_sqlite(conn, data)
        except Exception as e:
            logger.error(f"Failed to insert lineage: {e}")
            return False
    
    def _insert_lineage_postgres(self, conn, data: Dict[str, Any]) -> bool:
        """Insert lineage into PostgreSQL."""
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO data_lineage 
                (request_id, source, destination, transformations, security_metadata, timestamps)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                data['request_id'],
                data['source'],
                data['destination'],
                Json(data['transformations']),
                Json(data['security_metadata']),
                Json(data['timestamps'])
            ))
        conn.commit()
        return True
    
    def _insert_lineage_sqlite(self, conn, data: Dict[str, Any]) -> bool:
        """Insert lineage into SQLite."""
        import json
        
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO data_lineage 
            (request_id, source, destination, transformations, security_metadata, timestamps)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data['request_id'],
            data['source'],
            data['destination'],
            json.dumps(data['transformations']),
            json.dumps(data['security_metadata']),
            json.dumps(data['timestamps'])
        ))
        conn.commit()
        return True
    
    def query_audit_logs(self, filters: Optional[Dict[str, Any]] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query audit logs with optional filters.
        
        Args:
            filters: Optional dictionary of filter conditions
            limit: Maximum number of records to return
            
        Returns:
            List of audit log records
        """
        try:
            with self.get_connection() as conn:
                if self.use_postgres:
                    return self._query_audit_postgres(conn, filters, limit)
                else:
                    return self._query_audit_sqlite(conn, filters, limit)
        except Exception as e:
            logger.error(f"Failed to query audit logs: {e}")
            return []
    
    def _query_audit_postgres(self, conn, filters: Optional[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        """Query audit logs from PostgreSQL."""
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            query = "SELECT * FROM audit_log WHERE 1=1"
            params = []
            
            if filters:
                if 'agent_id' in filters:
                    query += " AND agent_id = %s"
                    params.append(filters['agent_id'])
                if 'decision' in filters:
                    query += " AND decision = %s"
                    params.append(filters['decision'])
            
            query += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def _query_audit_sqlite(self, conn, filters: Optional[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        """Query audit logs from SQLite."""
        cursor = conn.cursor()
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        
        if filters:
            if 'agent_id' in filters:
                query += " AND agent_id = ?"
                params.append(filters['agent_id'])
            if 'decision' in filters:
                query += " AND decision = ?"
                params.append(filters['decision'])
        
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Dictionary containing statistics
        """
        try:
            with self.get_connection() as conn:
                if self.use_postgres:
                    return self._get_statistics_postgres(conn)
                else:
                    return self._get_statistics_sqlite(conn)
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def _get_statistics_postgres(self, conn) -> Dict[str, Any]:
        """Get statistics from PostgreSQL."""
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_records,
                    COUNT(DISTINCT agent_id) as unique_agents,
                    SUM(CASE WHEN decision = 'APPROVED' THEN 1 ELSE 0 END) as approved,
                    SUM(CASE WHEN decision = 'DENIED' THEN 1 ELSE 0 END) as denied,
                    SUM(CASE WHEN decision = 'THROTTLED' THEN 1 ELSE 0 END) as throttled
                FROM audit_log
            """)
            return dict(cursor.fetchone())
    
    def _get_statistics_sqlite(self, conn) -> Dict[str, Any]:
        """Get statistics from SQLite."""
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total_records,
                COUNT(DISTINCT agent_id) as unique_agents,
                SUM(CASE WHEN decision = 'APPROVED' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN decision = 'DENIED' THEN 1 ELSE 0 END) as denied,
                SUM(CASE WHEN decision = 'THROTTLED' THEN 1 ELSE 0 END) as throttled
            FROM audit_log
        """)
        columns = [desc[0] for desc in cursor.description]
        row = cursor.fetchone()
        return dict(zip(columns, row)) if row else {}
    
    def close(self):
        """Close database connections."""
        if self.use_postgres:
            self.pool.closeall()
            logger.info("PostgreSQL connection pool closed")
        else:
            self.conn.close()
            logger.info("SQLite connection closed")


# Convenience functions for backward compatibility
def create_adapter(use_postgres: bool = None, config: Optional[Dict[str, Any]] = None) -> DatabaseAdapter:
    """
    Create a database adapter instance.
    
    Args:
        use_postgres: If True, use PostgreSQL; if None, read from environment
        config: Optional configuration dictionary
        
    Returns:
        DatabaseAdapter instance
    """
    if use_postgres is None:
        use_postgres = os.getenv('USE_POSTGRES', 'false').lower() == 'true'
    
    return DatabaseAdapter(use_postgres=use_postgres, config=config)

# Made with Bob
