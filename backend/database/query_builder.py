"""
Secure SQL query builder with parameterized queries, injection prevention,
and query optimization support.
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, date, time
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union, Set

try:
    from sqlalchemy import (
        text, select, insert, update, delete, and_, or_, not_,
        func, case, cast, distinct, exists, any_, all_,
        Table, Column, MetaData, Integer, String, Float, Boolean,
        DateTime, Date, Time, Numeric, Text, JSON, ARRAY,
        create_engine, inspect
    )
    from sqlalchemy.sql import Select, Insert, Update, Delete
    from sqlalchemy.sql.expression import ClauseElement, BinaryExpression
    from sqlalchemy.dialects import postgresql, mysql, sqlite, mssql
    from sqlalchemy.engine import Engine, Connection
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncConnection
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False

try:
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False


logger = logging.getLogger(__name__)

# Import result objects
from backend.common.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)


class QueryType(Enum):
    """Types of SQL queries."""
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    CREATE = "CREATE"
    ALTER = "ALTER"
    DROP = "DROP"
    TRUNCATE = "TRUNCATE"


class JoinType(Enum):
    """Types of SQL joins."""
    INNER = "INNER"
    LEFT = "LEFT"
    RIGHT = "RIGHT"
    FULL = "FULL"
    CROSS = "CROSS"


class OrderDirection(Enum):
    """Sort order directions."""
    ASC = "ASC"
    DESC = "DESC"


@dataclass
class QueryParameter:
    """Represents a query parameter with validation."""
    name: str
    value: Any
    data_type: Optional[type] = None
    validators: List[callable] = field(default_factory=list)
    
    def validate(self) -> bool:
        """Validate the parameter value."""
        # Type validation
        if self.data_type and not isinstance(self.value, self.data_type):
            raise ValueError(
                f"Parameter {self.name} must be of type {self.data_type.__name__}"
            )
        
        # Custom validators
        for validator in self.validators:
            if not validator(self.value):
                raise ValueError(f"Parameter {self.name} failed validation")
        
        return True


class SQLValidator:
    """Validates SQL queries for security issues."""
    
    # Dangerous SQL patterns
    DANGEROUS_PATTERNS = [
        r';\s*(DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)',  # Multiple statements
        r'--[^\n]*',  # SQL comments
        r'/\*.*?\*/',  # Multi-line comments
        r'\bUNION\b.*\bSELECT\b',  # UNION-based injection
        r'\bINTO\s+OUTFILE\b',  # File operations
        r'\bLOAD_FILE\s*\(',  # File loading
        r'\bBENCHMARK\s*\(',  # Time-based attacks
        r'\bSLEEP\s*\(',  # Time delays
        r'0x[0-9a-fA-F]+',  # Hex encoding
        r'CHAR\s*\([0-9,\s]+\)',  # Character encoding
        r'\b(sys|information_schema)\.',  # System tables
    ]
    
    # Whitelisted keywords (safe when properly parameterized)
    SAFE_KEYWORDS = {
        'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'LIKE',
        'BETWEEN', 'IS', 'NULL', 'ORDER', 'BY', 'GROUP', 'HAVING',
        'LIMIT', 'OFFSET', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'FULL',
        'ON', 'AS', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MIN', 'MAX',
        'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'EXISTS', 'ANY', 'ALL'
    }
    
    @classmethod
    def validate_query(cls, query: str) -> bool:
        """Validate a SQL query for security issues."""
        query_upper = query.upper()
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE | re.DOTALL):
                logger.warning(f"Dangerous SQL pattern detected: {pattern}")
                return False
        
        # Check for multiple statements
        if query.count(';') > 1:
            logger.warning("Multiple SQL statements detected")
            return False
        
        return True
    
    @classmethod
    def validate_identifier(cls, identifier: str) -> bool:
        """Validate a SQL identifier (table/column name)."""
        # Only allow alphanumeric and underscore
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
            logger.warning(f"Invalid SQL identifier: {identifier}")
            return False
        
        # Check length
        if len(identifier) > 64:  # Common DB limit
            logger.warning(f"SQL identifier too long: {identifier}")
            return False
        
        return True
    
    @classmethod
    def escape_identifier(cls, identifier: str, dialect: str = 'postgresql') -> str:
        """Properly escape a SQL identifier."""
        if not cls.validate_identifier(identifier):
            raise ValueError(f"Invalid identifier: {identifier}")
        
        if dialect == 'postgresql':
            return f'"{identifier}"'
        elif dialect == 'mysql':
            return f'`{identifier}`'
        elif dialect == 'mssql':
            return f'[{identifier}]'
        else:
            return f'"{identifier}"'


class ParameterizedQueryBuilder:
    """Builds parameterized SQL queries safely."""
    
    def __init__(self, dialect: str = 'postgresql'):
        self.dialect = dialect
        self.validator = SQLValidator()
        self._params: Dict[str, Any] = {}
        self._param_counter = 0
    
    def _next_param_name(self) -> str:
        """Generate next parameter name."""
        self._param_counter += 1
        return f"param_{self._param_counter}"
    
    def _add_parameter(self, value: Any) -> str:
        """Add a parameter and return its placeholder."""
        param_name = self._next_param_name()
        self._params[param_name] = value
        
        if self.dialect in ['postgresql', 'psycopg2']:
            return f"%({param_name})s"
        elif self.dialect == 'mysql':
            return f"%({param_name})s"
        elif self.dialect == 'sqlite':
            return f":{param_name}"
        elif self.dialect == 'mssql':
            return f"@{param_name}"
        else:
            return "?"
    
    def select(
        self,
        table: str,
        columns: Optional[List[str]] = None,
        where: Optional[Dict[str, Any]] = None,
        joins: Optional[List[Tuple[str, str, JoinType]]] = None,
        order_by: Optional[List[Tuple[str, OrderDirection]]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        distinct: bool = False
    ) -> Tuple[str, Dict[str, Any]]:
        """Build a parameterized SELECT query."""
        # Validate table name
        if not self.validator.validate_identifier(table):
            raise ValueError(f"Invalid table name: {table}")
        
        # Build SELECT clause
        if columns:
            for col in columns:
                if not self.validator.validate_identifier(col.split('.')[-1]):
                    raise ValueError(f"Invalid column name: {col}")
            columns_str = ', '.join(columns)
        else:
            columns_str = '*'
        
        query_parts = []
        
        if distinct:
            query_parts.append(f"SELECT DISTINCT {columns_str}")
        else:
            query_parts.append(f"SELECT {columns_str}")
        
        query_parts.append(f"FROM {self.validator.escape_identifier(table, self.dialect)}")
        
        # Add JOINs
        if joins:
            for join_table, join_condition, join_type in joins:
                if not self.validator.validate_identifier(join_table):
                    raise ValueError(f"Invalid join table: {join_table}")
                
                query_parts.append(
                    f"{join_type.value} JOIN {self.validator.escape_identifier(join_table, self.dialect)} "
                    f"ON {join_condition}"
                )
        
        # Add WHERE clause
        if where:
            where_conditions = []
            for key, value in where.items():
                if not self.validator.validate_identifier(key):
                    raise ValueError(f"Invalid column name: {key}")
                
                if value is None:
                    where_conditions.append(f"{key} IS NULL")
                elif isinstance(value, (list, tuple)):
                    placeholders = [self._add_parameter(v) for v in value]
                    where_conditions.append(f"{key} IN ({', '.join(placeholders)})")
                else:
                    placeholder = self._add_parameter(value)
                    where_conditions.append(f"{key} = {placeholder}")
            
            if where_conditions:
                query_parts.append(f"WHERE {' AND '.join(where_conditions)}")
        
        # Add ORDER BY
        if order_by:
            order_parts = []
            for col, direction in order_by:
                if not self.validator.validate_identifier(col):
                    raise ValueError(f"Invalid order column: {col}")
                order_parts.append(f"{col} {direction.value}")
            query_parts.append(f"ORDER BY {', '.join(order_parts)}")
        
        # Add LIMIT/OFFSET
        if limit is not None:
            limit_placeholder = self._add_parameter(limit)
            query_parts.append(f"LIMIT {limit_placeholder}")
        
        if offset is not None:
            offset_placeholder = self._add_parameter(offset)
            query_parts.append(f"OFFSET {offset_placeholder}")
        
        query = ' '.join(query_parts)
        return query, self._params.copy()
    
    def insert(
        self,
        table: str,
        data: Dict[str, Any],
        returning: Optional[List[str]] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """Build a parameterized INSERT query."""
        if not self.validator.validate_identifier(table):
            raise ValueError(f"Invalid table name: {table}")
        
        columns = []
        placeholders = []
        
        for key, value in data.items():
            if not self.validator.validate_identifier(key):
                raise ValueError(f"Invalid column name: {key}")
            
            columns.append(key)
            placeholders.append(self._add_parameter(value))
        
        query = (
            f"INSERT INTO {self.validator.escape_identifier(table, self.dialect)} "
            f"({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
        )
        
        if returning and self.dialect == 'postgresql':
            returning_cols = ', '.join(returning)
            query += f" RETURNING {returning_cols}"
        
        return query, self._params.copy()
    
    def update(
        self,
        table: str,
        data: Dict[str, Any],
        where: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Build a parameterized UPDATE query."""
        if not self.validator.validate_identifier(table):
            raise ValueError(f"Invalid table name: {table}")
        
        if not where:
            raise ValueError("UPDATE without WHERE clause is dangerous")
        
        # Build SET clause
        set_parts = []
        for key, value in data.items():
            if not self.validator.validate_identifier(key):
                raise ValueError(f"Invalid column name: {key}")
            
            placeholder = self._add_parameter(value)
            set_parts.append(f"{key} = {placeholder}")
        
        # Build WHERE clause
        where_parts = []
        for key, value in where.items():
            if not self.validator.validate_identifier(key):
                raise ValueError(f"Invalid column name: {key}")
            
            if value is None:
                where_parts.append(f"{key} IS NULL")
            else:
                placeholder = self._add_parameter(value)
                where_parts.append(f"{key} = {placeholder}")
        
        query = (
            f"UPDATE {self.validator.escape_identifier(table, self.dialect)} "
            f"SET {', '.join(set_parts)} "
            f"WHERE {' AND '.join(where_parts)}"
        )
        
        return query, self._params.copy()
    
    def delete(
        self,
        table: str,
        where: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Build a parameterized DELETE query."""
        if not self.validator.validate_identifier(table):
            raise ValueError(f"Invalid table name: {table}")
        
        if not where:
            raise ValueError("DELETE without WHERE clause is dangerous")
        
        # Build WHERE clause
        where_parts = []
        for key, value in where.items():
            if not self.validator.validate_identifier(key):
                raise ValueError(f"Invalid column name: {key}")
            
            if value is None:
                where_parts.append(f"{key} IS NULL")
            else:
                placeholder = self._add_parameter(value)
                where_parts.append(f"{key} = {placeholder}")
        
        query = (
            f"DELETE FROM {self.validator.escape_identifier(table, self.dialect)} "
            f"WHERE {' AND '.join(where_parts)}"
        )
        
        return query, self._params.copy()


class SQLAlchemyQueryBuilder:
    """Query builder using SQLAlchemy for maximum safety."""
    
    def __init__(self, engine: Union[Engine, AsyncEngine]):
        if not SQLALCHEMY_AVAILABLE:
            raise ImportError("SQLAlchemy is required for SQLAlchemyQueryBuilder")
        
        self.engine = engine
        self.metadata = MetaData()
        self._tables: Dict[str, Table] = {}
    
    async def reflect_tables(self):
        """Reflect database tables."""
        if isinstance(self.engine, AsyncEngine):
            async with self.engine.connect() as conn:
                await conn.run_sync(self.metadata.reflect)
        else:
            self.metadata.reflect(bind=self.engine)
        
        self._tables = {
            table.name: table for table in self.metadata.tables.values()
        }
    
    def get_table(self, name: str) -> Table:
        """Get a table object."""
        if name not in self._tables:
            raise ValueError(f"Table {name} not found")
        return self._tables[name]
    
    def build_select(
        self,
        table_name: str,
        columns: Optional[List[str]] = None,
        where: Optional[Dict[str, Any]] = None,
        joins: Optional[List[Tuple[str, str, str]]] = None,
        order_by: Optional[List[Tuple[str, str]]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None
    ) -> Select:
        """Build a SELECT query using SQLAlchemy."""
        table = self.get_table(table_name)
        
        # Select columns
        if columns:
            cols = [getattr(table.c, col) for col in columns]
            stmt = select(*cols)
        else:
            stmt = select(table)
        
        # Add WHERE conditions
        if where:
            conditions = []
            for key, value in where.items():
                col = getattr(table.c, key)
                if value is None:
                    conditions.append(col.is_(None))
                elif isinstance(value, (list, tuple)):
                    conditions.append(col.in_(value))
                else:
                    conditions.append(col == value)
            
            if conditions:
                stmt = stmt.where(and_(*conditions))
        
        # Add ORDER BY
        if order_by:
            for col_name, direction in order_by:
                col = getattr(table.c, col_name)
                if direction.upper() == 'DESC':
                    stmt = stmt.order_by(col.desc())
                else:
                    stmt = stmt.order_by(col.asc())
        
        # Add LIMIT/OFFSET
        if limit is not None:
            stmt = stmt.limit(limit)
        
        if offset is not None:
            stmt = stmt.offset(offset)
        
        return stmt
    
    def build_insert(
        self,
        table_name: str,
        data: Union[Dict[str, Any], List[Dict[str, Any]]],
        returning: Optional[List[str]] = None
    ) -> Insert:
        """Build an INSERT query using SQLAlchemy."""
        table = self.get_table(table_name)
        stmt = insert(table)
        
        if isinstance(data, list):
            stmt = stmt.values(data)
        else:
            stmt = stmt.values(**data)
        
        if returning:
            cols = [getattr(table.c, col) for col in returning]
            stmt = stmt.returning(*cols)
        
        return stmt
    
    def build_update(
        self,
        table_name: str,
        data: Dict[str, Any],
        where: Dict[str, Any]
    ) -> Update:
        """Build an UPDATE query using SQLAlchemy."""
        table = self.get_table(table_name)
        stmt = update(table)
        
        # Set values
        stmt = stmt.values(**data)
        
        # Add WHERE conditions
        conditions = []
        for key, value in where.items():
            col = getattr(table.c, key)
            if value is None:
                conditions.append(col.is_(None))
            else:
                conditions.append(col == value)
        
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        return stmt
    
    def build_delete(
        self,
        table_name: str,
        where: Dict[str, Any]
    ) -> Delete:
        """Build a DELETE query using SQLAlchemy."""
        table = self.get_table(table_name)
        stmt = delete(table)
        
        # Add WHERE conditions
        conditions = []
        for key, value in where.items():
            col = getattr(table.c, key)
            if value is None:
                conditions.append(col.is_(None))
            else:
                conditions.append(col == value)
        
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        return stmt


class QueryExecutor:
    """Executes parameterized queries safely."""
    
    def __init__(
        self,
        connection_string: str,
        max_query_time: float = 30.0,
        log_queries: bool = True
    ):
        self.connection_string = connection_string
        self.max_query_time = max_query_time
        self.log_queries = log_queries
        self._connection = None
        
    async def execute_async(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
        fetch: bool = True
    ) -> Union[List[Dict[str, Any]], int]:
        """Execute a query asynchronously."""
        if not ASYNCPG_AVAILABLE:
            raise ImportError("asyncpg is required for async execution")
        
        # Validate query
        if not SQLValidator.validate_query(query):
            raise ValueError("Query failed security validation")
        
        # Log query
        if self.log_queries:
            logger.info(f"Executing query: {query[:100]}...")
        
        # Execute with timeout
        conn = await asyncpg.connect(self.connection_string)
        try:
            # Set timeout
            await conn.execute(f"SET statement_timeout = {int(self.max_query_time * 1000)}")
            
            if fetch:
                result = await conn.fetch(query, *params.values() if params else [])
                return [dict(row) for row in result]
            else:
                result = await conn.execute(query, *params.values() if params else [])
                # Extract affected rows count
                count = int(result.split()[-1]) if result else 0
                return count
        finally:
            await conn.close()
    
    def execute_sync(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
        fetch: bool = True
    ) -> Union[List[Dict[str, Any]], int]:
        """Execute a query synchronously."""
        if not PSYCOPG2_AVAILABLE:
            raise ImportError("psycopg2 is required for sync execution")
        
        # Validate query
        if not SQLValidator.validate_query(query):
            raise ValueError("Query failed security validation")
        
        # Log query
        if self.log_queries:
            logger.info(f"Executing query: {query[:100]}...")
        
        conn = psycopg2.connect(self.connection_string)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Set timeout
                cursor.execute(f"SET statement_timeout = {int(self.max_query_time * 1000)}")
                
                cursor.execute(query, params)
                
                if fetch:
                    return cursor.fetchall()
                else:
                    conn.commit()
                    return cursor.rowcount
        finally:
            conn.close()


class PreparedStatementCache:
    """Cache for prepared statements to improve performance."""
    
    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self._cache: Dict[str, Any] = {}
        self._access_count: Dict[str, int] = {}
    
    def get_key(self, query: str, params: Dict[str, Any]) -> str:
        """Generate cache key for query."""
        param_types = {k: type(v).__name__ for k, v in params.items()}
        key_data = f"{query}:{json.dumps(param_types, sort_keys=True)}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def get(self, query: str, params: Dict[str, Any]):
        """Get cached prepared statement."""
        key = self.get_key(query, params)
        if key in self._cache:
            self._access_count[key] = self._access_count.get(key, 0) + 1
            return create_success_result(
                data=self._cache[key],
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="Prepared statement retrieved from cache",
                        details=f"Cache hit for query key: {key[:8]}..."
                    )
                )
            )
        return create_partial_success_result(
            data=None,
            error_code="CACHE_MISS",
            message="Prepared statement not found in cache",
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="Cache miss for prepared statement",
                    details=f"No cached statement found for query key: {key[:8]}..."
                )
            ),
            suggestions=["Prepare and cache the statement", "Check cache size limits", "Verify query parameters"]
        )
    
    def set(self, query: str, params: Dict[str, Any], statement: Any):
        """Cache a prepared statement."""
        # Evict least used if at capacity
        if len(self._cache) >= self.max_size:
            min_key = min(self._access_count, key=self._access_count.get)
            del self._cache[min_key]
            del self._access_count[min_key]
        
        key = self.get_key(query, params)
        self._cache[key] = statement
        self._access_count[key] = 1
    
    def clear(self):
        """Clear the cache."""
        self._cache.clear()
        self._access_count.clear()


class QueryOptimizer:
    """Optimize SQL queries for performance."""
    
    @staticmethod
    def add_index_hints(
        query: str,
        index_hints: Dict[str, str]
    ) -> str:
        """Add index hints to query (database-specific)."""
        for table, index in index_hints.items():
            # PostgreSQL style
            query = query.replace(
                f"FROM {table}",
                f"FROM {table} /*+ INDEX({index}) */"
            )
        return query
    
    @staticmethod
    def optimize_in_clause(
        values: List[Any],
        max_size: int = 1000
    ) -> List[List[Any]]:
        """Split large IN clauses into chunks."""
        if len(values) <= max_size:
            return [values]
        
        chunks = []
        for i in range(0, len(values), max_size):
            chunks.append(values[i:i + max_size])
        return chunks
    
    @staticmethod
    def add_query_timeout(
        query: str,
        timeout_ms: int,
        dialect: str = 'postgresql'
    ) -> str:
        """Add query timeout hint."""
        if dialect == 'postgresql':
            return f"SET LOCAL statement_timeout = {timeout_ms}; {query}"
        elif dialect == 'mysql':
            return f"SELECT /*+ MAX_EXECUTION_TIME({timeout_ms}) */ {query[6:]}"
        else:
            return query