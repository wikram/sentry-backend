import logging
from pathlib import Path
from typing import Any, Optional

import yaml

try:
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    pool = None
    psycopg2 = None
    RealDictCursor = None

logger = logging.getLogger(__name__)


DEFAULT_DATABASE_CONFIG = {
    "enabled": False,
    "driver": "postgresql",
    "host": "localhost",
    "port": 5432,
    "name": "sentry_backend",
    "user": "sentry_user",
    "password": "change_me",
    "pool_size": 10,
    "timeout_seconds": 30,
}


class DatabaseConnection:
    """Database connection manager for the Sentry backend."""

    def __init__(self, config_path: Path | str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.connection_pool: Optional[Any] = None
        self._initialized = False

    def _load_config(self) -> dict[str, Any]:
        """Load database configuration from config.yaml."""
        if not self.config_path.exists():
            logger.warning("Config file not found: %s, using defaults", self.config_path)
            return DEFAULT_DATABASE_CONFIG.copy()

        try:
            with self.config_path.open("r", encoding="utf-8") as fh:
                full_config = yaml.safe_load(fh) or {}
            db_config = full_config.get("database", {})
            return {**DEFAULT_DATABASE_CONFIG, **db_config}
        except Exception as e:
            logger.error("Failed to load database config: %s", e)
            return DEFAULT_DATABASE_CONFIG.copy()

    def is_enabled(self) -> bool:
        """Check if database is enabled in configuration."""
        return bool(self.config.get("enabled", False))

    def initialize(self) -> bool:
        """Initialize the database connection pool if enabled."""
        if not self.is_enabled():
            logger.info("Database is disabled in configuration")
            return False

        if not POSTGRES_AVAILABLE:
            logger.error("PostgreSQL driver not available. Install with: pip install psycopg2-binary")
            return False

        try:
            driver = self.config.get("driver", "postgresql")
            if driver != "postgresql":
                logger.error("Only PostgreSQL driver is currently supported")
                return False

            # Build connection string
            conn_string = (
                f"host={self.config['host']} "
                f"port={self.config['port']} "
                f"dbname={self.config['name']} "
                f"user={self.config['user']} "
                f"password={self.config['password']} "
                f"connect_timeout={self.config['timeout_seconds']}"
            )

            # Create connection pool
            pool_size = self.config.get("pool_size", 10)
            self.connection_pool = pool.SimpleConnectionPool(
                minconn=1,
                maxconn=pool_size,
                connection_factory=psycopg2.connect,
                dsn=conn_string
            )

            # Test connection
            conn = self.get_connection()
            if conn:
                conn.close()
                self._initialized = True
                logger.info("Database connection pool initialized successfully")
                return True
            else:
                logger.error("Failed to establish database connection")
                return False

        except Exception as e:
            logger.error("Failed to initialize database connection: %s", e)
            return False

    def get_connection(self) -> Optional[Any]:
        """Get a database connection from the pool."""
        if not self._initialized or not self.connection_pool:
            logger.error("Database not initialized")
            return None

        try:
            return self.connection_pool.getconn()
        except Exception as e:
            logger.error("Failed to get database connection: %s", e)
            return None

    def return_connection(self, conn: Any) -> None:
        """Return a connection to the pool."""
        if self.connection_pool and conn:
            try:
                self.connection_pool.putconn(conn)
            except Exception as e:
                logger.error("Failed to return connection to pool: %s", e)

    def execute_query(self, query: str, params: tuple = None, fetch: bool = True) -> Optional[list]:
        """Execute a database query and optionally fetch results."""
        conn = self.get_connection()
        if not conn:
            return None

        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, params or ())
                if fetch:
                    result = cursor.fetchall()
                    return [dict(row) for row in result] if result else []
                else:
                    conn.commit()
                    return None
        except Exception as e:
            logger.error("Database query failed: %s", e)
            conn.rollback()
            return None
        finally:
            self.return_connection(conn)

    def close(self) -> None:
        """Close the database connection pool."""
        if self.connection_pool:
            try:
                self.connection_pool.closeall()
                logger.info("Database connection pool closed")
            except Exception as e:
                logger.error("Error closing database connection pool: %s", e)
            finally:
                self.connection_pool = None
                self._initialized = False


# Global database instance
_db_instance: Optional[DatabaseConnection] = None


def get_database() -> DatabaseConnection:
    """Get the global database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseConnection()
    return _db_instance


def init_database() -> bool:
    """Initialize the global database connection."""
    db = get_database()
    return db.initialize()


def close_database() -> None:
    """Close the global database connection."""
    global _db_instance
    if _db_instance:
        _db_instance.close()
        _db_instance = None