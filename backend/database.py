"""Database module for the AI Proxy.

Supports both SQLite (local development) and PostgreSQL (production).
Auto-detects which to use based on DATABASE_URL environment variable.
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Union

# SQLite support
import aiosqlite

# PostgreSQL support (optional)
try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False


@dataclass
class ApiKeyRecord:
    """Represents an API key record from the database."""
    id: int
    key_hash: str
    key_prefix: str
    full_key: Optional[str]
    google_id: Optional[str]  # Google user ID (unique identifier)
    google_email: Optional[str]  # Google email for display
    ip_address: str  # Keep for logging purposes
    browser_fingerprint: Optional[str]
    current_rpm: int
    current_rpd: int
    last_rpm_reset: datetime
    last_rpd_reset: datetime
    enabled: bool
    bypass_ip_ban: bool  # If True, key is not blocked by IP ban list (admin-set)
    created_at: datetime
    last_used_at: Optional[datetime]


@dataclass
class UsageStats:
    """Usage statistics for an API key."""
    total_requests: int
    successful_requests: int
    total_tokens: int
    requests_today: int
    tokens_today: int


@dataclass
class RequestLogRecord:
    """Represents a request log record from the database."""
    id: int
    api_key_id: int
    key_prefix: str
    ip_address: str
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    success: bool
    error_message: Optional[str]
    request_time: datetime


@dataclass
class KeyAnalytics:
    """Analytics for a specific API key."""
    key_id: int
    key_prefix: str
    ip_address: str
    google_email: Optional[str]
    total_input_tokens: int
    total_output_tokens: int
    total_tokens: int
    total_requests: int
    successful_requests: int
    most_used_model: Optional[str]
    model_usage_count: int
    recent_requests: List["RequestLogRecord"]


@dataclass
class BannedIpRecord:
    """Represents a banned IP record from the database."""
    id: int
    ip_address: str
    reason: Optional[str]
    banned_at: datetime


@dataclass
class ProxyConfig:
    """Proxy configuration stored in the database."""
    target_api_url: str
    target_api_key: str
    max_context: int
    max_output_tokens: int


def create_database(database_url: Optional[str] = None, database_path: str = "./proxy.db") -> "Database":
    """Factory function to create the appropriate database instance."""
    if database_url:
        if not HAS_ASYNCPG:
            raise ImportError("asyncpg is required for PostgreSQL support. Install with: pip install asyncpg")
        return PostgreSQLDatabase(database_url)
    return SQLiteDatabase(database_path)


class Database(ABC):
    """Abstract base class for database operations."""
    
    @abstractmethod
    async def initialize(self) -> None:
        pass
    
    @abstractmethod
    async def close(self) -> None:
        pass
    
    # API Key operations
    @abstractmethod
    async def create_api_key(self, google_id: str, google_email: Optional[str], key_hash: str, key_prefix: str, full_key: str, ip_address: str = "unknown") -> int:
        pass
    
    @abstractmethod
    async def get_key_by_google_id(self, google_id: str) -> Optional[ApiKeyRecord]:
        pass
    
    @abstractmethod
    async def get_key_by_ip(self, ip_address: str) -> Optional[ApiKeyRecord]:
        pass
    
    @abstractmethod
    async def get_key_by_fingerprint(self, fingerprint: str) -> Optional[ApiKeyRecord]:
        pass
    
    @abstractmethod
    async def get_key_by_hash(self, key_hash: str) -> Optional[ApiKeyRecord]:
        pass
    
    @abstractmethod
    async def get_all_keys(self) -> List[ApiKeyRecord]:
        pass
    
    @abstractmethod
    async def count_keys_by_ip(self, ip_address: str) -> int:
        """Return the number of API keys currently associated with this IP."""
        pass
    
    @abstractmethod
    async def delete_key(self, key_id: int) -> bool:
        pass
    
    @abstractmethod
    async def toggle_key(self, key_id: int) -> bool:
        pass
    
    @abstractmethod
    async def update_key_ip(self, key_id: int, new_ip: str) -> None:
        pass
    
    @abstractmethod
    async def update_key_fingerprint(self, key_id: int, fingerprint: str) -> None:
        pass
    
    @abstractmethod
    async def set_key_bypass_ip_ban(self, key_id: int, bypass: bool) -> bool:
        """Set whether this key bypasses IP ban checks. Returns True if key existed."""
        pass
    
    # Rate limit operations
    @abstractmethod
    async def update_usage(self, key_id: int, rpm: int, rpd: int) -> None:
        pass
    
    @abstractmethod
    async def increment_usage(self, key_id: int) -> tuple[int, int]:
        pass
    
    @abstractmethod
    async def reset_rpm(self, key_id: int) -> None:
        pass
    
    @abstractmethod
    async def reset_rpd(self, key_id: int) -> None:
        pass
    
    @abstractmethod
    async def reset_all_rpd(self) -> int:
        pass
    
    @abstractmethod
    async def reset_all_rpm(self) -> int:
        pass
    
    # Usage logging
    @abstractmethod
    async def log_usage(self, key_id: int, model: str, tokens: int, success: bool,
                       ip_address: Optional[str] = None, input_tokens: int = 0,
                       output_tokens: int = 0, error_message: Optional[str] = None) -> None:
        pass
    
    @abstractmethod
    async def get_usage_stats(self, key_id: int) -> UsageStats:
        pass
    
    @abstractmethod
    async def get_recent_requests(self, limit: int = 10) -> List[RequestLogRecord]:
        pass
    
    @abstractmethod
    async def get_top_token_requests(self, limit: int = 3) -> List[RequestLogRecord]:
        pass
    
    @abstractmethod
    async def get_key_analytics(self, key_id: int) -> Optional[KeyAnalytics]:
        pass
    
    # IP ban operations
    @abstractmethod
    async def ban_ip(self, ip_address: str, reason: Optional[str] = None) -> None:
        pass
    
    @abstractmethod
    async def unban_ip(self, ip_address: str) -> bool:
        pass
    
    @abstractmethod
    async def is_ip_banned(self, ip_address: str) -> bool:
        pass
    
    @abstractmethod
    async def get_all_banned_ips(self) -> List[BannedIpRecord]:
        pass
    
    # Config operations
    @abstractmethod
    async def get_config(self) -> Optional[ProxyConfig]:
        pass
    
    @abstractmethod
    async def update_config(self, target_url: str, target_key: str, max_context: int, max_output_tokens: int = 4096) -> None:
        pass


class SQLiteDatabase(Database):
    """SQLite database implementation for local development."""

    def __init__(self, database_path: str):
        self.database_path = database_path
        self._connection: Optional[aiosqlite.Connection] = None

    async def _get_connection(self) -> aiosqlite.Connection:
        if self._connection is None:
            self._connection = await aiosqlite.connect(self.database_path)
            self._connection.row_factory = aiosqlite.Row
        return self._connection

    async def close(self) -> None:
        if self._connection is not None:
            await self._connection.close()
            self._connection = None

    async def initialize(self) -> None:
        conn = await self._get_connection()
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                full_key TEXT,
                google_id TEXT UNIQUE,
                google_email TEXT,
                ip_address TEXT NOT NULL DEFAULT 'unknown',
                browser_fingerprint TEXT,
                current_rpm INTEGER DEFAULT 0,
                current_rpd INTEGER DEFAULT 0,
                last_rpm_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_rpd_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP
            )
        """)
        
        # Migrations
        for col, sql in [
            ("google_id", "ALTER TABLE api_keys ADD COLUMN google_id TEXT UNIQUE"),
            ("google_email", "ALTER TABLE api_keys ADD COLUMN google_email TEXT"),
            ("browser_fingerprint", "ALTER TABLE api_keys ADD COLUMN browser_fingerprint TEXT"),
            ("full_key", "ALTER TABLE api_keys ADD COLUMN full_key TEXT"),
            ("bypass_ip_ban", "ALTER TABLE api_keys ADD COLUMN bypass_ip_ban BOOLEAN DEFAULT 0"),
        ]:
            try:
                await conn.execute(f"SELECT {col} FROM api_keys LIMIT 1")
            except Exception:
                await conn.execute(sql)
        
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_ip ON api_keys(ip_address)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_fingerprint ON api_keys(browser_fingerprint)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_google_id ON api_keys(google_id)")
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS usage_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_id INTEGER NOT NULL,
                ip_address TEXT,
                model TEXT,
                input_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                tokens_used INTEGER DEFAULT 0,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT,
                request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
            )
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS banned_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS proxy_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                target_api_url TEXT NOT NULL,
                target_api_key TEXT NOT NULL,
                max_context INTEGER DEFAULT 128000,
                max_output_tokens INTEGER DEFAULT 4096,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        try:
            await conn.execute("SELECT max_output_tokens FROM proxy_config LIMIT 1")
        except Exception:
            await conn.execute("ALTER TABLE proxy_config ADD COLUMN max_output_tokens INTEGER DEFAULT 4096")
        
        await conn.commit()

    async def create_api_key(self, google_id: str, google_email: Optional[str], key_hash: str, key_prefix: str, full_key: str, ip_address: str = "unknown") -> int:
        conn = await self._get_connection()
        cursor = await conn.execute(
            "INSERT INTO api_keys (google_id, google_email, ip_address, key_hash, key_prefix, full_key) VALUES (?, ?, ?, ?, ?, ?)",
            (google_id, google_email, ip_address, key_hash, key_prefix, full_key)
        )
        await conn.commit()
        return cursor.lastrowid

    async def get_key_by_google_id(self, google_id: str) -> Optional[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys WHERE google_id = ?", (google_id,))
        row = await cursor.fetchone()
        return self._row_to_api_key(row) if row else None

    async def get_key_by_ip(self, ip_address: str) -> Optional[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys WHERE ip_address = ?", (ip_address,))
        row = await cursor.fetchone()
        return self._row_to_api_key(row) if row else None

    async def get_key_by_fingerprint(self, fingerprint: str) -> Optional[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys WHERE browser_fingerprint = ?", (fingerprint,))
        row = await cursor.fetchone()
        return self._row_to_api_key(row) if row else None

    async def get_key_by_hash(self, key_hash: str) -> Optional[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,))
        row = await cursor.fetchone()
        return self._row_to_api_key(row) if row else None

    async def get_all_keys(self) -> List[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        return [self._row_to_api_key(row) for row in rows]

    async def count_keys_by_ip(self, ip_address: str) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT COUNT(*) FROM api_keys WHERE ip_address = ?", (ip_address,))
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def delete_key(self, key_id: int) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        await conn.commit()
        return cursor.rowcount > 0

    async def toggle_key(self, key_id: int) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("UPDATE api_keys SET enabled = NOT enabled WHERE id = ?", (key_id,))
        await conn.commit()
        return cursor.rowcount > 0

    async def update_key_ip(self, key_id: int, new_ip: str) -> None:
        conn = await self._get_connection()
        await conn.execute("UPDATE api_keys SET ip_address = ? WHERE id = ?", (new_ip, key_id))
        await conn.commit()

    async def update_key_fingerprint(self, key_id: int, fingerprint: str) -> None:
        conn = await self._get_connection()
        await conn.execute("UPDATE api_keys SET browser_fingerprint = ? WHERE id = ?", (fingerprint, key_id))
        await conn.commit()

    async def set_key_bypass_ip_ban(self, key_id: int, bypass: bool) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("UPDATE api_keys SET bypass_ip_ban = ? WHERE id = ?", (1 if bypass else 0, key_id))
        await conn.commit()
        return cursor.rowcount > 0

    async def update_usage(self, key_id: int, rpm: int, rpd: int) -> None:
        conn = await self._get_connection()
        await conn.execute(
            "UPDATE api_keys SET current_rpm = ?, current_rpd = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (rpm, rpd, key_id)
        )
        await conn.commit()

    async def increment_usage(self, key_id: int) -> tuple[int, int]:
        conn = await self._get_connection()
        await conn.execute(
            "UPDATE api_keys SET current_rpm = current_rpm + 1, current_rpd = current_rpd + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (key_id,)
        )
        await conn.commit()
        cursor = await conn.execute("SELECT current_rpm, current_rpd FROM api_keys WHERE id = ?", (key_id,))
        row = await cursor.fetchone()
        return (row["current_rpm"], row["current_rpd"]) if row else (0, 0)

    async def reset_rpm(self, key_id: int) -> None:
        conn = await self._get_connection()
        await conn.execute("UPDATE api_keys SET current_rpm = 0, last_rpm_reset = CURRENT_TIMESTAMP WHERE id = ?", (key_id,))
        await conn.commit()

    async def reset_rpd(self, key_id: int) -> None:
        conn = await self._get_connection()
        await conn.execute("UPDATE api_keys SET current_rpd = 0, last_rpd_reset = CURRENT_TIMESTAMP WHERE id = ?", (key_id,))
        await conn.commit()

    async def reset_all_rpd(self) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("UPDATE api_keys SET current_rpd = 0, last_rpd_reset = CURRENT_TIMESTAMP")
        await conn.commit()
        return cursor.rowcount

    async def reset_all_rpm(self) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("UPDATE api_keys SET current_rpm = 0, last_rpm_reset = CURRENT_TIMESTAMP")
        await conn.commit()
        return cursor.rowcount

    async def log_usage(self, key_id: int, model: str, tokens: int, success: bool,
                       ip_address: Optional[str] = None, input_tokens: int = 0,
                       output_tokens: int = 0, error_message: Optional[str] = None) -> None:
        conn = await self._get_connection()
        await conn.execute(
            "INSERT INTO usage_logs (api_key_id, ip_address, model, input_tokens, output_tokens, tokens_used, success, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (key_id, ip_address, model, input_tokens, output_tokens, tokens, success, error_message)
        )
        await conn.commit()

    async def get_usage_stats(self, key_id: int) -> UsageStats:
        conn = await self._get_connection()
        cursor = await conn.execute("""
            SELECT COUNT(*) as total_requests, SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_requests,
                   COALESCE(SUM(tokens_used), 0) as total_tokens
            FROM usage_logs WHERE api_key_id = ?
        """, (key_id,))
        total_row = await cursor.fetchone()
        
        cursor = await conn.execute("""
            SELECT COUNT(*) as requests_today, COALESCE(SUM(tokens_used), 0) as tokens_today
            FROM usage_logs WHERE api_key_id = ? AND DATE(request_time) = DATE('now')
        """, (key_id,))
        today_row = await cursor.fetchone()
        
        return UsageStats(
            total_requests=total_row["total_requests"] or 0,
            successful_requests=total_row["successful_requests"] or 0,
            total_tokens=total_row["total_tokens"] or 0,
            requests_today=today_row["requests_today"] or 0,
            tokens_today=today_row["tokens_today"] or 0,
        )

    async def get_recent_requests(self, limit: int = 10) -> List[RequestLogRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("""
            SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                   ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                   ul.error_message, ul.request_time
            FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
            ORDER BY ul.request_time DESC LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [self._row_to_request_log(row) for row in rows]

    async def get_top_token_requests(self, limit: int = 3) -> List[RequestLogRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("""
            SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                   ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                   ul.error_message, ul.request_time
            FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
            WHERE ul.success = 1 ORDER BY ul.tokens_used DESC LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [self._row_to_request_log(row) for row in rows]

    async def get_key_analytics(self, key_id: int) -> Optional[KeyAnalytics]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT key_prefix, ip_address, google_email FROM api_keys WHERE id = ?", (key_id,))
        key_row = await cursor.fetchone()
        if not key_row:
            return None
        
        cursor = await conn.execute("""
            SELECT COALESCE(SUM(input_tokens), 0) as total_input, COALESCE(SUM(output_tokens), 0) as total_output,
                   COALESCE(SUM(tokens_used), 0) as total_tokens, COUNT(*) as total_requests,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_requests
            FROM usage_logs WHERE api_key_id = ?
        """, (key_id,))
        stats_row = await cursor.fetchone()
        
        cursor = await conn.execute("""
            SELECT model, COUNT(*) as usage_count FROM usage_logs
            WHERE api_key_id = ? AND model IS NOT NULL AND model != 'models'
            GROUP BY model ORDER BY usage_count DESC LIMIT 1
        """, (key_id,))
        model_row = await cursor.fetchone()
        
        cursor = await conn.execute("""
            SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                   ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                   ul.error_message, ul.request_time
            FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
            WHERE ul.api_key_id = ? ORDER BY ul.request_time DESC LIMIT 5
        """, (key_id,))
        recent_rows = await cursor.fetchall()
        
        return KeyAnalytics(
            key_id=key_id, key_prefix=key_row["key_prefix"], ip_address=key_row["ip_address"],
            google_email=key_row["google_email"] if "google_email" in key_row.keys() else None,
            total_input_tokens=stats_row["total_input"] or 0, total_output_tokens=stats_row["total_output"] or 0,
            total_tokens=stats_row["total_tokens"] or 0, total_requests=stats_row["total_requests"] or 0,
            successful_requests=stats_row["successful_requests"] or 0,
            most_used_model=model_row["model"] if model_row else None,
            model_usage_count=model_row["usage_count"] if model_row else 0,
            recent_requests=[self._row_to_request_log(row) for row in recent_rows],
        )

    async def ban_ip(self, ip_address: str, reason: Optional[str] = None) -> None:
        conn = await self._get_connection()
        await conn.execute("INSERT OR REPLACE INTO banned_ips (ip_address, reason, banned_at) VALUES (?, ?, CURRENT_TIMESTAMP)", (ip_address, reason))
        await conn.commit()

    async def unban_ip(self, ip_address: str) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM banned_ips WHERE ip_address = ?", (ip_address,))
        await conn.commit()
        return cursor.rowcount > 0

    async def is_ip_banned(self, ip_address: str) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT 1 FROM banned_ips WHERE ip_address = ?", (ip_address,))
        return await cursor.fetchone() is not None

    async def get_all_banned_ips(self) -> List[BannedIpRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM banned_ips ORDER BY banned_at DESC")
        rows = await cursor.fetchall()
        return [BannedIpRecord(id=r["id"], ip_address=r["ip_address"], reason=r["reason"], banned_at=self._parse_ts(r["banned_at"])) for r in rows]

    async def get_config(self) -> Optional[ProxyConfig]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM proxy_config WHERE id = 1")
        row = await cursor.fetchone()
        if not row:
            return None
        max_out = row["max_output_tokens"] if "max_output_tokens" in row.keys() else 4096
        return ProxyConfig(target_api_url=row["target_api_url"], target_api_key=row["target_api_key"], max_context=row["max_context"], max_output_tokens=max_out)

    async def update_config(self, target_url: str, target_key: str, max_context: int, max_output_tokens: int = 4096) -> None:
        conn = await self._get_connection()
        await conn.execute("INSERT OR REPLACE INTO proxy_config (id, target_api_url, target_api_key, max_context, max_output_tokens, updated_at) VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)", (target_url, target_key, max_context, max_output_tokens))
        await conn.commit()

    def _row_to_api_key(self, row) -> ApiKeyRecord:
        return ApiKeyRecord(
            id=row["id"], key_hash=row["key_hash"], key_prefix=row["key_prefix"],
            full_key=row["full_key"] if "full_key" in row.keys() else None,
            google_id=row["google_id"] if "google_id" in row.keys() else None,
            google_email=row["google_email"] if "google_email" in row.keys() else None,
            ip_address=row["ip_address"],
            browser_fingerprint=row["browser_fingerprint"] if "browser_fingerprint" in row.keys() else None,
            current_rpm=row["current_rpm"], current_rpd=row["current_rpd"],
            last_rpm_reset=self._parse_ts(row["last_rpm_reset"]), last_rpd_reset=self._parse_ts(row["last_rpd_reset"]),
            enabled=bool(row["enabled"]),
            bypass_ip_ban=bool(row["bypass_ip_ban"]) if "bypass_ip_ban" in row.keys() else False,
            created_at=self._parse_ts(row["created_at"]),
            last_used_at=self._parse_ts(row["last_used_at"]) if row["last_used_at"] else None,
        )

    def _row_to_request_log(self, row) -> RequestLogRecord:
        return RequestLogRecord(
            id=row["id"], api_key_id=row["api_key_id"], key_prefix=row["key_prefix"] or "unknown",
            ip_address=row["ip_address"] or "unknown", model=row["model"] or "unknown",
            input_tokens=row["input_tokens"] or 0, output_tokens=row["output_tokens"] or 0,
            total_tokens=row["tokens_used"] or 0, success=bool(row["success"]),
            error_message=row["error_message"], request_time=self._parse_ts(row["request_time"]),
        )

    @staticmethod
    def _parse_ts(value) -> datetime:
        if isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")



class PostgreSQLDatabase(Database):
    """PostgreSQL database implementation for production."""

    def __init__(self, database_url: str):
        self.database_url = database_url
        self._pool = None

    async def _get_pool(self):
        if self._pool is None:
            self._pool = await asyncpg.create_pool(self.database_url, min_size=10, max_size=50)
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def initialize(self) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id SERIAL PRIMARY KEY,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT NOT NULL,
                    full_key TEXT,
                    google_id TEXT UNIQUE,
                    google_email TEXT,
                    ip_address TEXT NOT NULL DEFAULT 'unknown',
                    browser_fingerprint TEXT,
                    current_rpm INTEGER DEFAULT 0,
                    current_rpd INTEGER DEFAULT 0,
                    last_rpm_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_rpd_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP
                )
            """)
            # Migrations - add new columns if they don't exist
            # Check which columns exist
            existing_cols = await conn.fetch("""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = 'api_keys'
            """)
            existing_col_names = {row['column_name'] for row in existing_cols}
            
            # Add missing columns
            if 'full_key' not in existing_col_names:
                await conn.execute("ALTER TABLE api_keys ADD COLUMN full_key TEXT")
            if 'google_id' not in existing_col_names:
                await conn.execute("ALTER TABLE api_keys ADD COLUMN google_id TEXT")
            if 'google_email' not in existing_col_names:
                await conn.execute("ALTER TABLE api_keys ADD COLUMN google_email TEXT")
            if 'bypass_ip_ban' not in existing_col_names:
                await conn.execute("ALTER TABLE api_keys ADD COLUMN bypass_ip_ban BOOLEAN DEFAULT FALSE")
            
            # Create indexes (safe to run multiple times)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_ip ON api_keys(ip_address)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_fingerprint ON api_keys(browser_fingerprint)")
            
            # Create google_id index only if column exists now
            try:
                await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_google_id ON api_keys(google_id)")
            except Exception:
                pass  # Index might already exist or column issue
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_logs (
                    id SERIAL PRIMARY KEY,
                    api_key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
                    ip_address TEXT,
                    model TEXT,
                    input_tokens INTEGER DEFAULT 0,
                    output_tokens INTEGER DEFAULT 0,
                    tokens_used INTEGER DEFAULT 0,
                    success BOOLEAN DEFAULT TRUE,
                    error_message TEXT,
                    request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS banned_ips (
                    id SERIAL PRIMARY KEY,
                    ip_address TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS proxy_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    target_api_url TEXT NOT NULL,
                    target_api_key TEXT NOT NULL,
                    max_context INTEGER DEFAULT 128000,
                    max_output_tokens INTEGER DEFAULT 4096,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Migration: add max_output_tokens if missing
            config_cols = await conn.fetch("""
                SELECT column_name FROM information_schema.columns WHERE table_name = 'proxy_config'
            """)
            config_col_names = {r["column_name"] for r in config_cols}
            if "max_output_tokens" not in config_col_names:
                await conn.execute("ALTER TABLE proxy_config ADD COLUMN max_output_tokens INTEGER DEFAULT 4096")

    async def create_api_key(self, google_id: str, google_email: Optional[str], key_hash: str, key_prefix: str, full_key: str, ip_address: str = "unknown") -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO api_keys (google_id, google_email, ip_address, key_hash, key_prefix, full_key) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                google_id, google_email, ip_address, key_hash, key_prefix, full_key
            )
            return row["id"]

    async def get_key_by_google_id(self, google_id: str) -> Optional[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM api_keys WHERE google_id = $1", google_id)
            return self._row_to_api_key(row) if row else None

    async def get_key_by_ip(self, ip_address: str) -> Optional[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM api_keys WHERE ip_address = $1", ip_address)
            return self._row_to_api_key(row) if row else None

    async def get_key_by_fingerprint(self, fingerprint: str) -> Optional[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM api_keys WHERE browser_fingerprint = $1", fingerprint)
            return self._row_to_api_key(row) if row else None

    async def get_key_by_hash(self, key_hash: str) -> Optional[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM api_keys WHERE key_hash = $1", key_hash)
            return self._row_to_api_key(row) if row else None

    async def get_all_keys(self) -> List[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM api_keys ORDER BY created_at DESC")
            return [self._row_to_api_key(row) for row in rows]

    async def count_keys_by_ip(self, ip_address: str) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT COUNT(*) FROM api_keys WHERE ip_address = $1", ip_address)
            return row[0] if row else 0

    async def delete_key(self, key_id: int) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM api_keys WHERE id = $1", key_id)
            return result == "DELETE 1"

    async def toggle_key(self, key_id: int) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("UPDATE api_keys SET enabled = NOT enabled WHERE id = $1", key_id)
            return result == "UPDATE 1"

    async def update_key_ip(self, key_id: int, new_ip: str) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE api_keys SET ip_address = $1 WHERE id = $2", new_ip, key_id)

    async def update_key_fingerprint(self, key_id: int, fingerprint: str) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE api_keys SET browser_fingerprint = $1 WHERE id = $2", fingerprint, key_id)

    async def set_key_bypass_ip_ban(self, key_id: int, bypass: bool) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("UPDATE api_keys SET bypass_ip_ban = $1 WHERE id = $2", bypass, key_id)
            return result == "UPDATE 1"

    async def update_usage(self, key_id: int, rpm: int, rpd: int) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE api_keys SET current_rpm = $1, current_rpd = $2, last_used_at = CURRENT_TIMESTAMP WHERE id = $3", rpm, rpd, key_id)

    async def increment_usage(self, key_id: int) -> tuple[int, int]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE api_keys SET current_rpm = current_rpm + 1, current_rpd = current_rpd + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING current_rpm, current_rpd",
                key_id
            )
            return (row["current_rpm"], row["current_rpd"]) if row else (0, 0)

    async def reset_rpm(self, key_id: int) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE api_keys SET current_rpm = 0, last_rpm_reset = CURRENT_TIMESTAMP WHERE id = $1", key_id)

    async def reset_rpd(self, key_id: int) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE api_keys SET current_rpd = 0, last_rpd_reset = CURRENT_TIMESTAMP WHERE id = $1", key_id)

    async def reset_all_rpd(self) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("UPDATE api_keys SET current_rpd = 0, last_rpd_reset = CURRENT_TIMESTAMP")
            return int(result.split()[-1]) if result else 0

    async def reset_all_rpm(self) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("UPDATE api_keys SET current_rpm = 0, last_rpm_reset = CURRENT_TIMESTAMP")
            return int(result.split()[-1]) if result else 0

    async def log_usage(self, key_id: int, model: str, tokens: int, success: bool,
                       ip_address: Optional[str] = None, input_tokens: int = 0,
                       output_tokens: int = 0, error_message: Optional[str] = None) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO usage_logs (api_key_id, ip_address, model, input_tokens, output_tokens, tokens_used, success, error_message) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                key_id, ip_address, model, input_tokens, output_tokens, tokens, success, error_message
            )

    async def get_usage_stats(self, key_id: int) -> UsageStats:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            total_row = await conn.fetchrow("""
                SELECT COUNT(*) as total_requests, SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful_requests,
                       COALESCE(SUM(tokens_used), 0) as total_tokens
                FROM usage_logs WHERE api_key_id = $1
            """, key_id)
            today_row = await conn.fetchrow("""
                SELECT COUNT(*) as requests_today, COALESCE(SUM(tokens_used), 0) as tokens_today
                FROM usage_logs WHERE api_key_id = $1 AND DATE(request_time) = CURRENT_DATE
            """, key_id)
            return UsageStats(
                total_requests=total_row["total_requests"] or 0, successful_requests=total_row["successful_requests"] or 0,
                total_tokens=total_row["total_tokens"] or 0, requests_today=today_row["requests_today"] or 0,
                tokens_today=today_row["tokens_today"] or 0,
            )

    async def get_recent_requests(self, limit: int = 10) -> List[RequestLogRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                       ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                       ul.error_message, ul.request_time
                FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
                ORDER BY ul.request_time DESC LIMIT $1
            """, limit)
            return [self._row_to_request_log(row) for row in rows]

    async def get_top_token_requests(self, limit: int = 3) -> List[RequestLogRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                       ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                       ul.error_message, ul.request_time
                FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
                WHERE ul.success = TRUE ORDER BY ul.tokens_used DESC LIMIT $1
            """, limit)
            return [self._row_to_request_log(row) for row in rows]

    async def get_key_analytics(self, key_id: int) -> Optional[KeyAnalytics]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            key_row = await conn.fetchrow("SELECT key_prefix, ip_address, google_email FROM api_keys WHERE id = $1", key_id)
            if not key_row:
                return None
            
            stats_row = await conn.fetchrow("""
                SELECT COALESCE(SUM(input_tokens), 0) as total_input, COALESCE(SUM(output_tokens), 0) as total_output,
                       COALESCE(SUM(tokens_used), 0) as total_tokens, COUNT(*) as total_requests,
                       SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful_requests
                FROM usage_logs WHERE api_key_id = $1
            """, key_id)
            
            model_row = await conn.fetchrow("""
                SELECT model, COUNT(*) as usage_count FROM usage_logs
                WHERE api_key_id = $1 AND model IS NOT NULL AND model != 'models'
                GROUP BY model ORDER BY usage_count DESC LIMIT 1
            """, key_id)
            
            recent_rows = await conn.fetch("""
                SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                       ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                       ul.error_message, ul.request_time
                FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
                WHERE ul.api_key_id = $1 ORDER BY ul.request_time DESC LIMIT 5
            """, key_id)
            
            return KeyAnalytics(
                key_id=key_id, key_prefix=key_row["key_prefix"], ip_address=key_row["ip_address"],
                google_email=key_row.get("google_email"),
                total_input_tokens=stats_row["total_input"] or 0, total_output_tokens=stats_row["total_output"] or 0,
                total_tokens=stats_row["total_tokens"] or 0, total_requests=stats_row["total_requests"] or 0,
                successful_requests=stats_row["successful_requests"] or 0,
                most_used_model=model_row["model"] if model_row else None,
                model_usage_count=model_row["usage_count"] if model_row else 0,
                recent_requests=[self._row_to_request_log(row) for row in recent_rows],
            )

    async def ban_ip(self, ip_address: str, reason: Optional[str] = None) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO banned_ips (ip_address, reason, banned_at) VALUES ($1, $2, CURRENT_TIMESTAMP)
                ON CONFLICT (ip_address) DO UPDATE SET reason = $2, banned_at = CURRENT_TIMESTAMP
            """, ip_address, reason)

    async def unban_ip(self, ip_address: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM banned_ips WHERE ip_address = $1", ip_address)
            return result == "DELETE 1"

    async def is_ip_banned(self, ip_address: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT 1 FROM banned_ips WHERE ip_address = $1", ip_address)
            return row is not None

    async def get_all_banned_ips(self) -> List[BannedIpRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM banned_ips ORDER BY banned_at DESC")
            return [BannedIpRecord(id=r["id"], ip_address=r["ip_address"], reason=r["reason"], banned_at=r["banned_at"]) for r in rows]

    async def get_config(self) -> Optional[ProxyConfig]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM proxy_config WHERE id = 1")
            if not row:
                return None
            return ProxyConfig(
                target_api_url=row["target_api_url"],
                target_api_key=row["target_api_key"],
                max_context=row["max_context"],
                max_output_tokens=row.get("max_output_tokens", 4096),
            )

    async def update_config(self, target_url: str, target_key: str, max_context: int, max_output_tokens: int = 4096) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO proxy_config (id, target_api_url, target_api_key, max_context, max_output_tokens, updated_at) VALUES (1, $1, $2, $3, $4, CURRENT_TIMESTAMP)
                ON CONFLICT (id) DO UPDATE SET target_api_url = $1, target_api_key = $2, max_context = $3, max_output_tokens = $4, updated_at = CURRENT_TIMESTAMP
            """, target_url, target_key, max_context, max_output_tokens)

    def _row_to_api_key(self, row) -> ApiKeyRecord:
        return ApiKeyRecord(
            id=row["id"], key_hash=row["key_hash"], key_prefix=row["key_prefix"],
            full_key=row.get("full_key"),
            google_id=row.get("google_id"),
            google_email=row.get("google_email"),
            ip_address=row["ip_address"],
            browser_fingerprint=row.get("browser_fingerprint"),
            current_rpm=row["current_rpm"], current_rpd=row["current_rpd"],
            last_rpm_reset=row["last_rpm_reset"], last_rpd_reset=row["last_rpd_reset"],
            enabled=row["enabled"],
            bypass_ip_ban=row.get("bypass_ip_ban", False),
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
        )

    def _row_to_request_log(self, row) -> RequestLogRecord:
        return RequestLogRecord(
            id=row["id"], api_key_id=row["api_key_id"], key_prefix=row["key_prefix"] or "unknown",
            ip_address=row["ip_address"] or "unknown", model=row["model"] or "unknown",
            input_tokens=row["input_tokens"] or 0, output_tokens=row["output_tokens"] or 0,
            total_tokens=row["tokens_used"] or 0, success=row["success"],
            error_message=row["error_message"], request_time=row["request_time"],
        )
