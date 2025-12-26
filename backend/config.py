"""Configuration module for the AI Proxy.

Handles loading settings from environment variables with sensible defaults.
"""

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv


@dataclass
class Settings:
    """Application settings loaded from environment variables."""
    
    admin_password: str
    target_api_url: str
    target_api_key: str
    port: int
    max_context: int
    database_path: str
    database_url: Optional[str]  # PostgreSQL connection URL


def load_settings(env_path: Optional[str] = None) -> Settings:
    """Load settings from environment variables.
    
    Args:
        env_path: Optional path to .env file. If None, searches for .env
                  in current directory and parent directories.
    
    Returns:
        Settings dataclass with all configuration values.
    
    Raises:
        ValueError: If required environment variables are missing.
    """
    # Load .env file if it exists
    if env_path:
        load_dotenv(env_path)
    else:
        load_dotenv()
    
    # Required settings
    admin_password = os.getenv("ADMIN_PASSWORD")
    if not admin_password:
        raise ValueError("ADMIN_PASSWORD environment variable is required")
    
    target_api_key = os.getenv("TARGET_API_KEY")
    if not target_api_key:
        raise ValueError("TARGET_API_KEY environment variable is required")
    
    # Optional settings with defaults
    target_api_url = os.getenv("TARGET_API_URL", "https://api.openai.com/v1")
    port = int(os.getenv("PORT", "8000"))
    max_context = int(os.getenv("MAX_CONTEXT", "128000"))
    database_path = os.getenv("DATABASE_PATH", "./proxy.db")
    
    # PostgreSQL URL (if set, will be used instead of SQLite)
    database_url = os.getenv("DATABASE_URL")
    
    return Settings(
        admin_password=admin_password,
        target_api_url=target_api_url,
        target_api_key=target_api_key,
        port=port,
        max_context=max_context,
        database_path=database_path,
        database_url=database_url,
    )
