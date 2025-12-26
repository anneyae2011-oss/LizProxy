#!/usr/bin/env python3
"""Application entry point for Zeabur deployment.

This is the main entry point that Zeabur looks for.
It simply imports and runs the same logic as run.py.
"""

import os
import sys

# Load environment variables from .env file before importing anything else
from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()

import uvicorn

from backend.config import load_settings


def main():
    """Main entry point for the application."""
    # Try to load settings to validate configuration
    try:
        settings = load_settings()
        port = settings.port
        print(f"✓ Configuration loaded successfully")
        print(f"  - Admin password: {'*' * len(settings.admin_password)} ({len(settings.admin_password)} chars)")
        print(f"  - Target API URL: {settings.target_api_url}")
        print(f"  - Max context: {settings.max_context}")
        if settings.database_url:
            print(f"  - Database: PostgreSQL")
        else:
            print(f"  - Database: SQLite ({settings.database_path})")
    except ValueError as e:
        print(f"⚠ Warning: {e}")
        print("  Using default configuration for development")
        port = int(os.getenv("PORT", "8000"))
    
    print(f"\n🚀 Starting AI Proxy on port {port}...")
    print(f"   Public frontend: http://0.0.0.0:{port}/")
    print(f"   Admin dashboard: http://0.0.0.0:{port}/admin")
    print(f"   API docs: http://0.0.0.0:{port}/docs\n")
    
    # Run the uvicorn server
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=port,
        reload=False,  # No reload in production
    )


if __name__ == "__main__":
    main()
