#!/usr/bin/env python3
"""Entry point for Zeabur deployment."""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8080)
