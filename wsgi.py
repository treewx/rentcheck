#!/usr/bin/env python3
"""
WSGI entry point for production deployment
Usage: gunicorn -c gunicorn.conf.py wsgi:app
"""

from app import app

if __name__ == "__main__":
    app.run()