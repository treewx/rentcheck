#!/usr/bin/env python3
"""
WSGI entry point for production deployment
Usage: gunicorn -c gunicorn.conf.py wsgi:app
"""

from app import app, init_db

# Ensure database is initialized in production
print("Initializing database from wsgi.py...")
init_db()

if __name__ == "__main__":
    app.run()