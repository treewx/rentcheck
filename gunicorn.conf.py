"""
Gunicorn configuration for production deployment
"""
import multiprocessing
import os

# Server socket
port = os.environ.get('PORT', '8000')
bind = f"0.0.0.0:{port}"
backlog = 2048

# Worker processes
workers = int(os.environ.get('WORKERS', 2))
worker_class = 'sync'
worker_connections = 1000
timeout = 120
keepalive = 2

# Restart workers after this many requests
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = '-'  # Log to stdout for Railway
errorlog = '-'   # Log to stderr for Railway
loglevel = os.environ.get('LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s
"%(f)s" "%(a)s"'

# Process naming
proc_name = 'rentcheck'

# Server mechanics
daemon = False
tmp_upload_dir = None
