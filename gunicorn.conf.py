"""
Gunicorn configuration for production deployment
"""
import multiprocessing
from decouple import config

# Server socket
bind = config('BIND', default='127.0.0.1:8000')
backlog = 2048

# Worker processes
workers = config('WORKERS', default=multiprocessing.cpu_count() * 2 + 1, cast=int)
worker_class = 'sync'
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests, to help with memory leaks
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = 'logs/access.log'
errorlog = 'logs/error.log'
loglevel = config('LOG_LEVEL', default='info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = 'rentcheck'

# Server mechanics
daemon = False
pidfile = 'rentcheck.pid'
user = None
group = None
tmp_upload_dir = None

# SSL (if certificates are available)
# keyfile = 'path/to/private.key'
# certfile = 'path/to/certificate.crt'