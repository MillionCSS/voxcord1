# gunicorn.conf.py - Fixed for Digital Ocean App Platform
import multiprocessing
import os

# Server socket - CRITICAL: Use the PORT that Digital Ocean provides
bind = f"0.0.0.0:{os.environ.get('PORT', '8080')}"
backlog = 2048

# Worker processes - Scale based on available CPUs
workers = int(os.environ.get('GUNICORN_WORKERS', max(2, multiprocessing.cpu_count())))
worker_class = "sync"  # Changed from "gevent" to "sync" for better compatibility
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
preload_app = True

# Restart workers after this many requests to prevent memory leaks
max_requests = 1200
max_requests_jitter = 200

# Timeout settings - Important for Digital Ocean health checks
timeout = 30  # Reduced from 120 to 30 seconds
keepalive = 5
graceful_timeout = 30

# Logging - Critical for debugging
accesslog = "-"  # Log to stdout
errorlog = "-"   # Log to stderr
loglevel = "info"
capture_output = True
enable_stdio_inheritance = True

# Process naming
proc_name = "voxcord"

# Server mechanics
daemon = False
pidfile = None
user = None
group = None

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

def when_ready(server):
    server.log.info("Voxcord server is ready and listening on: %s", server.address)

def worker_int(worker):
    worker.log.info("Worker received INT or QUIT signal")

def pre_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_worker_init(worker):
    worker.log.info("Worker initialized (pid: %s)", worker.pid)
