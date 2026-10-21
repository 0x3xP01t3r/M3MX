"""Threaded streaming server; loaded-image state belongs to one process."""
bind = "0.0.0.0:5000"  # Container port is published only on host loopback.
workers = 1
worker_class = "gthread"
threads = 8
timeout = 120
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
preload_app = False
