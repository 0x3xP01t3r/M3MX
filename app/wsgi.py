"""Production entry point. Use one process until runtime state is shared."""
import os
from .forensics import detect_volatility
from .main import create_app

paths = detect_volatility()
for key in ("vol2", "vol3"):
    paths[key] = os.environ.get(f"{key.upper()}_PATH") or paths[key]
application = create_app(volatility_paths=paths)
