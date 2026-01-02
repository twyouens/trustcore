import logging
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler

# Environment-configurable settings
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.getenv(
    "LOG_FILE",
    str(Path(__file__).resolve().parents[2] / "logs" / "app.log"),
)
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", 10 * 1024 * 1024))  # 10MB
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", 5))

# Ensure log directory exists when using a file
try:
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
except Exception:
    # If directory creation fails, continue; file handler setup will raise if necessary.
    pass

# Create and configure the named logger for the application
logger = logging.getLogger("trustcore")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
logger.propagate = False  # avoid double logging if root logger is configured elsewhere

# Only add handlers once
if not logger.handlers:
    fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    formatter = logging.Formatter(fmt)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Rotating file handler (if path is writable)
    try:
        fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8")
        fh.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except Exception:
        # If file handler cannot be created (permissions, invalid path), skip it silently.
        pass


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Return the application logger or a child logger.
    Usage:
        log = get_logger("module.sub")
    """
    if not name:
        return logger
    return logger.getChild(name)


__all__ = ["logger", "get_logger"]