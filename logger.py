import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import yaml


DEFAULT_LOGGING_CONFIG = {
    "enabled": False,
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": None,
    "rotate": False,
    "max_bytes": 10485760,
    "backup_count": 5,
}


def load_logging_config(config_path: Path | str = "config.yaml") -> dict[str, Any]:
    """Load the logging configuration block from config.yaml."""
    path = Path(config_path)
    if not path.exists():
        return DEFAULT_LOGGING_CONFIG.copy()

    with path.open("r", encoding="utf-8") as fh:
        full_config = yaml.safe_load(fh) or {}

    logging_config = full_config.get("logging", {})
    return {**DEFAULT_LOGGING_CONFIG, **logging_config}


def configure_logging(config_path: Path | str = "config.yaml") -> None:
    """Configure Python logging from config.yaml if logging is enabled."""
    config = load_logging_config(config_path)
    if not config.get("enabled", False):
        return

    level_name = str(config.get("level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    log_format = str(config.get("format", DEFAULT_LOGGING_CONFIG["format"]))

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    formatter = logging.Formatter(log_format)

    # Console handler
    if not any(isinstance(handler, logging.StreamHandler) for handler in root_logger.handlers):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    # File handler
    log_file = config.get("file")
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        if config.get("rotate", False):
            handler = RotatingFileHandler(
                log_path,
                maxBytes=int(config.get("max_bytes", DEFAULT_LOGGING_CONFIG["max_bytes"])),
                backupCount=int(config.get("backup_count", DEFAULT_LOGGING_CONFIG["backup_count"])),
            )
        else:
            handler = logging.FileHandler(log_path)

        handler.setLevel(level)
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
