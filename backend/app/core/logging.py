"""Structured logging setup using structlog.

Emits JSON in production/staging, human-readable in development.
Correlation IDs are bound to context vars per request (see middleware).
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.contextvars import merge_contextvars
from structlog.processors import (
    JSONRenderer,
    StackInfoRenderer,
    TimeStamper,
    add_log_level,
    format_exc_info,
)

from app.core.config import Settings


def configure_logging(settings: Settings) -> None:
    """Configure structlog and stdlib logging consistently."""

    timestamper = TimeStamper(fmt="iso", utc=True)

    shared_processors: list[Any] = [
        merge_contextvars,
        add_log_level,
        structlog.processors.add_log_level,
        timestamper,
        StackInfoRenderer(),
        format_exc_info,
    ]

    if settings.environment == "development":
        renderer: Any = structlog.dev.ConsoleRenderer(colors=True)
    else:
        renderer = JSONRenderer()

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[settings.log_level]
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logs through structlog
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.log_level)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
