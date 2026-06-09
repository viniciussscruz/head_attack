"""Utilities shared across scanner modules."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def emit_event(
    emit: Callable[[dict[str, Any]], Any],
    event: str,
    message: str,
    data: dict[str, Any],
) -> None:
    """Build and dispatch a structured event payload, awaiting it when emit is a coroutine function."""
    payload = {"ts": utc_now(), "event": event, "message": message, "data": data}
    maybe = emit(payload)
    if asyncio.iscoroutine(maybe):
        await maybe


def save_json_report(path: Path, data: dict[str, Any]) -> None:
    """Write *data* as pretty-printed JSON to *path*, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
