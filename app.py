import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from scanner import REPORTS_DIR, ScanError, run_scan, validate_target


app = FastAPI(title="Security Network Audit", version="1.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")


class ScanRequest(BaseModel):
    target: str = Field(..., examples=["192.168.15.0/24", "100.64.0.0/24"])
    profile: str = Field(default="quick", pattern="^(quick|full)$")


class ScheduleRequest(ScanRequest):
    interval_minutes: int = Field(default=60, ge=5, le=1440)
    run_now: bool = True


class ScanState:
    def __init__(self, scan_id: str, target: str, profile: str) -> None:
        self.scan_id = scan_id
        self.target = target
        self.profile = profile
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.status = "queued"
        self.events: list[dict[str, Any]] = []
        self.subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self.report: dict[str, Any] | None = None
        self.error: str | None = None

    async def publish(self, payload: dict[str, Any]) -> None:
        self.events.append(payload)
        for queue in list(self.subscribers):
            await queue.put(payload)


class ScheduleState:
    def __init__(self, schedule_id: str, request: ScheduleRequest) -> None:
        self.schedule_id = schedule_id
        self.target = request.target
        self.profile = request.profile
        self.interval_minutes = request.interval_minutes
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.last_scan_id: str | None = None
        self.next_run_at: str | None = None
        self.task: asyncio.Task[None] | None = None


scans: dict[str, ScanState] = {}
schedules: dict[str, ScheduleState] = {}


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return Path("static/index.html").read_text(encoding="utf-8")


@app.post("/api/scans")
async def create_scan(request: ScanRequest) -> dict[str, str]:
    try:
        validate_target(request.target)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan_id = uuid.uuid4().hex[:12]
    state = ScanState(scan_id, request.target, request.profile)
    scans[scan_id] = state
    asyncio.create_task(_scan_task(state))
    return {"scan_id": scan_id, "events_url": f"/api/scans/{scan_id}/events"}


@app.get("/api/scans")
async def list_scans() -> list[dict[str, Any]]:
    return [
        {
            "id": state.scan_id,
            "target": state.target,
            "profile": state.profile,
            "status": state.status,
            "created_at": state.created_at,
            "error": state.error,
            "report_url": f"/api/scans/{state.scan_id}/report.md" if state.report else None,
        }
        for state in sorted(scans.values(), key=lambda item: item.created_at, reverse=True)
    ]


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    state = _scan_or_404(scan_id)
    return {
        "id": state.scan_id,
        "target": state.target,
        "profile": state.profile,
        "status": state.status,
        "created_at": state.created_at,
        "events": state.events,
        "report": state.report,
        "error": state.error,
    }


@app.get("/api/scans/{scan_id}/events")
async def scan_events(scan_id: str) -> StreamingResponse:
    state = _scan_or_404(scan_id)

    async def event_stream():
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        state.subscribers.add(queue)
        try:
            for payload in state.events:
                yield _sse(payload)
            while state.status in {"queued", "running"}:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                    yield _sse(payload)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
            while not queue.empty():
                yield _sse(queue.get_nowait())
            yield _sse({"event": "stream_closed", "message": "Conexao de eventos finalizada."})
        finally:
            state.subscribers.discard(queue)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/scans/{scan_id}/report.json")
async def report_json(scan_id: str) -> FileResponse:
    path = REPORTS_DIR / f"{scan_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Relatorio ainda nao existe.")
    return FileResponse(path, media_type="application/json", filename=path.name)


@app.get("/api/scans/{scan_id}/report.md")
async def report_markdown(scan_id: str) -> FileResponse:
    path = REPORTS_DIR / f"{scan_id}.md"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Relatorio ainda nao existe.")
    return FileResponse(path, media_type="text/markdown", filename=path.name)


@app.get("/api/reports")
async def list_reports() -> list[dict[str, Any]]:
    REPORTS_DIR.mkdir(exist_ok=True)
    items = []
    for path in sorted(REPORTS_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        items.append(
            {
                "id": data.get("id"),
                "target": data.get("target"),
                "finished_at": data.get("finished_at"),
                "status": data.get("summary", {}).get("overall_status"),
                "hosts": data.get("summary", {}).get("hosts_found"),
                "findings": data.get("summary", {}).get("findings_by_severity"),
                "markdown_url": f"/api/scans/{data.get('id')}/report.md",
                "json_url": f"/api/scans/{data.get('id')}/report.json",
            }
        )
    return items


@app.post("/api/schedules")
async def create_schedule(request: ScheduleRequest) -> dict[str, Any]:
    try:
        validate_target(request.target)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    schedule_id = uuid.uuid4().hex[:10]
    state = ScheduleState(schedule_id, request)
    schedules[schedule_id] = state
    state.task = asyncio.create_task(_schedule_loop(state, run_now=request.run_now))
    return _schedule_payload(state)


@app.get("/api/schedules")
async def list_schedules() -> list[dict[str, Any]]:
    return [_schedule_payload(item) for item in schedules.values()]


@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str) -> dict[str, str]:
    state = schedules.pop(schedule_id, None)
    if state is None:
        raise HTTPException(status_code=404, detail="Agendamento nao encontrado.")
    if state.task:
        state.task.cancel()
    return {"status": "removed"}


async def _scan_task(state: ScanState) -> None:
    state.status = "running"
    try:
        state.report = await run_scan(state.scan_id, state.target, state.profile, state.publish)
        state.status = "finished"
    except Exception as exc:
        state.error = str(exc)
        state.status = "failed"
        await state.publish({"event": "failed", "message": str(exc), "data": {}})


async def _schedule_loop(state: ScheduleState, run_now: bool) -> None:
    if not run_now:
        await _sleep_until_next(state)
    while state.schedule_id in schedules:
        response = await create_scan(ScanRequest(target=state.target, profile=state.profile))
        state.last_scan_id = response["scan_id"]
        await _sleep_until_next(state)


async def _sleep_until_next(state: ScheduleState) -> None:
    seconds = state.interval_minutes * 60
    next_run = datetime.now(timezone.utc).timestamp() + seconds
    state.next_run_at = datetime.fromtimestamp(next_run, timezone.utc).isoformat()
    await asyncio.sleep(seconds)


def _scan_or_404(scan_id: str) -> ScanState:
    state = scans.get(scan_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Scan nao encontrado.")
    return state


def _schedule_payload(state: ScheduleState) -> dict[str, Any]:
    return {
        "id": state.schedule_id,
        "target": state.target,
        "profile": state.profile,
        "interval_minutes": state.interval_minutes,
        "created_at": state.created_at,
        "last_scan_id": state.last_scan_id,
        "next_run_at": state.next_run_at,
    }


def _sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
