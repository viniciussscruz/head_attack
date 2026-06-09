import asyncio
import json
import re
import urllib.parse
import uuid
from collections.abc import Coroutine
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from bad_agent import AGENT_MEDIA_DIR, SAFE_TESTS, list_ai_models, run_bad_agent
from network_performance import run_network_performance
from report_exports import export_report
from scanner import REPORTS_DIR, ScanError, run_scan, validate_target
from website_security import run_website_security


app = FastAPI(title="Security Network Audit", version="1.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

_T = TypeVar("_T")

# ── Request models ────────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    target: str = Field(..., examples=["192.168.15.0/24", "100.64.0.0/24"])
    profile: str = Field(default="quick", pattern="^(quick|full)$")


class ScheduleRequest(ScanRequest):
    interval_minutes: int = Field(default=60, ge=5, le=1440)
    run_now: bool = True


class BadAgentRequest(BaseModel):
    target: str = Field(..., examples=["192.168.15.0/24"])
    tests: list[str] = Field(default_factory=lambda: list(SAFE_TESTS))
    capture_rtsp_frame: bool = False
    ai_endpoint: str | None = "https://api.openai.com/v1/chat/completions"
    ai_model: str | None = "gpt-4.1-mini"
    ai_api_key: str | None = None


class AiModelsRequest(BaseModel):
    ai_endpoint: str | None = "https://api.openai.com/v1/chat/completions"
    ai_api_key: str | None = None


class PerformanceRequest(BaseModel):
    interface: str | None = None
    sample_seconds: int = Field(default=15, ge=5, le=60)
    run_speedtest: bool = True
    ai_endpoint: str | None = "https://api.openai.com/v1/chat/completions"
    ai_model: str | None = "gpt-4.1-mini"
    ai_api_key: str | None = None


class WebsiteSecurityRequest(BaseModel):
    url: str
    confirm_authorized: bool = False
    include_sensitive_paths: bool = True
    ai_endpoint: str | None = "https://api.openai.com/v1/chat/completions"
    ai_model: str | None = "gpt-4.1-mini"
    ai_api_key: str | None = None


# ── State classes ─────────────────────────────────────────────────────────────


class RunState:
    """Base state shared by all async runs (scan, bad-agent, performance, website)."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.status: str = "queued"
        self.events: list[dict[str, Any]] = []
        self.subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self.report: dict[str, Any] | None = None
        self.error: str | None = None

    async def publish(self, payload: dict[str, Any]) -> None:
        self.events.append(payload)
        for queue in list(self.subscribers):
            await queue.put(payload)


class ScanState(RunState):
    def __init__(self, scan_id: str, target: str, profile: str) -> None:
        super().__init__(scan_id)
        self.scan_id = scan_id
        self.target = target
        self.profile = profile


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


class BadAgentState(RunState):
    def __init__(self, agent_id: str, request: BadAgentRequest) -> None:
        super().__init__(agent_id)
        self.agent_id = agent_id
        self.target = request.target
        self.tests = request.tests


class PerformanceState(RunState):
    def __init__(self, analysis_id: str, request: PerformanceRequest) -> None:
        super().__init__(analysis_id)
        self.analysis_id = analysis_id
        self.interface = request.interface


class WebsiteSecurityState(RunState):
    def __init__(self, scan_id: str, request: WebsiteSecurityRequest) -> None:
        super().__init__(scan_id)
        self.scan_id = scan_id
        self.url = request.url


# ── In-memory registries ──────────────────────────────────────────────────────

scans: dict[str, ScanState] = {}
schedules: dict[str, ScheduleState] = {}
bad_agents: dict[str, BadAgentState] = {}
performance_runs: dict[str, PerformanceState] = {}
website_runs: dict[str, WebsiteSecurityState] = {}

# ── Shared helpers ────────────────────────────────────────────────────────────


def _or_404(registry: dict[str, _T], key: str, detail: str) -> _T:
    item = registry.get(key)
    if item is None:
        raise HTTPException(status_code=404, detail=detail)
    return item


def _scan_or_404(scan_id: str) -> ScanState:
    return _or_404(scans, scan_id, "Scan nao encontrado.")


def _bad_agent_or_404(agent_id: str) -> BadAgentState:
    return _or_404(bad_agents, agent_id, "test_bad_agent nao encontrado.")


def _performance_or_404(analysis_id: str) -> PerformanceState:
    return _or_404(performance_runs, analysis_id, "Network Performance não encontrado.")


def _website_security_or_404(scan_id: str) -> WebsiteSecurityState:
    return _or_404(website_runs, scan_id, "Website Security não encontrado.")


async def _event_stream(state: RunState):
    """Generic SSE generator — works with any RunState subclass."""
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


async def _run_task(state: RunState, coro: Coroutine[Any, Any, dict[str, Any]]) -> None:
    """Generic task runner — drives any run coroutine and updates state accordingly."""
    state.status = "running"
    try:
        state.report = await coro
        state.status = "finished"
    except Exception as exc:
        state.error = str(exc)
        state.status = "failed"
        await state.publish({"event": "failed", "message": str(exc), "data": {}})


def _sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _ai_config(request: BadAgentRequest | PerformanceRequest | WebsiteSecurityRequest) -> dict[str, str | None]:
    return {"endpoint": request.ai_endpoint, "model": request.ai_model, "api_key": request.ai_api_key}


# ── Routes: general ───────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return Path("static/index.html").read_text(encoding="utf-8")


# ── Routes: scans ─────────────────────────────────────────────────────────────


@app.post("/api/scans")
async def create_scan(request: ScanRequest) -> dict[str, str]:
    try:
        validate_target(request.target)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan_id = uuid.uuid4().hex[:12]
    state = ScanState(scan_id, request.target, request.profile)
    scans[scan_id] = state
    asyncio.create_task(_run_task(state, run_scan(scan_id, request.target, request.profile, state.publish)))
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
    return StreamingResponse(_event_stream(_scan_or_404(scan_id)), media_type="text/event-stream")


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


# ── Routes: exports ───────────────────────────────────────────────────────────


@app.get("/api/exports/{report_type}/{report_id}.{format_name}")
async def export_report_endpoint(report_type: str, report_id: str, format_name: str) -> Response:
    try:
        content, media_type, filename = export_report(report_type, report_id, format_name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Relatorio nao encontrado.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    encoded_name = urllib.parse.quote(filename, safe="")
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}"},
    )


# ── Routes: schedules ─────────────────────────────────────────────────────────


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


# ── Routes: bad-agent ─────────────────────────────────────────────────────────


@app.get("/api/bad-agent/tests")
async def bad_agent_tests() -> dict[str, str]:
    return SAFE_TESTS


@app.post("/api/bad-agent/models")
async def bad_agent_models(request: AiModelsRequest) -> dict[str, Any]:
    return await list_ai_models(request.ai_endpoint, request.ai_api_key)


@app.post("/api/ai/models")
async def ai_models(request: AiModelsRequest) -> dict[str, Any]:
    return await list_ai_models(request.ai_endpoint, request.ai_api_key)


@app.get("/api/bad-agent/media/{file_name}")
async def bad_agent_media(file_name: str) -> FileResponse:
    if not re.fullmatch(r"[A-Za-z0-9_.%-]{1,120}", file_name):
        raise HTTPException(status_code=400, detail="Nome de arquivo invalido.")
    path = AGENT_MEDIA_DIR / file_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Midia nao encontrada.")
    return FileResponse(path, media_type="image/jpeg", filename=file_name)


@app.post("/api/bad-agent")
async def create_bad_agent(request: BadAgentRequest) -> dict[str, str]:
    try:
        validate_target(request.target)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    agent_id = uuid.uuid4().hex[:12]
    state = BadAgentState(agent_id, request)
    bad_agents[agent_id] = state
    asyncio.create_task(_run_task(state, run_bad_agent(
        agent_id,
        request.target,
        request.tests,
        request.capture_rtsp_frame,
        _ai_config(request),
        state.publish,
    )))
    return {"agent_id": agent_id, "events_url": f"/api/bad-agent/{agent_id}/events"}


@app.get("/api/bad-agent/{agent_id}")
async def get_bad_agent(agent_id: str) -> dict[str, Any]:
    state = _bad_agent_or_404(agent_id)
    return {
        "id": state.agent_id,
        "target": state.target,
        "tests": state.tests,
        "status": state.status,
        "created_at": state.created_at,
        "events": state.events,
        "report": state.report,
        "error": state.error,
    }


@app.get("/api/bad-agent/{agent_id}/events")
async def bad_agent_events(agent_id: str) -> StreamingResponse:
    return StreamingResponse(_event_stream(_bad_agent_or_404(agent_id)), media_type="text/event-stream")


# ── Routes: performance ───────────────────────────────────────────────────────


@app.post("/api/performance")
async def create_performance(request: PerformanceRequest) -> dict[str, str]:
    analysis_id = uuid.uuid4().hex[:12]
    state = PerformanceState(analysis_id, request)
    performance_runs[analysis_id] = state
    asyncio.create_task(_run_task(state, run_network_performance(
        analysis_id,
        request.interface,
        request.sample_seconds,
        request.run_speedtest,
        _ai_config(request),
        state.publish,
    )))
    return {"analysis_id": analysis_id, "events_url": f"/api/performance/{analysis_id}/events"}


@app.get("/api/performance/{analysis_id}")
async def get_performance(analysis_id: str) -> dict[str, Any]:
    state = _performance_or_404(analysis_id)
    return {
        "id": state.analysis_id,
        "interface": state.interface,
        "status": state.status,
        "created_at": state.created_at,
        "events": state.events,
        "report": state.report,
        "error": state.error,
    }


@app.get("/api/performance/{analysis_id}/events")
async def performance_events(analysis_id: str) -> StreamingResponse:
    return StreamingResponse(_event_stream(_performance_or_404(analysis_id)), media_type="text/event-stream")


# ── Routes: website-security ──────────────────────────────────────────────────


@app.post("/api/website-security")
async def create_website_security(request: WebsiteSecurityRequest) -> dict[str, str]:
    if not request.confirm_authorized:
        raise HTTPException(status_code=400, detail="Confirme que você tem autorização para testar este site.")
    scan_id = uuid.uuid4().hex[:12]
    state = WebsiteSecurityState(scan_id, request)
    website_runs[scan_id] = state
    asyncio.create_task(_run_task(state, run_website_security(
        scan_id,
        request.url,
        request.include_sensitive_paths,
        _ai_config(request),
        state.publish,
    )))
    return {"scan_id": scan_id, "events_url": f"/api/website-security/{scan_id}/events"}


@app.get("/api/website-security/{scan_id}")
async def get_website_security(scan_id: str) -> dict[str, Any]:
    state = _website_security_or_404(scan_id)
    return {
        "id": state.scan_id,
        "url": state.url,
        "status": state.status,
        "created_at": state.created_at,
        "events": state.events,
        "report": state.report,
        "error": state.error,
    }


@app.get("/api/website-security/{scan_id}/events")
async def website_security_events(scan_id: str) -> StreamingResponse:
    return StreamingResponse(_event_stream(_website_security_or_404(scan_id)), media_type="text/event-stream")


# ── Schedule internals ────────────────────────────────────────────────────────


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
