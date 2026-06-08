import asyncio
import json
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from scanner import (
    HTTP_PORTS,
    REPORTS_DIR,
    PortResult,
    grab_http_title,
    ip_list,
    scan_ports,
    serialize_dataclass,
    tcp_connect,
    utc_now,
    validate_target,
)


AGENT_MEDIA_DIR = REPORTS_DIR / "agent_media"
SAFE_TESTS = {
    "admin_panels": "Painéis administrativos HTTP/HTTPS expostos",
    "insecure_services": "Serviços inseguros ou sensíveis",
    "camera_rtsp": "Câmeras/DVR com RTSP aberto",
    "segmentation": "Sinais de falta de segmentação",
}
SENSITIVE_PORTS = [21, 22, 23, 80, 139, 443, 445, 554, 1883, 5000, 5001, 5900, 8000, 8080, 8443, 8888, 9000, 3389]


@dataclass
class AgentEvidence:
    target: str
    title: str
    severity: str
    detail: str
    proof: str
    correction: str
    links: list[dict[str, str]] = field(default_factory=list)
    media: dict[str, str] | None = None


async def run_bad_agent(
    agent_id: str,
    target: str,
    tests: list[str],
    capture_rtsp_frame: bool,
    ai_config: dict[str, str | None],
    emit: Callable[[dict[str, Any]], Any],
) -> dict[str, Any]:
    network = validate_target(target)
    selected = [test for test in tests if test in SAFE_TESTS]
    if not selected:
        selected = ["admin_panels", "insecure_services", "camera_rtsp", "segmentation"]

    started = utc_now()
    started_ts = time.perf_counter()
    await _emit(emit, "started", f"test_bad_agent iniciado em {network}", {"agent_id": agent_id, "tests": selected})
    await _emit(
        emit,
        "guardrail",
        "Modo seguro: sem brute force, sem exploits, sem senhas padrao e sem alteracao de configuracao.",
        {},
    )

    hosts = await discover_hosts(ip_list(network), emit)
    evidence: list[AgentEvidence] = []

    await _emit(emit, "phase", f"Checando {len(hosts)} host(s) com portas sensiveis comuns.", {})
    scanned_hosts = await scan_agent_hosts(hosts, emit)

    if "admin_panels" in selected:
        evidence.extend(await test_admin_panels(scanned_hosts, emit))
    if "insecure_services" in selected:
        evidence.extend(await test_insecure_services(scanned_hosts, emit))
    if "camera_rtsp" in selected:
        evidence.extend(await test_camera_rtsp(agent_id, scanned_hosts, capture_rtsp_frame, emit))
    if "segmentation" in selected:
        evidence.extend(await test_segmentation(scanned_hosts, emit))

    summary = summarize(evidence, len(hosts), started_ts)
    ai_analysis = await maybe_ai_analysis(ai_config, network=str(network), summary=summary, evidence=evidence)
    if ai_analysis:
        await _emit(emit, "ai_analysis", "Análise da IA concluída.", {"analysis": ai_analysis})

    report = {
        "id": agent_id,
        "target": str(network),
        "tests": selected,
        "started_at": started,
        "finished_at": utc_now(),
        "summary": summary,
        "hosts": scanned_hosts,
        "evidence": [serialize_dataclass(item) for item in evidence],
        "ai_analysis": ai_analysis,
        "safety": {
            "no_bruteforce": True,
            "no_exploitation": True,
            "no_default_password_attempts": True,
            "rtsp_frame_requires_opt_in": True,
        },
    }
    save_agent_report(agent_id, report)
    await _emit(emit, "finished", "test_bad_agent concluído.", report)
    return report


async def discover_hosts(hosts: list[str], emit: Callable[[dict[str, Any]], Any]) -> list[str]:
    alive: list[str] = []
    sem = asyncio.Semaphore(64)

    async def check(ip: str) -> None:
        async with sem:
            probes = [tcp_connect(ip, port, timeout=0.35) for port in [80, 443, 22, 23, 445, 554, 8080]]
            if any(await asyncio.gather(*probes)):
                alive.append(ip)
                await _emit(emit, "host_found", f"Host com superfície exposta: {ip}", {"ip": ip})

    await _emit(emit, "phase", f"Descobrindo hosts por sondagem TCP leve em {len(hosts)} endereços.", {})
    await asyncio.gather(*(check(ip) for ip in hosts))
    return sorted(alive, key=lambda value: tuple(int(part) for part in value.split(".")))


async def scan_agent_hosts(hosts: list[str], emit: Callable[[dict[str, Any]], Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(16)

    async def scan_one(ip: str) -> None:
        async with sem:
            ports = await scan_ports(ip, SENSITIVE_PORTS)
            result = {"ip": ip, "open_ports": [serialize_dataclass(port) for port in ports]}
            results.append(result)
            await _emit(emit, "host_scanned", f"{ip}: {len(ports)} porta(s) sensível(eis) aberta(s).", result)

    await asyncio.gather(*(scan_one(ip) for ip in hosts))
    return sorted(results, key=lambda item: tuple(int(part) for part in item["ip"].split(".")))


async def test_admin_panels(hosts: list[dict[str, Any]], emit: Callable[[dict[str, Any]], Any]) -> list[AgentEvidence]:
    await _emit(emit, "test", "Testando painéis HTTP/HTTPS acessíveis.", {"test": "admin_panels"})
    evidence = []
    for host in hosts:
        ip = host["ip"]
        for port in _ports(host, HTTP_PORTS):
            title = await grab_http_title(ip, port.port)
            scheme = _scheme(port.port)
            links = [{"label": f"Abrir {scheme.upper()} {port.port}", "url": _url(ip, port.port)}]
            severity = "medium" if scheme == "http" else "low"
            evidence.append(
                AgentEvidence(
                    target=f"{ip}:{port.port}",
                    title="Painel web acessível",
                    severity=severity,
                    detail="Um serviço web respondeu na rede testada. Pode ser roteador, repetidor, câmera, DVR, NAS ou IoT.",
                    proof=f"Título/servidor observado: {title or port.title or port.banner or 'sem título'}",
                    correction="Confirmar se o painel é necessário, usar senha forte, atualizar firmware e restringir acesso por rede/VLAN.",
                    links=links,
                )
            )
    return evidence


async def test_insecure_services(hosts: list[dict[str, Any]], emit: Callable[[dict[str, Any]], Any]) -> list[AgentEvidence]:
    await _emit(emit, "test", "Testando serviços inseguros ou sensíveis.", {"test": "insecure_services"})
    notes = {
        21: ("FTP exposto", "high", "FTP pode expor credenciais e arquivos sem proteção adequada.", "Desativar FTP ou trocar por SFTP/VPN."),
        23: ("Telnet exposto", "critical", "Telnet transmite credenciais em texto claro.", "Desativar Telnet imediatamente."),
        445: ("SMB exposto", "high", "SMB acessível aumenta risco de movimento lateral.", "Bloquear SMB para redes visitante/IoT e revisar compartilhamentos."),
        1883: ("MQTT exposto", "high", "MQTT aberto pode afetar automação e IoT.", "Exigir autenticação/TLS ou isolar o broker."),
        3389: ("RDP exposto", "high", "RDP deve ficar restrito a VPN/Tailscale e hosts confiáveis.", "Bloquear RDP em redes não confiáveis."),
        5900: ("VNC exposto", "high", "VNC deve ser evitado fora de VPN e senha forte.", "Usar VPN/Tailscale e firewall local."),
    }
    evidence = []
    for host in hosts:
        ip = host["ip"]
        for port in _ports(host, set(notes)):
            title, severity, detail, correction = notes[port.port]
            evidence.append(
                AgentEvidence(
                    target=f"{ip}:{port.port}",
                    title=title,
                    severity=severity,
                    detail=detail,
                    proof=f"Conexão TCP aceita em {ip}:{port.port}. Banner: {port.banner or 'não coletado'}",
                    correction=correction,
                )
            )
    return evidence


async def test_camera_rtsp(
    agent_id: str,
    hosts: list[dict[str, Any]],
    capture_rtsp_frame: bool,
    emit: Callable[[dict[str, Any]], Any],
) -> list[AgentEvidence]:
    await _emit(emit, "test", "Testando RTSP sem autenticação agressiva.", {"test": "camera_rtsp"})
    evidence = []
    for host in hosts:
        ip = host["ip"]
        for port in _ports(host, {554}):
            rtsp_url = f"rtsp://{ip}:{port.port}/"
            options_result = await rtsp_options(ip, port.port)
            media = None
            proof = options_result or "Porta RTSP aceitou conexão TCP."
            if capture_rtsp_frame:
                media = await capture_rtsp_snapshot(agent_id, ip, port.port, emit)
                if media:
                    proof = f"{proof} Frame RTSP sem credencial capturado com sucesso."
            evidence.append(
                AgentEvidence(
                    target=f"{ip}:{port.port}",
                    title="RTSP de câmera/DVR acessível",
                    severity="high" if media or options_result else "medium",
                    detail="RTSP aberto indica câmera/DVR ou fluxo de vídeo acessível na rede testada.",
                    proof=proof,
                    correction="Trocar senha da câmera/DVR, atualizar firmware, isolar em rede IoT e impedir acesso por visitantes/internet.",
                    links=[{"label": "URL RTSP base", "url": rtsp_url}],
                    media=media,
                )
            )
    return evidence


async def test_segmentation(hosts: list[dict[str, Any]], emit: Callable[[dict[str, Any]], Any]) -> list[AgentEvidence]:
    await _emit(emit, "test", "Avaliando sinais de segmentação fraca.", {"test": "segmentation"})
    web_hosts = [host for host in hosts if _ports(host, HTTP_PORTS)]
    camera_hosts = [host for host in hosts if _ports(host, {554})]
    smb_hosts = [host for host in hosts if _ports(host, {139, 445})]
    evidence = []
    if len(web_hosts) >= 4:
        evidence.append(
            AgentEvidence(
                target="rede",
                title="Muitos painéis internos acessíveis",
                severity="medium",
                detail=f"Foram encontrados {len(web_hosts)} hosts com HTTP/HTTPS ou painéis alternativos.",
                proof="Um atacante conectado à mesma rede teria vários alvos administrativos para tentar acessar manualmente.",
                correction="Separar IoT/visitantes, restringir painéis por VLAN/firewall e padronizar senhas fortes.",
            )
        )
    if camera_hosts and smb_hosts:
        evidence.append(
            AgentEvidence(
                target="rede",
                title="Câmeras e compartilhamento na mesma superfície",
                severity="high",
                detail="Foram vistos sinais de câmeras/DVR e SMB na mesma varredura.",
                proof="Essa combinação aumenta risco de movimento lateral caso um IoT seja comprometido.",
                correction="Isolar câmeras/DVR em rede IoT e bloquear acesso delas aos PCs/NAS.",
            )
        )
    return evidence


async def rtsp_options(ip: str, port: int) -> str | None:
    def probe() -> str | None:
        request = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: HeadAttackSafeProbe/1.0\r\n\r\n"
        try:
            with socket.create_connection((ip, port), timeout=1.5) as sock:
                sock.sendall(request.encode("ascii"))
                raw = sock.recv(512).decode("utf-8", errors="replace")
        except OSError:
            return None
        status = raw.splitlines()[0] if raw else ""
        public = next((line for line in raw.splitlines() if line.lower().startswith("public:")), "")
        return " ".join(part for part in [status, public] if part)[:220] or None

    return await asyncio.to_thread(probe)


async def capture_rtsp_snapshot(
    agent_id: str,
    ip: str,
    port: int,
    emit: Callable[[dict[str, Any]], Any],
) -> dict[str, str] | None:
    if not shutil.which("ffmpeg"):
        await _emit(emit, "rtsp_snapshot", "ffmpeg não encontrado; frame RTSP não será capturado.", {"ip": ip})
        return None

    AGENT_MEDIA_DIR.mkdir(parents=True, exist_ok=True)
    file_name = f"{agent_id}_{ip.replace('.', '_')}_{port}.jpg"
    output = AGENT_MEDIA_DIR / file_name
    command = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-i",
        f"rtsp://{ip}:{port}/",
        "-frames:v",
        "1",
        "-y",
        str(output),
    ]
    await _emit(emit, "rtsp_snapshot", f"Tentando capturar 1 frame RTSP sem credenciais em {ip}:{port}.", {"ip": ip})
    try:
        result = await asyncio.to_thread(subprocess.run, command, capture_output=True, text=True, timeout=8, check=False)
    except subprocess.TimeoutExpired:
        await _emit(emit, "rtsp_snapshot", f"Timeout ao tentar capturar frame RTSP em {ip}:{port}.", {"ip": ip})
        return None

    if result.returncode == 0 and output.exists() and output.stat().st_size > 0:
        return {"type": "image", "url": f"/api/bad-agent/media/{file_name}", "caption": f"Frame capturado de rtsp://{ip}:{port}/"}
    output.unlink(missing_ok=True)
    return None


async def maybe_ai_analysis(ai_config: dict[str, str | None], network: str, summary: dict[str, Any], evidence: list[AgentEvidence]) -> str | None:
    api_key = (ai_config.get("api_key") or "").strip()
    if not api_key:
        return local_analysis(summary, evidence)

    endpoint = (ai_config.get("endpoint") or "https://api.openai.com/v1/chat/completions").strip()
    model = (ai_config.get("model") or "gpt-4.1-mini").strip()
    if not endpoint.startswith("https://"):
        return local_analysis(summary, evidence) + "\n\nObservação: endpoint de IA ignorado porque apenas HTTPS é aceito."
    prompt = {
        "network": network,
        "summary": summary,
        "evidence": [serialize_dataclass(item) for item in evidence[:30]],
        "instruction": "Write a concise Portuguese defensive report. Do not provide exploit steps, brute-force guidance, payloads, or instructions for attacking third-party systems. Explain business risk, evidence, priority, and remediation.",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a defensive network security analyst. Keep advice authorized, safe, and remediation-focused."},
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
        ],
        "temperature": 0.2,
    }

    def call_ai() -> str | None:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return None
        return data.get("choices", [{}])[0].get("message", {}).get("content")

    return await asyncio.to_thread(call_ai) or local_analysis(summary, evidence)


def local_analysis(summary: dict[str, Any], evidence: list[AgentEvidence]) -> str:
    critical = [item for item in evidence if item.severity == "critical"]
    high = [item for item in evidence if item.severity == "high"]
    medium = [item for item in evidence if item.severity == "medium"]
    lines = [
        f"Análise local: {summary['total_evidence']} evidências foram encontradas.",
        f"Priorize {len(critical)} crítico(s) e {len(high)} alto(s) antes dos itens médios.",
    ]
    for item in (critical + high + medium)[:8]:
        lines.append(f"- {item.target}: {item.title}. Correção: {item.correction}")
    return "\n".join(lines)


def summarize(evidence: list[AgentEvidence], hosts_found: int, started_ts: float) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in evidence:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    return {
        "duration_seconds": round(time.perf_counter() - started_ts, 2),
        "hosts_found": hosts_found,
        "total_evidence": len(evidence),
        "by_severity": counts,
        "overall_status": "critical" if counts["critical"] else "attention" if counts["high"] else "review" if counts["medium"] else "ok",
    }


def save_agent_report(agent_id: str, report: dict[str, Any]) -> None:
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / f"bad_agent_{agent_id}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def _ports(host: dict[str, Any], ports: set[int]) -> list[PortResult]:
    found = []
    for item in host.get("open_ports", []):
        if item["port"] in ports:
            found.append(PortResult(**item))
    return found


def _scheme(port: int) -> str:
    return "https" if port in {443, 5001, 8443} else "http"


def _url(ip: str, port: int) -> str:
    scheme = _scheme(port)
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{ip}{'' if default else f':{port}'}"


async def _emit(emit: Callable[[dict[str, Any]], Any], event: str, message: str, data: dict[str, Any]) -> None:
    payload = {"ts": utc_now(), "event": event, "message": message, "data": data}
    maybe = emit(payload)
    if asyncio.iscoroutine(maybe):
        await maybe
