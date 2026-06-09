import asyncio
import json
import re
import shutil
import socket
import ssl
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
    "bruteforce_readiness": "Superfícies prováveis de força bruta sem tentar senhas",
    "reset_exposure": "Indícios de reset/reboot expostos sem acionar ações",
    "upnp_exposure": "UPnP/SSDP ativo na rede",
}
SENSITIVE_PORTS = [21, 22, 23, 80, 139, 443, 445, 554, 1883, 5000, 5001, 5900, 8000, 8080, 8443, 8888, 9000, 3389]
DEFAULT_AI_MODEL = "gpt-4.1-mini"


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
    if "bruteforce_readiness" in selected:
        evidence.extend(await test_bruteforce_readiness(scanned_hosts, emit))
    if "reset_exposure" in selected:
        evidence.extend(await test_reset_exposure(scanned_hosts, emit))
    if "upnp_exposure" in selected:
        evidence.extend(await test_upnp_exposure(emit))

    summary = summarize(evidence, len(hosts), started_ts)
    ai_analysis = await maybe_ai_analysis(ai_config, network=str(network), summary=summary, evidence=evidence)
    await _emit(
        emit,
        "ai_analysis",
        "Análise por IA concluída." if ai_analysis["used_api"] else "Análise local concluída; nenhum token de IA foi consumido.",
        {"analysis": ai_analysis},
    )

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


async def test_bruteforce_readiness(hosts: list[dict[str, Any]], emit: Callable[[dict[str, Any]], Any]) -> list[AgentEvidence]:
    await _emit(emit, "test", "Simulando avaliação de força bruta sem tentar credenciais.", {"test": "bruteforce_readiness"})
    evidence = []
    brute_ports = {
        21: ("FTP", "high"),
        22: ("SSH", "medium"),
        23: ("Telnet", "critical"),
        3389: ("RDP", "high"),
        5900: ("VNC", "high"),
    }
    for host in hosts:
        ip = host["ip"]
        for port in _ports(host, set(brute_ports)):
            service, severity = brute_ports[port.port]
            evidence.append(
                AgentEvidence(
                    target=f"{ip}:{port.port}",
                    title=f"{service} seria alvo comum de força bruta",
                    severity=severity,
                    detail="O agente não tentou usuário/senha, mas este serviço costuma ser atacado por tentativas automatizadas.",
                    proof=f"Conexão TCP aceita em {ip}:{port.port}; nenhuma credencial foi enviada.",
                    correction="Permitir acesso apenas por VPN/Tailscale/rede administrativa, usar senha forte/chaves/MFA quando disponível e ativar bloqueio por tentativas.",
                )
            )

        for port in _ports(host, HTTP_PORTS):
            sample = await fetch_http_sample(ip, port.port)
            if sample and looks_like_login(sample["body"]):
                evidence.append(
                    AgentEvidence(
                        target=f"{ip}:{port.port}",
                        title="Tela de login exposta a tentativas manuais/automatizadas",
                        severity="medium",
                        detail="Foi encontrada uma superfície de login web. Nenhuma senha foi testada.",
                        proof=f"Página contém campos/termos de login. Status: {sample['status'] or 'desconhecido'}",
                        correction="Usar senha forte, desativar usuário padrão, limitar origem por rede/VLAN e verificar se há bloqueio por tentativas.",
                        links=[{"label": "Abrir painel", "url": _url(ip, port.port)}],
                    )
                )
    return evidence


async def test_reset_exposure(hosts: list[dict[str, Any]], emit: Callable[[dict[str, Any]], Any]) -> list[AgentEvidence]:
    await _emit(emit, "test", "Procurando indícios de reset/reboot sem acionar endpoints.", {"test": "reset_exposure"})
    evidence = []
    reset_pattern = re.compile(r"\b(reset|reboot|restart|factory|restore|reiniciar|restaurar|padr[aã]o de f[aá]brica)\b", re.I)
    for host in hosts:
        ip = host["ip"]
        for port in _ports(host, HTTP_PORTS):
            sample = await fetch_http_sample(ip, port.port)
            if not sample:
                continue
            body = sample["body"]
            if reset_pattern.search(body):
                evidence.append(
                    AgentEvidence(
                        target=f"{ip}:{port.port}",
                        title="Painel menciona reset/reboot",
                        severity="medium",
                        detail="A página inicial/painel contém termos de reset/reboot. O agente não chamou rotas de ação.",
                        proof="Termos sensíveis encontrados no HTML retornado pela página acessível.",
                        correction="Confirmar que ações de reset/reboot exigem autenticação, token anti-CSRF e não aceitam GET direto.",
                        links=[{"label": "Abrir painel", "url": _url(ip, port.port)}],
                    )
                )
    return evidence


async def test_upnp_exposure(emit: Callable[[dict[str, Any]], Any]) -> list[AgentEvidence]:
    await _emit(emit, "test", "Enviando descoberta SSDP única para detectar UPnP.", {"test": "upnp_exposure"})
    devices = await ssdp_discover()
    evidence = []
    for device in devices:
        server = device.get("server") or "servidor não informado"
        location = device.get("location") or ""
        target = device.get("address") or "rede"
        severity = "high" if "InternetGatewayDevice" in device.get("st", "") else "medium"
        evidence.append(
            AgentEvidence(
                target=target,
                title="UPnP/SSDP respondeu na rede",
                severity=severity,
                detail="UPnP pode permitir abertura automática de portas e descoberta de dispositivos. SSDP é multicast local e reflete a rede onde este PC está conectado.",
                proof=f"ST: {device.get('st', 'desconhecido')}; Server: {server}",
                correction="Desativar UPnP no roteador principal e revisar dispositivos que anunciam serviços SSDP.",
                links=[{"label": "Descrição UPnP", "url": location}] if location.startswith(("http://", "https://")) else [],
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


async def fetch_http_sample(ip: str, port: int) -> dict[str, str] | None:
    def fetch() -> dict[str, str] | None:
        scheme = _scheme(port)
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: HeadAttackSafeProbe/1.0\r\nConnection: close\r\n\r\n"
        try:
            with socket.create_connection((ip, port), timeout=1.5) as sock:
                if scheme == "https":
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                        tls_sock.sendall(request.encode("ascii"))
                        raw = tls_sock.recv(8192)
                else:
                    sock.sendall(request.encode("ascii"))
                    raw = sock.recv(8192)
        except OSError:
            return None
        text = raw.decode("utf-8", errors="replace")
        status = text.splitlines()[0] if text else ""
        return {"status": status[:120], "body": text[:8192]}

    return await asyncio.to_thread(fetch)


def looks_like_login(body: str) -> bool:
    login_terms = ["password", "senha", "login", "username", "usuario", "usuário", "admin"]
    lowered = body.lower()
    return "<input" in lowered and any(term in lowered for term in login_terms)


async def ssdp_discover() -> list[dict[str, str]]:
    def discover() -> list[dict[str, str]]:
        message = "\r\n".join(
            [
                "M-SEARCH * HTTP/1.1",
                "HOST: 239.255.255.250:1900",
                'MAN: "ssdp:discover"',
                "MX: 1",
                "ST: ssdp:all",
                "",
                "",
            ]
        ).encode("ascii")
        devices: list[dict[str, str]] = []
        seen = set()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                sock.settimeout(1.5)
                sock.sendto(message, ("239.255.255.250", 1900))
                while True:
                    try:
                        raw, address = sock.recvfrom(4096)
                    except socket.timeout:
                        break
                    text = raw.decode("utf-8", errors="replace")
                    headers = parse_ssdp_headers(text)
                    key = (address[0], headers.get("st", ""), headers.get("location", ""))
                    if key in seen:
                        continue
                    seen.add(key)
                    devices.append(
                        {
                            "address": address[0],
                            "st": headers.get("st", ""),
                            "server": headers.get("server", ""),
                            "location": headers.get("location", ""),
                        }
                    )
        except OSError:
            return []
        return devices[:20]

    return await asyncio.to_thread(discover)


def parse_ssdp_headers(text: str) -> dict[str, str]:
    headers = {}
    for line in text.splitlines()[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


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


async def list_ai_models(endpoint: str | None, api_key: str | None) -> dict[str, Any]:
    key = (api_key or "").strip()
    if not key:
        return {
            "models": [],
            "source": "not_loaded",
            "message": "Informe uma API key para carregar os modelos disponíveis para sua conta.",
        }

    models_endpoint = models_endpoint_from_chat_endpoint(endpoint or "https://api.openai.com/v1/chat/completions")
    if not models_endpoint.startswith("https://"):
        return {"models": [], "source": "blocked", "message": "Apenas endpoints HTTPS são aceitos."}

    def call_models() -> dict[str, Any]:
        request = urllib.request.Request(
            models_endpoint,
            headers={"Authorization": f"Bearer {key}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            return {"models": [], "source": "error", "message": f"Não foi possível carregar modelos: {exc}"}

        models = sorted(
            item.get("id", "")
            for item in data.get("data", [])
            if isinstance(item, dict) and item.get("id")
        )
        return {"models": models, "source": "api", "message": f"{len(models)} modelo(s) carregado(s)."}

    return await asyncio.to_thread(call_models)


async def maybe_ai_analysis(ai_config: dict[str, str | None], network: str, summary: dict[str, Any], evidence: list[AgentEvidence]) -> dict[str, Any]:
    api_key = (ai_config.get("api_key") or "").strip()
    if not api_key:
        return local_ai_result(local_analysis(summary, evidence), "API key não informada.")

    endpoint = (ai_config.get("endpoint") or "https://api.openai.com/v1/chat/completions").strip()
    model = (ai_config.get("model") or DEFAULT_AI_MODEL).strip()
    if not endpoint.startswith("https://"):
        return local_ai_result(local_analysis(summary, evidence), "Endpoint de IA ignorado porque apenas HTTPS é aceito.")
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

    def call_ai() -> dict[str, Any]:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            return local_ai_result(local_analysis(summary, evidence), f"Falha ao chamar IA; fallback local usado: {exc}")

        content = data.get("choices", [{}])[0].get("message", {}).get("content") or ""
        usage = data.get("usage") or {}
        return {
            "content": content or local_analysis(summary, evidence),
            "used_api": bool(content),
            "provider": "openai_compatible",
            "model": data.get("model") or model,
            "token_usage": {
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            "fallback_reason": None if content else "Resposta sem conteúdo; análise local usada.",
        }

    return await asyncio.to_thread(call_ai)


def models_endpoint_from_chat_endpoint(endpoint: str) -> str:
    clean = endpoint.strip().rstrip("/")
    if clean.endswith("/chat/completions"):
        return clean[: -len("/chat/completions")] + "/models"
    if clean.endswith("/responses"):
        return clean[: -len("/responses")] + "/models"
    if clean.endswith("/models"):
        return clean
    return clean + "/models"


def local_ai_result(content: str, reason: str) -> dict[str, Any]:
    return {
        "content": content,
        "used_api": False,
        "provider": "local",
        "model": "local-summary",
        "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "fallback_reason": reason,
    }


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
