import asyncio
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from utils import emit_event, save_json_report, utc_now


PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # Tailscale/CGNAT
]

COMMON_PORTS = {
    21: ("FTP", "high", "FTP aberto pode expor arquivos e credenciais sem protecao adequada."),
    22: ("SSH", "medium", "SSH aberto deve usar senha forte ou chave, e acesso restrito."),
    23: ("Telnet", "critical", "Telnet transmite credenciais em texto claro e deve ser desativado."),
    53: ("DNS", "medium", "DNS interno deve responder apenas para clientes autorizados."),
    80: ("HTTP", "medium", "Painel web sem HTTPS deve ter senha forte e acesso restrito."),
    139: ("NetBIOS", "medium", "Compartilhamento legado pode aumentar risco de movimento lateral."),
    443: ("HTTPS", "info", "HTTPS aberto pode ser painel administrativo ou servico interno."),
    445: ("SMB", "high", "SMB aberto na LAN deve ter compartilhamentos e permissoes revisados."),
    554: ("RTSP", "high", "RTSP costuma indicar camera/DVR; isole IoT e troque senhas padrao."),
    631: ("IPP", "medium", "Impressora acessivel deve ficar restrita a usuarios confiaveis."),
    1883: ("MQTT", "high", "MQTT sem autenticacao pode expor automacao/IoT."),
    5000: ("HTTP-alt", "medium", "Servico web alternativo pode ser painel de NAS, camera ou IoT."),
    5001: ("HTTPS-alt", "medium", "Servico web alternativo deve ter autenticacao e atualizacoes."),
    5900: ("VNC", "high", "VNC aberto deve ser evitado ou protegido por VPN e senha forte."),
    8000: ("HTTP-alt", "medium", "Painel web alternativo deve ser revisado."),
    8080: ("HTTP-alt", "medium", "Painel web alternativo deve ser revisado."),
    8443: ("HTTPS-alt", "medium", "Painel HTTPS alternativo deve ser revisado."),
    8888: ("HTTP-alt", "medium", "Painel web alternativo deve ser revisado."),
    9000: ("HTTP-alt", "medium", "Servico web alternativo deve ser revisado."),
    9100: ("JetDirect", "medium", "Porta de impressao direta pode permitir impressao indevida na LAN."),
    3389: ("RDP", "high", "RDP deve ficar bloqueado na LAN nao confiavel e nunca exposto diretamente."),
}

DISCOVERY_PORTS = [80, 443, 22, 23, 445, 554, 8080]
HTTP_PORTS = {80, 443, 5000, 5001, 8000, 8080, 8443, 8888, 9000}
REPORTS_DIR = Path("reports")


@dataclass
class PortResult:
    port: int
    service: str
    severity: str
    note: str
    banner: str | None = None
    title: str | None = None
    cves: list[dict] = field(default_factory=list)


@dataclass
class HostResult:
    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor_hint: str | None = None
    latency_ms: float | None = None
    open_ports: list[PortResult] = field(default_factory=list)
    role_hints: list[str] = field(default_factory=list)


@dataclass
class Finding:
    severity: str
    target: str
    title: str
    detail: str
    correction: str


class ScanError(ValueError):
    pass


def validate_target(target: str, max_hosts: int = 512) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError as exc:
        raise ScanError("Informe uma rede valida, por exemplo 192.168.15.0/24.") from exc

    if network.version != 4:
        raise ScanError("Por enquanto o scanner aceita apenas IPv4.")

    if not any(network.subnet_of(allowed) or network.overlaps(allowed) for allowed in PRIVATE_RANGES):
        raise ScanError("Por seguranca, use apenas redes privadas ou Tailscale/CGNAT.")

    if network.num_addresses > max_hosts:
        raise ScanError(f"Rede muito grande para uma checagem leve. Limite atual: {max_hosts} enderecos.")

    return network


def local_context() -> dict[str, Any]:
    return {
        "default_route": _run_text(["ip", "route", "show", "default"]),
        "addresses": _run_text(["ip", "-br", "addr"]),
        "dns": _read_resolv_conf(),
        "neighbors": parse_neighbors(),
    }


def parse_neighbors() -> dict[str, dict[str, str | None]]:
    output = _run_text(["ip", "neigh", "show"])
    neighbors: dict[str, dict[str, str | None]] = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        mac = None
        if "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1]
        neighbors[ip] = {"mac": mac, "state": parts[-1] if parts else None}
    return neighbors


def _read_resolv_conf() -> list[str]:
    path = Path("/etc/resolv.conf")
    if not path.exists():
        return []
    nameservers = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("nameserver "):
            nameservers.append(line.split()[1])
    return nameservers


def _run_text(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip()


def ip_list(network: ipaddress.IPv4Network) -> list[str]:
    if network.prefixlen == 32:
        return [str(network.network_address)]
    return [str(ip) for ip in network.hosts()]


async def run_scan(
    scan_id: str,
    target: str,
    profile: str,
    emit: Callable[[dict[str, Any]], Any],
) -> dict[str, Any]:
    network = validate_target(target)
    ports = _ports_for_profile(profile)
    hosts = ip_list(network)
    started = utc_now()
    started_ts = time.perf_counter()

    await emit_event(emit, "started", f"Iniciando varredura defensiva em {network}", {"scan_id": scan_id})
    context = local_context()
    await emit_event(emit, "context", "Contexto local coletado: rotas, DNS e vizinhos ARP.", context)

    alive_hosts: list[str] = []
    discovery_sem = asyncio.Semaphore(64)

    async def discover(ip: str) -> None:
        async with discovery_sem:
            latency = await ping_host(ip)
            open_probe = False
            if latency is None:
                open_probe = await has_any_tcp_port(ip, DISCOVERY_PORTS)
            if latency is not None or open_probe:
                alive_hosts.append(ip)
                await emit_event(emit, "host_found", f"Host ativo encontrado: {ip}", {"ip": ip, "latency_ms": latency})

    await emit_event(emit, "phase", f"Descobrindo hosts ativos em {len(hosts)} enderecos.", {})
    await asyncio.gather(*(discover(ip) for ip in hosts))
    alive_hosts.sort(key=lambda value: int(ipaddress.ip_address(value)))

    await emit_event(emit, "phase", f"{len(alive_hosts)} host(s) ativo(s). Checando portas comuns.", {})

    neighbors = parse_neighbors()
    results: list[HostResult] = []
    scan_sem = asyncio.Semaphore(24)

    async def scan_one(ip: str) -> None:
        async with scan_sem:
            host = HostResult(ip=ip)
            host.latency_ms = await ping_host(ip)
            neighbor = neighbors.get(ip) or context["neighbors"].get(ip) or {}
            host.mac = neighbor.get("mac")
            host.hostname = await reverse_dns(ip)
            host.open_ports = await scan_ports(ip, ports)
            host.role_hints = role_hints(host)
            results.append(host)
            await emit_event(
                emit,
                "host_scanned",
                f"{ip}: {len(host.open_ports)} porta(s) aberta(s).",
                {"host": serialize_dataclass(host)},
            )

    await asyncio.gather(*(scan_one(ip) for ip in alive_hosts))
    results.sort(key=lambda item: int(ipaddress.ip_address(item.ip)))

    await enrich_with_cves(results, emit)

    findings = build_findings(results, network)
    summary = build_summary(results, findings, started_ts)
    report = {
        "id": scan_id,
        "target": str(network),
        "profile": profile,
        "started_at": started,
        "finished_at": utc_now(),
        "local_context": context,
        "summary": summary,
        "hosts": [serialize_dataclass(host) for host in results],
        "findings": [serialize_dataclass(item) for item in findings],
        "manual_checklist": manual_checklist(),
    }
    save_report(scan_id, report)
    await emit_event(emit, "finished", "Scan concluido e relatorio salvo.", report)
    return report


def _ports_for_profile(profile: str) -> list[int]:
    if profile == "quick":
        return [22, 23, 53, 80, 139, 443, 445, 554, 631, 8080, 9100, 3389]
    return sorted(COMMON_PORTS)


async def ping_host(ip: str) -> float | None:
    started = time.perf_counter()
    proc = await asyncio.create_subprocess_exec(
        "ping",
        "-c",
        "1",
        "-W",
        "1",
        ip,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        code = await asyncio.wait_for(proc.wait(), timeout=1.5)
    except asyncio.TimeoutError:
        proc.kill()
        return None
    if code == 0:
        return round((time.perf_counter() - started) * 1000, 2)
    return None


async def has_any_tcp_port(ip: str, ports: list[int]) -> bool:
    tasks = [tcp_connect(ip, port, timeout=0.35) for port in ports]
    results = await asyncio.gather(*tasks)
    return any(results)


async def tcp_connect(ip: str, port: int, timeout: float = 0.6) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def scan_ports(ip: str, ports: list[int]) -> list[PortResult]:
    sem = asyncio.Semaphore(24)
    found: list[PortResult] = []

    async def check(port: int) -> None:
        async with sem:
            if await tcp_connect(ip, port):
                service, severity, note = COMMON_PORTS.get(port, ("unknown", "info", "Porta aberta identificada."))
                banner = await grab_banner(ip, port)
                title = await grab_http_title(ip, port) if port in HTTP_PORTS else None
                found.append(PortResult(port=port, service=service, severity=severity, note=note, banner=banner, title=title))

    await asyncio.gather(*(check(port) for port in ports))
    return sorted(found, key=lambda item: item.port)


async def grab_banner(ip: str, port: int) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.7)
        if port in {21, 22, 23}:
            raw = await asyncio.wait_for(reader.read(120), timeout=0.7)
        else:
            writer.write(b"\r\n")
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(120), timeout=0.7)
        writer.close()
        await writer.wait_closed()
    except (OSError, asyncio.TimeoutError, UnicodeDecodeError):
        return None
    text = raw.decode("utf-8", errors="replace").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:120] or None


async def grab_http_title(ip: str, port: int) -> str | None:
    use_tls = port in {443, 5001, 8443}
    try:
        raw = await asyncio.to_thread(_fetch_http_head, ip, port, use_tls)
    except OSError:
        return None
    match = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
    if not match:
        server = re.search(r"^Server:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
        return server.group(1).strip()[:120] if server else None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:120] or None


def _fetch_http_head(ip: str, port: int, use_tls: bool) -> str:
    request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: SecurityNetworkAudit/1.0\r\nConnection: close\r\n\r\n"
    with socket.create_connection((ip, port), timeout=1.2) as sock:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                tls_sock.sendall(request.encode("ascii"))
                return tls_sock.recv(4096).decode("utf-8", errors="replace")
        sock.sendall(request.encode("ascii"))
        return sock.recv(4096).decode("utf-8", errors="replace")


async def reverse_dns(ip: str) -> str | None:
    try:
        hostname, _, _ = await asyncio.to_thread(socket.gethostbyaddr, ip)
    except (OSError, socket.herror):
        return None
    return hostname


def role_hints(host: HostResult) -> list[str]:
    ports = {item.port for item in host.open_ports}
    hints = []
    if {80, 443, 8080, 8443} & ports:
        hints.append("painel_web")
    if 554 in ports:
        hints.append("camera_ou_dvr")
    if {631, 9100} & ports:
        hints.append("impressora")
    if {445, 139} & ports:
        hints.append("compartilhamento_windows")
    if 3389 in ports:
        hints.append("desktop_remoto")
    if 1883 in ports:
        hints.append("iot_mqtt")
    return hints


def build_findings(hosts: list[HostResult], network: ipaddress.IPv4Network) -> list[Finding]:
    findings: list[Finding] = []
    if not hosts:
        findings.append(
            Finding(
                severity="info",
                target=str(network),
                title="Nenhum host ativo encontrado",
                detail="A rede nao respondeu aos testes leves de descoberta.",
                correction="Confirme se o PC esta na rede certa, se ha bloqueio de ICMP e se o alvo foi digitado corretamente.",
            )
        )
        return findings

    for host in hosts:
        ports = {item.port for item in host.open_ports}
        for port in host.open_ports:
            if port.severity == "info":
                continue
            findings.append(
                Finding(
                    severity=port.severity,
                    target=f"{host.ip}:{port.port}",
                    title=f"{port.service} aberto",
                    detail=port.note,
                    correction=correction_for_port(port.port),
                )
            )

        if 80 in ports and 443 not in ports:
            findings.append(
                Finding(
                    severity="medium",
                    target=host.ip,
                    title="Painel HTTP sem HTTPS aparente",
                    detail="O host tem HTTP aberto e nao apresentou HTTPS nas portas testadas.",
                    correction="Use HTTPS quando disponivel, troque senha padrao e restrinja acesso ao painel administrativo.",
                )
            )

        if "camera_ou_dvr" in host.role_hints:
            findings.append(
                Finding(
                    severity="high",
                    target=host.ip,
                    title="Camera/DVR detectado na rede principal",
                    detail="Dispositivos de camera e DVR costumam ter firmware antigo e credenciais fracas.",
                    correction="Mover para rede IoT/visitante isolada, atualizar firmware e desativar acesso externo direto.",
                )
            )

    web_admin_hosts = [host.ip for host in hosts if "painel_web" in host.role_hints]
    if len(web_admin_hosts) >= 4:
        findings.append(
            Finding(
                severity="medium",
                target=str(network),
                title="Muitos paineis web internos",
                detail=f"Foram encontrados {len(web_admin_hosts)} hosts com painel web ou servico HTTP/HTTPS.",
                correction="Identifique roteadores/repetidores/IoT, padronize senhas fortes e limite quem pode acessar administracao.",
            )
        )

    return sorted(findings, key=lambda item: severity_rank(item.severity), reverse=True)


def correction_for_port(port: int) -> str:
    corrections = {
        21: "Desative FTP ou substitua por SFTP/VPN. Se mantiver, use usuarios individuais e senha forte.",
        22: "Permita SSH apenas para administradores, prefira chave publica e desative login por senha se possivel.",
        23: "Desative Telnet imediatamente e use SSH/HTTPS para administracao.",
        53: "Garanta que DNS nao seja aberto para visitantes ou internet; use apenas como resolver interno.",
        80: "Troque senha padrao, atualize firmware e restrinja acesso ao painel.",
        139: "Desative NetBIOS/SMB legado quando nao necessario.",
        445: "Revise compartilhamentos, permissoes e firewall local; bloqueie para redes visitante/IoT.",
        554: "Troque senha da camera, atualize firmware, isole em rede IoT e evite encaminhamento de porta.",
        631: "Restrinja impressora para a rede confiavel e atualize firmware.",
        1883: "Exija autenticacao/TLS no MQTT ou isole o broker.",
        3389: "Nao exponha RDP diretamente; use VPN/Tailscale e regras de firewall.",
        5900: "Evite VNC aberto; use VPN/Tailscale e senha forte.",
        9100: "Restrinja acesso a impressora e desative impressao direta se nao usa.",
    }
    return corrections.get(port, "Confirme se o servico e necessario; se nao for, desative ou bloqueie por firewall.")


def severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)


def build_summary(hosts: list[HostResult], findings: list[Finding], started_ts: float) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    open_ports = sum(len(host.open_ports) for host in hosts)
    return {
        "duration_seconds": round(time.perf_counter() - started_ts, 2),
        "hosts_found": len(hosts),
        "open_ports": open_ports,
        "findings_by_severity": counts,
        "overall_status": overall_status(counts),
    }


def overall_status(counts: dict[str, int]) -> str:
    if counts.get("critical", 0):
        return "critical"
    if counts.get("high", 0):
        return "attention"
    if counts.get("medium", 0):
        return "review"
    return "ok"


def manual_checklist() -> list[dict[str, str]]:
    return [
        {
            "item": "WPS",
            "why": "WPS facilita conexao indevida quando habilitado.",
            "action": "Desativar WPS no roteador principal e nos repetidores.",
        },
        {
            "item": "UPnP",
            "why": "UPnP pode abrir portas automaticamente para a internet.",
            "action": "Desativar UPnP, exceto se houver necessidade muito clara.",
        },
        {
            "item": "Rede visitante",
            "why": "Visitantes nao devem acessar roteador, cameras, impressora ou PCs.",
            "action": "Testar isolamento conectando um celular na visitante e tentando acessar 192.168.15.1.",
        },
        {
            "item": "IoT separado",
            "why": "Cameras, DVR, assistentes e automacao sao alvos frequentes.",
            "action": "Manter IoT em rede separada/visitante isolada quando possivel.",
        },
        {
            "item": "Firmware",
            "why": "Roteadores, repetidores e cameras antigos acumulam vulnerabilidades.",
            "action": "Atualizar firmware e remover dispositivos sem suporte.",
        },
    ]


def save_report(scan_id: str, report: dict[str, Any]) -> None:
    save_json_report(REPORTS_DIR / f"{scan_id}.json", report)
    (REPORTS_DIR / f"{scan_id}.md").write_text(markdown_report(report), encoding="utf-8")


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        f"# Relatorio de Seguranca da Rede",
        "",
        f"- Scan: `{report['id']}`",
        f"- Alvo: `{report['target']}`",
        f"- Perfil: `{report['profile']}`",
        f"- Inicio: `{report['started_at']}`",
        f"- Fim: `{report['finished_at']}`",
        f"- Status geral: `{report['summary']['overall_status']}`",
        "",
        "## Resumo",
        "",
        f"- Hosts ativos: {report['summary']['hosts_found']}",
        f"- Portas abertas: {report['summary']['open_ports']}",
        f"- Duracao: {report['summary']['duration_seconds']}s",
        "",
        "## Achados",
        "",
    ]
    if report["findings"]:
        for finding in report["findings"]:
            lines.extend(
                [
                    f"### [{finding['severity'].upper()}] {finding['title']}",
                    "",
                    f"- Alvo: `{finding['target']}`",
                    f"- Detalhe: {finding['detail']}",
                    f"- Correcao: {finding['correction']}",
                    "",
                ]
            )
    else:
        lines.extend(["Nenhum achado relevante nos testes automaticos.", ""])

    lines.extend(["## Hosts", ""])
    for host in report["hosts"]:
        port_text = ", ".join(f"{port['port']}/{port['service']}" for port in host["open_ports"]) or "sem portas abertas nos testes"
        lines.append(f"- `{host['ip']}`: {port_text}")

    lines.extend(["", "## Checklist Manual", ""])
    for item in report["manual_checklist"]:
        lines.append(f"- {item['item']}: {item['action']}")
    lines.append("")
    return "\n".join(lines)


def serialize_dataclass(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    return value


# ── CVE enrichment via NVD API ────────────────────────────────────────────────

_cve_cache: dict[str, list[dict]] = {}

_SERVICE_KEYWORDS: dict[str, str] = {
    "FTP": "FTP server",
    "SSH": "SSH OpenSSH",
    "Telnet": "Telnet",
    "DNS": "DNS BIND",
    "HTTP": "HTTP Apache nginx web server",
    "HTTPS": "HTTPS TLS",
    "NetBIOS": "NetBIOS",
    "SMB": "SMB Samba",
    "RTSP": "RTSP",
    "MQTT": "MQTT broker",
    "VNC": "VNC",
    "RDP": "Remote Desktop Protocol Windows",
    "HTTP-alt": "HTTP web server",
    "HTTPS-alt": "HTTPS",
    "JetDirect": "HP JetDirect printer",
    "IPP": "IPP printer",
}


def _fetch_nvd(keyword: str, max_results: int = 3) -> list[dict]:
    """Synchronous NVD API v2 call — run via to_thread."""
    params = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": max_results})
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "SecurityNetworkAudit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return []

    cves = []
    for item in data.get("vulnerabilities", [])[:max_results]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        score, severity = None, "unknown"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = cve.get("metrics", {}).get(key, [])
            if entries:
                cvss = entries[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity", "unknown").lower()
                break
        if cve_id:
            cves.append({
                "id": cve_id,
                "description": desc[:250],
                "score": score,
                "severity": severity,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
    return cves


async def lookup_cves(service: str) -> list[dict]:
    if service in _cve_cache:
        return _cve_cache[service]
    keyword = _SERVICE_KEYWORDS.get(service)
    if not keyword:
        _cve_cache[service] = []
        return []
    try:
        result = await asyncio.wait_for(asyncio.to_thread(_fetch_nvd, keyword), timeout=15)
    except Exception:
        result = []
    _cve_cache[service] = result
    return result


async def enrich_with_cves(results: list[HostResult], emit: Callable[[dict[str, Any]], Any]) -> None:
    services = {port.service for host in results for port in host.open_ports if port.service in _SERVICE_KEYWORDS}
    if not services:
        return
    await emit_event(emit, "phase", f"Consultando NVD para {len(services)} serviço(s) detectado(s).", {})
    for i, service in enumerate(services):
        if i > 0:
            await asyncio.sleep(6)  # stay safely under NVD rate limit (5 req/30s without API key)
        await lookup_cves(service)
    for host in results:
        for port in host.open_ports:
            port.cves = _cve_cache.get(port.service, [])
