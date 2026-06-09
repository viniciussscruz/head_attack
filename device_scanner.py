import asyncio
import ipaddress
import re
import socket
import subprocess
import urllib.parse
import urllib.request
from typing import Any, Callable

from scanner import validate_target
from utils import emit_event, save_json_report, utc_now
from pathlib import Path

DEVICE_REPORTS_DIR = Path("reports/devices")

_vendor_cache: dict[str, str] = {}


async def run_device_scan(
    scan_id: str,
    target: str,
    emit: Callable[[dict[str, Any]], Any],
) -> dict[str, Any]:
    started = utc_now()
    network = validate_target(target)

    await emit_event(emit, "started", f"Descoberta de dispositivos em {network}", {"scan_id": scan_id})

    await emit_event(emit, "phase", "Executando varredura com nmap -sn...", {})
    devices = await _nmap_scan(str(network), emit)

    if not devices:
        await emit_event(emit, "phase", "nmap sem resultados com privilégios; usando ping + ARP...", {})
        devices = await _ping_arp_scan(network, emit)

    # Enrich vendor for MACs that nmap didn't resolve
    need_vendor = [d for d in devices if d.get("mac") and not d.get("vendor")]
    if need_vendor:
        await emit_event(
            emit, "phase",
            f"Consultando fabricantes para {len(need_vendor)} MAC(s) via macvendors.com...",
            {},
        )
        await _enrich_vendors(need_vendor, emit)

    # Hostname resolution
    for device in devices:
        if not device.get("hostname") and device.get("ip"):
            try:
                hostname, _, _ = await asyncio.wait_for(
                    asyncio.to_thread(socket.gethostbyaddr, device["ip"]),
                    timeout=1.0,
                )
                device["hostname"] = hostname
            except Exception:
                pass

    devices.sort(key=lambda d: _ip_int(d["ip"]))

    summary = {
        "total_devices": len(devices),
        "with_mac": sum(1 for d in devices if d.get("mac")),
        "with_vendor": sum(1 for d in devices if d.get("vendor")),
    }

    await emit_event(
        emit, "discovered",
        f"{len(devices)} dispositivo(s) encontrado(s).",
        {"summary": summary, "devices": devices},
    )

    report = {
        "id": scan_id,
        "type": "device_scan",
        "target": str(network),
        "started_at": started,
        "finished_at": utc_now(),
        "summary": summary,
        "devices": devices,
    }

    save_json_report(DEVICE_REPORTS_DIR / f"{scan_id}.json", report)
    await emit_event(emit, "finished", "Varredura de dispositivos concluída.", report)
    return report


async def _nmap_scan(target: str, emit: Callable) -> list[dict]:
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(
                subprocess.run,
                ["nmap", "-sn", target],
                capture_output=True, text=True, timeout=90,
            ),
            timeout=100,
        )
        devices = _parse_nmap_output(result.stdout)
        if devices:
            await emit_event(emit, "phase", f"nmap encontrou {len(devices)} host(s).", {})
        return devices
    except Exception:
        return []


def _parse_nmap_output(output: str) -> list[dict]:
    devices: list[dict] = []
    current: dict[str, Any] = {}

    for line in output.splitlines():
        line = line.strip()

        if "Nmap scan report for" in line:
            if current.get("ip"):
                devices.append(current)
            ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            host_m = re.match(r"Nmap scan report for (.+?) \(", line)
            current = {
                "ip": ip_m.group(1) if ip_m else "",
                "hostname": host_m.group(1) if host_m else None,
                "mac": None,
                "vendor": None,
                "latency_ms": None,
                "status": "up",
            }

        elif "Host is up" in line and current:
            lat = re.search(r"\((\d+\.?\d*)\s*s\s+latency\)", line)
            if lat:
                current["latency_ms"] = round(float(lat.group(1)) * 1000, 2)

        elif "MAC Address:" in line and current:
            mac_m = re.search(r"MAC Address:\s+([A-F0-9:]{17})", line, re.IGNORECASE)
            vend_m = re.search(r"MAC Address:\s+[A-F0-9:]{17}\s+\((.+)\)", line, re.IGNORECASE)
            if mac_m:
                current["mac"] = mac_m.group(1).upper()
            if vend_m:
                current["vendor"] = vend_m.group(1)

    if current.get("ip"):
        devices.append(current)

    return [d for d in devices if d["ip"]]


async def _ping_arp_scan(network: ipaddress.IPv4Network, emit: Callable) -> list[dict]:
    hosts = (
        [str(ip) for ip in network.hosts()]
        if network.prefixlen < 32
        else [str(network.network_address)]
    )
    await emit_event(emit, "phase", f"Ping sweep em {len(hosts)} endereço(s)...", {})

    sem = asyncio.Semaphore(64)
    alive: list[str] = []

    async def _ping(ip: str) -> None:
        async with sem:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "1", ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                code = await asyncio.wait_for(proc.wait(), timeout=1.5)
                if code == 0:
                    alive.append(ip)
                    await emit_event(emit, "host_found", f"Host ativo: {ip}", {"ip": ip})
            except asyncio.TimeoutError:
                proc.kill()

    await asyncio.gather(*(_ping(h) for h in hosts))

    neighbors = _read_arp_table()
    return [
        {
            "ip": ip,
            "hostname": None,
            "mac": neighbors.get(ip, {}).get("mac"),
            "vendor": None,
            "latency_ms": None,
            "status": "up",
        }
        for ip in alive
    ]


def _read_arp_table() -> dict[str, dict]:
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=3, check=False,
        )
    except Exception:
        return {}
    neighbors: dict[str, dict] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        mac = None
        if "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1].upper()
        neighbors[ip] = {"mac": mac}
    return neighbors


async def _enrich_vendors(devices: list[dict], emit: Callable) -> None:
    for i, device in enumerate(devices):
        mac = device.get("mac")
        if not mac:
            continue
        prefix = mac[:8]
        if prefix in _vendor_cache:
            device["vendor"] = _vendor_cache[prefix] or None
            continue
        if i > 0:
            await asyncio.sleep(1.1)  # macvendors.com rate limit ~1 req/s
        try:
            vendor = await asyncio.wait_for(
                asyncio.to_thread(_fetch_vendor, mac),
                timeout=6,
            )
            _vendor_cache[prefix] = vendor
            device["vendor"] = vendor or None
            if vendor:
                await emit_event(emit, "vendor_found", f"{mac} → {vendor}", {"ip": device["ip"], "mac": mac, "vendor": vendor})
        except Exception:
            _vendor_cache[prefix] = ""


def _fetch_vendor(mac: str) -> str:
    url = f"https://api.macvendors.com/{urllib.parse.quote(mac)}"
    req = urllib.request.Request(url, headers={"User-Agent": "SecurityNetworkAudit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                return resp.read().decode("utf-8", errors="replace").strip()
    except Exception:
        pass
    return ""


def _ip_int(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip))
    except Exception:
        return 0
