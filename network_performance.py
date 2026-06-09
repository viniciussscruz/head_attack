import asyncio
import json
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

from bad_agent import DEFAULT_AI_MODEL, local_ai_result
from scanner import REPORTS_DIR, parse_neighbors, utc_now
from utils import emit_event, save_json_report


PERFORMANCE_REPORTS_DIR = REPORTS_DIR / "performance"


async def run_network_performance(
    analysis_id: str,
    interface: str | None,
    sample_seconds: int,
    run_speedtest: bool,
    ai_config: dict[str, str | None],
    emit: Callable[[dict[str, Any]], Any],
) -> dict[str, Any]:
    started = utc_now()
    started_ts = time.perf_counter()
    iface = interface or default_interface()
    sample_seconds = max(5, min(sample_seconds, 60))

    await emit_event(emit, "started", "Network Performance iniciado.", {"analysis_id": analysis_id, "interface": iface})
    await emit_event(emit, "phase", "Coletando rotas, interfaces e vizinhos locais.", {})
    local = collect_local_network_state()

    await emit_event(emit, "phase", f"Amostrando broadcast/multicast por {sample_seconds}s.", {"interface": iface})
    broadcast = await sample_broadcasts(iface, sample_seconds)
    await emit_event(emit, "broadcast_done", "Amostra de broadcast/multicast concluída.", broadcast)

    speed = {"status": "skipped", "message": "Speed test não solicitado."}
    if run_speedtest:
        await emit_event(emit, "phase", "Rodando speed test de internet.", {})
        speed = await run_internet_speedtest()
        await emit_event(emit, "speedtest_done", "Speed test concluído.", speed)

    findings = build_performance_findings(local, broadcast, speed)
    summary = build_summary(findings, broadcast, speed, started_ts)
    ai_analysis = await maybe_performance_ai(ai_config, local, broadcast, speed, findings, summary)
    await emit_event(
        emit,
        "ai_analysis",
        "Análise por IA concluída." if ai_analysis["used_api"] else "Análise local concluída; nenhum token de IA foi consumido.",
        {"analysis": ai_analysis},
    )

    report = {
        "id": analysis_id,
        "started_at": started,
        "finished_at": utc_now(),
        "interface": iface,
        "sample_seconds": sample_seconds,
        "summary": summary,
        "local_network": local,
        "broadcast_sample": broadcast,
        "speedtest": speed,
        "findings": findings,
        "ai_analysis": ai_analysis,
    }
    save_performance_report(analysis_id, report)
    await emit_event(emit, "finished", "Network Performance concluído.", report)
    return report


def collect_local_network_state() -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "default_route": run_text(["ip", "route", "show", "default"]),
        "addresses": run_text(["ip", "-br", "addr"]),
        "links": parse_ip_json(["ip", "-j", "-s", "link"]),
        "neighbors": parse_neighbors(),
    }


async def sample_broadcasts(interface: str | None, sample_seconds: int) -> dict[str, Any]:
    if not interface:
        return {"status": "unavailable", "message": "Interface padrão não encontrada.", "talkers": [], "protocols": {}}

    command = [
        "timeout",
        str(sample_seconds),
        "tcpdump",
        "-i",
        interface,
        "-nn",
        "-e",
        "-tt",
        "-l",
        "broadcast or multicast or arp",
    ]

    try:
        result = await asyncio.to_thread(subprocess.run, command, capture_output=True, text=True, timeout=sample_seconds + 4, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "message": f"Não foi possível executar tcpdump: {exc}", "talkers": [], "protocols": {}}

    output = "\n".join([result.stdout or "", result.stderr or ""])
    if "permission denied" in output.lower() or "you don't have permission" in output.lower():
        return {
            "status": "permission_denied",
            "message": "tcpdump sem permissão. Rode o serviço com permissão de captura ou configure capabilities para tcpdump.",
            "talkers": [],
            "protocols": {},
            "raw_error": output[-800:],
        }

    talkers: dict[str, dict[str, Any]] = {}
    protocols: Counter[str] = Counter()
    total_packets = 0
    for line in output.splitlines():
        parsed = parse_tcpdump_line(line)
        if not parsed:
            continue
        total_packets += 1
        src = parsed["src_mac"]
        proto = parsed["protocol"]
        protocols[proto] += 1
        if src not in talkers:
            talkers[src] = {"mac": src, "packets": 0, "protocols": defaultdict(int), "examples": []}
        talkers[src]["packets"] += 1
        talkers[src]["protocols"][proto] += 1
        if len(talkers[src]["examples"]) < 3:
            talkers[src]["examples"].append(line[:240])

    normalized_talkers = []
    for item in talkers.values():
        normalized_talkers.append(
            {
                "mac": item["mac"],
                "packets": item["packets"],
                "packets_per_second": round(item["packets"] / max(sample_seconds, 1), 2),
                "protocols": dict(sorted(item["protocols"].items(), key=lambda entry: entry[1], reverse=True)),
                "examples": item["examples"],
            }
        )

    normalized_talkers.sort(key=lambda item: item["packets"], reverse=True)
    return {
        "status": "ok",
        "interface": interface,
        "duration_seconds": sample_seconds,
        "total_packets": total_packets,
        "packets_per_second": round(total_packets / max(sample_seconds, 1), 2),
        "talkers": normalized_talkers[:20],
        "protocols": dict(protocols.most_common()),
    }


def parse_tcpdump_line(line: str) -> dict[str, str] | None:
    mac_match = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})\s+>\s+(([0-9a-f]{2}:){5}[0-9a-f]{2}|Broadcast|IPv4mcast|IPv6mcast)", line, re.I)
    if not mac_match:
        return None
    return {"src_mac": mac_match.group(1).lower(), "protocol": classify_protocol(line)}


def classify_protocol(line: str) -> str:
    lowered = line.lower()
    if " arp " in lowered or " arp," in lowered:
        return "ARP"
    if ".5353" in lowered or " mdns" in lowered or "224.0.0.251" in lowered:
        return "mDNS"
    if ".1900" in lowered or "ssdp" in lowered or "239.255.255.250" in lowered:
        return "SSDP/UPnP"
    if ".5355" in lowered or "224.0.0.252" in lowered:
        return "LLMNR"
    if ".137" in lowered or ".138" in lowered:
        return "NetBIOS"
    if ".67" in lowered or ".68" in lowered or "bootps" in lowered or "bootpc" in lowered:
        return "DHCP"
    if " igmp" in lowered:
        return "IGMP"
    if " ip6" in lowered or "icmp6" in lowered:
        return "IPv6 multicast"
    return "Other broadcast/multicast"


async def run_internet_speedtest() -> dict[str, Any]:
    def run() -> dict[str, Any]:
        try:
            import speedtest  # type: ignore
        except Exception:
            return {
                "status": "missing_dependency",
                "message": "Pacote speedtest-cli não está instalado. Rode: pip install -r requirements.txt",
            }

        try:
            tester = speedtest.Speedtest()
            tester.get_best_server()
            download = tester.download()
            upload = tester.upload()
            ping_ms = tester.results.ping
            server = tester.results.server or {}
        except Exception as exc:
            return {"status": "error", "message": f"Speed test falhou: {exc}"}

        return {
            "status": "ok",
            "download_mbps": round(download / 1_000_000, 2),
            "upload_mbps": round(upload / 1_000_000, 2),
            "ping_ms": round(float(ping_ms), 2),
            "server": {
                "sponsor": server.get("sponsor"),
                "name": server.get("name"),
                "country": server.get("country"),
            },
        }

    return await asyncio.to_thread(run)


def build_performance_findings(local: dict[str, Any], broadcast: dict[str, Any], speed: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    if broadcast.get("status") == "permission_denied":
        findings.append(
            {
                "severity": "medium",
                "title": "Amostra de broadcast sem permissão",
                "detail": "Não foi possível medir quais dispositivos geram broadcast/multicast.",
                "recommendation": "Execute com permissão de captura ou configure capabilities para tcpdump.",
            }
        )
    elif broadcast.get("status") == "ok":
        pps = broadcast.get("packets_per_second", 0)
        if pps >= 20:
            findings.append(
                {
                    "severity": "high",
                    "title": "Volume alto de broadcast/multicast",
                    "detail": f"A amostra mediu {pps} pacotes/s de broadcast/multicast.",
                    "recommendation": "Identificar os maiores talkers, revisar IoT/repetidores e separar dispositivos barulhentos em VLAN/rede IoT.",
                }
            )
        elif pps >= 5:
            findings.append(
                {
                    "severity": "medium",
                    "title": "Volume moderado de broadcast/multicast",
                    "detail": f"A amostra mediu {pps} pacotes/s de broadcast/multicast.",
                    "recommendation": "Monitorar maiores talkers e reduzir protocolos desnecessários como SSDP, mDNS, LLMNR e NetBIOS.",
                }
            )

        for talker in broadcast.get("talkers", [])[:5]:
            if talker.get("packets_per_second", 0) >= 3:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Dispositivo fala muito em broadcast/multicast",
                        "detail": f"{talker['mac']} gerou {talker['packets_per_second']} pacotes/s. Protocolos: {talker['protocols']}",
                        "recommendation": "Mapear esse MAC para o equipamento/repetidor e verificar loops, descoberta UPnP/mDNS excessiva ou firmware desatualizado.",
                    }
                )

    if speed.get("status") == "ok":
        if speed.get("ping_ms", 0) > 80:
            findings.append(
                {
                    "severity": "medium",
                    "title": "Latência de internet elevada",
                    "detail": f"Ping medido: {speed['ping_ms']} ms.",
                    "recommendation": "Testar via cabo, revisar uso de banda e comparar com o plano contratado.",
                }
            )
    elif speed.get("status") not in {"skipped", None}:
        findings.append(
            {
                "severity": "low",
                "title": "Speed test não executado",
                "detail": speed.get("message", "Speed test indisponível."),
                "recommendation": "Instalar dependências ou executar novamente quando a internet estiver disponível.",
            }
        )

    if not findings:
        findings.append(
            {
                "severity": "info",
                "title": "Nenhum gargalo óbvio encontrado",
                "detail": "A amostra não encontrou volume anormal ou speed test ruim.",
                "recommendation": "Repetir em horário de lentidão para comparar.",
            }
        )
    return findings


def build_summary(findings: list[dict[str, Any]], broadcast: dict[str, Any], speed: dict[str, Any], started_ts: float) -> dict[str, Any]:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "duration_seconds": round(time.perf_counter() - started_ts, 2),
        "broadcast_pps": broadcast.get("packets_per_second", 0),
        "top_talkers": len(broadcast.get("talkers", [])),
        "speedtest_status": speed.get("status"),
        "by_severity": counts,
        "overall_status": "attention" if counts["high"] else "review" if counts["medium"] else "ok",
    }


async def maybe_performance_ai(
    ai_config: dict[str, str | None],
    local: dict[str, Any],
    broadcast: dict[str, Any],
    speed: dict[str, Any],
    findings: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, Any]:
    api_key = (ai_config.get("api_key") or "").strip()
    if not api_key:
        return local_ai_result(local_performance_analysis(summary, broadcast, speed, findings), "API key não informada.")

    endpoint = (ai_config.get("endpoint") or "https://api.openai.com/v1/chat/completions").strip()
    model = (ai_config.get("model") or DEFAULT_AI_MODEL).strip()
    if not endpoint.startswith("https://"):
        return local_ai_result(local_performance_analysis(summary, broadcast, speed, findings), "Endpoint de IA ignorado porque apenas HTTPS é aceito.")

    prompt = {
        "summary": summary,
        "interfaces": summarize_links(local.get("links", [])),
        "neighbors": local.get("neighbors", {}),
        "broadcast_sample": broadcast,
        "speedtest": speed,
        "findings": findings,
        "instruction": "Write a concise Portuguese network performance analysis. Explain likely broadcast/multicast sources, Wi-Fi/repeater impact, internet speed interpretation, and practical remediation. Do not include offensive guidance.",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a defensive network performance analyst. Keep advice practical and remediation-focused."},
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
            return local_ai_result(local_performance_analysis(summary, broadcast, speed, findings), f"Falha ao chamar IA; fallback local usado: {exc}")

        content = data.get("choices", [{}])[0].get("message", {}).get("content") or ""
        usage = data.get("usage") or {}
        return {
            "content": content or local_performance_analysis(summary, broadcast, speed, findings),
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


def local_performance_analysis(summary: dict[str, Any], broadcast: dict[str, Any], speed: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    lines = [
        f"Análise local de performance: status {summary['overall_status']}.",
        f"Broadcast/multicast medido: {summary.get('broadcast_pps', 0)} pacotes/s.",
    ]
    if speed.get("status") == "ok":
        lines.append(f"Internet: {speed['download_mbps']} Mbps down, {speed['upload_mbps']} Mbps up, ping {speed['ping_ms']} ms.")
    else:
        lines.append(f"Speed test: {speed.get('message', speed.get('status', 'não executado'))}.")
    for finding in findings[:8]:
        lines.append(f"- {finding['title']}: {finding['recommendation']}")
    return "\n".join(lines)


def summarize_links(links: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary = []
    for link in links:
        stats = link.get("stats64") or link.get("stats") or {}
        summary.append(
            {
                "ifname": link.get("ifname"),
                "operstate": link.get("operstate"),
                "address": link.get("address"),
                "rx": stats.get("rx"),
                "tx": stats.get("tx"),
            }
        )
    return summary


def default_interface() -> str | None:
    route = run_text(["ip", "route", "show", "default"])
    match = re.search(r"\bdev\s+(\S+)", route)
    return match.group(1) if match else None


def run_text(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip()


def parse_ip_json(args: list[str]) -> list[dict[str, Any]]:
    text = run_text(args)
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return []


def save_performance_report(analysis_id: str, report: dict[str, Any]) -> None:
    save_json_report(PERFORMANCE_REPORTS_DIR / f"{analysis_id}.json", report)


