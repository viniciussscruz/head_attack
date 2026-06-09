import asyncio
import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from bad_agent import DEFAULT_AI_MODEL, local_ai_result
from utils import emit_event, save_json_report, utc_now

CODE_ANALYSIS_REPORTS_DIR = Path("reports/code_analysis")


async def run_code_analysis(
    analysis_id: str,
    project_path: str,
    emit: Callable[[dict[str, Any]], Any],
    ai_config: dict[str, str | None] | None = None,
) -> dict[str, Any]:
    started = utc_now()
    await emit_event(emit, "started", f"Análise SCA iniciada: {project_path}", {"analysis_id": analysis_id})

    path = Path(project_path).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"Caminho não encontrado: {path}")

    if path.is_file():
        if path.suffix != ".txt":
            raise ValueError("Informe um arquivo requirements.txt ou um diretório de projeto.")
        cmd = ["pip-audit", "--format", "json", "--no-deps", "-r", str(path)]
        await emit_event(emit, "phase", f"Analisando arquivo: {path.name}", {})
    elif path.is_dir():
        req = path / "requirements.txt"
        if req.exists():
            cmd = ["pip-audit", "--format", "json", "--no-deps", "-r", str(req)]
            await emit_event(emit, "phase", f"requirements.txt encontrado em {path.name}", {})
        else:
            cmd = ["pip-audit", "--format", "json", "--no-deps", "--local"]
            await emit_event(emit, "phase", "Analisando ambiente Python atual (sem requirements.txt).", {})
    else:
        raise ValueError("Informe um diretório de projeto ou arquivo requirements.txt.")

    await emit_event(emit, "phase", "Executando pip-audit — aguarde alguns segundos...", {})

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True, timeout=120),
            timeout=130,
        )
    except asyncio.TimeoutError:
        raise ValueError("pip-audit excedeu o tempo limite de 2 minutos.")

    raw = result.stdout.strip()
    if not raw:
        err = result.stderr.strip()
        if not err or "command not found" in err.lower() or "no such file" in err.lower():
            raise ValueError("pip-audit não encontrado. Instale com: pip install pip-audit")
        raise ValueError(f"pip-audit falhou: {err[:400]}")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Saída inesperada do pip-audit: {raw[:300]}") from exc

    deps = data.get("dependencies", data) if isinstance(data, dict) else data

    vulnerabilities: list[dict[str, Any]] = []
    for dep in deps:
        for vuln in dep.get("vulns", []):
            aliases = vuln.get("aliases") or []
            cve_ids = [a for a in aliases if a.startswith("CVE-")]
            severity = _infer_severity(vuln)
            fix = vuln.get("fix_versions") or []
            vulnerabilities.append({
                "package": dep.get("name", "?"),
                "installed_version": dep.get("version", "?"),
                "advisory_id": vuln.get("id", ""),
                "cve_ids": cve_ids,
                "description": (vuln.get("description") or "")[:400],
                "fix_versions": fix,
                "severity": severity,
            })

    _rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    vulnerabilities.sort(key=lambda v: _rank.get(v["severity"], 0), reverse=True)

    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for v in vulnerabilities:
        by_severity[v["severity"]] = by_severity.get(v["severity"], 0) + 1

    packages_affected = len({v["package"] for v in vulnerabilities})
    summary = {
        "total_vulnerabilities": len(vulnerabilities),
        "packages_affected": packages_affected,
        "by_severity": by_severity,
        "overall_status": _overall_status(by_severity),
    }

    await emit_event(
        emit,
        "analysis_done",
        f"{len(vulnerabilities)} vulnerabilidade(s) em {packages_affected} pacote(s) afetado(s).",
        {"summary": summary},
    )

    if ai_config and vulnerabilities:
        await emit_event(emit, "phase", "Consultando IA para análise de risco...", {})
    ai_analysis = await maybe_code_ai(ai_config or {}, vulnerabilities, summary)

    report = {
        "id": analysis_id,
        "type": "code_analysis",
        "project_path": str(path),
        "started_at": started,
        "finished_at": utc_now(),
        "summary": summary,
        "vulnerabilities": vulnerabilities,
        "ai_analysis": ai_analysis,
    }

    _save_report(analysis_id, report)
    await emit_event(emit, "finished", "Análise concluída e relatório salvo.", report)
    return report


async def maybe_code_ai(
    ai_config: dict[str, str | None],
    vulnerabilities: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, Any]:
    api_key = (ai_config.get("api_key") or "").strip()
    if not api_key:
        return local_ai_result(_local_code_analysis(summary, vulnerabilities), "API key não informada.")

    endpoint = (ai_config.get("endpoint") or "https://api.openai.com/v1/chat/completions").strip()
    model = (ai_config.get("model") or DEFAULT_AI_MODEL).strip()

    if not endpoint.startswith("https://"):
        return local_ai_result(_local_code_analysis(summary, vulnerabilities), "Endpoint ignorado: apenas HTTPS aceito.")

    prompt = {
        "summary": summary,
        "vulnerabilities": vulnerabilities[:30],
        "instruction": (
            "Write a concise Portuguese defensive security report for these Python dependency vulnerabilities. "
            "Explain business risk, severity rationale, and prioritized remediation steps. "
            "Do not provide exploit instructions."
        ),
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a defensive application security analyst specializing in software composition analysis (SCA). Keep advice remediation-focused."},
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
        ],
        "temperature": 0.2,
    }

    def _call() -> dict[str, Any]:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            return local_ai_result(_local_code_analysis(summary, vulnerabilities), f"Falha ao chamar IA; análise local usada: {exc}")
        content = data.get("choices", [{}])[0].get("message", {}).get("content") or ""
        usage = data.get("usage") or {}
        return {
            "content": content or _local_code_analysis(summary, vulnerabilities),
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

    return await asyncio.to_thread(_call)


def _local_code_analysis(summary: dict[str, Any], vulnerabilities: list[dict[str, Any]]) -> str:
    lines = [
        f"Análise local SCA: {summary['total_vulnerabilities']} vulnerabilidade(s) em {summary['packages_affected']} pacote(s).",
        f"Status geral: {summary['overall_status']}.",
    ]
    by_sev = summary.get("by_severity", {})
    if by_sev.get("critical"):
        lines.append(f"CRÍTICO: {by_sev['critical']} vulnerabilidade(s) — atualização urgente necessária.")
    if by_sev.get("high"):
        lines.append(f"ALTO: {by_sev['high']} vulnerabilidade(s) — prioridade alta de correção.")
    for v in vulnerabilities[:5]:
        fix = f" → corrigido em {v['fix_versions'][0]}" if v.get("fix_versions") else ""
        lines.append(f"- {v['package']} {v['installed_version']}: {v['advisory_id']}{fix}")
    return "\n".join(lines)


def _infer_severity(vuln: dict[str, Any]) -> str:
    sev = (vuln.get("severity") or "").lower()
    return sev if sev in ("critical", "high", "medium", "low") else "unknown"


def _overall_status(counts: dict[str, int]) -> str:
    if counts.get("critical", 0):
        return "critical"
    if counts.get("high", 0):
        return "attention"
    if counts.get("medium", 0) or counts.get("low", 0) or counts.get("unknown", 0):
        return "review"
    return "ok"


def _save_report(analysis_id: str, report: dict[str, Any]) -> None:
    save_json_report(CODE_ANALYSIS_REPORTS_DIR / f"{analysis_id}.json", report)
