import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any, Callable

from utils import emit_event, save_json_report, utc_now

CODE_ANALYSIS_REPORTS_DIR = Path("reports/code_analysis")


async def run_code_analysis(
    analysis_id: str,
    project_path: str,
    emit: Callable[[dict[str, Any]], Any],
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

    report = {
        "id": analysis_id,
        "type": "code_analysis",
        "project_path": str(path),
        "started_at": started,
        "finished_at": utc_now(),
        "summary": summary,
        "vulnerabilities": vulnerabilities,
    }

    _save_report(analysis_id, report)
    await emit_event(emit, "finished", "Análise concluída e relatório salvo.", report)
    return report


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
