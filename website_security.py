import asyncio
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Callable

from bad_agent import DEFAULT_AI_MODEL, local_ai_result
from scanner import REPORTS_DIR, utc_now


WEBSITE_REPORTS_DIR = REPORTS_DIR / "website_security"
SECURITY_HEADERS = {
    "strict-transport-security": {
        "title": "HSTS ausente",
        "severity": "high",
        "recommendation": "Adicionar Strict-Transport-Security com max-age adequado, includeSubDomains quando aplicável e preload somente após validação.",
    },
    "content-security-policy": {
        "title": "CSP ausente",
        "severity": "medium",
        "recommendation": "Adicionar Content-Security-Policy começando em modo Report-Only e depois aplicar política restritiva.",
    },
    "x-frame-options": {
        "title": "Proteção contra clickjacking ausente",
        "severity": "medium",
        "recommendation": "Adicionar X-Frame-Options DENY/SAMEORIGIN ou frame-ancestors no CSP.",
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options ausente",
        "severity": "low",
        "recommendation": "Adicionar X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "title": "Referrer-Policy ausente",
        "severity": "low",
        "recommendation": "Adicionar Referrer-Policy como strict-origin-when-cross-origin ou política mais restrita.",
    },
    "permissions-policy": {
        "title": "Permissions-Policy ausente",
        "severity": "low",
        "recommendation": "Adicionar Permissions-Policy para limitar recursos do navegador não usados pela aplicação.",
    },
}
SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/.svn/entries",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/server-status",
    "/wp-config.php.bak",
    "/config.php~",
]


async def run_website_security(
    scan_id: str,
    url: str,
    include_sensitive_paths: bool,
    ai_config: dict[str, str | None],
    emit: Callable[[dict[str, Any]], Any],
) -> dict[str, Any]:
    normalized_url = normalize_url(url)
    started = utc_now()
    started_ts = time.perf_counter()
    await _emit(emit, "started", f"Website Security iniciado em {normalized_url}", {"scan_id": scan_id})
    await _emit(emit, "guardrail", "Modo seguro: sem login, sem força bruta, sem payload ofensivo e sem fuzzing pesado.", {})

    await _emit(emit, "phase", "Coletando página inicial e cabeçalhos HTTP.", {})
    page = await fetch_url(normalized_url, method="GET", max_bytes=250_000)
    await _emit(emit, "http_done", "Página inicial coletada.", {"status": page.get("status"), "final_url": page.get("final_url")})

    final_url = page.get("final_url") or normalized_url
    parsed = urllib.parse.urlparse(final_url)

    await _emit(emit, "phase", "Validando TLS e certificado.", {})
    tls = await inspect_tls(parsed.hostname, parsed.port or 443) if parsed.scheme == "https" and parsed.hostname else {"status": "skipped", "message": "Site não usa HTTPS."}

    await _emit(emit, "phase", "Analisando headers, cookies, CORS, formulários e conteúdo misto.", {})
    findings = []
    findings.extend(check_security_headers(page, final_url))
    findings.extend(check_cookies(page, final_url))
    findings.extend(check_tls(tls, final_url))
    findings.extend(check_forms(page, final_url))
    findings.extend(check_mixed_content(page, final_url))
    cors = await check_cors(final_url)
    findings.extend(cors["findings"])

    sensitive_results = []
    if include_sensitive_paths:
        await _emit(emit, "phase", "Checando arquivos sensíveis comuns com requisições leves.", {})
        sensitive_results = await check_sensitive_paths(final_url)
        findings.extend(sensitive_results["findings"])

    summary = build_summary(findings, started_ts)
    ai_analysis = await maybe_website_ai(ai_config, page, tls, cors, sensitive_results, findings, summary)
    await _emit(
        emit,
        "ai_analysis",
        "Análise por IA concluída." if ai_analysis["used_api"] else "Análise local concluída; nenhum token de IA foi consumido.",
        {"analysis": ai_analysis},
    )

    report = {
        "id": scan_id,
        "target": normalized_url,
        "final_url": final_url,
        "started_at": started,
        "finished_at": utc_now(),
        "summary": summary,
        "page": redact_page(page),
        "tls": tls,
        "cors": cors,
        "sensitive_paths": sensitive_results,
        "findings": findings,
        "ai_analysis": ai_analysis,
        "safety": {
            "no_login": True,
            "no_bruteforce": True,
            "no_exploit_payloads": True,
            "limited_sensitive_path_checks": include_sensitive_paths,
        },
    }
    save_website_report(scan_id, report)
    await _emit(emit, "finished", "Website Security concluído.", report)
    return report


def normalize_url(url: str) -> str:
    value = url.strip()
    if not value:
        raise ValueError("Informe uma URL.")
    if "://" not in value:
        value = "https://" + value
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Use uma URL HTTP/HTTPS válida.")
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


async def fetch_url(url: str, method: str = "GET", headers: dict[str, str] | None = None, max_bytes: int = 80_000) -> dict[str, Any]:
    def run() -> dict[str, Any]:
        req = urllib.request.Request(
            url,
            method=method,
            headers={
                "User-Agent": "HeadAttackWebsiteSecurity/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                **(headers or {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as response:
                body = response.read(max_bytes) if method != "HEAD" else b""
                return {
                    "ok": True,
                    "status": response.status,
                    "reason": response.reason,
                    "final_url": response.geturl(),
                    "headers": dict(response.headers.items()),
                    "body": body.decode("utf-8", errors="replace"),
                }
        except urllib.error.HTTPError as exc:
            body = exc.read(max_bytes).decode("utf-8", errors="replace") if method != "HEAD" else ""
            return {
                "ok": False,
                "status": exc.code,
                "reason": exc.reason,
                "final_url": exc.geturl(),
                "headers": dict(exc.headers.items()),
                "body": body,
                "error": str(exc),
            }
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return {"ok": False, "status": None, "headers": {}, "body": "", "error": str(exc), "final_url": url}

    return await asyncio.to_thread(run)


async def inspect_tls(hostname: str | None, port: int) -> dict[str, Any]:
    if not hostname:
        return {"status": "error", "message": "Hostname ausente."}

    def run() -> dict[str, Any]:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    not_after = cert.get("notAfter")
                    expires_at = None
                    days_remaining = None
                    if not_after:
                        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        expires_at = expires.isoformat()
                        days_remaining = (expires - datetime.now(timezone.utc)).days
                    return {
                        "status": "ok",
                        "version": tls_sock.version(),
                        "cipher": tls_sock.cipher(),
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "expires_at": expires_at,
                        "days_remaining": days_remaining,
                    }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    return await asyncio.to_thread(run)


def check_security_headers(page: dict[str, Any], final_url: str) -> list[dict[str, Any]]:
    headers = lower_headers(page.get("headers", {}))
    findings = []
    scheme = urllib.parse.urlparse(final_url).scheme
    for header, meta in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and scheme != "https":
            continue
        if header not in headers:
            findings.append(
                finding(
                    meta["severity"],
                    meta["title"],
                    f"Header {header} não foi encontrado na resposta principal.",
                    meta["recommendation"],
                    "headers",
                )
            )
    csp = headers.get("content-security-policy", "")
    if csp and ("'unsafe-inline'" in csp or "*" in csp):
        findings.append(
            finding(
                "medium",
                "CSP permissiva",
                "A Content-Security-Policy parece permitir inline scripts ou curingas amplos.",
                "Revisar a CSP e reduzir unsafe-inline, unsafe-eval e curingas quando possível.",
                "headers",
            )
        )
    return findings


def check_cookies(page: dict[str, Any], final_url: str) -> list[dict[str, Any]]:
    headers = page.get("headers", {})
    set_cookie_values = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            set_cookie_values.append(value)
    findings = []
    for raw in set_cookie_values:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        lowered = raw.lower()
        for name in cookie:
            if "secure" not in lowered and urllib.parse.urlparse(final_url).scheme == "https":
                findings.append(finding("medium", "Cookie sem Secure", f"Cookie {name} não parece usar Secure.", "Adicionar Secure em cookies de sessão em HTTPS.", "cookies"))
            if "httponly" not in lowered:
                findings.append(finding("medium", "Cookie sem HttpOnly", f"Cookie {name} não parece usar HttpOnly.", "Adicionar HttpOnly para reduzir impacto de XSS em cookies sensíveis.", "cookies"))
            if "samesite" not in lowered:
                findings.append(finding("low", "Cookie sem SameSite", f"Cookie {name} não informa SameSite.", "Adicionar SameSite=Lax ou Strict quando compatível.", "cookies"))
    return findings


def check_tls(tls: dict[str, Any], final_url: str) -> list[dict[str, Any]]:
    parsed = urllib.parse.urlparse(final_url)
    findings = []
    if parsed.scheme != "https":
        findings.append(finding("high", "Site sem HTTPS", "A URL final não usa HTTPS.", "Habilitar HTTPS e redirecionar HTTP para HTTPS.", "tls"))
        return findings
    if tls.get("status") != "ok":
        findings.append(finding("high", "TLS inválido ou inacessível", tls.get("message", "Falha ao validar TLS."), "Corrigir certificado, cadeia e configuração TLS.", "tls"))
        return findings
    days = tls.get("days_remaining")
    if isinstance(days, int) and days < 15:
        findings.append(finding("high", "Certificado perto de expirar", f"Certificado expira em {days} dia(s).", "Renovar certificado e automatizar renovação.", "tls"))
    version = tls.get("version") or ""
    if version in {"TLSv1", "TLSv1.1"}:
        findings.append(finding("high", "TLS antigo", f"Versão negociada: {version}.", "Desabilitar TLS 1.0/1.1 e manter TLS 1.2/1.3.", "tls"))
    return findings


def check_forms(page: dict[str, Any], final_url: str) -> list[dict[str, Any]]:
    body = page.get("body", "")
    findings = []
    forms = re.findall(r"<form\b[^>]*>.*?</form>", body, flags=re.I | re.S)
    for form in forms[:20]:
        form_open = re.search(r"<form\b([^>]*)>", form, flags=re.I)
        attrs = form_open.group(1) if form_open else ""
        action = attr_value(attrs, "action") or final_url
        method = (attr_value(attrs, "method") or "GET").upper()
        resolved = urllib.parse.urljoin(final_url, action)
        has_password = re.search(r'type=["\']?password', form, flags=re.I) is not None
        has_csrf_hint = re.search(r"(csrf|xsrf|authenticity_token)", form, flags=re.I) is not None
        if has_password and urllib.parse.urlparse(resolved).scheme != "https":
            findings.append(finding("high", "Formulário de senha sem HTTPS", f"Formulário {method} envia para {resolved}.", "Garantir HTTPS em toda autenticação.", "forms"))
        if has_password and not has_csrf_hint:
            findings.append(finding("medium", "Formulário sensível sem indício de CSRF token", "Foi visto campo de senha sem token CSRF aparente no HTML.", "Confirmar proteção CSRF server-side para ações autenticadas.", "forms"))
        if method == "GET" and has_password:
            findings.append(finding("high", "Senha em formulário GET", "Formulário com senha usa método GET.", "Usar POST para autenticação e dados sensíveis.", "forms"))
    return findings


def check_mixed_content(page: dict[str, Any], final_url: str) -> list[dict[str, Any]]:
    if urllib.parse.urlparse(final_url).scheme != "https":
        return []
    body = page.get("body", "")
    http_assets = re.findall(r"""(?:src|href)=["'](http://[^"']+)["']""", body, flags=re.I)
    if http_assets:
        sample = ", ".join(http_assets[:3])
        return [finding("medium", "Possível conteúdo misto", f"Foram vistos recursos HTTP em página HTTPS: {sample}", "Servir todos os recursos por HTTPS.", "content")]
    return []


async def check_cors(final_url: str) -> dict[str, Any]:
    page = await fetch_url(final_url, method="GET", headers={"Origin": "https://head-attack.invalid"}, max_bytes=20_000)
    headers = lower_headers(page.get("headers", {}))
    findings = []
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials")
    if acao == "*":
        findings.append(finding("medium", "CORS permite qualquer origem", "Access-Control-Allow-Origin está como *.", "Restringir CORS às origens necessárias.", "cors"))
    if acac and acac.lower() == "true" and acao in {"*", "https://head-attack.invalid"}:
        findings.append(finding("high", "CORS permissivo com credenciais", "CORS aparenta permitir credenciais para origem ampla/refletida.", "Permitir credenciais apenas para origens confiáveis e explícitas.", "cors"))
    return {"headers": {k: headers.get(k) for k in ["access-control-allow-origin", "access-control-allow-credentials"] if headers.get(k)}, "findings": findings}


async def check_sensitive_paths(final_url: str) -> dict[str, Any]:
    base = urllib.parse.urljoin(final_url, "/")
    checked = []
    findings = []
    for path in SENSITIVE_PATHS:
        url = urllib.parse.urljoin(base, path.lstrip("/"))
        page = await fetch_url(url, method="GET", max_bytes=4096)
        status = page.get("status")
        exposed = status in {200, 206}
        checked.append({"path": path, "status": status, "exposed": exposed})
        if exposed and looks_sensitive(page.get("body", ""), path):
            findings.append(
                finding(
                    "critical",
                    "Arquivo sensível possivelmente exposto",
                    f"{path} respondeu HTTP {status} com conteúdo compatível com arquivo sensível.",
                    "Remover o arquivo da raiz pública, revisar deploy e bloquear via servidor web.",
                    "exposure",
                    url,
                )
            )
        elif exposed:
            findings.append(
                finding(
                    "medium",
                    "Caminho sensível respondeu",
                    f"{path} respondeu HTTP {status}.",
                    "Confirmar se o conteúdo é esperado; caso contrário, bloquear/remover.",
                    "exposure",
                    url,
                )
            )
    return {"checked": checked, "findings": findings}


def looks_sensitive(body: str, path: str) -> bool:
    lowered = body.lower()
    if path == "/.env":
        return "=" in body and any(key in lowered for key in ["password", "secret", "key", "token", "database"])
    if path == "/.git/HEAD":
        return "ref: refs/" in lowered
    if path.endswith(".sql"):
        return "create table" in lowered or "insert into" in lowered
    if "phpinfo()" in lowered or "php version" in lowered:
        return True
    return len(body.strip()) > 0


async def maybe_website_ai(
    ai_config: dict[str, str | None],
    page: dict[str, Any],
    tls: dict[str, Any],
    cors: dict[str, Any],
    sensitive: Any,
    findings: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, Any]:
    api_key = (ai_config.get("api_key") or "").strip()
    if not api_key:
        return local_ai_result(local_website_analysis(summary, findings), "API key não informada.")
    endpoint = (ai_config.get("endpoint") or "https://api.openai.com/v1/chat/completions").strip()
    model = (ai_config.get("model") or DEFAULT_AI_MODEL).strip()
    if not endpoint.startswith("https://"):
        return local_ai_result(local_website_analysis(summary, findings), "Endpoint de IA ignorado porque apenas HTTPS é aceito.")

    prompt = {
        "summary": summary,
        "target": page.get("final_url"),
        "status": page.get("status"),
        "headers": safe_header_subset(page.get("headers", {})),
        "tls": tls,
        "cors": cors,
        "sensitive_paths": sensitive,
        "findings": findings,
        "instruction": "Write a concise Portuguese defensive web security report. Explain risk, evidence, priority and remediation. Do not provide exploit payloads or attack instructions.",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a defensive web application security analyst. Keep advice remediation-focused and safe."},
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
            return local_ai_result(local_website_analysis(summary, findings), f"Falha ao chamar IA; fallback local usado: {exc}")
        content = data.get("choices", [{}])[0].get("message", {}).get("content") or ""
        usage = data.get("usage") or {}
        return {
            "content": content or local_website_analysis(summary, findings),
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


def local_website_analysis(summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    lines = [
        f"Análise local de Website Security: status {summary['overall_status']}.",
        f"{summary['total_findings']} achado(s), sendo {summary['by_severity'].get('critical', 0)} crítico(s) e {summary['by_severity'].get('high', 0)} alto(s).",
    ]
    for item in findings[:10]:
        lines.append(f"- {item['title']}: {item['recommendation']}")
    return "\n".join(lines)


def build_summary(findings: list[dict[str, Any]], started_ts: float) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return {
        "duration_seconds": round(time.perf_counter() - started_ts, 2),
        "total_findings": len(findings),
        "by_severity": counts,
        "overall_status": "critical" if counts["critical"] else "attention" if counts["high"] else "review" if counts["medium"] else "ok",
    }


def finding(severity: str, title: str, detail: str, recommendation: str, category: str, url: str | None = None) -> dict[str, Any]:
    return {"severity": severity, "title": title, "detail": detail, "recommendation": recommendation, "category": category, "url": url}


def lower_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def attr_value(attrs: str, name: str) -> str | None:
    match = re.search(rf'{name}\s*=\s*["\']([^"\']+)["\']', attrs, flags=re.I)
    return match.group(1) if match else None


def safe_header_subset(headers: dict[str, str]) -> dict[str, str]:
    allowed = {
        "server",
        "x-powered-by",
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "access-control-allow-origin",
        "access-control-allow-credentials",
    }
    return {k: v for k, v in headers.items() if k.lower() in allowed}


def redact_page(page: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": page.get("ok"),
        "status": page.get("status"),
        "reason": page.get("reason"),
        "final_url": page.get("final_url"),
        "headers": safe_header_subset(page.get("headers", {})),
        "body_size": len(page.get("body", "")),
        "title": page_title(page.get("body", "")),
    }


def page_title(body: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160]


def save_website_report(scan_id: str, report: dict[str, Any]) -> None:
    WEBSITE_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (WEBSITE_REPORTS_DIR / f"{scan_id}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


async def _emit(emit: Callable[[dict[str, Any]], Any], event: str, message: str, data: dict[str, Any]) -> None:
    payload = {"ts": utc_now(), "event": event, "message": message, "data": data}
    maybe = emit(payload)
    if asyncio.iscoroutine(maybe):
        await maybe
