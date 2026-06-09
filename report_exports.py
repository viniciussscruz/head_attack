import csv
import io
import json
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner import REPORTS_DIR


REPORT_KINDS = {
    "scan": {"prefix": "", "directory": REPORTS_DIR, "title": "Network Scan Report"},
    "bad-agent": {"prefix": "bad_agent_", "directory": REPORTS_DIR, "title": "Bad Agent Report"},
    "performance": {"prefix": "", "directory": REPORTS_DIR / "performance", "title": "Network Performance Report"},
    "website": {"prefix": "", "directory": REPORTS_DIR / "website_security", "title": "Website Security Report"},
}

MEDIA_TYPES = {
    "json": "application/json",
    "md": "text/markdown; charset=utf-8",
    "pdf": "application/pdf",
    "csv": "text/csv; charset=utf-8",
}


def export_report(report_kind: str, report_id: str, format_name: str) -> tuple[bytes, str, str]:
    kind = _normal_report_kind(report_kind)
    output_format = _normal_format(format_name)
    report = load_report(kind, report_id)
    base_name = _safe_filename(f"{kind}_{report.get('id') or report_id}")

    if output_format == "json":
        content = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
    elif output_format == "md":
        content = build_markdown(kind, report).encode("utf-8")
    elif output_format == "csv":
        content = build_csv(kind, report).encode("utf-8-sig")
    elif output_format == "pdf":
        content = build_pdf(build_markdown(kind, report))
    else:
        raise ValueError("Unsupported export format.")

    return content, MEDIA_TYPES[output_format], f"{base_name}.{output_format}"


def load_report(report_kind: str, report_id: str) -> dict[str, Any]:
    config = REPORT_KINDS[report_kind]
    safe_id = _safe_report_id(report_id)
    path = Path(config["directory"]) / f"{config['prefix']}{safe_id}.json"
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def build_markdown(report_kind: str, report: dict[str, Any]) -> str:
    config = REPORT_KINDS[report_kind]
    summary = report.get("summary", {})
    target = report.get("target") or report.get("final_url") or report.get("url") or report.get("interface") or "unknown"
    lines = [
        f"# {config['title']}",
        "",
        f"- ID: `{report.get('id', 'unknown')}`",
        f"- Target: `{target}`",
        f"- Finished at: `{report.get('finished_at', 'unknown')}`",
        f"- Overall status: `{summary.get('overall_status', 'unknown')}`",
        f"- Exported at: `{datetime.now(timezone.utc).isoformat()}`",
        "",
        "## Summary",
        "",
    ]

    for key, value in sorted(summary.items()):
        lines.append(f"- {_label(key)}: {_flat_value(value)}")

    if report_kind == "scan":
        _add_scan_sections(lines, report)
    elif report_kind == "bad-agent":
        _add_evidence_section(lines, report.get("evidence", []))
        _add_ai_section(lines, report)
    elif report_kind == "performance":
        _add_performance_sections(lines, report)
        _add_ai_section(lines, report)
    elif report_kind == "website":
        _add_website_sections(lines, report)
        _add_ai_section(lines, report)

    return "\n".join(lines).strip() + "\n"


def build_csv(report_kind: str, report: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["report_type", "report_id", "section", "severity", "target", "title", "detail", "correction", "reference"],
    )
    writer.writeheader()

    for row in _csv_rows(report_kind, report):
        writer.writerow(row)

    return output.getvalue()


def build_pdf(markdown: str) -> bytes:
    plain_lines = _markdown_to_plain_lines(markdown)
    pages = []
    page_lines: list[str] = []
    for line in plain_lines:
        wrapped = textwrap.wrap(line, width=92) or [""]
        for item in wrapped:
            page_lines.append(item)
            if len(page_lines) >= 52:
                pages.append(page_lines)
                page_lines = []
    if page_lines:
        pages.append(page_lines)
    if not pages:
        pages = [["Empty report"]]

    objects: list[bytes] = [b""]
    catalog_id = len(objects)
    objects.append(b"")
    pages_id = len(objects)
    objects.append(b"")
    font_id = len(objects)
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    page_ids = []
    for lines in pages:
        content = _pdf_text_stream(lines)
        content_id = len(objects)
        objects.append(f"<< /Length {len(content)} >>\nstream\n".encode("latin-1") + content + b"\nendstream")
        page_id = len(objects)
        page_ids.append(page_id)
        objects.append(
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode("latin-1")
        )

    objects[catalog_id] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("latin-1")
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[pages_id] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("latin-1")

    pdf = io.BytesIO()
    pdf.write(b"%PDF-1.4\n")
    offsets = [0]
    for idx in range(1, len(objects)):
        offsets.append(pdf.tell())
        pdf.write(f"{idx} 0 obj\n".encode("latin-1"))
        pdf.write(objects[idx])
        pdf.write(b"\nendobj\n")
    xref_at = pdf.tell()
    pdf.write(f"xref\n0 {len(objects)}\n".encode("latin-1"))
    pdf.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.write(f"{offset:010d} 00000 n \n".encode("latin-1"))
    pdf.write(
        f"trailer\n<< /Size {len(objects)} /Root {catalog_id} 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode("latin-1")
    )
    return pdf.getvalue()


def _add_scan_sections(lines: list[str], report: dict[str, Any]) -> None:
    lines.extend(["", "## Findings", ""])
    findings = report.get("findings", [])
    if not findings:
        lines.append("No findings recorded.")
    for finding in findings:
        _add_item(lines, finding)

    lines.extend(["", "## Hosts", ""])
    hosts = report.get("hosts", [])
    if not hosts:
        lines.append("No active hosts recorded.")
    for host in hosts:
        ports = ", ".join(str(port.get("port")) for port in host.get("open_ports", []))
        lines.append(f"- `{host.get('ip')}` {host.get('hostname') or ''} ports: {ports or 'none'}")

    checklist = report.get("manual_checklist", [])
    if checklist:
        lines.extend(["", "## Manual Checklist", ""])
        for item in checklist:
            lines.append(f"- {item}")


def _add_evidence_section(lines: list[str], evidence: list[dict[str, Any]]) -> None:
    lines.extend(["", "## Evidence", ""])
    if not evidence:
        lines.append("No evidence recorded.")
    for item in evidence:
        _add_item(lines, item)


def _add_performance_sections(lines: list[str], report: dict[str, Any]) -> None:
    broadcast = report.get("broadcast_sample", {})
    speed = report.get("speedtest", {})
    lines.extend(["", "## Broadcast And Multicast Talkers", ""])
    talkers = broadcast.get("talkers", [])
    if not talkers:
        lines.append(broadcast.get("message") or "No talkers recorded.")
    for talker in talkers:
        lines.append(
            f"- `{talker.get('source') or talker.get('mac') or 'unknown'}` "
            f"{talker.get('packets', 0)} packets, protocols: {_flat_value(talker.get('protocols', {}))}"
        )

    lines.extend(["", "## Speed Test", ""])
    if speed:
        for key, value in sorted(speed.items()):
            lines.append(f"- {_label(key)}: {_flat_value(value)}")
    else:
        lines.append("No speed test result recorded.")

    lines.extend(["", "## Findings", ""])
    findings = report.get("findings", [])
    if not findings:
        lines.append("No performance findings recorded.")
    for finding in findings:
        _add_item(lines, finding)


def _add_website_sections(lines: list[str], report: dict[str, Any]) -> None:
    page = report.get("page", {})
    tls = report.get("tls", {})
    sensitive = report.get("sensitive_paths", {})
    lines.extend(["", "## Page", ""])
    for key, value in sorted(page.items()):
        if key not in {"body_preview"}:
            lines.append(f"- {_label(key)}: {_flat_value(value)}")

    lines.extend(["", "## Findings", ""])
    findings = report.get("findings", [])
    if not findings:
        lines.append("No website findings recorded.")
    for finding in findings:
        _add_item(lines, finding)

    lines.extend(["", "## TLS", ""])
    if tls:
        for key, value in sorted(tls.items()):
            lines.append(f"- {_label(key)}: {_flat_value(value)}")
    else:
        lines.append("No TLS details recorded.")

    checked = sensitive.get("checked", [])
    if checked:
        lines.extend(["", "## Sensitive Paths", ""])
        for item in checked:
            lines.append(f"- `{item.get('path')}` status: {item.get('status')} url: {item.get('url')}")


def _add_ai_section(lines: list[str], report: dict[str, Any]) -> None:
    ai = report.get("ai_analysis") or {}
    if not ai:
        return
    usage = ai.get("token_usage") or {}
    lines.extend(
        [
            "",
            "## AI Analysis",
            "",
            f"- Used API: `{bool(ai.get('used_api'))}`",
            f"- Model: `{ai.get('model') or 'local'}`",
            f"- Prompt tokens: `{usage.get('prompt_tokens', 0)}`",
            f"- Completion tokens: `{usage.get('completion_tokens', 0)}`",
            f"- Total tokens: `{usage.get('total_tokens', 0)}`",
            "",
            ai.get("content") or "No AI analysis content recorded.",
        ]
    )


def _add_item(lines: list[str], item: dict[str, Any]) -> None:
    title = item.get("title") or item.get("test") or item.get("name") or "Untitled"
    severity = item.get("severity", "info")
    target = item.get("target") or item.get("host") or item.get("url") or item.get("endpoint") or ""
    lines.append(f"### {title}")
    lines.append("")
    lines.append(f"- Severity: `{severity}`")
    if target:
        lines.append(f"- Target: `{target}`")
    for key in ["detail", "evidence", "correction", "recommendation", "reference"]:
        if item.get(key):
            lines.append(f"- {_label(key)}: {_flat_value(item.get(key))}")
    lines.append("")


def _csv_rows(report_kind: str, report: dict[str, Any]) -> list[dict[str, str]]:
    report_id = str(report.get("id", "unknown"))
    rows: list[dict[str, str]] = []

    if report_kind == "scan":
        rows.extend(_finding_rows(report_kind, report_id, "findings", report.get("findings", [])))
        for host in report.get("hosts", []):
            rows.append(_row(report_kind, report_id, "hosts", "info", host.get("ip"), host.get("hostname"), host, "", ""))
    elif report_kind == "bad-agent":
        rows.extend(_finding_rows(report_kind, report_id, "evidence", report.get("evidence", [])))
    elif report_kind == "performance":
        rows.extend(_finding_rows(report_kind, report_id, "findings", report.get("findings", [])))
        for talker in report.get("broadcast_sample", {}).get("talkers", []):
            rows.append(_row(report_kind, report_id, "talkers", "info", talker.get("source") or talker.get("mac"), "Broadcast talker", talker, "", ""))
    elif report_kind == "website":
        rows.extend(_finding_rows(report_kind, report_id, "findings", report.get("findings", [])))
        for item in report.get("sensitive_paths", {}).get("checked", []):
            rows.append(_row(report_kind, report_id, "sensitive_paths", "info", item.get("url"), item.get("path"), item, "", item.get("url")))

    if not rows:
        summary = report.get("summary", {})
        rows.append(_row(report_kind, report_id, "summary", summary.get("overall_status", "info"), "", "Summary", summary, "", ""))

    return rows


def _finding_rows(report_kind: str, report_id: str, section: str, items: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        _row(
            report_kind,
            report_id,
            section,
            item.get("severity", "info"),
            item.get("target") or item.get("host") or item.get("url") or item.get("endpoint") or "",
            item.get("title") or item.get("test") or item.get("name") or "",
            item.get("detail") or item.get("evidence") or item,
            item.get("correction") or item.get("recommendation") or "",
            item.get("reference") or item.get("url") or "",
        )
        for item in items
    ]


def _row(
    report_kind: str,
    report_id: str,
    section: str,
    severity: Any,
    target: Any,
    title: Any,
    detail: Any,
    correction: Any,
    reference: Any,
) -> dict[str, str]:
    return {
        "report_type": str(report_kind),
        "report_id": str(report_id),
        "section": str(section),
        "severity": str(severity or ""),
        "target": _flat_value(target),
        "title": _flat_value(title),
        "detail": _flat_value(detail),
        "correction": _flat_value(correction),
        "reference": _flat_value(reference),
    }


def _normal_report_kind(report_kind: str) -> str:
    aliases = {
        "bad_agent": "bad-agent",
        "badagent": "bad-agent",
        "network-performance": "performance",
        "network_performance": "performance",
        "website-security": "website",
        "website_security": "website",
    }
    normalized = aliases.get(report_kind, report_kind)
    if normalized not in REPORT_KINDS:
        raise ValueError("Unsupported report type.")
    return normalized


def _normal_format(format_name: str) -> str:
    aliases = {"markdown": "md", "planilha": "csv", "spreadsheet": "csv"}
    normalized = aliases.get(format_name.lower(), format_name.lower())
    if normalized not in MEDIA_TYPES:
        raise ValueError("Unsupported export format.")
    return normalized


def _safe_report_id(report_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", report_id):
        raise ValueError("Invalid report id.")
    return report_id


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "report"


def _label(value: str) -> str:
    return value.replace("_", " ").strip().title()


def _flat_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _markdown_to_plain_lines(markdown: str) -> list[str]:
    lines = []
    for line in markdown.splitlines():
        clean = re.sub(r"`([^`]+)`", r"\1", line)
        clean = re.sub(r"^#{1,6}\s*", "", clean)
        clean = re.sub(r"^\s*[-*]\s*", "- ", clean)
        lines.append(clean)
    return lines


def _pdf_text_stream(lines: list[str]) -> bytes:
    commands = ["BT", "/F1 10 Tf", "50 760 Td", "14 TL"]
    for line in lines:
        commands.append(f"({_pdf_escape(line)}) Tj")
        commands.append("T*")
    commands.append("ET")
    return "\n".join(commands).encode("latin-1", errors="replace")


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
