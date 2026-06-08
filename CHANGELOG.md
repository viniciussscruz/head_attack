# Changelog

All notable changes to this project will be documented in this file.

The format follows the spirit of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses simple date-based release entries while it is still early.

## [0.1.0] - 2026-06-08

### Added

- Initial FastAPI web service.
- Web dashboard for starting authorized network scans.
- Real-time scan progress using Server-Sent Events.
- Defensive target validation for private IPv4 and Tailscale/CGNAT ranges.
- Host discovery using ICMP and lightweight TCP probing.
- Quick and full scan profiles for common LAN services.
- Common service checks for HTTP, HTTPS, SSH, Telnet, FTP, SMB, RDP, RTSP, MQTT, printer services, and alternate web panels.
- Severity-based findings with practical remediation guidance.
- JSON and Markdown report generation under `reports/`.
- In-memory recurring scan scheduling from the dashboard.
- Example `systemd` unit for long-running local deployment.
- Project documentation, safety scope, quick start, report format, and responsible-use guidance.
