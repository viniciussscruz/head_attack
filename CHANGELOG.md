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
- `test_bad_agent` tab for controlled adversary simulation on authorized private networks.
- Optional OpenAI-compatible AI analysis for defensive interpretation of findings.
- Safe RTSP exposure validation with opt-in single-frame capture when an unauthenticated stream is reachable.
- Heavy simulation checks for brute-force readiness, reset/reboot exposure indicators, and UPnP/SSDP exposure without performing destructive actions.
- OpenAI-compatible model loading from the dashboard and token usage reporting for `test_bad_agent` AI analysis.
- `Network Performance` tab with local interface/neighbor inventory, passive broadcast/multicast talker sampling, optional speed test, findings, and AI token usage.

### Changed

- Made the dashboard's visual report the primary report experience.
- Added readable report sections for priority findings, passed checks, device cards, open ports, manual checklist items, and direct HTTP/HTTPS device panel links.
