# Head Attack

Head Attack is a local web service for authorized, defensive network auditing. It discovers live hosts, checks common exposed services, streams test progress in real time, and presents a visual report with findings, successful checks, device shortcuts, and suggested fixes.

The project is designed for home labs, small office networks, IoT-heavy environments, and private Tailscale ranges where you have explicit authorization to test.

## Safety Scope

Head Attack is intentionally limited to private and Tailscale/CGNAT ranges:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `100.64.0.0/10`

The default maximum target size is 512 IPv4 addresses per scan. The scanner does not run exploits, brute force attacks, denial-of-service tests, password guessing, or configuration changes.

## Features

- Web dashboard for launching scans.
- `test_bad_agent` tab for controlled adversary simulation on authorized private networks.
- `Network Performance` tab for broadcast/multicast analysis, top talkers, internet speed tests, and AI-assisted performance interpretation.
- `Website Security` tab for authorized web application checks, security headers, TLS, cookies, forms, CORS, common sensitive-file exposure, and AI-assisted remediation.
- Real-time scan output using Server-Sent Events.
- Quick and controlled full scan profiles.
- Host discovery using ICMP and lightweight TCP probing.
- Common service checks for routers, repeaters, cameras, DVRs, printers, SMB, RDP, MQTT, SSH, FTP, Telnet, and web panels.
- Finding severity classification: `critical`, `high`, `medium`, `low`, and `info`.
- Practical remediation guidance for each finding.
- Visual dashboard reports with prioritized findings, passed checks, affected devices, and direct HTTP/HTTPS shortcuts when a device panel is detected.
- Report export from every visual report in Markdown, JSON, PDF, and spreadsheet-friendly CSV formats.
- In-memory recurring scan scheduling.
- Example `systemd` service for running the dashboard continuously.

## test_bad_agent

The `test_bad_agent` tab is a controlled adversary-simulation workflow. It is meant to show where a malicious actor would likely focus attention without turning the tool into an autonomous exploit runner.

It can run these safe checks:

- Exposed HTTP/HTTPS administration panels.
- Insecure or sensitive services such as FTP, Telnet, SMB, MQTT, VNC, RDP, and RTSP.
- Camera/DVR RTSP exposure.
- Segmentation weakness signals, such as cameras and SMB appearing in the same reachable surface.
- Brute-force readiness signals without sending credentials.
- Reset/reboot exposure signals without requesting reset or reboot URLs.
- UPnP/SSDP exposure with a single local multicast discovery probe.

Safety limits:

- No brute force.
- No exploit execution.
- No default-password attempts.
- No configuration changes.
- No reset, reboot, factory restore, or denial-of-service actions.
- RTSP frame capture is opt-in and only attempts a single unauthenticated frame from the base RTSP URL.
- UPnP/SSDP discovery reflects the local network where the app is running; it does not inspect a remote Tailscale subnet through multicast.

The AI fields are optional. When an OpenAI-compatible chat completions endpoint, model, and API key are supplied, the app sends only summarized findings and asks for a defensive remediation-focused explanation. The API key is not saved to disk. If no key is supplied, the app generates a local summary.

The dashboard can load the models available to your API key through the configured OpenAI-compatible endpoint. After an agent run, the result shows whether the API was actually used, which model answered, and the prompt/completion/total token counts returned by the provider. Local fallback analysis shows `0` tokens.

## Network Performance

The `Network Performance` tab checks local network health from this machine's point of view.

It collects:

- Local routes, interfaces, link counters, and neighbor table entries.
- A short passive broadcast/multicast sample using `tcpdump`, when the process has capture permission.
- Top talkers by source MAC address and protocol family, such as ARP, mDNS, SSDP/UPnP, LLMNR, NetBIOS, DHCP, and IPv6 multicast.
- Optional internet speed test using `speedtest-cli`.
- AI-assisted analysis with token usage reporting.

Notes:

- Broadcast/multicast sampling may require running with packet-capture permission or setting capabilities on `tcpdump`.
- Speed tests need internet access and the `speedtest-cli` dependency from `requirements.txt`.
- The AI API key is not saved to disk.

## Website Security

The `Website Security` tab runs safe checks against websites you own or are explicitly authorized to assess.

It checks:

- HTTP status, redirects, response headers, and selected server hints.
- Security headers such as HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- TLS certificate status, negotiated TLS version, cipher, and expiry.
- Cookie flags such as Secure, HttpOnly, and SameSite.
- Form risks such as password forms over non-HTTPS, password forms using GET, and missing visible CSRF token hints.
- CORS headers using a harmless synthetic Origin.
- Mixed-content references on HTTPS pages.
- A short fixed list of common sensitive paths such as `/.env`, `/.git/HEAD`, and backup/database filenames.
- AI-assisted remediation with token usage reporting.

Safety limits:

- Requires explicit authorization confirmation in the UI.
- Does not attempt login.
- Does not run brute force.
- Does not send exploit payloads.
- Does not run heavy fuzzing or high-volume crawling.

## Requirements

- Linux
- Python 3.12+
- `ping` and `ip` commands available on the host

Python dependencies are listed in `requirements.txt`.

## Quick Start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8088
```

Open the dashboard:

```text
http://127.0.0.1:8088
```

From another device on the same LAN, use this machine's LAN IP:

```text
http://192.168.15.X:8088
```

## Example Targets

Home LAN:

```text
192.168.15.0/24
```

Single router or host:

```text
192.168.15.1/32
```

Small Tailscale range:

```text
100.64.0.0/24
```

## Running As A Service

An example `systemd` unit is included in `security-network-audit.service`.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
sudo cp security-network-audit.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now security-network-audit.service
sudo systemctl status security-network-audit.service
```

The included service assumes the project lives at:

```text
/home/vinicius/IOT/security_network
```

Update the unit file if you deploy it somewhere else.

## Reports

Reports can be opened directly in the dashboard. The visual report shows:

- Top-level status and severity counts.
- Prioritized findings with remediation guidance.
- Passed checks that help confirm what is already healthy.
- Device cards with open ports and direct links to detected web panels.
- Manual checks that still need router or Wi-Fi controller access.

Every visual report includes an export control. The user can download the current report as:

- Markdown (`.md`)
- JSON (`.json`)
- PDF (`.pdf`)
- Spreadsheet-friendly CSV (`.csv`)

Network scan JSON and Markdown exports are also written to:

```text
reports/
```

Each scan creates:

- `reports/<scan_id>.json`
- `reports/<scan_id>.md`

The visual report is the primary reading experience. The Markdown report is useful for sharing a quick text summary, and the JSON report is useful for automation, diffing, or feeding another reporting pipeline.

The Bad Agent, Network Performance, and Website Security tabs save their JSON reports under their own report folders and expose the same dashboard export formats.

## Dashboard Workflow

1. Enter an authorized target range.
2. Choose `Quick` or `Full`.
3. Start the scan.
4. Watch each phase and host result in real time.
5. Review the summary and generated report.
6. Apply fixes and rescan to validate improvements.

For `test_bad_agent`:

1. Open the `test_bad_agent` tab.
2. Enter an authorized private or Tailscale target.
3. Select the adversary-simulation checks.
4. Optionally provide an AI API key for defensive analysis.
5. Optionally enable RTSP frame capture if you want to prove that a camera stream is open without credentials.
6. Review evidence, links, media, and remediation guidance.

For `Network Performance`:

1. Open the `Network Performance` tab.
2. Leave interface blank for auto-detect or enter an interface such as `wlan0`.
3. Choose the sample duration.
4. Keep speed test enabled if you want internet download/upload/ping.
5. Optionally provide an AI API key and load available models.
6. Review top broadcast/multicast talkers, speed test results, findings, and AI token usage.

For `Website Security`:

1. Open the `Website Security` tab.
2. Enter an authorized URL.
3. Confirm that you have permission to test it.
4. Choose whether to check common sensitive paths.
5. Optionally provide an AI API key and load available models.
6. Review findings, TLS details, sensitive-path results, and AI token usage.

## Recommended Manual Checks

Automated checks cannot see every router setting. After each scan, manually verify:

- WPS is disabled on the main router and repeaters.
- UPnP is disabled unless there is a clear operational need.
- Guest Wi-Fi cannot reach routers, cameras, printers, or computers.
- Cameras, DVRs, smart speakers, TVs, and automation devices are isolated from trusted computers where possible.
- Router, repeater, camera, printer, and DVR firmware is current.
- Remote administration is disabled unless protected by VPN or Tailscale.
- Port forwarding and DMZ rules are documented and justified.

## Responsible Use

Use Head Attack only on networks and devices you own or are explicitly authorized to assess. The tool is built for defensive visibility, hardening, and validation.
