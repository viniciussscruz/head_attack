# Head Attack

Head Attack is a local web service for authorized, defensive network auditing. It discovers live hosts, checks common exposed services, streams test progress in real time, and generates JSON and Markdown reports with findings, successful checks, and suggested fixes.

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
- Real-time scan output using Server-Sent Events.
- Quick and controlled full scan profiles.
- Host discovery using ICMP and lightweight TCP probing.
- Common service checks for routers, repeaters, cameras, DVRs, printers, SMB, RDP, MQTT, SSH, FTP, Telnet, and web panels.
- Finding severity classification: `critical`, `high`, `medium`, `low`, and `info`.
- Practical remediation guidance for each finding.
- Markdown and JSON report generation.
- In-memory recurring scan scheduling.
- Example `systemd` service for running the dashboard continuously.

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

Reports are written to:

```text
reports/
```

Each scan creates:

- `reports/<scan_id>.json`
- `reports/<scan_id>.md`

The Markdown report is meant for quick reading. The JSON report is useful for automation, diffing, or feeding another reporting pipeline.

## Dashboard Workflow

1. Enter an authorized target range.
2. Choose `Quick` or `Full`.
3. Start the scan.
4. Watch each phase and host result in real time.
5. Review the summary and generated report.
6. Apply fixes and rescan to validate improvements.

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
