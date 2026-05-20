IoT Vulnerability Scanner & Auditor
=================================

What this project does
----------------------
A small command-line tool to discover devices on an IP subnet, probe common TCP ports, perform a minimal MQTT anonymous-connect/subscription audit, classify devices by open ports, and emit JSON and optional HTML reports.

The main program is `iot.py`.

Quick features
--------------
- Host discovery using ARP (Scapy), ICMP ping, or TCP-connect fallback
- Concurrent port scanning (configurable ports/workers)
- Simple MQTT anonymous-connect and subscribe checks (port 1883)
- Classification tags (mqtt-broker, web-ui, ssh-enabled, telnet-enabled, coap-device, smart-device)
- JSON + optional HTML reports
- Friendly CLI with interactive prompts and formatted output (uses `rich` if available)

Files in this repository
------------------------
- `iot.py` — Main scanner/auditor script (CLI)
- `requirements.txt` — Recommended dependencies (rich, scapy, Jinja2)
- `merge_reports.py` — Helper script to merge multiple per-IP JSON reports into one combined report (created in this workspace)

Requirements
------------
Recommended (install with pip):

```powershell
python -m pip install -r requirements.txt
```

Minimum useful installs:

```powershell
python -m pip install rich
# Optional for ARP discovery and nicer HTML
python -m pip install scapy Jinja2
```

Usage examples
--------------
Generate an offline demo report:

```powershell
python iot.py demo
python iot.py demo --html demo-report.html
```

Scan a single host (treat IP as /32 subnet):

```powershell
python iot.py scan --subnet 192.168.31.84/32 --timeout 0.5 --workers 20 --output iot-audit.192.168.31.84.json --html report.192.168.31.84.html
```

Scan an entire /24 subnet (only scan networks you are authorized to test):

```powershell
python iot.py scan --subnet 192.168.31.0/24 --timeout 1.0 --workers 64 --html report.html
```

Interactive usage (omit `--subnet` to be prompted):

```powershell
python iot.py scan
# you'll be prompted to enter the target subnet
```

Batch scanning multiple IPs (PowerShell example)
------------------------------------------------
Scan a list of IPs individually and save per-host JSON+HTML reports.

```powershell
$ips = "192.168.31.84","192.168.31.165","192.168.31.88"
foreach ($ip in $ips) {
  python iot.py scan --subnet "$ip/32" --timeout 0.5 --workers 20 --output "iot-audit.$ip.json" --html "report.$ip.html"
}
```

Merging per-host reports
------------------------
If you have multiple per-host JSON reports (created with `--output iot-audit.<ip>.json`), the helper `merge_reports.py` will combine them into `iot-audit.merged.json` and attempt to render `iot-audit.merged.html` using the existing renderer in `iot.py`.

To run the helper:

```powershell
python merge_reports.py
```

The script can be edited to attach MAC addresses and device names. See the `metadata` dict at the top of `merge_reports.py`.

Report format (JSON)
--------------------
Top-level keys:
- `tool` — tool name
- `summary` — scan summary (subnet, live_hosts, open_mqtt_brokers, anonymous_mqtt_allowed, generated_at)
- `scan` — scan configuration (ports, subnet, discovery method)
- `hosts` — list of host records, each with:
  - `ip`, `mac`, `alive_via`, `open_ports`, `services`, `tags`, `mqtt` (audit result)

Notes & limitations
-------------------
- ARP discovery requires `scapy` and often Administrator/root privileges.
- ICMP ping uses the system `ping` command — behavior differs across OSes.
- MQTT audit is minimal: anonymous CONNECT + optional SUBSCRIBE. It does not perform authentication or message publishing tests.
- IPv6 is partially supported for listing addresses, but ARP/ND and MQTT checks are IPv4-focused.
- Only perform network scanning where you have permission.

Security & ethics
-----------------
Network scanning and vulnerability testing can be intrusive. Only scan networks and devices you own or have explicit authorization to test. Misuse may violate policies, terms of service or laws.

Development notes
-----------------
- The CLI will use `rich` (if installed) to produce tables and colored output. Without `rich`, the tool falls back to plain text output.
- The HTML report uses Jinja2 if available; otherwise a simple fallback HTML is produced.

Support / Next steps
--------------------
If you'd like, I can:
- Merge your per-IP results and annotate them with MACs/device names you provided.
- Add OUI (MAC vendor) lookup to annotate manufacturers automatically.
- Add IPv6 neighbor discovery and IPv6 scanning improvements.
- Add an option to output CSV or other formats.

License
-------
Use at your own risk. No explicit license is included in this repository.


