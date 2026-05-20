from __future__ import annotations

import argparse
import concurrent.futures
import html as html_lib
import ipaddress
import json
import os
import platform
import shlex
import socket
import struct
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
	from rich.console import Console
	from rich.table import Table
	from rich.panel import Panel
	from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
	from rich.style import Style
	from rich import box
	HAS_RICH = True
except ImportError:
	HAS_RICH = False

console = Console() if HAS_RICH else None


DEFAULT_PORTS = [22, 23, 80, 443, 1883, 5683]
SERVICE_NAMES = {
	22: "ssh",
	23: "telnet",
	80: "http",
	443: "https",
	1883: "mqtt",
	5683: "coap",
}


@dataclass
class HostResult:
	ip: str
	mac: Optional[str] = None
	alive_via: str = "unknown"
	open_ports: List[int] = field(default_factory=list)
	services: List[str] = field(default_factory=list)
	tags: List[str] = field(default_factory=list)
	mqtt: Optional[Dict[str, Any]] = None


def utc_now() -> str:
	return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_ports(text: str) -> List[int]:
	ports: List[int] = []
	seen = set()
	for chunk in text.split(","):
		value = chunk.strip()
		if not value:
			continue
		port = int(value)
		if port < 1 or port > 65535:
			raise ValueError(f"Invalid port: {port}")
		if port not in seen:
			seen.add(port)
			ports.append(port)
	if not ports:
		raise ValueError("At least one port must be provided")
	return ports


def iter_hosts(subnet: str) -> List[str]:
	network = ipaddress.ip_network(subnet, strict=False)
	return [str(ip) for ip in network.hosts()]


def _probe_port(host: str, port: int, timeout: float) -> bool:
	try:
		with socket.create_connection((host, port), timeout=timeout):
			return True
	except OSError:
		return False


def _ping_host(host: str, timeout: float) -> bool:
	system = platform.system().lower()
	if system.startswith("win"):
		cmd = ["ping", "-n", "1", "-w", str(max(1, int(timeout * 1000))), host]
	else:
		cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
	try:
		completed = subprocess.run(
			cmd,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
			check=False,
		)
		return completed.returncode == 0
	except (FileNotFoundError, OSError):
		return False


def _scapy_arp_discovery(subnet: str, timeout: float) -> Optional[List[HostResult]]:
	try:
		from scapy.all import ARP, Ether, srp  # type: ignore
	except Exception:
		return None

	try:
		answered, _ = srp(
			Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
			timeout=timeout,
			verbose=False,
		)
	except Exception:
		return None

	hosts: List[HostResult] = []
	for _, reply in answered:
		hosts.append(
			HostResult(
				ip=getattr(reply, "psrc", ""),
				mac=getattr(reply, "hwsrc", None),
				alive_via="arp",
			)
		)
	return hosts


def discover_hosts(
	subnet: str,
	method: str = "auto",
	timeout: float = 1.0,
	workers: int = 64,
) -> List[HostResult]:
	method = method.lower()
	if method not in {"auto", "arp", "ping", "tcp"}:
		raise ValueError("discover_method must be one of: auto, arp, ping, tcp")

	if method in {"auto", "arp"}:
		scapy_hosts = _scapy_arp_discovery(subnet, timeout)
		if scapy_hosts:
			return sorted(scapy_hosts, key=lambda item: item.ip)
		if method == "arp":
			return []

	hosts = iter_hosts(subnet)

	if method in {"auto", "ping"}:
		alive: List[HostResult] = []
		with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
			future_map = {
				executor.submit(_ping_host, host, timeout): host
				for host in hosts
			}
			for future in concurrent.futures.as_completed(future_map):
				host = future_map[future]
				try:
					if future.result():
						alive.append(HostResult(ip=host, alive_via="ping"))
				except Exception:
					continue
		if alive or method == "ping":
			return sorted(alive, key=lambda item: item.ip)

	# TCP discovery fallback is used if ping is unavailable or explicitly requested.
	alive = []
	with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
		future_map = {
			executor.submit(_probe_port, host, port, timeout): (host, port)
			for host in hosts
			for port in DEFAULT_PORTS
		}
		found: Dict[str, str] = {}
		for future in concurrent.futures.as_completed(future_map):
			host, port = future_map[future]
			try:
				if future.result() and host not in found:
					found[host] = str(port)
			except Exception:
				continue
	for host, port in found.items():
		alive.append(HostResult(ip=host, alive_via=f"tcp:{port}"))
	return sorted(alive, key=lambda item: item.ip)


def scan_ports(hosts: Sequence[HostResult], ports: Sequence[int], timeout: float, workers: int) -> None:
	tasks: Dict[concurrent.futures.Future[bool], Tuple[HostResult, int]] = {}
	with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
		for host in hosts:
			for port in ports:
				tasks[executor.submit(_probe_port, host.ip, port, timeout)] = (host, port)

		open_map: Dict[str, List[int]] = {host.ip: [] for host in hosts}
		for future in concurrent.futures.as_completed(tasks):
			host, port = tasks[future]
			try:
				if future.result():
					open_map[host.ip].append(port)
			except Exception:
				continue

	for host in hosts:
		host.open_ports = sorted(open_map.get(host.ip, []))
		host.services = [SERVICE_NAMES.get(port, f"port-{port}") for port in host.open_ports]
		host.tags = classify_host(host.open_ports)


def classify_host(open_ports: Sequence[int]) -> List[str]:
	ports = set(open_ports)
	tags: List[str] = []
	if 1883 in ports:
		tags.append("mqtt-broker")
	if 23 in ports:
		tags.append("telnet-enabled")
	if 80 in ports or 443 in ports:
		tags.append("web-ui")
	if 22 in ports:
		tags.append("ssh-enabled")
	if 5683 in ports:
		tags.append("coap-device")
	if 1883 in ports and (80 in ports or 443 in ports):
		tags.append("smart-device")
	if not tags and ports:
		tags.append("networked-device")
	return tags


def _mqtt_encode_string(text: str) -> bytes:
	data = text.encode("utf-8")
	return struct.pack("!H", len(data)) + data


def _mqtt_encode_varint(value: int) -> bytes:
	encoded = bytearray()
	while True:
		digit = value % 128
		value //= 128
		if value > 0:
			digit |= 0x80
		encoded.append(digit)
		if value == 0:
			break
	return bytes(encoded)


def _mqtt_connect_packet(client_id: str) -> bytes:
	variable_header = (
		_mqtt_encode_string("MQTT")
		+ b"\x04"
		+ b"\x02"  # Clean session, no username/password.
		+ struct.pack("!H", 10)
	)
	payload = _mqtt_encode_string(client_id)
	remaining = variable_header + payload
	return b"\x10" + _mqtt_encode_varint(len(remaining)) + remaining


def _mqtt_subscribe_packet(topic_filter: str, packet_id: int = 1) -> bytes:
	variable_header = struct.pack("!H", packet_id)
	payload = _mqtt_encode_string(topic_filter) + b"\x00"
	remaining = variable_header + payload
	return b"\x82" + _mqtt_encode_varint(len(remaining)) + remaining


def _recv_exact(sock: socket.socket, size: int) -> bytes:
	chunks: List[bytes] = []
	remaining = size
	while remaining > 0:
		chunk = sock.recv(remaining)
		if not chunk:
			break
		chunks.append(chunk)
		remaining -= len(chunk)
	return b"".join(chunks)


def _recv_mqtt_packet(sock: socket.socket) -> Optional[Tuple[int, bytes]]:
	first = _recv_exact(sock, 1)
	if not first:
		return None
	packet_type = first[0]

	multiplier = 1
	remaining_length = 0
	while True:
		encoded = _recv_exact(sock, 1)
		if not encoded:
			return None
		digit = encoded[0]
		remaining_length += (digit & 0x7F) * multiplier
		if (digit & 0x80) == 0:
			break
		multiplier *= 128
		if multiplier > 128 * 128 * 128 * 128:
			return None

	payload = _recv_exact(sock, remaining_length)
	if len(payload) != remaining_length:
		return None
	return packet_type, payload


def mqtt_audit(host: HostResult, port: int = 1883, timeout: float = 2.0, topic_filter: Optional[str] = None) -> Dict[str, Any]:
	result: Dict[str, Any] = {
		"port": port,
		"anonymous_connect": False,
		"status": "not_tested",
		"subscription_tested": False,
		"subscription_allowed": None,
		"details": "MQTT broker not tested",
	}

	if port not in host.open_ports:
		result["status"] = "skipped"
		result["details"] = "MQTT port not open"
		return result

	client_id = f"iot-audit-{uuid.uuid4().hex[:8]}"
	try:
		with socket.create_connection((host.ip, port), timeout=timeout) as sock:
			sock.settimeout(timeout)
			sock.sendall(_mqtt_connect_packet(client_id))
			packet = _recv_mqtt_packet(sock)
			if not packet:
				result["status"] = "no-response"
				result["details"] = "No MQTT CONNACK received"
				return result

			packet_type, payload = packet
			if packet_type >> 4 != 2 or len(payload) < 2:
				result["status"] = "unexpected-response"
				result["details"] = "Broker returned a non-CONNACK packet"
				return result

			return_code = payload[1]
			if return_code != 0:
				result["status"] = "connection-denied"
				result["details"] = f"Broker denied anonymous connection (code {return_code})"
				return result

			result["anonymous_connect"] = True
			result["status"] = "anonymous-connect-allowed"
			result["details"] = "Broker accepted anonymous MQTT connection"

			if topic_filter:
				result["subscription_tested"] = True
				sock.sendall(_mqtt_subscribe_packet(topic_filter))
				suback = _recv_mqtt_packet(sock)
				if not suback:
					result["subscription_allowed"] = False
					result["details"] += "; SUBACK not received"
					return result

				sub_type, sub_payload = suback
				if sub_type >> 4 != 9 or len(sub_payload) < 3:
					result["subscription_allowed"] = False
					result["details"] += "; unexpected SUBACK response"
					return result

				qos_return_code = sub_payload[-1]
				result["subscription_allowed"] = qos_return_code != 0x80
				if result["subscription_allowed"]:
					result["status"] = "anonymous-connect-and-subscribe-allowed"
					result["details"] += f"; subscription to {topic_filter!r} allowed"
				else:
					result["details"] += f"; subscription to {topic_filter!r} denied"

			return result
	except (socket.timeout, ConnectionError, OSError) as exc:
		result["status"] = "error"
		result["details"] = f"MQTT audit failed: {exc}"
		return result


def generate_report(
	subnet: str,
	discovery_method: str,
	hosts: Sequence[HostResult],
	ports: Sequence[int],
	mqtt_topic: Optional[str],
) -> Dict[str, Any]:
	host_records = [asdict(host) for host in hosts]
	mqtt_records = [host.get("mqtt") or {} for host in host_records]
	summary = {
		"subnet": subnet,
		"discovery_method": discovery_method,
		"port_count": len(list(ports)),
		"live_hosts": len(host_records),
		"open_mqtt_brokers": sum(1 for host in host_records if 1883 in host.get("open_ports", [])),
		"anonymous_mqtt_allowed": sum(1 for mqtt in mqtt_records if mqtt.get("anonymous_connect")),
		"generated_at": utc_now(),
	}
	return {
		"tool": "iot-vulnerability-audit",
		"summary": summary,
		"scan": {
			"subnet": subnet,
			"discovery_method": discovery_method,
			"ports": list(ports),
			"mqtt_topic": mqtt_topic,
		},
		"hosts": host_records,
	}


def attach_mqtt_audit(hosts: Sequence[HostResult], timeout: float, mqtt_topic: Optional[str]) -> None:
	for host in hosts:
		if 1883 in host.open_ports:
			host.mqtt = mqtt_audit(host, timeout=timeout, topic_filter=mqtt_topic)
		else:
			host.mqtt = {
				"port": 1883,
				"anonymous_connect": False,
				"status": "skipped",
				"subscription_tested": False,
				"subscription_allowed": None,
				"details": "MQTT port not open",
			}


def render_html_report(report: Dict[str, Any]) -> str:
	try:
		from jinja2 import Template  # type: ignore
	except Exception:
		Template = None

	template_text = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>IoT Audit Report</title>
  <style>
	body { font-family: Arial, sans-serif; margin: 24px; background: #f8fafc; color: #111827; }
	.card { background: white; border-radius: 12px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
	h1, h2, h3 { margin-top: 0; }
	table { width: 100%; border-collapse: collapse; }
	th, td { text-align: left; border-bottom: 1px solid #e5e7eb; padding: 8px; vertical-align: top; }
	.tag { display: inline-block; background: #dbeafe; color: #1d4ed8; padding: 2px 8px; border-radius: 999px; margin: 2px 4px 2px 0; font-size: 12px; }
	.muted { color: #6b7280; }
	.good { color: #047857; font-weight: 600; }
	.warn { color: #b45309; font-weight: 600; }
	.bad { color: #b91c1c; font-weight: 600; }
	code, pre { background: #f3f4f6; padding: 2px 4px; border-radius: 4px; }
  </style>
</head>
<body>
  <div class=\"card\">
	<h1>IoT Audit Report</h1>
	<p class=\"muted\">Generated {{ summary.generated_at }} for subnet <code>{{ summary.subnet }}</code>.</p>
	<ul>
	  <li>Discovery method: <strong>{{ summary.discovery_method }}</strong></li>
	  <li>Live hosts: <strong>{{ summary.live_hosts }}</strong></li>
	  <li>Open MQTT brokers: <strong>{{ summary.open_mqtt_brokers }}</strong></li>
	  <li>Anonymous MQTT allowed: <strong>{{ summary.anonymous_mqtt_allowed }}</strong></li>
	</ul>
  </div>

  {% for host in hosts %}
  <div class=\"card\">
	<h2>{{ host.ip }}</h2>
	<p class=\"muted\">Alive via <strong>{{ host.alive_via }}</strong>{% if host.mac %} · MAC <code>{{ host.mac }}</code>{% endif %}</p>
	<p>
	  {% if host.open_ports %}
		{% for port in host.open_ports %}<span class=\"tag\">{{ port }} {{ services[port] }}</span>{% endfor %}
	  {% else %}
		<span class=\"warn\">No open ports detected</span>
	  {% endif %}
	</p>
	<p>
	  {% for tag in host.tags %}<span class=\"tag\">{{ tag }}</span>{% endfor %}
	</p>
	<h3>MQTT audit</h3>
	<p class=\"{{ 'good' if host.mqtt and host.mqtt.anonymous_connect else 'bad' if host.mqtt and host.mqtt.status == 'connection-denied' else 'muted' }}\">
	  {{ host.mqtt.details if host.mqtt else 'Not tested' }}
	</p>
  </div>
  {% endfor %}
</body>
</html>"""

	context = {
		"summary": report["summary"],
		"hosts": report["hosts"],
		"services": SERVICE_NAMES,
	}

	if Template is not None:
		return Template(template_text).render(**context)

	# Fallback renderer without Jinja2.
	lines = [
		"<!doctype html>",
		"<html lang='en'>",
		"<head>",
		"<meta charset='utf-8' />",
		"<title>IoT Audit Report</title>",
		"</head>",
		"<body>",
		f"<h1>IoT Audit Report</h1>",
		f"<p>Generated {html_lib.escape(report['summary']['generated_at'])} for subnet <code>{html_lib.escape(report['summary']['subnet'])}</code>.</p>",
	]
	for host in report["hosts"]:
		lines.append(f"<h2>{html_lib.escape(host['ip'])}</h2>")
		lines.append(f"<p>Alive via {html_lib.escape(host.get('alive_via', 'unknown'))}</p>")
		lines.append("<ul>")
		for port in host.get("open_ports", []):
			lines.append(f"<li>{port} {html_lib.escape(SERVICE_NAMES.get(port, f'port-{port}'))}</li>")
		lines.append("</ul>")
		if host.get("mqtt"):
			lines.append(f"<p>{html_lib.escape(host['mqtt'].get('details', ''))}</p>")
	lines.append("</body></html>")
	return "\n".join(lines)


def write_outputs(report: Dict[str, Any], output_path: Path, html_path: Optional[Path], pretty: bool = True) -> None:
	output_path.parent.mkdir(parents=True, exist_ok=True)
	with output_path.open("w", encoding="utf-8") as handle:
		json.dump(report, handle, indent=2 if pretty else None, sort_keys=True)
		handle.write("\n")

	if html_path is not None:
		html_path.parent.mkdir(parents=True, exist_ok=True)
		html_text = render_html_report(report)
		html_path.write_text(html_text, encoding="utf-8")


def demo_report() -> Dict[str, Any]:
	hosts = [
		HostResult(
			ip="192.168.1.10",
			mac="aa:bb:cc:dd:ee:01",
			alive_via="demo",
			open_ports=[80, 1883],
			services=["http", "mqtt"],
			tags=["mqtt-broker", "web-ui", "smart-device"],
			mqtt={
				"port": 1883,
				"anonymous_connect": True,
				"status": "anonymous-connect-allowed",
				"subscription_tested": True,
				"subscription_allowed": True,
				"details": "Broker accepted anonymous MQTT connection; subscription to '#' allowed",
			},
		),
		HostResult(
			ip="192.168.1.15",
			mac="aa:bb:cc:dd:ee:02",
			alive_via="demo",
			open_ports=[23, 80],
			services=["telnet", "http"],
			tags=["telnet-enabled", "web-ui"],
			mqtt={
				"port": 1883,
				"anonymous_connect": False,
				"status": "skipped",
				"subscription_tested": False,
				"subscription_allowed": None,
				"details": "MQTT port not open",
			},
		),
	]
	return generate_report("192.168.1.0/24", "demo", hosts, DEFAULT_PORTS, "#")


def print_summary(report: Dict[str, Any]) -> None:
	summary = report["summary"]

	if HAS_RICH and console:
		# Rich formatted output
		console.print()
		console.print(f"[bold cyan]IoT Audit Report[/bold cyan]")
		console.print(f"[dim]Subnet:[/dim] [yellow]{summary['subnet']}[/yellow] [dim]({summary['discovery_method']})[/dim]")
		console.print()

		# Summary stats
		table = Table(title="[bold]Scan Summary[/bold]", box=box.ROUNDED)
		table.add_column("Metric", style="cyan")
		table.add_column("Value", style="green")
		table.add_row("Live Hosts", str(summary['live_hosts']))
		table.add_row("MQTT Brokers", str(summary['open_mqtt_brokers']))
		table.add_row("Anonymous MQTT", str(summary['anonymous_mqtt_allowed']))
		console.print(table)
		console.print()

		# Host details table
		if report["hosts"]:
			hosts_table = Table(title="[bold]Discovered Hosts[/bold]", box=box.ROUNDED)
			hosts_table.add_column("IP Address", style="cyan")
			hosts_table.add_column("Ports", style="yellow")
			hosts_table.add_column("Tags", style="magenta")
			hosts_table.add_column("MQTT Status", style="blue")

			for host in report["hosts"]:
				ports = ", ".join(str(port) for port in host.get("open_ports", [])) or "—"
				tags = ", ".join(host.get("tags", [])) or "—"
				mqtt_status = host.get("mqtt", {}).get("status", "—")
				if mqtt_status == "anonymous-connect-allowed":
					mqtt_status = f"[red]{mqtt_status}[/red]"
				elif mqtt_status == "skipped":
					mqtt_status = f"[dim]{mqtt_status}[/dim]"
				hosts_table.add_row(host['ip'], ports, tags, mqtt_status)

			console.print(hosts_table)
			console.print()

			# Detailed host info
			for host in report["hosts"]:
				console.print(f"[bold blue]→ {host['ip']}[/bold blue]")
				console.print(f"  [dim]Alive via:[/dim] {host.get('alive_via', 'unknown')}")
				if host.get("mac"):
					console.print(f"  [dim]MAC:[/dim] {host['mac']}")
				if host.get("mqtt"):
					mqtt = host['mqtt']
					console.print(f"  [dim]MQTT:[/dim] {mqtt.get('details', 'N/A')}")
				console.print()
	else:
		# Fallback plain text output
		print(f"IoT audit for {summary['subnet']} ({summary['discovery_method']})")
		print(f"  Live hosts: {summary['live_hosts']}")
		print(f"  MQTT brokers: {summary['open_mqtt_brokers']}")
		print(f"  Anonymous MQTT allowed: {summary['anonymous_mqtt_allowed']}")
		for host in report["hosts"]:
			ports = ", ".join(str(port) for port in host.get("open_ports", [])) or "none"
			tags = ", ".join(host.get("tags", [])) or "none"
			print(f"  - {host['ip']}: ports [{ports}] tags [{tags}]")
			if host.get("mqtt"):
				print(f"      MQTT: {host['mqtt'].get('status')} - {host['mqtt'].get('details')}")


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		description="[bold cyan]IoT Vulnerability Scanner & Audit Tool[/bold cyan]",
		formatter_class=argparse.ArgumentDefaultsHelpFormatter,
	)
	subparsers = parser.add_subparsers(dest="command")

	scan = subparsers.add_parser("scan", help="Scan a subnet for IoT devices")
	scan.add_argument("--subnet", default=None, help="Target subnet, e.g. 192.168.1.0/24")
	scan.add_argument("--discover-method", default="auto", choices=["auto", "arp", "ping", "tcp"], help="Host discovery method")
	scan.add_argument("--ports", default=",".join(str(port) for port in DEFAULT_PORTS), help="Comma-separated TCP ports to scan")
	scan.add_argument("--timeout", type=float, default=1.0, help="Socket/ping timeout in seconds")
	scan.add_argument("--workers", type=int, default=64, help="Maximum worker threads")
	scan.add_argument("--mqtt-topic", default=None, help="Optional MQTT subscription test topic/filter (e.g. # or home/+/status)")
	scan.add_argument("--output", default="iot-audit.json", help="Path to the JSON report")
	scan.add_argument("--html", default=None, help="Optional path to an HTML report")
	scan.add_argument("--no-summary", action="store_true", help="Do not print a console summary")

	demo = subparsers.add_parser("demo", help="Generate a sample offline report")
	demo.add_argument("--output", default="iot-audit.demo.json", help="Path to the JSON report")
	demo.add_argument("--html", default=None, help="Optional path to an HTML report")
	demo.add_argument("--no-summary", action="store_true", help="Do not print a console summary")

	parser.set_defaults(command="scan")
	return parser


def run_scan(args: argparse.Namespace) -> Dict[str, Any]:
	ports = parse_ports(args.ports)
	hosts = discover_hosts(
		subnet=args.subnet,
		method=args.discover_method,
		timeout=max(0.1, float(args.timeout)),
		workers=max(1, int(args.workers)),
	)
	scan_ports(hosts, ports, timeout=max(0.1, float(args.timeout)), workers=max(1, int(args.workers)))
	attach_mqtt_audit(hosts, timeout=max(0.5, float(args.timeout)), mqtt_topic=args.mqtt_topic)
	return generate_report(args.subnet, args.discover_method, hosts, ports, args.mqtt_topic)


def run_demo(args: argparse.Namespace) -> Dict[str, Any]:
	report = demo_report()
	return report


def main(argv: Optional[Sequence[str]] = None) -> int:
	# Show welcome banner
	if HAS_RICH and console:
		console.print()
		console.print("[bold cyan]╔════════════════════════════════════════╗[/bold cyan]")
		console.print("[bold cyan]║   IoT Vulnerability Scanner & Auditor  ║[/bold cyan]")
		console.print("[bold cyan]╚════════════════════════════════════════╝[/bold cyan]")
		console.print()

	parser = build_parser()
	try:
		args = parser.parse_args(argv)

		# Interactive subnet prompt if not provided for scan
		if args.command == "scan" and not args.subnet:
			if HAS_RICH and console:
				console.print("[yellow]No subnet specified.[/yellow]")
				args.subnet = console.input("[bold cyan]Enter target subnet (e.g., 192.168.1.0/24):[/bold cyan] ").strip()
			else:
				args.subnet = input("Enter target subnet (e.g., 192.168.1.0/24): ").strip()

			if not args.subnet:
				if HAS_RICH and console:
					console.print("[red]Error: Subnet is required[/red]")
				else:
					print("Error: Subnet is required")
				return 1

		if args.command == "demo":
			if HAS_RICH and console:
				console.print("[blue]Generating demo report...[/blue]")
			report = run_demo(args)
		else:
			if HAS_RICH and console:
				console.print(f"[blue]Scanning subnet:[/blue] [yellow]{args.subnet}[/yellow]")
				console.print(f"[blue]Method:[/blue] [yellow]{args.discover_method}[/yellow]")
				console.print()
			report = run_scan(args)
	except ValueError as exc:
		parser.error(str(exc))
		return 2

	output_path = Path(getattr(args, "output", "iot-audit.json"))
	html_arg = getattr(args, "html", None)
	html_path = Path(html_arg) if html_arg else None
	write_outputs(report, output_path=output_path, html_path=html_path, pretty=True)

	if not getattr(args, "no_summary", False):
		print_summary(report)
		if HAS_RICH and console:
			console.print()
			console.print(f"[green]✓[/green] [dim]JSON report:[/dim] [cyan]{output_path.resolve()}[/cyan]")
			if html_path is not None:
				console.print(f"[green]✓[/green] [dim]HTML report:[/dim] [cyan]{html_path.resolve()}[/cyan]")
			console.print()
		else:
			print(f"\nJSON report: {output_path.resolve()}")
			if html_path is not None:
				print(f"HTML report: {html_path.resolve()}")

	return 0


if __name__ == "__main__":
	raise SystemExit(main())

