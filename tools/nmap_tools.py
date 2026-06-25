from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse
import json
import xml.etree.ElementTree as ET

from core.scope import ScopeManager
from core.run_context import RunContext
from tools.tool_runner import ToolRunner


SAFE_DEFAULT_PORTS = "80,443,3000,8080,8443"


@dataclass
class NmapPortService:
    port: int
    protocol: str
    state: str
    reason: str
    service_name: str | None
    product: str | None
    version: str | None
    tunnel: str | None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NmapScanSummary:
    target: str
    target_host: str
    ports: str
    command: list[str]
    success: bool
    host_up: bool
    open_port_count: int
    services: list[dict]
    xml_output_path: str | None
    parsed_json_path: str
    markdown_path: str
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class NmapTools:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.runner = ToolRunner(run_context.run_dir)
        self.parsed_dir = Path(run_context.parsed_dir)
        self.reports_dir = Path(run_context.reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def run_safe_port_scan(
        self,
        target: str,
        ports: str = SAFE_DEFAULT_PORTS,
        timeout_seconds: int = 120,
    ) -> NmapScanSummary:
        parsed_target = self.scope.parse_target(target)
        target_host = parsed_target["host"]
        if not target_host:
            raise ValueError(f"Could not determine target host from: {target}")

        xml_output_path = self.parsed_dir / "nmap_scan.xml"
        command = [
            "nmap",
            "-Pn",
            "-sT",
            "-T2",
            "-n",
            "--max-retries",
            "1",
            "--host-timeout",
            "30s",
            "--open",
            "-p",
            ports,
            "-oX",
            str(xml_output_path),
            target_host,
        ]

        tool_result = self.runner.run(
            tool_name="nmap",
            command=command,
            output_name="nmap_scan",
            timeout_seconds=timeout_seconds,
        )

        services: list[NmapPortService] = []
        host_up = False
        error = (tool_result.error or tool_result.stderr).strip() or None

        if tool_result.success and xml_output_path.exists():
            host_up, services = self._parse_xml(xml_output_path)

        summary = NmapScanSummary(
            target=target,
            target_host=target_host,
            ports=ports,
            command=command,
            success=tool_result.success,
            host_up=host_up,
            open_port_count=len(services),
            services=[item.to_dict() for item in services],
            xml_output_path=str(xml_output_path) if xml_output_path.exists() else None,
            parsed_json_path=str(self.parsed_dir / "nmap_scan.json"),
            markdown_path=str(self.reports_dir / "nmap_scan.md"),
            error=error if not tool_result.success else None,
        )

        self._write_summary(summary)
        self.ctx.add_event(
            event_type="nmap_scan_completed",
            message="Safe nmap scan completed.",
            data=summary.to_dict(),
        )
        return summary

    def _parse_xml(self, xml_path: Path) -> tuple[bool, list[NmapPortService]]:
        root = ET.fromstring(xml_path.read_text(encoding="utf-8", errors="ignore"))
        host = root.find("host")
        if host is None:
            return False, []

        status = host.find("status")
        host_up = status is not None and status.attrib.get("state") == "up"

        services: list[NmapPortService] = []
        ports_node = host.find("ports")
        if ports_node is None:
            return host_up, services

        for port_node in ports_node.findall("port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.attrib.get("state") != "open":
                continue

            service_node = port_node.find("service")
            services.append(
                NmapPortService(
                    port=int(port_node.attrib.get("portid", "0")),
                    protocol=port_node.attrib.get("protocol", "tcp"),
                    state=state_node.attrib.get("state", "unknown"),
                    reason=state_node.attrib.get("reason", ""),
                    service_name=service_node.attrib.get("name") if service_node is not None else None,
                    product=service_node.attrib.get("product") if service_node is not None else None,
                    version=service_node.attrib.get("version") if service_node is not None else None,
                    tunnel=service_node.attrib.get("tunnel") if service_node is not None else None,
                )
            )

        return host_up, services

    def _write_summary(self, summary: NmapScanSummary) -> None:
        json_path = Path(summary.parsed_json_path)
        json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        lines: list[str] = []
        lines.append("# Safe Nmap Scan")
        lines.append("")
        lines.append("> Conservative TCP service discovery only. No vulnerability scripts, no UDP, no aggressive timing.")
        lines.append("")
        lines.append(f"- **Target:** `{summary.target}`")
        lines.append(f"- **Target Host:** `{summary.target_host}`")
        lines.append(f"- **Ports:** `{summary.ports}`")
        lines.append(f"- **Success:** `{summary.success}`")
        lines.append(f"- **Host Up:** `{summary.host_up}`")
        lines.append(f"- **Open Port Count:** `{summary.open_port_count}`")
        if summary.error:
            lines.append(f"- **Error:** `{summary.error}`")
        lines.append("")
        lines.append("## Open Services")
        lines.append("")

        if not summary.services:
            lines.append("- No open services were recorded.")
        else:
            for item in summary.services:
                service = item.get("service_name") or "unknown"
                product = item.get("product") or ""
                version = item.get("version") or ""
                reason = item.get("reason") or ""
                lines.append(
                    f"- `{item['protocol']}/{item['port']}` `{service}` `{product}` `{version}` `{reason}`"
                )

        lines.append("")
        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- This is infrastructure recon, not proof of a vulnerability.")
        lines.append("- Use results only when the selected program policy explicitly allows port scanning.")
        lines.append("- Do not add vuln scripts or UDP scans unless a later profile explicitly permits them.")
        lines.append("")

        Path(summary.markdown_path).write_text("\n".join(lines), encoding="utf-8")
