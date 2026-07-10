"""Parse Nmap XML output into normalized hosts and services.

Scanner output is untrusted (build plan working rule 10 and Section 27.3): the
XML is parsed with ``defusedxml`` to prevent XML external-entity and
entity-expansion ("billion laughs") attacks, and callers must bound the input
size before calling here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree.ElementTree import Element, ParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

from app.models.enums import ServiceState, ServiceTransport

# Port states we treat as a live service worth recording.
_LIVE_STATES = {ServiceState.OPEN, ServiceState.OPEN_FILTERED}


class NmapParseError(ValueError):
    """Raised when Nmap XML is malformed or unsafe."""


@dataclass
class ParsedService:
    transport: ServiceTransport
    port: int
    state: ServiceState
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None


@dataclass
class ParsedHost:
    ip: str | None = None
    mac: str | None = None
    mac_vendor: str | None = None
    hostnames: list[str] = field(default_factory=list)
    operating_system: str | None = None
    services: list[ParsedService] = field(default_factory=list)


def parse_nmap_xml(xml_bytes: bytes) -> list[ParsedHost]:
    """Parse Nmap XML bytes into a list of up hosts with their services."""
    try:
        root = fromstring(xml_bytes)
    except (ParseError, DefusedXmlException, ValueError) as exc:
        raise NmapParseError(f"Invalid Nmap XML: {exc}") from exc
    if root is None or root.tag != "nmaprun":
        raise NmapParseError("Not an nmaprun document")

    hosts: list[ParsedHost] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        host = _parse_host(host_el)
        if host.ip is not None or host.mac is not None:
            hosts.append(host)
    return hosts


def _parse_host(host_el: Element) -> ParsedHost:
    host = ParsedHost()
    for addr in host_el.findall("address"):
        addr_type = addr.get("addrtype")
        value = addr.get("addr")
        if value is None:
            continue
        if addr_type in ("ipv4", "ipv6") and host.ip is None:
            host.ip = value
        elif addr_type == "mac":
            host.mac = value
            host.mac_vendor = addr.get("vendor")

    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        for hn in hostnames_el.findall("hostname"):
            name = hn.get("name")
            if name:
                host.hostnames.append(name)

    os_el = host_el.find("os")
    if os_el is not None:
        best_accuracy = -1
        for match in os_el.findall("osmatch"):
            try:
                accuracy = int(match.get("accuracy", "0"))
            except ValueError:
                accuracy = 0
            if accuracy > best_accuracy and match.get("name"):
                best_accuracy = accuracy
                host.operating_system = match.get("name")

    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            service = _parse_port(port_el)
            if service is not None:
                host.services.append(service)
    return host


def _parse_port(port_el: Element) -> ParsedService | None:
    state_el = port_el.find("state")
    state_value = state_el.get("state") if state_el is not None else None
    try:
        state = ServiceState(state_value) if state_value else ServiceState.OPEN
    except ValueError:
        return None
    if state not in _LIVE_STATES:
        return None

    try:
        transport = ServiceTransport(port_el.get("protocol", "tcp"))
    except ValueError:
        transport = ServiceTransport.TCP
    try:
        port = int(port_el.get("portid", ""))
    except ValueError:
        return None
    if not (0 < port <= 65535):
        return None

    service = ParsedService(transport=transport, port=port, state=state)
    svc_el = port_el.find("service")
    if svc_el is not None:
        service.service_name = svc_el.get("name")
        service.product = svc_el.get("product")
        service.version = svc_el.get("version")
        cpe_el = svc_el.find("cpe")
        if cpe_el is not None and cpe_el.text:
            service.cpe = cpe_el.text
    return service
