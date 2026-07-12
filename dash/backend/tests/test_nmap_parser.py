"""Unit tests for the Nmap XML parser, including malicious-input defenses."""

from __future__ import annotations

import pytest
from app.models.enums import ServiceState, ServiceTransport
from app.services.nmap_parser import NmapParseError, parse_nmap_xml

SAMPLE_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.20.0.5" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Acme Corp"/>
    <hostnames><hostname name="host5.lan" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="23"><state state="closed"/></port>
    </ports>
    <os>
      <osmatch name="Linux 4.x" accuracy="90"/>
      <osmatch name="Linux 5.4" accuracy="95"/>
    </os>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.20.0.6" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_parses_up_host_only() -> None:
    hosts = parse_nmap_xml(SAMPLE_XML)
    assert len(hosts) == 1  # the down host is skipped
    host = hosts[0]
    assert host.ip == "10.20.0.5"
    assert host.mac == "00:11:22:33:44:55"
    assert host.mac_vendor == "Acme Corp"
    assert host.hostnames == ["host5.lan"]
    assert host.operating_system == "Linux 5.4"  # highest-accuracy osmatch


# No <os> block (unprivileged connect scan): OS is fingerprinted from -sV signals.
SV_ONLY_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.20.0.7" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Microsoft Windows Server" ostype="Windows">
          <cpe>cpe:/o:microsoft:windows</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" ostype="Windows"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH">
          <cpe>cpe:/a:openbsd:openssh</cpe>
          <cpe>cpe:/o:linux:linux_kernel</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_os_fingerprinted_from_service_detection() -> None:
    host = parse_nmap_xml(SV_ONLY_XML)[0]
    # Two services say Windows (ostype), one implies Linux (OS CPE): majority wins.
    assert host.operating_system == "Windows"
    ports = {s.port: s for s in host.services}
    assert ports[445].os_hint == "Windows"
    assert ports[22].os_hint == "Linux"  # derived from cpe:/o:linux:linux_kernel


# nmap often embeds the OS in the version string rather than a structured field.
VERSION_STRING_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.20.0.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13.16">
          <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.25"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_os_inferred_from_version_string() -> None:
    host = parse_nmap_xml(VERSION_STRING_XML)[0]
    # "OpenSSH 9.6p1 Ubuntu" implies Linux even without ostype/OS-CPE; the plain
    # Apache banner contributes no OS keyword, so Linux stands.
    assert host.operating_system == "Linux"


def test_osmatch_takes_priority_over_service_hints() -> None:
    # When a raw-socket OS scan is present, its result wins over -sV guesses.
    host = parse_nmap_xml(SAMPLE_XML)[0]
    assert host.operating_system == "Linux 5.4"


def test_parses_open_services_only() -> None:
    host = parse_nmap_xml(SAMPLE_XML)[0]
    ports = {s.port: s for s in host.services}
    assert set(ports) == {22, 80}  # closed port 23 is excluded
    assert ports[22].transport == ServiceTransport.TCP
    assert ports[22].state == ServiceState.OPEN
    assert ports[22].service_name == "ssh"
    assert ports[22].product == "OpenSSH"
    assert ports[22].version == "8.9p1"
    assert ports[22].cpe == "cpe:/a:openbsd:openssh:8.9p1"
    assert ports[80].product == "nginx"


def test_malformed_xml_raises() -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(b"<nmaprun><host></nmaprun")


def test_non_nmaprun_raises() -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(b"<other></other>")


def test_xxe_entity_is_blocked() -> None:
    # An external-entity payload must be rejected, not resolved.
    payload = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        b"<nmaprun>&xxe;</nmaprun>"
    )
    with pytest.raises(NmapParseError):
        parse_nmap_xml(payload)


def test_billion_laughs_is_blocked() -> None:
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<!DOCTYPE lolz [\n"
        b'  <!ENTITY lol "lol">\n'
        b'  <!ENTITY lol2 "&lol;&lol;&lol;&lol;">\n'
        b"]>\n"
        b"<nmaprun>&lol2;</nmaprun>"
    )
    with pytest.raises(NmapParseError):
        parse_nmap_xml(payload)


def test_empty_scan_returns_no_hosts() -> None:
    assert parse_nmap_xml(b'<nmaprun scanner="nmap"></nmaprun>') == []
