"""Smoke tests. Tests that hit the network are skipped without root."""

from __future__ import annotations

import os
import sys

import pytest

import libpnet_pyo3 as ln


def _is_root() -> bool:
    return getattr(os, "geteuid", lambda: 1)() == 0


def test_version_string():
    assert isinstance(ln.__version__, str)
    assert ln.__version__.count(".") >= 1


def test_flag_constants():
    assert ln.SYN == 0x02
    assert ln.ACK == 0x10
    assert ln.RST == 0x04
    assert (ln.SYN | ln.ACK) == 0x12


def test_list_interfaces():
    ifaces = ln.list_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) >= 1
    # Each interface has a name; at least one is loopback on every platform.
    assert any(i.is_loopback for i in ifaces), ifaces


def test_source_ipv4_for_localhost():
    # No network required — the kernel routes 127.0.0.1 to loopback.
    src = ln.source_ipv4_for("127.0.0.1")
    assert src == "127.0.0.1"


def test_build_tcp_packet_returns_bytes():
    pkt = ln.build_tcp_packet(dst="127.0.0.1", dport=80, flags="S", src="127.0.0.1")
    assert isinstance(pkt, (bytes, bytearray))
    # IPv4 header (20) + TCP header (20) = 40 bytes minimum.
    assert len(pkt) >= 40
    # First nibble is IP version 4.
    assert pkt[0] >> 4 == 4
    # Byte 9 of IPv4 header is the next-protocol field; 6 = TCP.
    assert pkt[9] == 6


def test_build_udp_packet_returns_bytes():
    pkt = ln.build_udp_packet(dst="127.0.0.1", dport=53, payload=b"hello", src="127.0.0.1")
    assert pkt[9] == 17  # UDP
    # Total length field at IPv4 bytes 2..4
    total_len = int.from_bytes(pkt[2:4], "big")
    assert total_len == len(pkt)


def test_build_icmp_echo_returns_bytes():
    pkt = ln.build_icmp_echo(dst="127.0.0.1", src="127.0.0.1", ident=0x1234, seq=7)
    assert pkt[9] == 1  # ICMP
    # ICMP header starts at byte 20 — type 8 = echo request.
    assert pkt[20] == 8


def test_build_arp_request_returns_bytes():
    pytest.importorskip_marker = None  # no-op so pytest doesn't complain
    try:
        pkt = ln.build_arp_request("192.0.2.1")
    except Exception as e:
        # Some CI hosts have no Ethernet-style iface (containers w/ only lo).
        pytest.skip(f"no Ethernet interface available: {e}")
    assert isinstance(pkt, (bytes, bytearray))
    # Ethernet (14) + ARP (28) = 42 bytes.
    assert len(pkt) == 42


@pytest.mark.skipif(not _is_root(), reason="raw socket sr1 needs root")
def test_tcp_sr1_localhost_closed_port():
    # Port 1 is virtually never bound on a dev host; we expect a RST
    # (or None if the OS swallows it). Just verify the call doesn't blow up
    # and returns the right type.
    resp = ln.tcp_sr1(dst="127.0.0.1", dport=1, timeout=0.5)
    assert resp is None or resp.is_rst() or resp.is_synack()


@pytest.mark.skipif(not _is_root(), reason="ICMP needs root")
def test_icmp_ping_localhost():
    resp = ln.icmp_ping("127.0.0.1", timeout=1.0)
    # On most kernels loopback echoes back; on some restrictive setups it
    # doesn't. Don't hard-fail; just verify the call shape.
    if resp is not None:
        assert resp.is_echo_reply()
        assert resp.src == "127.0.0.1"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
