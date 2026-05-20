"""pyo3 bindings for libpnet.

Re-exports the native pyo3 module and adds small pure-Python conveniences.
The native module is built from `src/` via `maturin`.

API summary:

    tcp_sr1(dst, dport, flags="S", ...)       send-and-receive-one TCP
    tcp_send(dst, dport, flags="S", ...)      send TCP without waiting
    udp_sr1(dst, dport, payload, ...)         send-and-receive-one UDP
    udp_send(dst, dport, payload, ...)        send UDP without waiting
    icmp_ping(dst, ...)                       ICMP echo request/reply
    arp_who_has(target_ip, ...)               resolve IP → MAC via ARP
    sniff(iface=..., count=..., timeout=...)  capture L2 frames

    build_tcp_packet(...) / build_udp_packet(...) /
    build_icmp_echo(...) / build_arp_request(...)   → bytes
    send_ipv4_bytes(dst, packet, protocol=)         L3 raw send
    send_l2_bytes(packet, iface=)                   L2 (Ethernet) send

    list_interfaces() / default_interface() / interface_for(name)
    source_ipv4_for(dst)
"""

from libpnet_pyo3._native import (  # noqa: F401
    # Response types
    TcpResponse,
    UdpResponse,
    IcmpResponse,
    ArpReply,
    SniffedPacket,
    Interface,
    RawTcp,
    RawUdp,
    RawIcmpEcho,
    # Send-receive
    tcp_sr1,
    tcp_send,
    udp_sr1,
    udp_send,
    icmp_ping,
    arp_who_has,
    sniff,
    # Packet builders
    build_tcp_packet,
    build_udp_packet,
    build_icmp_echo,
    build_arp_request,
    send_ipv4_bytes,
    send_l2_bytes,
    # Helpers
    source_ipv4_for,
    list_interfaces,
    default_interface,
    interface_for,
    # Flag constants
    FIN,
    SYN,
    RST,
    PSH,
    ACK,
    URG,
    ECE,
    CWR,
    __version__,
)

__all__ = [
    "TcpResponse",
    "UdpResponse",
    "IcmpResponse",
    "ArpReply",
    "SniffedPacket",
    "Interface",
    "RawTcp",
    "RawUdp",
    "RawIcmpEcho",
    "tcp_sr1",
    "tcp_send",
    "udp_sr1",
    "udp_send",
    "icmp_ping",
    "arp_who_has",
    "sniff",
    "build_tcp_packet",
    "build_udp_packet",
    "build_icmp_echo",
    "build_arp_request",
    "send_ipv4_bytes",
    "send_l2_bytes",
    "source_ipv4_for",
    "list_interfaces",
    "default_interface",
    "interface_for",
    "FIN",
    "SYN",
    "RST",
    "PSH",
    "ACK",
    "URG",
    "ECE",
    "CWR",
    "__version__",
]
