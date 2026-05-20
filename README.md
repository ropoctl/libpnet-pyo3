# libpnet-pyo3

pyo3 bindings for [libpnet](https://github.com/libpnet/libpnet).

**Status:** alpha. Wheels published for Linux + macOS in v0.1. libpnet itself supports Windows (via Npcap or `winpkfilter`); the Windows wheel build for this wrapper is planned for a later release.

## Install

```bash
pip install libpnet-pyo3
```

Wheels published for Linux (x86_64, aarch64) and macOS (x86_64, aarch64), Python 3.10+ (abi3).

Raw sockets need elevated privilege:

- **Linux**: `sudo` or grant `CAP_NET_RAW` to the Python interpreter
- **macOS**: `sudo` (BPF and raw sockets are root-only)

## Quick start

```python
from libpnet_pyo3 import tcp_sr1, icmp_ping, sniff, arp_who_has

# TCP SYN probe
resp = tcp_sr1(dst="1.2.3.4", dport=80, flags="S", timeout=1.0)
if resp and resp.is_synack():
    print(f"open, ttl={resp.ttl}, window={resp.window}")

# Ping
echo = icmp_ping("1.1.1.1", timeout=1.0)
if echo and echo.is_echo_reply():
    print(f"reply from {echo.src} ttl={echo.ttl}")

# ARP
reply = arp_who_has("192.168.1.1")
if reply:
    print(f"{reply.ip} is at {reply.mac}")

# Sniff
for pkt in sniff(count=10, timeout=5.0):
    print(pkt)
```

## API

### Send-and-receive

| Function | Returns |
|---|---|
| `tcp_sr1(dst, dport, flags="S", *, sport=None, src=None, seq=None, window=64240, ttl=64, payload=None, timeout=1.0)` | `TcpResponse \| None` |
| `udp_sr1(dst, dport, payload, *, sport=None, src=None, ttl=64, timeout=1.0)` | `UdpResponse \| None` |
| `icmp_ping(dst, *, src=None, ident=None, seq=1, ttl=64, payload=None, timeout=1.0)` | `IcmpResponse \| None` |
| `arp_who_has(target_ip, *, iface=None, timeout=1.0)` | `ArpReply \| None` |

### Send-only

| Function | |
|---|---|
| `tcp_send(dst, dport, flags="S", ...)` | fire-and-forget TCP |
| `udp_send(dst, dport, payload, ...)` | fire-and-forget UDP |
| `send_ipv4_bytes(dst, packet, *, protocol="tcp")` | send pre-built IPv4 bytes |
| `send_l2_bytes(packet, *, iface=None)` | send pre-built Ethernet frame |

### Capture

`sniff(*, iface=None, count=None, timeout=None) -> list[SniffedPacket]` — at least one of `count`/`timeout` is required.

### Packet builders (return raw bytes)

`build_tcp_packet`, `build_udp_packet`, `build_icmp_echo`, `build_arp_request` — same kwargs as the send-receive equivalents.

### Helpers

| Function | |
|---|---|
| `list_interfaces()` | `list[Interface]` — name/mac/ipv4/ipv6/is_up/is_loopback/index |
| `default_interface()` | first up, non-loopback iface with an IPv4 |
| `interface_for(name)` | look up by name |
| `source_ipv4_for(dst)` | source IPv4 the kernel would pick for `dst` |

### Response objects

- `TcpResponse`: `src dst sport dport flags seq ack window ttl payload`, methods `has_flag(f)`, `is_synack()`, `is_rst()`
- `UdpResponse`: `src dst sport dport ttl payload`
- `IcmpResponse`: `src icmp_type icmp_code ttl ident seq payload`, method `is_echo_reply()`
- `ArpReply`: `ip mac iface`
- `SniffedPacket`: `iface bytes ts_secs`, method `ethertype()`

### TCP flag constants

`SYN`, `ACK`, `RST`, `FIN`, `PSH`, `URG`, `ECE`, `CWR` — combine with `|` or pass a string like `"SA"` to `flags=`.

## Not in v0.1 (planned)

- IPv6 (IPv4 only today)
- BPF filter expressions on `sniff`
- pcap read/write
- Multi-reply send (`sr` returning a list)
- Windows wheels (libpnet supports Windows via Npcap / winpkfilter — this wrapper just hasn't wired it up yet)

## Build from source

Requires Rust (stable, 1.74+) and Python 3.10+.

```bash
git clone https://github.com/Lazarus-AI/libpnet-pyo3
cd libpnet-pyo3
python -m venv .venv && source .venv/bin/activate
pip install maturin
maturin develop --release
```

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
