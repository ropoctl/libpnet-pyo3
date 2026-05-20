from typing import Optional, List

FIN: int
SYN: int
RST: int
PSH: int
ACK: int
URG: int
ECE: int
CWR: int
__version__: str


class TcpResponse:
    src: str
    dst: str
    sport: int
    dport: int
    flags: int
    seq: int
    ack: int
    window: int
    ttl: int
    payload: bytes
    def has_flag(self, flag: int) -> bool: ...
    def is_synack(self) -> bool: ...
    def is_rst(self) -> bool: ...


class UdpResponse:
    src: str
    dst: str
    sport: int
    dport: int
    ttl: int
    payload: bytes


class IcmpResponse:
    src: str
    icmp_type: int
    icmp_code: int
    ttl: int
    ident: int
    seq: int
    payload: bytes
    def is_echo_reply(self) -> bool: ...


class ArpReply:
    ip: str
    mac: str
    iface: str


class SniffedPacket:
    iface: str
    bytes: bytes
    ts_secs: float
    def ethertype(self) -> Optional[int]: ...


class Interface:
    name: str
    mac: Optional[str]
    ipv4: List[str]
    ipv6: List[str]
    is_up: bool
    is_loopback: bool
    index: int


class RawTcp:
    bytes: bytes


class RawUdp:
    bytes: bytes


class RawIcmpEcho:
    bytes: bytes


def tcp_sr1(
    dst: str,
    dport: int,
    flags: str = "S",
    *,
    sport: Optional[int] = None,
    src: Optional[str] = None,
    seq: Optional[int] = None,
    window: int = 64240,
    ttl: int = 64,
    payload: Optional[bytes] = None,
    timeout: float = 1.0,
) -> Optional[TcpResponse]: ...


def tcp_send(
    dst: str,
    dport: int,
    flags: str = "S",
    *,
    sport: Optional[int] = None,
    src: Optional[str] = None,
    seq: Optional[int] = None,
    window: int = 64240,
    ttl: int = 64,
    payload: Optional[bytes] = None,
) -> None: ...


def udp_sr1(
    dst: str,
    dport: int,
    payload: bytes,
    *,
    sport: Optional[int] = None,
    src: Optional[str] = None,
    ttl: int = 64,
    timeout: float = 1.0,
) -> Optional[UdpResponse]: ...


def udp_send(
    dst: str,
    dport: int,
    payload: bytes,
    *,
    sport: Optional[int] = None,
    src: Optional[str] = None,
    ttl: int = 64,
) -> None: ...


def icmp_ping(
    dst: str,
    *,
    src: Optional[str] = None,
    ident: Optional[int] = None,
    seq: int = 1,
    ttl: int = 64,
    payload: Optional[bytes] = None,
    timeout: float = 1.0,
) -> Optional[IcmpResponse]: ...


def arp_who_has(
    target_ip: str,
    *,
    iface: Optional[str] = None,
    timeout: float = 1.0,
) -> Optional[ArpReply]: ...


def sniff(
    *,
    iface: Optional[str] = None,
    count: Optional[int] = None,
    timeout: Optional[float] = None,
) -> List[SniffedPacket]: ...


def build_tcp_packet(
    dst: str,
    dport: int,
    flags: str = "S",
    *,
    sport: Optional[int] = None,
    src: Optional[str] = None,
    seq: Optional[int] = None,
    ack: int = 0,
    window: int = 64240,
    ttl: int = 64,
    payload: Optional[bytes] = None,
) -> bytes: ...


def build_udp_packet(
    dst: str,
    dport: int,
    *,
    sport: Optional[int] = None,
    src: Optional[str] = None,
    ttl: int = 64,
    payload: Optional[bytes] = None,
) -> bytes: ...


def build_icmp_echo(
    dst: str,
    *,
    src: Optional[str] = None,
    ident: Optional[int] = None,
    seq: int = 1,
    ttl: int = 64,
    payload: Optional[bytes] = None,
) -> bytes: ...


def build_arp_request(
    target_ip: str,
    *,
    iface: Optional[str] = None,
    src_ip: Optional[str] = None,
    src_mac: Optional[str] = None,
) -> bytes: ...


def send_ipv4_bytes(dst: str, packet: bytes, *, protocol: str = "tcp") -> None: ...


def send_l2_bytes(packet: bytes, *, iface: Optional[str] = None) -> None: ...


def source_ipv4_for(dst: str) -> str: ...


def list_interfaces() -> List[Interface]: ...


def default_interface() -> Interface: ...


def interface_for(name: str) -> Interface: ...
