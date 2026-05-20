//! Low-level packet builders + raw senders. Each builder returns the raw
//! bytes of a complete packet (with checksums set), so callers can either
//! send them via the high-level helpers or pipe them somewhere else
//! (a pcap, a socket they control, a test fixture).

use std::net::Ipv4Addr;

use pnet::datalink::{Channel, MacAddr};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::icmp::{checksum as icmp_checksum, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum as ipv4_checksum, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum as tcp_ipv4_checksum, MutableTcpPacket};
use pnet::packet::udp::{ipv4_checksum as udp_ipv4_checksum, MutableUdpPacket};
use pnet::transport::{transport_channel, TransportChannelType};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::Rng;

use crate::datalink::interface_or_default;
use crate::error::{io_to_py, parse_ipv4, parse_mac, parse_tcp_flags};
use crate::route::source_ipv4_for_addr;

pub const IPV4_HEADER_LEN: usize = 20;
pub const TCP_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;
pub const ICMP_HEADER_LEN: usize = 8;
pub const ETHERNET_HEADER_LEN: usize = 14;
pub const ARP_PACKET_LEN: usize = 28;

/// Build an IPv4 + TCP packet with all checksums computed. Returns the
/// concatenated bytes (no Ethernet header).
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    window: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total = IPV4_HEADER_LEN + TCP_HEADER_LEN + payload.len();
    let mut buf = vec![0u8; total];

    {
        let mut tcp = MutableTcpPacket::new(&mut buf[IPV4_HEADER_LEN..]).expect("tcp buf");
        tcp.set_source(sport);
        tcp.set_destination(dport);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        tcp.set_window(window);
        tcp.set_urgent_ptr(0);
        if !payload.is_empty() {
            tcp.set_payload(payload);
        }
        let csum = tcp_ipv4_checksum(&tcp.to_immutable(), &src, &dst);
        tcp.set_checksum(csum);
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..IPV4_HEADER_LEN]).expect("ip buf");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_length(total as u16);
        ip.set_identification(rand::thread_rng().gen());
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_fragment_offset(0);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(ipv4_checksum(&ip.to_immutable()));
    }
    buf
}

#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    let mut buf = vec![0u8; total];

    {
        let mut udp = MutableUdpPacket::new(&mut buf[IPV4_HEADER_LEN..]).expect("udp buf");
        udp.set_source(sport);
        udp.set_destination(dport);
        udp.set_length((UDP_HEADER_LEN + payload.len()) as u16);
        if !payload.is_empty() {
            udp.set_payload(payload);
        }
        let csum = udp_ipv4_checksum(&udp.to_immutable(), &src, &dst);
        udp.set_checksum(csum);
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..IPV4_HEADER_LEN]).expect("ip buf");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total as u16);
        ip.set_identification(rand::thread_rng().gen());
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(ipv4_checksum(&ip.to_immutable()));
    }
    buf
}

pub fn build_ipv4_icmp_echo(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ident: u16,
    seq: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total = IPV4_HEADER_LEN + ICMP_HEADER_LEN + payload.len();
    let mut buf = vec![0u8; total];

    {
        let h = &mut buf[IPV4_HEADER_LEN..IPV4_HEADER_LEN + ICMP_HEADER_LEN];
        h[0] = IcmpTypes::EchoRequest.0;
        h[1] = 0;
        h[4..6].copy_from_slice(&ident.to_be_bytes());
        h[6..8].copy_from_slice(&seq.to_be_bytes());
    }
    if !payload.is_empty() {
        buf[IPV4_HEADER_LEN + ICMP_HEADER_LEN..].copy_from_slice(payload);
    }
    {
        let mut icmp = MutableIcmpPacket::new(&mut buf[IPV4_HEADER_LEN..]).expect("icmp buf");
        let csum = icmp_checksum(&icmp.to_immutable());
        icmp.set_checksum(csum);
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..IPV4_HEADER_LEN]).expect("ip buf");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total as u16);
        ip.set_identification(rand::thread_rng().gen());
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(ipv4_checksum(&ip.to_immutable()));
    }
    buf
}

pub fn build_arp_request_bytes(
    iface_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};

    let mut buf = vec![0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..ETHERNET_HEADER_LEN]).expect("eth");
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(iface_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut buf[ETHERNET_HEADER_LEN..]).expect("arp");
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(iface_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }
    buf
}

// ------------- pyo3 wrappers -------------

/// Build the bytes of an IPv4/TCP packet with checksums set. Returns bytes.
#[pyfunction]
#[pyo3(signature = (
    dst,
    dport,
    flags = "S",
    *,
    sport = None,
    src = None,
    seq = None,
    ack = 0,
    window = 64240,
    ttl = 64,
    payload = None,
))]
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet<'py>(
    py: Python<'py>,
    dst: &str,
    dport: u16,
    flags: &str,
    sport: Option<u16>,
    src: Option<&str>,
    seq: Option<u32>,
    ack: u32,
    window: u16,
    ttl: u8,
    payload: Option<Vec<u8>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let dst_ip = parse_ipv4(dst)?;
    let src_ip = match src {
        Some(s) => parse_ipv4(s)?,
        None => source_ipv4_for_addr(dst_ip).map_err(|e| io_to_py(e, "source_ipv4_for_addr"))?,
    };
    let mut rng = rand::thread_rng();
    let sport = sport.unwrap_or_else(|| rng.gen_range(32768..60999));
    let seq = seq.unwrap_or_else(|| rng.gen());
    let flags_u8 = parse_tcp_flags(flags);
    let payload = payload.unwrap_or_default();
    let bytes = build_ipv4_tcp(
        src_ip, dst_ip, sport, dport, flags_u8, seq, ack, window, ttl, &payload,
    );
    Ok(PyBytes::new_bound(py, &bytes))
}

#[pyfunction]
#[pyo3(signature = (
    dst,
    dport,
    *,
    sport = None,
    src = None,
    ttl = 64,
    payload = None,
))]
pub fn build_udp_packet<'py>(
    py: Python<'py>,
    dst: &str,
    dport: u16,
    sport: Option<u16>,
    src: Option<&str>,
    ttl: u8,
    payload: Option<Vec<u8>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let dst_ip = parse_ipv4(dst)?;
    let src_ip = match src {
        Some(s) => parse_ipv4(s)?,
        None => source_ipv4_for_addr(dst_ip).map_err(|e| io_to_py(e, "source_ipv4_for_addr"))?,
    };
    let mut rng = rand::thread_rng();
    let sport = sport.unwrap_or_else(|| rng.gen_range(32768..60999));
    let payload = payload.unwrap_or_default();
    let bytes = build_ipv4_udp(src_ip, dst_ip, sport, dport, ttl, &payload);
    Ok(PyBytes::new_bound(py, &bytes))
}

#[pyfunction]
#[pyo3(signature = (
    dst,
    *,
    src = None,
    ident = None,
    seq = 1,
    ttl = 64,
    payload = None,
))]
pub fn build_icmp_echo<'py>(
    py: Python<'py>,
    dst: &str,
    src: Option<&str>,
    ident: Option<u16>,
    seq: u16,
    ttl: u8,
    payload: Option<Vec<u8>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let dst_ip = parse_ipv4(dst)?;
    let src_ip = match src {
        Some(s) => parse_ipv4(s)?,
        None => source_ipv4_for_addr(dst_ip).map_err(|e| io_to_py(e, "source_ipv4_for_addr"))?,
    };
    let ident = ident.unwrap_or_else(|| rand::thread_rng().gen());
    let payload = payload.unwrap_or_default();
    let bytes = build_ipv4_icmp_echo(src_ip, dst_ip, ident, seq, ttl, &payload);
    Ok(PyBytes::new_bound(py, &bytes))
}

#[pyfunction]
#[pyo3(signature = (target_ip, *, iface = None, src_ip = None, src_mac = None))]
pub fn build_arp_request<'py>(
    py: Python<'py>,
    target_ip: &str,
    iface: Option<&str>,
    src_ip: Option<&str>,
    src_mac: Option<&str>,
) -> PyResult<Bound<'py, PyBytes>> {
    let target = parse_ipv4(target_ip)?;
    let iface_info = interface_or_default(iface)?;
    let mac = match src_mac {
        Some(m) => parse_mac(m)?,
        None => iface_info.mac.ok_or_else(|| {
            crate::error::value_err(format!(
                "interface '{}' has no MAC address",
                iface_info.name
            ))
        })?,
    };
    let src = match src_ip {
        Some(s) => parse_ipv4(s)?,
        None => iface_info.ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
    };
    let bytes = build_arp_request_bytes(mac, src, target);
    Ok(PyBytes::new_bound(py, &bytes))
}

/// Send pre-built IPv4 packet bytes via a Layer3 raw socket.
#[pyfunction]
#[pyo3(signature = (dst, packet, *, protocol = "tcp"))]
pub fn send_ipv4_bytes(
    py: Python<'_>,
    dst: &str,
    packet: Vec<u8>,
    protocol: &str,
) -> PyResult<()> {
    let dst_ip = parse_ipv4(dst)?;
    let proto = match protocol.to_ascii_lowercase().as_str() {
        "tcp" => IpNextHeaderProtocols::Tcp,
        "udp" => IpNextHeaderProtocols::Udp,
        "icmp" => IpNextHeaderProtocols::Icmp,
        other => {
            return Err(crate::error::value_err(format!(
                "unknown protocol '{other}'; use tcp, udp, or icmp"
            )))
        }
    };
    py.allow_threads(|| {
        let (mut tx, _rx) = transport_channel(4096, TransportChannelType::Layer3(proto))
            .map_err(|e| io_to_py(e, "transport_channel"))?;
        let ip_pkt = pnet::packet::ipv4::Ipv4Packet::new(&packet)
            .ok_or_else(|| crate::error::value_err("packet bytes too short for IPv4"))?;
        tx.send_to(ip_pkt, std::net::IpAddr::V4(dst_ip))
            .map_err(|e| io_to_py(e, "send"))?;
        Ok(())
    })
}

/// Send pre-built Layer 2 (Ethernet) bytes on `iface`. Equivalent to
/// scapy `sendp`. Requires the bytes to start with an Ethernet header.
#[pyfunction]
#[pyo3(signature = (packet, *, iface = None))]
pub fn send_l2_bytes(py: Python<'_>, packet: Vec<u8>, iface: Option<&str>) -> PyResult<()> {
    let iface_info = interface_or_default(iface)?;
    let pnet_iface = iface_info.pnet.clone();
    py.allow_threads(move || {
        let (mut tx, _rx) = match pnet::datalink::channel(&pnet_iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(crate::error::value_err("unsupported datalink channel type")),
            Err(e) => return Err(io_to_py(e, "datalink::channel")),
        };
        tx.send_to(&packet, None)
            .unwrap_or(Ok(()))
            .map_err(|e| io_to_py(e, "send_to"))?;
        Ok(())
    })
}

// ------------- packet handles returned to Python -------------

/// Lightweight TCP packet handle. Returned by build helpers when the caller
/// wants to introspect rather than just hand the bytes off.
#[pyclass]
#[derive(Clone)]
pub struct RawTcp {
    pub bytes: Vec<u8>,
}

#[pymethods]
impl RawTcp {
    fn __repr__(&self) -> String {
        format!("RawTcp(len={})", self.bytes.len())
    }
    fn __len__(&self) -> usize {
        self.bytes.len()
    }
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.bytes)
    }
}

#[pyclass]
#[derive(Clone)]
pub struct RawUdp {
    pub bytes: Vec<u8>,
}

#[pymethods]
impl RawUdp {
    fn __repr__(&self) -> String {
        format!("RawUdp(len={})", self.bytes.len())
    }
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.bytes)
    }
}

#[pyclass]
#[derive(Clone)]
pub struct RawIcmpEcho {
    pub bytes: Vec<u8>,
}

#[pymethods]
impl RawIcmpEcho {
    fn __repr__(&self) -> String {
        format!("RawIcmpEcho(len={})", self.bytes.len())
    }
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.bytes)
    }
}
