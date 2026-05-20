use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pnet::transport::{ipv4_packet_iter, transport_channel, TransportChannelType};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::Rng;

use crate::error::{io_to_py, parse_ipv4, parse_tcp_flags};
use crate::packet::build_ipv4_tcp;
use crate::route::source_ipv4_for_addr;

/// A TCP response captured from the raw socket. Mirrors what scapy returns
/// from `sr1` when the reply has an IP/TCP layer.
#[pyclass]
#[derive(Clone, Debug)]
pub struct TcpResponse {
    #[pyo3(get)]
    pub src: String,
    #[pyo3(get)]
    pub dst: String,
    #[pyo3(get)]
    pub sport: u16,
    #[pyo3(get)]
    pub dport: u16,
    #[pyo3(get)]
    pub flags: u8,
    #[pyo3(get)]
    pub seq: u32,
    #[pyo3(get)]
    pub ack: u32,
    #[pyo3(get)]
    pub window: u16,
    #[pyo3(get)]
    pub ttl: u8,
    pub payload: Vec<u8>,
}

#[pymethods]
impl TcpResponse {
    fn __repr__(&self) -> String {
        format!(
            "TcpResponse(src={}, sport={}, dport={}, flags=0x{:02x}, ttl={}, window={}, seq={}, ack={})",
            self.src, self.sport, self.dport, self.flags, self.ttl, self.window, self.seq, self.ack
        )
    }

    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.payload)
    }

    fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag == flag
    }

    fn is_synack(&self) -> bool {
        use pnet::packet::tcp::TcpFlags;
        self.flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK)
    }

    fn is_rst(&self) -> bool {
        use pnet::packet::tcp::TcpFlags;
        self.flags & TcpFlags::RST != 0
    }
}

#[pyfunction]
#[pyo3(signature = (
    dst,
    dport,
    flags = "S",
    *,
    sport = None,
    src = None,
    seq = None,
    window = 64240,
    ttl = 64,
    payload = None,
    timeout = 1.0,
))]
#[allow(clippy::too_many_arguments)]
pub fn tcp_sr1(
    py: Python<'_>,
    dst: &str,
    dport: u16,
    flags: &str,
    sport: Option<u16>,
    src: Option<&str>,
    seq: Option<u32>,
    window: u16,
    ttl: u8,
    payload: Option<Vec<u8>>,
    timeout: f64,
) -> PyResult<Option<TcpResponse>> {
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

    let pkt = build_ipv4_tcp(
        src_ip, dst_ip, sport, dport, flags_u8, seq, 0, window, ttl, &payload,
    );

    py.allow_threads(|| do_sr1(src_ip, dst_ip, sport, dport, &pkt, timeout))
}

#[pyfunction]
#[pyo3(signature = (
    dst,
    dport,
    flags = "S",
    *,
    sport = None,
    src = None,
    seq = None,
    window = 64240,
    ttl = 64,
    payload = None,
))]
#[allow(clippy::too_many_arguments)]
pub fn tcp_send(
    py: Python<'_>,
    dst: &str,
    dport: u16,
    flags: &str,
    sport: Option<u16>,
    src: Option<&str>,
    seq: Option<u32>,
    window: u16,
    ttl: u8,
    payload: Option<Vec<u8>>,
) -> PyResult<()> {
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
    let pkt = build_ipv4_tcp(
        src_ip, dst_ip, sport, dport, flags_u8, seq, 0, window, ttl, &payload,
    );

    py.allow_threads(|| {
        let proto = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
        let (mut tx, _rx) =
            transport_channel(4096, proto).map_err(|e| io_to_py(e, "transport_channel"))?;
        let ip_pkt = Ipv4Packet::new(&pkt).expect("built packet");
        tx.send_to(ip_pkt, std::net::IpAddr::V4(dst_ip))
            .map_err(|e| io_to_py(e, "send"))?;
        Ok(())
    })
}

fn do_sr1(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    pkt_bytes: &[u8],
    timeout: f64,
) -> PyResult<Option<TcpResponse>> {
    let proto = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tx, mut rx) =
        transport_channel(4096, proto).map_err(|e| io_to_py(e, "transport_channel"))?;

    let ip_pkt = Ipv4Packet::new(pkt_bytes).expect("built packet");
    tx.send_to(ip_pkt, std::net::IpAddr::V4(dst_ip))
        .map_err(|e| io_to_py(e, "send"))?;

    let deadline = Instant::now() + Duration::from_secs_f64(timeout);
    let mut iter = ipv4_packet_iter(&mut rx);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match iter.next_with_timeout(remaining) {
            Ok(Some((ip, _addr))) => {
                if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                    continue;
                }
                if ip.get_source() != dst_ip {
                    continue;
                }
                if ip.get_destination() != src_ip {
                    continue;
                }
                let Some(tcp) = TcpPacket::new(ip.payload()) else {
                    continue;
                };
                if tcp.get_source() != dport || tcp.get_destination() != sport {
                    continue;
                }
                return Ok(Some(TcpResponse {
                    src: ip.get_source().to_string(),
                    dst: ip.get_destination().to_string(),
                    sport: tcp.get_source(),
                    dport: tcp.get_destination(),
                    flags: tcp.get_flags(),
                    seq: tcp.get_sequence(),
                    ack: tcp.get_acknowledgement(),
                    window: tcp.get_window(),
                    ttl: ip.get_ttl(),
                    payload: tcp.payload().to_vec(),
                }));
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    }
    Ok(None)
}
