use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::transport::{ipv4_packet_iter, transport_channel, TransportChannelType};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::Rng;

use crate::error::{io_to_py, parse_ipv4};
use crate::packet::build_ipv4_udp;
use crate::route::source_ipv4_for_addr;

#[pyclass]
#[derive(Clone, Debug)]
pub struct UdpResponse {
    #[pyo3(get)]
    pub src: String,
    #[pyo3(get)]
    pub dst: String,
    #[pyo3(get)]
    pub sport: u16,
    #[pyo3(get)]
    pub dport: u16,
    #[pyo3(get)]
    pub ttl: u8,
    pub payload: Vec<u8>,
}

#[pymethods]
impl UdpResponse {
    fn __repr__(&self) -> String {
        format!(
            "UdpResponse(src={}, sport={}, dport={}, ttl={}, payload_len={})",
            self.src,
            self.sport,
            self.dport,
            self.ttl,
            self.payload.len()
        )
    }

    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.payload)
    }
}

#[pyfunction]
#[pyo3(signature = (dst, dport, payload, *, sport = None, src = None, ttl = 64, timeout = 1.0))]
pub fn udp_sr1(
    py: Python<'_>,
    dst: &str,
    dport: u16,
    payload: Vec<u8>,
    sport: Option<u16>,
    src: Option<&str>,
    ttl: u8,
    timeout: f64,
) -> PyResult<Option<UdpResponse>> {
    let dst_ip = parse_ipv4(dst)?;
    let src_ip = match src {
        Some(s) => parse_ipv4(s)?,
        None => source_ipv4_for_addr(dst_ip).map_err(|e| io_to_py(e, "source_ipv4_for_addr"))?,
    };
    let sport = sport.unwrap_or_else(|| rand::thread_rng().gen_range(32768..60999));
    let pkt = build_ipv4_udp(src_ip, dst_ip, sport, dport, ttl, &payload);
    py.allow_threads(|| do_udp_sr1(src_ip, dst_ip, sport, dport, &pkt, timeout))
}

#[pyfunction]
#[pyo3(signature = (dst, dport, payload, *, sport = None, src = None, ttl = 64))]
pub fn udp_send(
    py: Python<'_>,
    dst: &str,
    dport: u16,
    payload: Vec<u8>,
    sport: Option<u16>,
    src: Option<&str>,
    ttl: u8,
) -> PyResult<()> {
    let dst_ip = parse_ipv4(dst)?;
    let src_ip = match src {
        Some(s) => parse_ipv4(s)?,
        None => source_ipv4_for_addr(dst_ip).map_err(|e| io_to_py(e, "source_ipv4_for_addr"))?,
    };
    let sport = sport.unwrap_or_else(|| rand::thread_rng().gen_range(32768..60999));
    let pkt = build_ipv4_udp(src_ip, dst_ip, sport, dport, ttl, &payload);

    py.allow_threads(|| {
        let proto = TransportChannelType::Layer3(IpNextHeaderProtocols::Udp);
        let (mut tx, _rx) =
            transport_channel(4096, proto).map_err(|e| io_to_py(e, "transport_channel"))?;
        let ip_pkt = Ipv4Packet::new(&pkt).expect("built");
        tx.send_to(ip_pkt, std::net::IpAddr::V4(dst_ip))
            .map_err(|e| io_to_py(e, "send"))?;
        Ok(())
    })
}

fn do_udp_sr1(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    pkt_bytes: &[u8],
    timeout: f64,
) -> PyResult<Option<UdpResponse>> {
    let proto = TransportChannelType::Layer3(IpNextHeaderProtocols::Udp);
    let (mut tx, mut rx) =
        transport_channel(4096, proto).map_err(|e| io_to_py(e, "transport_channel"))?;
    let ip_pkt = Ipv4Packet::new(pkt_bytes).expect("built");
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
                if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                    continue;
                }
                if ip.get_source() != dst_ip || ip.get_destination() != src_ip {
                    continue;
                }
                let Some(udp) = UdpPacket::new(ip.payload()) else {
                    continue;
                };
                if udp.get_source() != dport || udp.get_destination() != sport {
                    continue;
                }
                return Ok(Some(UdpResponse {
                    src: ip.get_source().to_string(),
                    dst: ip.get_destination().to_string(),
                    sport: udp.get_source(),
                    dport: udp.get_destination(),
                    ttl: ip.get_ttl(),
                    payload: udp.payload().to_vec(),
                }));
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    }
    Ok(None)
}
