use std::time::{Duration, Instant};

use pnet::packet::icmp::{IcmpPacket, IcmpType, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{ipv4_packet_iter, transport_channel, TransportChannelType};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::Rng;

use crate::error::{io_to_py, parse_ipv4};
use crate::packet::build_ipv4_icmp_echo;
use crate::route::source_ipv4_for_addr;

#[pyclass]
#[derive(Clone, Debug)]
pub struct IcmpResponse {
    #[pyo3(get)]
    pub src: String,
    #[pyo3(get)]
    pub icmp_type: u8,
    #[pyo3(get)]
    pub icmp_code: u8,
    #[pyo3(get)]
    pub ttl: u8,
    #[pyo3(get)]
    pub ident: u16,
    #[pyo3(get)]
    pub seq: u16,
    pub payload: Vec<u8>,
}

#[pymethods]
impl IcmpResponse {
    fn __repr__(&self) -> String {
        format!(
            "IcmpResponse(src={}, type={}, code={}, ttl={}, ident={}, seq={})",
            self.src, self.icmp_type, self.icmp_code, self.ttl, self.ident, self.seq
        )
    }

    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.payload)
    }

    fn is_echo_reply(&self) -> bool {
        self.icmp_type == IcmpTypes::EchoReply.0
    }
}

/// scapy `sr1(IP(dst=...)/ICMP())`. Sends an ICMP echo request and waits
/// for the matching echo reply (matched by identifier).
#[pyfunction]
#[pyo3(signature = (
    dst,
    *,
    src = None,
    ident = None,
    seq = 1,
    ttl = 64,
    payload = None,
    timeout = 1.0,
))]
pub fn icmp_ping(
    py: Python<'_>,
    dst: &str,
    src: Option<&str>,
    ident: Option<u16>,
    seq: u16,
    ttl: u8,
    payload: Option<Vec<u8>>,
    timeout: f64,
) -> PyResult<Option<IcmpResponse>> {
    let dst_ip = parse_ipv4(dst)?;
    let src_ip = match src {
        Some(s) => parse_ipv4(s)?,
        None => source_ipv4_for_addr(dst_ip).map_err(|e| io_to_py(e, "source_ipv4_for_addr"))?,
    };
    let ident = ident.unwrap_or_else(|| rand::thread_rng().gen());
    let payload = payload.unwrap_or_default();
    let pkt = build_ipv4_icmp_echo(src_ip, dst_ip, ident, seq, ttl, &payload);

    py.allow_threads(|| {
        let proto = TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp);
        let (mut tx, mut rx) =
            transport_channel(4096, proto).map_err(|e| io_to_py(e, "transport_channel"))?;
        let ip_pkt = pnet::packet::ipv4::Ipv4Packet::new(&pkt).expect("built");
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
                    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                        continue;
                    }
                    let Some(icmp) = IcmpPacket::new(ip.payload()) else {
                        continue;
                    };
                    // Match identifier (offset 4..6 of ICMP header).
                    let body = icmp.payload();
                    let rest = icmp.packet();
                    if rest.len() < 8 {
                        continue;
                    }
                    let recv_ident = u16::from_be_bytes([rest[4], rest[5]]);
                    let recv_seq = u16::from_be_bytes([rest[6], rest[7]]);
                    if recv_ident != ident {
                        continue;
                    }
                    let icmp_type: IcmpType = icmp.get_icmp_type();
                    return Ok(Some(IcmpResponse {
                        src: ip.get_source().to_string(),
                        icmp_type: icmp_type.0,
                        icmp_code: icmp.get_icmp_code().0,
                        ttl: ip.get_ttl(),
                        ident: recv_ident,
                        seq: recv_seq,
                        payload: body.to_vec(),
                    }));
                }
                Ok(None) => continue,
                Err(_) => break,
            }
        }
        Ok(None)
    })
}
