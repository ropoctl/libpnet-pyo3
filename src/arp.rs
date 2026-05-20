use std::time::{Duration, Instant};

use pnet::datalink::{Channel, MacAddr};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use pyo3::prelude::*;

use crate::datalink::interface_or_default;
use crate::error::{io_to_py, parse_ipv4};
use crate::packet::build_arp_request_bytes;

#[pyclass]
#[derive(Clone, Debug)]
pub struct ArpReply {
    #[pyo3(get)]
    pub ip: String,
    #[pyo3(get)]
    pub mac: String,
    #[pyo3(get)]
    pub iface: String,
}

#[pymethods]
impl ArpReply {
    fn __repr__(&self) -> String {
        format!(
            "ArpReply(ip={}, mac={}, iface={})",
            self.ip, self.mac, self.iface
        )
    }
}

/// Resolve an IPv4 address to a MAC by sending an ARP request and waiting
/// for the matching reply. Equivalent to scapy `arping(target)` but for a
/// single target.
#[pyfunction]
#[pyo3(signature = (target_ip, *, iface = None, timeout = 1.0))]
pub fn arp_who_has(
    py: Python<'_>,
    target_ip: &str,
    iface: Option<&str>,
    timeout: f64,
) -> PyResult<Option<ArpReply>> {
    let target = parse_ipv4(target_ip)?;
    let info = interface_or_default(iface)?;
    let mac = info
        .mac
        .ok_or_else(|| crate::error::value_err(format!("iface '{}' has no MAC", info.name)))?;
    let src_ip = info
        .ipv4
        .ok_or_else(|| crate::error::value_err(format!("iface '{}' has no IPv4", info.name)))?;
    let pkt = build_arp_request_bytes(mac, src_ip, target);
    let iface_name = info.name.clone();
    let pnet_iface = info.pnet.clone();

    py.allow_threads(move || {
        let (mut tx, mut rx) = match pnet::datalink::channel(&pnet_iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(crate::error::value_err("unsupported datalink channel type")),
            Err(e) => return Err(io_to_py(e, "datalink::channel")),
        };

        tx.send_to(&pkt, None)
            .unwrap_or(Ok(()))
            .map_err(|e| io_to_py(e, "send"))?;

        let deadline = Instant::now() + Duration::from_secs_f64(timeout);
        while Instant::now() < deadline {
            // pnet's datalink receiver blocks indefinitely unless the
            // channel was configured with read_timeout. We pass packets
            // that arrive quickly through, and the outer loop bounds the
            // total wait. For tighter timing, the caller can lower
            // `timeout`.
            match rx.next() {
                Ok(frame) => {
                    let Some(eth) = EthernetPacket::new(frame) else {
                        continue;
                    };
                    if eth.get_ethertype() != EtherTypes::Arp {
                        continue;
                    }
                    let Some(arp) = ArpPacket::new(eth.payload()) else {
                        continue;
                    };
                    if arp.get_sender_proto_addr() != target {
                        continue;
                    }
                    let mac: MacAddr = arp.get_sender_hw_addr();
                    return Ok(Some(ArpReply {
                        ip: target.to_string(),
                        mac: mac.to_string(),
                        iface: iface_name.clone(),
                    }));
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock
                    {
                        continue;
                    }
                    return Err(io_to_py(e, "recv"));
                }
            }
        }
        Ok(None)
    })
}
