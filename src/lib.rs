//! libpnet-pyo3 — pyo3 bindings for libpnet.
//!
//! See README.md for the Python API surface.

// pyo3 macro expansions trip these lints — globally suppress.
#![allow(clippy::useless_conversion, clippy::too_many_arguments)]

use pnet::packet::tcp::TcpFlags;
use pyo3::prelude::*;

mod arp;
mod datalink;
mod error;
mod icmp;
mod packet;
mod route;
mod sniff;
mod tcp;
mod udp;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Response types
    m.add_class::<tcp::TcpResponse>()?;
    m.add_class::<udp::UdpResponse>()?;
    m.add_class::<icmp::IcmpResponse>()?;
    m.add_class::<arp::ArpReply>()?;
    m.add_class::<sniff::SniffedPacket>()?;
    m.add_class::<datalink::Interface>()?;
    m.add_class::<packet::RawTcp>()?;
    m.add_class::<packet::RawUdp>()?;
    m.add_class::<packet::RawIcmpEcho>()?;

    // High-level send-receive
    m.add_function(wrap_pyfunction!(tcp::tcp_sr1, m)?)?;
    m.add_function(wrap_pyfunction!(tcp::tcp_send, m)?)?;
    m.add_function(wrap_pyfunction!(udp::udp_sr1, m)?)?;
    m.add_function(wrap_pyfunction!(udp::udp_send, m)?)?;
    m.add_function(wrap_pyfunction!(icmp::icmp_ping, m)?)?;
    m.add_function(wrap_pyfunction!(arp::arp_who_has, m)?)?;
    m.add_function(wrap_pyfunction!(sniff::sniff, m)?)?;

    // Low-level packet builders (produce bytes)
    m.add_function(wrap_pyfunction!(packet::build_tcp_packet, m)?)?;
    m.add_function(wrap_pyfunction!(packet::build_udp_packet, m)?)?;
    m.add_function(wrap_pyfunction!(packet::build_icmp_echo, m)?)?;
    m.add_function(wrap_pyfunction!(packet::build_arp_request, m)?)?;
    m.add_function(wrap_pyfunction!(packet::send_ipv4_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(packet::send_l2_bytes, m)?)?;

    // Routing / interface helpers
    m.add_function(wrap_pyfunction!(route::source_ipv4_for, m)?)?;
    m.add_function(wrap_pyfunction!(datalink::list_interfaces, m)?)?;
    m.add_function(wrap_pyfunction!(datalink::default_interface, m)?)?;
    m.add_function(wrap_pyfunction!(datalink::interface_for, m)?)?;

    // TCP flag constants (mirror scapy's "S", "SA", etc. when OR'd)
    m.add("FIN", TcpFlags::FIN)?;
    m.add("SYN", TcpFlags::SYN)?;
    m.add("RST", TcpFlags::RST)?;
    m.add("PSH", TcpFlags::PSH)?;
    m.add("ACK", TcpFlags::ACK)?;
    m.add("URG", TcpFlags::URG)?;
    m.add("ECE", TcpFlags::ECE)?;
    m.add("CWR", TcpFlags::CWR)?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
