use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use pyo3::prelude::*;

use crate::error::{io_to_py, parse_ipv4};

/// Return the source IPv4 address the kernel would use to reach `dst`.
///
/// Uses the classic "connect a UDP socket and read local_addr" trick — no
/// packet is actually sent (UDP connect is just a routing/source-selection
/// operation in the kernel). Works on Linux, macOS, and Windows.
pub fn source_ipv4_for_addr(dst: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect((dst, 65535))?;
    match sock.local_addr()?.ip() {
        IpAddr::V4(a) => Ok(a),
        IpAddr::V6(_) => Err(std::io::Error::other("expected IPv4 source")),
    }
}

#[pyfunction]
#[pyo3(name = "source_ipv4_for")]
pub fn source_ipv4_for(dst: &str) -> PyResult<String> {
    let dst = parse_ipv4(dst)?;
    let src = source_ipv4_for_addr(dst).map_err(|e| io_to_py(e, "source_ipv4_for"))?;
    Ok(src.to_string())
}
