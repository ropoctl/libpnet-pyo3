use pyo3::exceptions::{PyOSError, PyPermissionError, PyValueError};
use pyo3::PyErr;

/// Map a `std::io::Error` into the closest Python exception.
///
/// EPERM/EACCES → PermissionError (matches scapy's "you need root" error)
/// Everything else → OSError with kind info.
pub fn io_to_py(err: std::io::Error, ctx: &str) -> PyErr {
    use std::io::ErrorKind::*;
    match err.kind() {
        PermissionDenied => PyPermissionError::new_err(format!(
            "{ctx}: {err}. Raw sockets need root (sudo) or CAP_NET_RAW on Linux."
        )),
        _ => PyOSError::new_err(format!("{ctx}: {err}")),
    }
}

pub fn value_err(msg: impl Into<String>) -> PyErr {
    PyValueError::new_err(msg.into())
}

pub fn parse_ipv4(s: &str) -> Result<std::net::Ipv4Addr, PyErr> {
    s.parse()
        .map_err(|e: std::net::AddrParseError| value_err(format!("invalid IPv4 '{s}': {e}")))
}

pub fn parse_mac(s: &str) -> Result<pnet::util::MacAddr, PyErr> {
    s.parse()
        .map_err(|e: pnet::util::ParseMacAddrErr| value_err(format!("invalid MAC '{s}': {e:?}")))
}

/// Parse a scapy-style flags string like "SA" or "S" into a u8 bitmask.
/// Each char maps to one TCP flag bit; case-insensitive; unknown chars are ignored.
pub fn parse_tcp_flags(flags: &str) -> u8 {
    use pnet::packet::tcp::TcpFlags;
    let mut out = 0u8;
    for c in flags.chars() {
        out |= match c.to_ascii_uppercase() {
            'F' => TcpFlags::FIN,
            'S' => TcpFlags::SYN,
            'R' => TcpFlags::RST,
            'P' => TcpFlags::PSH,
            'A' => TcpFlags::ACK,
            'U' => TcpFlags::URG,
            'E' => TcpFlags::ECE,
            'C' => TcpFlags::CWR,
            _ => 0,
        };
    }
    out
}
