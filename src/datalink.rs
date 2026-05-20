//! Network interface helpers — list, default selection, lookup by name.

use std::net::Ipv4Addr;

use pnet::datalink::NetworkInterface;
use pyo3::prelude::*;

use crate::error::value_err;

/// Python-facing interface descriptor. Mirrors `scapy.arch.get_if_list()`
/// plus the per-interface attributes (mac, ip) most callers want.
#[pyclass]
#[derive(Clone)]
pub struct Interface {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub mac: Option<String>,
    #[pyo3(get)]
    pub ipv4: Vec<String>,
    #[pyo3(get)]
    pub ipv6: Vec<String>,
    #[pyo3(get)]
    pub is_up: bool,
    #[pyo3(get)]
    pub is_loopback: bool,
    #[pyo3(get)]
    pub index: u32,
}

#[pymethods]
impl Interface {
    fn __repr__(&self) -> String {
        format!(
            "Interface(name={}, mac={:?}, ipv4={:?}, up={})",
            self.name, self.mac, self.ipv4, self.is_up
        )
    }
}

impl From<&NetworkInterface> for Interface {
    fn from(i: &NetworkInterface) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for ip in &i.ips {
            match ip.ip() {
                std::net::IpAddr::V4(a) => v4.push(a.to_string()),
                std::net::IpAddr::V6(a) => v6.push(a.to_string()),
            }
        }
        Interface {
            name: i.name.clone(),
            mac: i.mac.map(|m| m.to_string()),
            ipv4: v4,
            ipv6: v6,
            is_up: i.is_up(),
            is_loopback: i.is_loopback(),
            index: i.index,
        }
    }
}

/// Helper struct used internally — combines the pnet handle with a parsed
/// IPv4 address for builders that need both.
pub struct InterfaceInfo {
    pub pnet: NetworkInterface,
    pub name: String,
    pub mac: Option<pnet::datalink::MacAddr>,
    pub ipv4: Option<Ipv4Addr>,
}

pub fn interface_or_default(name: Option<&str>) -> Result<InterfaceInfo, PyErr> {
    let ifaces = pnet::datalink::interfaces();
    let chosen = match name {
        Some(n) => ifaces
            .into_iter()
            .find(|i| i.name == n)
            .ok_or_else(|| value_err(format!("no interface named '{n}'; see list_interfaces()")))?,
        None => {
            // Default: first up, non-loopback, with an IPv4 address.
            ifaces
                .into_iter()
                .find(|i| i.is_up() && !i.is_loopback() && i.ips.iter().any(|x| x.is_ipv4()))
                .ok_or_else(|| value_err("no suitable default interface found"))?
        }
    };
    let ipv4 = chosen.ips.iter().find_map(|x| match x.ip() {
        std::net::IpAddr::V4(a) => Some(a),
        _ => None,
    });
    Ok(InterfaceInfo {
        name: chosen.name.clone(),
        mac: chosen.mac,
        ipv4,
        pnet: chosen,
    })
}

#[pyfunction]
pub fn list_interfaces() -> PyResult<Vec<Interface>> {
    Ok(pnet::datalink::interfaces()
        .iter()
        .map(Interface::from)
        .collect())
}

#[pyfunction]
pub fn default_interface() -> PyResult<Interface> {
    let info = interface_or_default(None)?;
    Ok(Interface::from(&info.pnet))
}

#[pyfunction]
#[pyo3(signature = (name))]
pub fn interface_for(name: &str) -> PyResult<Interface> {
    let info = interface_or_default(Some(name))?;
    Ok(Interface::from(&info.pnet))
}
