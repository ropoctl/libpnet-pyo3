use std::time::{Duration, Instant};

use pnet::datalink::{Channel, Config};
use pnet::packet::ethernet::EthernetPacket;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::datalink::interface_or_default;
use crate::error::{io_to_py, value_err};

#[pyclass]
#[derive(Clone, Debug)]
pub struct SniffedPacket {
    #[pyo3(get)]
    pub iface: String,
    pub bytes: Vec<u8>,
    #[pyo3(get)]
    pub ts_secs: f64,
}

#[pymethods]
impl SniffedPacket {
    fn __repr__(&self) -> String {
        format!(
            "SniffedPacket(iface={}, len={}, ts={:.3})",
            self.iface,
            self.bytes.len(),
            self.ts_secs
        )
    }

    fn __len__(&self) -> usize {
        self.bytes.len()
    }

    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.bytes)
    }

    fn ethertype(&self) -> Option<u16> {
        EthernetPacket::new(&self.bytes).map(|e| e.get_ethertype().0)
    }
}

/// Capture packets off `iface` for up to `timeout` seconds or until
/// `count` packets have been seen. Returns a list of SniffedPacket.
///
/// scapy `sniff(iface=..., count=..., timeout=...)` — bpf_filter is not
/// supported in v0.1 (pnet's datalink layer doesn't expose BPF directly).
#[pyfunction]
#[pyo3(signature = (*, iface = None, count = None, timeout = None))]
pub fn sniff(
    py: Python<'_>,
    iface: Option<&str>,
    count: Option<usize>,
    timeout: Option<f64>,
) -> PyResult<Vec<SniffedPacket>> {
    if count.is_none() && timeout.is_none() {
        return Err(value_err("sniff() requires at least one of count= or timeout="));
    }

    let info = interface_or_default(iface)?;
    let iface_name = info.name.clone();
    let pnet_iface = info.pnet.clone();

    py.allow_threads(move || {
        let mut cfg = Config::default();
        cfg.read_timeout = Some(Duration::from_millis(200));
        let (_tx, mut rx) = match pnet::datalink::channel(&pnet_iface, cfg) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(value_err("unsupported datalink channel type")),
            Err(e) => return Err(io_to_py(e, "datalink::channel")),
        };

        let mut out = Vec::new();
        let start = Instant::now();
        let deadline = timeout.map(|t| start + Duration::from_secs_f64(t));

        loop {
            if let Some(c) = count {
                if out.len() >= c {
                    break;
                }
            }
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    break;
                }
            }

            match rx.next() {
                Ok(frame) => {
                    let now = start.elapsed().as_secs_f64();
                    out.push(SniffedPacket {
                        iface: iface_name.clone(),
                        bytes: frame.to_vec(),
                        ts_secs: now,
                    });
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
        Ok(out)
    })
}
