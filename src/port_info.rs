use chrono::{DateTime, Utc};
use edamame_backend::lanscan_port_info_backend::PortInfoBackend;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Ord, Eq, PartialEq, PartialOrd)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub banner: String,
    pub dismissed: bool,
    // Last time a scan by THIS host saw the port answer open, or, for a port a
    // community peer reported, the time that peer says it saw it open. It is
    // what expires one port on its own clock
    // (`DeviceInfo::expire_stale_port_evidence`): a port that stops answering
    // without ever being refused (a firewall that starts dropping it) keeps
    // the device-level `last_port_scan` fresh through its neighbours and would
    // otherwise never leave the list.
    //
    // `serde(default)`: PortInfo is persisted inside the lanscan cache
    // (`FlodbaddLANScan.devices`), and caches written before this field existed
    // must still load. `None` is backfilled from the device's `last_port_scan`
    // on first use, so an upgrade does not expire every cached port at once.
    #[serde(default)]
    pub last_confirmed: Option<DateTime<Utc>>,
}

impl Into<PortInfoBackend> for PortInfo {
    fn into(self) -> PortInfoBackend {
        PortInfoBackend {
            port: self.port,
            protocol: self.protocol,
            service: self.service,
            banner: self.banner,
            vulnerabilities: Vec::new(),
        }
    }
}
