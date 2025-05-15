use anyhow::Result;
use serde::{ser::SerializeStruct, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Device {
    pub(crate) id: Uuid,
    pub(crate) name: String, // interface name, e.g. "eth0", "ppp0"
    pub(crate) ip: String,   // IP address of the interface
}

impl Serialize for Device {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Device", 3)?;
        state.serialize_field("id", &self.id.to_string())?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("ip", &self.ip)?;
        state.end()
    }
}

/// Helper: read /proc/net/route and return the iface whose Destination is 0.0.0.0
pub fn get_default_interface() -> Result<String> {
    let data = std::fs::read_to_string("/proc/net/route")?;
    for line in data.lines().skip(1) {
        let cols: Vec<_> = line.split_whitespace().collect();
        if cols.get(1) == Some(&"00000000") {
            return Ok(cols[0].to_string());
        }
    }
    Err(anyhow::anyhow!("no default route interface found"))
}
