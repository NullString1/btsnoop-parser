use std::{
    collections::HashMap,
    fmt::{Debug, Display},
};

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct FileHeader {
    pub identifier: [u8; 8],
    pub version: u32,
    pub data_link_type: u32,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RawPacketHeader {
    pub original_length: u32,
    pub included_length: u32,
    pub packet_flags: u32,
    pub cumulative_drops: u32,
    pub timestamp_milliseconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum HciPacketType {
    None = 0x00,
    Command = 0x01,
    Event = 0x04,
    ACLData = 0x02,
    SCOData = 0x03,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct BluetoothHCIHeader {
    pub hci_packet_type: HciPacketType,
    pub hci_handle: HCIHandle,
    pub data_total_length: u16,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct HCIHandle(pub u16);
impl HCIHandle {
    pub fn new(handle: u16) -> Self {
        HCIHandle(handle)
    }
    pub fn bc_flags(&self) -> u8 {
        ((self.0 >> 14) & 0b11) as u8
    }
    pub fn pb_flags(&self) -> u8 {
        ((self.0 >> 12) & 0b11) as u8
    }
    pub fn handle(&self) -> u16 {
        self.0 & 0x0FFF
    }
    pub fn raw(&self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct L2CAPacketHeader {
    pub length: u16,
    pub channel_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum ATTCommand {
    None = 0x00,
    WriteCommand = 0x52,
    HandleValueNotification = 0x1b,
}

#[derive(Debug, Clone, Serialize)]
pub struct ATTHeader {
    pub command: ATTCommand,
    pub handle: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketRecord {
    pub header: RawPacketHeader,
    pub hci_header: BluetoothHCIHeader,
    pub l2cap_header: L2CAPacketHeader,
    pub att_header: ATTHeader,
    pub packet_data: Vec<u8>,
    pub packet_number: u32,
    pub dest_addr: [u8; 6],
}

impl PacketRecord {
    pub fn mac_address(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.dest_addr[5],
            self.dest_addr[4],
            self.dest_addr[3],
            self.dest_addr[2],
            self.dest_addr[1],
            self.dest_addr[0]
        )
    }
}
impl Display for PacketRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data_str = match std::str::from_utf8(&self.packet_data) {
            Ok(s) => s.to_string(),
            Err(_) => self
                .packet_data
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" "),
        };

        write!(
            f,
            "PacketRecord {{ packet_number: {}, dest_addr: {}, att_command: {:?}, data: \"{}\" }}",
            self.packet_number,
            self.mac_address(),
            self.att_header.command,
            data_str
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BTSnoopFile {
    pub header: FileHeader,
    pub packets: Vec<PacketRecord>,
    pub handle_addr_map: HashMap<u16, [u8; 6]>,
}
