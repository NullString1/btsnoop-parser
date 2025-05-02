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

impl Default for FileHeader {
    fn default() -> Self {
        Self {
            identifier: [0u8; 8],
            version: 0,
            data_link_type: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RawPacketHeader {
    pub original_length: u32,
    pub included_length: u32,
    pub packet_flags: u32,
    pub cumulative_drops: u32,
    pub timestamp_milliseconds: u64,
}

impl Default for RawPacketHeader {
    fn default() -> Self {
        Self {
            original_length: 0,
            included_length: 0,
            packet_flags: 0,
            cumulative_drops: 0,
            timestamp_milliseconds: 0,
        }
    }
}

impl RawPacketHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&self.original_length.to_le_bytes());
        bytes.extend_from_slice(&self.included_length.to_le_bytes());
        bytes.extend_from_slice(&self.packet_flags.to_le_bytes());
        bytes.extend_from_slice(&self.cumulative_drops.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp_milliseconds.to_le_bytes());
        bytes
    }
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

impl Default for L2CAPacketHeader {
    fn default() -> Self {
        Self {
            length: 0,
            channel_id: 0,
        }
    }
}

/// ATT Protocol Operation Codes as defined in Bluetooth Core Specification
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum ATTCommand {
    None,
    ErrorResponse = 0x01,
    ExchangeMTURequest = 0x02,
    ExchangeMTUResponse = 0x03,
    FindInformationRequest = 0x04,
    FindInformationResponse = 0x05,
    FindByTypeValueRequest = 0x06,
    FindByTypeValueResponse = 0x07,
    ReadByTypeRequest = 0x08,
    ReadByTypeResponse = 0x09,
    ReadRequest = 0x0A,
    ReadResponse = 0x0B,
    ReadBlobRequest = 0x0C,
    ReadBlobResponse = 0x0D,
    ReadMultipleRequest = 0x0E,
    ReadMultipleResponse = 0x0F,
    ReadByGroupTypeRequest = 0x10,
    ReadByGroupTypeResponse = 0x11,
    WriteRequest = 0x12,
    WriteResponse = 0x13,
    WriteCommand = 0x52,
    SignedWriteCommand = 0xD2,
    PrepareWriteRequest = 0x16,
    PrepareWriteResponse = 0x17,
    ExecuteWriteRequest = 0x18,
    ExecuteWriteResponse = 0x19,
    HandleValueNotification = 0x1B,
    HandleValueIndication = 0x1D,
    HandleValueConfirmation = 0x1E,
}

impl Default for ATTCommand {
    fn default() -> Self {
        ATTCommand::None
    }
}

impl From<u8> for ATTCommand {
    fn from(value: u8) -> Self {
        match value {
            0x01 => ATTCommand::ErrorResponse,
            0x02 => ATTCommand::ExchangeMTURequest,
            0x03 => ATTCommand::ExchangeMTUResponse,
            0x04 => ATTCommand::FindInformationRequest,
            0x05 => ATTCommand::FindInformationResponse,
            0x06 => ATTCommand::FindByTypeValueRequest,
            0x07 => ATTCommand::FindByTypeValueResponse,
            0x08 => ATTCommand::ReadByTypeRequest,
            0x09 => ATTCommand::ReadByTypeResponse,
            0x0A => ATTCommand::ReadRequest,
            0x0B => ATTCommand::ReadResponse,
            0x0C => ATTCommand::ReadBlobRequest,
            0x0D => ATTCommand::ReadBlobResponse,
            0x0E => ATTCommand::ReadMultipleRequest,
            0x0F => ATTCommand::ReadMultipleResponse,
            0x10 => ATTCommand::ReadByGroupTypeRequest,
            0x11 => ATTCommand::ReadByGroupTypeResponse,
            0x12 => ATTCommand::WriteRequest,
            0x13 => ATTCommand::WriteResponse,
            0x52 => ATTCommand::WriteCommand,
            0xD2 => ATTCommand::SignedWriteCommand,
            0x16 => ATTCommand::PrepareWriteRequest,
            0x17 => ATTCommand::PrepareWriteResponse,
            0x18 => ATTCommand::ExecuteWriteRequest,
            0x19 => ATTCommand::ExecuteWriteResponse,
            0x1B => ATTCommand::HandleValueNotification,
            0x1D => ATTCommand::HandleValueIndication,
            0x1E => ATTCommand::HandleValueConfirmation,
            _ => ATTCommand::None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ATTHeader {
    pub command: ATTCommand,
    pub handle: u16,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub data: Vec<u8>,
}

impl Default for ATTHeader {
    fn default() -> Self {
        Self {
            command: ATTCommand::None,
            handle: 0,
            data: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketRecord {
    pub header: RawPacketHeader,
    pub hci_header: BluetoothHCIHeader,
    pub l2cap_header: Option<L2CAPacketHeader>,
    pub att_header: Option<ATTHeader>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub packet_data: Vec<u8>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub packet_data_str: String,
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
        write!(
            f,
            "PacketRecord {{ packet_number: {}, dest_addr: {}, att_command: {:?}, data: \"{}\" }}",
            self.packet_number,
            self.mac_address(),
            self.att_header.as_ref().map(|h| h.command),
            self.packet_data_str
                .chars()
                .take(20)
                .collect::<String>()
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BTSnoopFile {
    pub header: FileHeader,
    pub packets: Vec<PacketRecord>,
    pub handle_addr_map: HashMap<u16, [u8; 6]>,
}

impl BTSnoopFile {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            header: FileHeader::default(),
            packets: Vec::with_capacity(capacity),
            handle_addr_map: std::collections::HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.handle_addr_map.clear();
    }
}
