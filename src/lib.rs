mod tests;

use std::{
    error::Error,
    fs::File,
    io::{Read, Seek},
};

#[derive(Debug, Clone, Copy)]
pub struct FileHeader {
    pub identifier: [u8; 8],
    pub version: u32,
    pub data_link_type: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct RawPacketHeader {
    pub original_length: u32,
    pub included_length: u32,
    pub packet_flags: u32,
    pub cumulative_drops: u32,
    pub timestamp_microseconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HciPacketType {
    None = 0x00,
    Command = 0x01,
    Event = 0x04,
    ACLData = 0x02,
    SCOData = 0x03,
}

#[derive(Debug, Clone)]
pub struct BluetoothHCIHeader {
    pub hci_packet_type: HciPacketType,
    pub command: u16,
    pub data_total_length: u16,
}

#[derive(Debug, Clone)]
pub struct L2CAPacketHeader {
    pub length: u16,
    pub channel_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ATTCommand {
    None = 0x00,
    WriteCommand = 0x52,
    HandleValueNotification = 0x1b,
}

#[derive(Debug, Clone)]
pub struct ATTHeader {
    pub command: ATTCommand,
    pub handle: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PacketRecord {
    pub header: RawPacketHeader,
    pub hci_header: BluetoothHCIHeader,
    pub l2cap_header: L2CAPacketHeader,
    pub att_header: ATTHeader,
    pub packet_data: Vec<u8>,
    pub packet_number: u32,
}

#[derive(Debug, Clone)]
pub struct BTSnoopFile {
    pub header: FileHeader,
    pub packets: Vec<PacketRecord>,
}

pub fn parse_btsnoop_file(mut file: File) -> Result<BTSnoopFile, Box<dyn Error>> {
    let mut header = FileHeader {
        identifier: [0u8; 8],
        version: 0,
        data_link_type: 0,
    };
    file.read_exact(&mut header.identifier)?;
    let mut buffer = [0u8; 4];
    file.read_exact(&mut buffer)?;
    header.version = u32::from_be_bytes(buffer);
    file.read_exact(&mut buffer)?;
    header.data_link_type = u32::from_be_bytes(buffer);
    if header.identifier != *b"btsnoop\0" {
        return Err("Invalid btsnoop file".into());
    }
    let mut packets = Vec::new();
    let length = file.metadata()?.len();
    let mut counter = 0;
    while file.stream_position()? < length {
        counter += 1;
        let mut packet_header = RawPacketHeader {
            original_length: 0,
            included_length: 0,
            packet_flags: 0,
            cumulative_drops: 0,
            timestamp_microseconds: 0,
        };

        let mut buffer = [0u8; 4];

        file.read_exact(&mut buffer)?;
        packet_header.original_length = u32::from_be_bytes(buffer);

        file.read_exact(&mut buffer)?;
        packet_header.included_length = u32::from_be_bytes(buffer);

        file.read_exact(&mut buffer)?;
        packet_header.packet_flags = u32::from_be_bytes(buffer);

        file.read_exact(&mut buffer)?;
        packet_header.cumulative_drops = u32::from_be_bytes(buffer);

        let mut buffer_8 = [0u8; 8];
        file.read_exact(&mut buffer_8)?;
        packet_header.timestamp_microseconds = u64::from_be_bytes(buffer_8);

        let mut hci_header = BluetoothHCIHeader {
            hci_packet_type: HciPacketType::None,
            command: 0,
            data_total_length: 0,
        };

        let mut buffer = [0u8; 1];
        file.read_exact(&mut buffer)?;
        hci_header.hci_packet_type = match buffer[0] {
            0x01 => HciPacketType::Command,
            0x04 => HciPacketType::Event,
            0x02 => HciPacketType::ACLData,
            0x03 => HciPacketType::SCOData,
            _ => HciPacketType::None,
        };
        if hci_header.hci_packet_type != HciPacketType::ACLData {
            file.seek(std::io::SeekFrom::Current(
                (packet_header.included_length - 1) as i64,
            ))?;
            continue;
        }
        let mut buffer = [0u8; 2];
        file.read_exact(&mut buffer)?;
        hci_header.command = u16::from_be_bytes(buffer);

        file.read_exact(&mut buffer)?;
        hci_header.data_total_length = u16::from_le_bytes(buffer);

        let mut l2cap_header = L2CAPacketHeader {
            length: 0,
            channel_id: 0,
        };
        let mut buffer = [0u8; 2];
        file.read_exact(&mut buffer)?;
        l2cap_header.length = u16::from_le_bytes(buffer);
        file.read_exact(&mut buffer)?;
        l2cap_header.channel_id = u16::from_le_bytes(buffer);

        let mut att_header = ATTHeader {
            command: ATTCommand::None,
            handle: 0,
            data: Vec::new(),
        };
        let mut buffer = [0u8; 1];
        file.read_exact(&mut buffer)?;
        att_header.command = match buffer[0] {
            0x52 => ATTCommand::WriteCommand,
            0x1b => ATTCommand::HandleValueNotification,
            _ => ATTCommand::None,
        };

        if att_header.command != ATTCommand::WriteCommand
            && att_header.command != ATTCommand::HandleValueNotification
        {
            file.seek(std::io::SeekFrom::Current(
                (packet_header.included_length - 10) as i64,
            ))?;
            continue;
        }

        let mut buffer = [0u8; 2];
        file.read_exact(&mut buffer)?;
        att_header.handle = u16::from_le_bytes(buffer);

        let mut packet_data = vec![0u8; (packet_header.included_length - 12) as usize];
        file.read_exact(&mut packet_data)?;
        att_header.data = packet_data.clone();

        packets.push(PacketRecord {
            header: packet_header,
            hci_header: hci_header,
            l2cap_header: l2cap_header,
            att_header: att_header,
            packet_data: packet_data,
            packet_number: counter,
        });
    }

    Ok(BTSnoopFile { header, packets })
}
