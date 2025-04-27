use std::{
    error::Error,
    fs::File,
    io::{Read, Seek},
};

fn main() {
    let file_path = "btsnoop_hci.log";
    let file = File::open(file_path).expect("Failed to open file");

    let btsnoop_file = parse_btsnoop_file(file).expect("Failed to parse btsnoop file");
    println!("Parsed {} write packets", btsnoop_file.packets.len());
    for packet in btsnoop_file.packets {
        let ascii_str = String::from_utf8_lossy(&packet.packet_data);
        let ascii_str = ascii_str.trim().trim_ascii();
        let ascii_str: String = ascii_str.chars().filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()).collect();
        println!("Packet Number: {}", packet.packet_number);
        println!("Packet Data: {}", ascii_str);
    }
}

#[derive(Debug, Clone, Copy)]
struct FileHeader {
    pub identifier: [u8; 8],
    pub version: u32,
    pub data_link_type: u32,
}

#[derive(Debug, Clone, Copy)]
struct RawPacketHeader {
    pub original_length: u32,
    pub included_length: u32,
    pub packet_flags: u32,
    pub cumulative_drops: u32,
    pub timestamp_microseconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum HciPacketType {
    None = 0x00,
    Command = 0x01,
    Event = 0x04,
    ACLData = 0x02,
    SCOData = 0x03,
}

#[derive(Debug, Clone)]
struct BluetoothHCIHeader {
    pub hci_packet_type: HciPacketType,
    pub command: u16,
    pub data_total_length: u16,
}

#[derive(Debug, Clone)]
struct L2CAPacketHeader {
    pub length: u16,
    pub channel_id: u16,
}

#[derive(Debug, Clone)]
struct ATTHeader {
    pub command: u8,
    pub handle: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PacketRecord {
    pub header: RawPacketHeader,
    pub hci_header: BluetoothHCIHeader,
    pub l2cap_header: L2CAPacketHeader,
    pub att_header: ATTHeader,
    pub packet_data: Vec<u8>,
    pub packet_number: u32,
}
#[derive(Debug, Clone)]

struct BTSnoopFile {
    pub header: FileHeader,
    pub packets: Vec<PacketRecord>,
}

fn parse_btsnoop_file(mut file: File) -> Result<BTSnoopFile, Box<dyn Error>> {
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
            //println!("Skipping non-data packet");
            file.seek(std::io::SeekFrom::Current(
                (packet_header.included_length - 1) as i64,
            ))?;
            continue;
        }
        //println!("Timestamp: {}", packet_header.timestamp_microseconds);
        //println!("Counter: {}", counter);
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
            command: 0,
            handle: 0,
            data: Vec::new(),
        };
        let mut buffer = [0u8; 1];
        file.read_exact(&mut buffer)?;
        att_header.command = buffer[0];

        if att_header.command != 0x52 {
            //println!("Skipping non-write command");
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
