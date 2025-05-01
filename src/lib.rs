mod data;

#[cfg(test)]
mod tests;

#[cfg(target_os = "android")]
mod android;

use data::*;
use std::{
    error::Error,
    io::{Cursor, Read, Seek},
};

fn seek_to_next_packet(
    file: &mut Cursor<Vec<u8>>,
    start_position: u64,
    packet_header: &RawPacketHeader,
) -> Result<(), Box<dyn Error>> {
    let seek = packet_header.included_length as i64
        - (file.stream_position()? as i64 - start_position as i64);
    file.seek(std::io::SeekFrom::Current(seek))?;
    Ok(())
}

pub fn parse_btsnoop_file(bytes: Vec<u8>) -> Result<BTSnoopFile, Box<dyn Error>> {
    let mut connection_handle_address_map = std::collections::HashMap::new();
    let mut file = Cursor::new(bytes);
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
    let length = file.get_ref().len();
    let mut counter = 0;
    while file.stream_position()? < length.try_into().unwrap() {
        counter += 1;
        let mut packet_header = RawPacketHeader {
            original_length: 0,
            included_length: 0,
            packet_flags: 0,
            cumulative_drops: 0,
            timestamp_milliseconds: 0,
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
        packet_header.timestamp_milliseconds = u64::from_be_bytes(buffer_8);

        let mut hci_header = BluetoothHCIHeader {
            hci_packet_type: HciPacketType::None,
            hci_handle: HCIHandle(0),
            data_total_length: 0,
        };
        let start_position = file.stream_position()?;

        let mut buffer = [0u8; 1];
        file.read_exact(&mut buffer)?;
        hci_header.hci_packet_type = match buffer[0] {
            0x01 => HciPacketType::Command,
            0x04 => HciPacketType::Event,
            0x02 => HciPacketType::ACLData,
            0x03 => HciPacketType::SCOData,
            _ => HciPacketType::None,
        };
        if hci_header.hci_packet_type == HciPacketType::Event {
            let mut event_code = [0u8; 1];
            file.read_exact(&mut event_code)?;
            if event_code[0] == 0x3E {
                // Is Le Meta
                file.seek(std::io::SeekFrom::Current(1))?; // Skip the parameter length
                let mut sub_event_code = [0u8; 1];
                file.read_exact(&mut sub_event_code)?;
                if sub_event_code[0] == 0x0a {
                    // Is LE Enhanced Connection Complete
                    let mut status = [0u8; 1];
                    file.read_exact(&mut status)?;
                    if status[0] == 0x00 {
                        // Is Success
                        let mut handle = [0u8; 2];
                        file.read_exact(&mut handle)?;
                        let mut role = [0u8; 1];
                        file.read_exact(&mut role)?;
                        let mut peer_address_type = [0u8; 1];
                        file.read_exact(&mut peer_address_type)?;
                        let mut peer_address = [0u8; 6];
                        file.read_exact(&mut peer_address)?;
                        connection_handle_address_map
                            .insert(u16::from_le_bytes(handle), peer_address);
                    }
                }
            }
            seek_to_next_packet(&mut file, start_position, &packet_header)?;
            continue;
        }
        if hci_header.hci_packet_type != HciPacketType::ACLData {
            seek_to_next_packet(&mut file, start_position, &packet_header)?;
            continue;
        }
        let mut buffer = [0u8; 2];
        file.read_exact(&mut buffer)?;
        hci_header.hci_handle = HCIHandle(u16::from_le_bytes(buffer));

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
            seek_to_next_packet(&mut file, start_position, &packet_header)?;
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
            dest_addr: connection_handle_address_map
                .get(&hci_header.hci_handle.handle())
                .cloned()
                .unwrap_or([0; 6]),
        });
    }

    Ok(BTSnoopFile {
        header,
        packets,
        handle_addr_map: connection_handle_address_map,
    })
}
