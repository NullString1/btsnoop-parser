mod data;

#[cfg(test)]
mod tests;

#[cfg(target_os = "android")]
mod android;

use data::*;
use std::io::{Cursor, Read, Seek};

#[derive(Debug)]
pub enum BTSnoopError {
    IoError(std::io::Error),
    InvalidFile(&'static str),
    InvalidSize(u8),
    InvalidConversion(&'static str),
}

impl std::error::Error for BTSnoopError {}
impl std::fmt::Display for BTSnoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BTSnoopError::IoError(e) => write!(f, "IO error: {}", e),
            BTSnoopError::InvalidFile(msg) => write!(f, "Invalid file: {}", msg),
            BTSnoopError::InvalidSize(size) => write!(f, "Invalid size: {}", size),
            BTSnoopError::InvalidConversion(msg) => write!(f, "Conversion error: {}", msg),
        }
    }
}

impl From<std::io::Error> for BTSnoopError {
    fn from(err: std::io::Error) -> Self {
        BTSnoopError::IoError(err)
    }
}

fn seek_to_next_packet(
    file: &mut Cursor<Vec<u8>>,
    start_position: u64,
    packet_header: &RawPacketHeader,
) {
    let seek = packet_header.included_length as i64
        - (file
            .stream_position()
            .expect("Failed to get stream position") as i64
            - start_position as i64);
    file.seek(std::io::SeekFrom::Current(seek))
        .expect("Failed to seek to next packet");
}

fn read_unsigned<const N: usize, T>(file: &mut Cursor<Vec<u8>>, le: bool) -> Result<T, BTSnoopError>
where
    T: TryFrom<u64>,
    <T as TryFrom<u64>>::Error: std::error::Error + 'static,
{
    let mut buffer = [0u8; N];
    file.read_exact(&mut buffer)?;

    let value = match N {
        1 => buffer[0] as u64,
        2 => {
            (if le {
                u16::from_le_bytes([buffer[0], buffer[1]])
            } else {
                u16::from_be_bytes([buffer[0], buffer[1]])
            }) as u64
        }
        4 => {
            (if le {
                u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]])
            } else {
                u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]])
            }) as u64
        }
        8 => {
            (if le {
                u64::from_le_bytes([
                    buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6],
                    buffer[7],
                ])
            } else {
                u64::from_be_bytes([
                    buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6],
                    buffer[7],
                ])
            }) as u64
        }
        _ => return Err(BTSnoopError::InvalidSize(N as u8)),
    };

    T::try_from(value).map_err(|_| BTSnoopError::InvalidConversion("Integer conversion failed"))
}

fn read_unsigned_be<const N: usize, T>(file: &mut Cursor<Vec<u8>>) -> Result<T, BTSnoopError>
where
    T: TryFrom<u64>,
    <T as TryFrom<u64>>::Error: std::error::Error + 'static,
{
    read_unsigned::<N, T>(file, false)
}

fn read_unsigned_le<const N: usize, T>(file: &mut Cursor<Vec<u8>>) -> Result<T, BTSnoopError>
where
    T: TryFrom<u64>,
    <T as TryFrom<u64>>::Error: std::error::Error + 'static,
{
    read_unsigned::<N, T>(file, true)
}

pub fn parse_btsnoop_file(bytes: Vec<u8>) -> Result<BTSnoopFile, BTSnoopError> {
    let mut connection_handle_address_map = std::collections::HashMap::new();
    let mut file = Cursor::new(bytes);

    let mut header = FileHeader {
        identifier: [0u8; 8],
        version: 0,
        data_link_type: 0,
    };

    file.read_exact(&mut header.identifier)?;
    header.version = read_unsigned_be::<4, u32>(&mut file)?;
    header.data_link_type = read_unsigned_be::<4, u32>(&mut file)?;

    if header.identifier != *b"btsnoop\0" {
        return Err(BTSnoopError::InvalidFile("Invalid btsnoop file"));
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

        packet_header.original_length = read_unsigned_be::<4, u32>(&mut file)?;
        packet_header.included_length = read_unsigned_be::<4, u32>(&mut file)?;
        packet_header.packet_flags = read_unsigned_be::<4, u32>(&mut file)?;
        packet_header.cumulative_drops = read_unsigned_be::<4, u32>(&mut file)?;
        packet_header.timestamp_milliseconds = read_unsigned_be::<8, u64>(&mut file)?;

        let mut hci_header = BluetoothHCIHeader {
            hci_packet_type: HciPacketType::None,
            hci_handle: HCIHandle(0),
            data_total_length: 0,
        };
        let start_position = file.stream_position()?;

        hci_header.hci_packet_type = match read_unsigned_le::<1, u8>(&mut file)? {
            0x01 => HciPacketType::Command,
            0x04 => HciPacketType::Event,
            0x02 => HciPacketType::ACLData,
            0x03 => HciPacketType::SCOData,
            _ => HciPacketType::None,
        };
        if hci_header.hci_packet_type == HciPacketType::Event {
            let event_code = read_unsigned_le::<1, u8>(&mut file)?;
            if event_code == 0x3E {
                // Is Le Meta
                file.seek(std::io::SeekFrom::Current(1))?; // Skip the parameter length
                let sub_event_code = read_unsigned_le::<1, u8>(&mut file)?;
                if sub_event_code == 0x0a {
                    // Is LE Enhanced Connection Complete
                    let status = read_unsigned_le::<1, u8>(&mut file)?;
                    if status == 0x00 {
                        // Is Success
                        let handle = read_unsigned_le::<2, u16>(&mut file)?;
                        let _role = read_unsigned_le::<1, u8>(&mut file)?;
                        let _peer_address_type = read_unsigned_le::<1, u8>(&mut file)?;
                        let mut peer_address = [0u8; 6];
                        file.read_exact(&mut peer_address)?;
                        connection_handle_address_map.insert(handle, peer_address);
                    }
                }
            }
            seek_to_next_packet(&mut file, start_position, &packet_header);
            continue;
        }
        if hci_header.hci_packet_type != HciPacketType::ACLData {
            seek_to_next_packet(&mut file, start_position, &packet_header);
            continue;
        }
        hci_header.hci_handle = HCIHandle(read_unsigned_le::<2, u16>(&mut file)?);

        hci_header.data_total_length = read_unsigned_le::<2, u16>(&mut file)?;

        let mut l2cap_header = L2CAPacketHeader {
            length: 0,
            channel_id: 0,
        };

        l2cap_header.length = read_unsigned_le::<2, u16>(&mut file)?;
        l2cap_header.channel_id = read_unsigned_le::<2, u16>(&mut file)?;

        let mut att_header = ATTHeader {
            command: ATTCommand::None,
            handle: 0,
            data: Vec::new(),
        };
        att_header.command = match read_unsigned_le::<1, u8>(&mut file)? {
            0x52 => ATTCommand::WriteCommand,
            0x1b => ATTCommand::HandleValueNotification,
            _ => ATTCommand::None,
        };

        if att_header.command != ATTCommand::WriteCommand
            && att_header.command != ATTCommand::HandleValueNotification
        {
            seek_to_next_packet(&mut file, start_position, &packet_header);
            continue;
        }

        att_header.handle = read_unsigned_le::<2, u16>(&mut file)?;

        let mut packet_data = vec![
            0u8;
            (packet_header.included_length as i64
                - (file.stream_position()? as i64 - start_position as i64))
                as usize
        ];
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
