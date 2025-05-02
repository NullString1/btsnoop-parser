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
    fn from(error: std::io::Error) -> Self {
        BTSnoopError::IoError(error)
    }
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

#[derive(Debug, Clone)]
pub struct PacketStream {
    file: Cursor<Vec<u8>>,
    connection_handles: std::collections::HashMap<u16, [u8; 6]>,
    packet_count: u32,
}

impl PacketStream {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            file: Cursor::new(bytes),
            connection_handles: std::collections::HashMap::new(),
            packet_count: 0,
        }
    }

    fn read_be<const N: usize, T>(&mut self) -> Result<T, BTSnoopError>
    where
        T: TryFrom<u64>,
        <T as TryFrom<u64>>::Error: std::error::Error + 'static,
    {
        read_unsigned::<N, T>(&mut self.file, false)
    }

    fn read_le<const N: usize, T>(&mut self) -> Result<T, BTSnoopError>
    where
        T: TryFrom<u64>,
        <T as TryFrom<u64>>::Error: std::error::Error + 'static,
    {
        read_unsigned::<N, T>(&mut self.file, true)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), BTSnoopError> {
        self.file.read_exact(buf).map_err(BTSnoopError::from)
    }

    fn position(&mut self) -> Result<u64, BTSnoopError> {
        self.file.stream_position().map_err(BTSnoopError::from)
    }

    fn seek(&mut self, pos: std::io::SeekFrom) -> Result<u64, BTSnoopError> {
        self.file.seek(pos).map_err(BTSnoopError::from)
    }

    fn read_header(&mut self) -> Result<FileHeader, BTSnoopError> {
        let mut header = FileHeader {
            identifier: [0u8; 8],
            version: 0,
            data_link_type: 0,
        };

        self.read_exact(&mut header.identifier)?;
        header.version = self.read_be::<4, u32>()?;
        header.data_link_type = self.read_be::<4, u32>()?;

        if header.identifier != *b"btsnoop\0" {
            return Err(BTSnoopError::InvalidFile("Invalid btsnoop file"));
        }

        Ok(header)
    }

    fn read_packet_header(&mut self) -> Result<RawPacketHeader, BTSnoopError> {
        Ok(RawPacketHeader {
            original_length: self.read_be::<4, u32>()?,
            included_length: self.read_be::<4, u32>()?,
            packet_flags: self.read_be::<4, u32>()?,
            cumulative_drops: self.read_be::<4, u32>()?,
            timestamp_milliseconds: self.read_be::<8, u64>()?,
        })
    }

    fn read_hci_header(&mut self) -> Result<(BluetoothHCIHeader, u64), BTSnoopError> {
        let mut hci_header = BluetoothHCIHeader {
            hci_packet_type: HciPacketType::None,
            hci_handle: HCIHandle(0),
            data_total_length: 0,
        };
        let start_position = self.position()?;

        hci_header.hci_packet_type = match self.read_le::<1, u8>()? {
            0x01 => HciPacketType::Command,
            0x04 => HciPacketType::Event,
            0x02 => HciPacketType::ACLData,
            0x03 => HciPacketType::SCOData,
            _ => HciPacketType::None,
        };

        if hci_header.hci_packet_type == HciPacketType::ACLData {
            hci_header.hci_handle = HCIHandle(self.read_le::<2, u16>()?);
            hci_header.data_total_length = self.read_le::<2, u16>()?;
        }

        Ok((hci_header, start_position))
    }

    fn handle_event(
        &mut self,
        packet_header: &RawPacketHeader,
        start_position: u64,
    ) -> Result<bool, BTSnoopError> {
        if packet_header.included_length < 3 {
            // Minimum size for event code + param length + subevent
            return Err(BTSnoopError::InvalidFile("Event packet too small"));
        }

        let event_code = self.read_le::<1, u8>()?;
        if event_code != 0x3E {
            // HCI_LE_Meta_Event
            return Ok(false);
        }

        let param_length = self.read_le::<1, u8>()?;
        let expected_position = start_position + packet_header.included_length as u64;

        if param_length as u64 > (expected_position - self.position()?) {
            return Err(BTSnoopError::InvalidFile(
                "Event parameter length exceeds packet size",
            ));
        }

        let sub_event_code = self.read_le::<1, u8>()?;
        if sub_event_code != 0x0a {
            // HCI_LE_Connection_Complete
            return Ok(false);
        }

        let status = self.read_le::<1, u8>()?;
        if status == 0x00 {
            // Success
            let handle = self.read_le::<2, u16>()?;
            self.seek(std::io::SeekFrom::Current(2))?; // Skip role and peer_address_type
            let mut peer_address = [0u8; 6];
            self.read_exact(&mut peer_address)?;
            self.connection_handles.insert(handle, peer_address);
        }

        Ok(true)
    }

    fn read_l2cap_header(&mut self) -> Result<L2CAPacketHeader, BTSnoopError> {
        Ok(L2CAPacketHeader {
            length: self.read_le::<2, u16>()?,
            channel_id: self.read_le::<2, u16>()?,
        })
    }

    fn read_att_header(&mut self) -> Result<ATTHeader, BTSnoopError> {
        let command = ATTCommand::from(self.read_le::<1, u8>()?);

        // Only read handle and prepare for data for commands that have them
        match command {
            ATTCommand::WriteCommand
            | ATTCommand::HandleValueNotification
            | ATTCommand::HandleValueIndication
            | ATTCommand::WriteRequest
            | ATTCommand::PrepareWriteRequest => {
                Ok(ATTHeader {
                    command,
                    handle: self.read_le::<2, u16>()?,
                    data: Vec::new(), // Will be filled later
                })
            }
            _ => Ok(ATTHeader {
                command,
                handle: 0,
                data: Vec::new(),
            }),
        }
    }

    pub fn next_packet(&mut self) -> Result<Option<PacketRecord>, BTSnoopError> {
        if self.position()? >= self.file.get_ref().len() as u64 {
            return Ok(None);
        }

        self.packet_count += 1;
        let packet_header = self.read_packet_header()?;
        let start_position = self.position()?;
        let (hci_header, _) = self.read_hci_header()?;

        // Process events to build connection handle map
        if hci_header.hci_packet_type == HciPacketType::Event {
            // Handle the event but don't skip the packet
            let _ = self.handle_event(&packet_header, start_position);
            // Make sure we're at the right position after event processing
            self.seek(std::io::SeekFrom::Start(
                start_position + packet_header.included_length as u64,
            ))?;
            return Ok(Some(PacketRecord {
                header: packet_header,
                hci_header,
                l2cap_header: None,
                att_header: None,
                packet_data: Vec::new(),
                packet_number: self.packet_count,
                dest_addr: [0; 6],
                packet_data_str: String::new(),
            }));
        }

        // For ACL Data packets, read L2CAP and ATT headers
        let (l2cap_header, mut att_header) = if hci_header.hci_packet_type == HciPacketType::ACLData
        {
            (Some(self.read_l2cap_header()?), Some(self.read_att_header()?))
        } else {
            // For non-ACL packets, skip to the end of packet
            let skip_to = start_position + packet_header.included_length as u64;
            self.seek(std::io::SeekFrom::Start(skip_to))?;
            return Ok(Some(PacketRecord {
                header: packet_header,
                hci_header,
                l2cap_header: None,
                att_header: None,
                packet_data: Vec::new(),
                packet_number: self.packet_count,
                dest_addr: [0; 6],
                packet_data_str: String::new(),
            }));
        };

        let current_position = self.position()?;
        let total_packet_size = packet_header.included_length as u64;
        let headers_size = current_position - start_position;

        if headers_size > total_packet_size {
            return Err(BTSnoopError::InvalidFile("Headers larger than packet size"));
        }

        let data_size = total_packet_size - headers_size;
        let mut packet_data = vec![0u8; data_size as usize];
        self.read_exact(&mut packet_data)?;
        if let Some(ref mut att_header) = att_header {
            att_header.data = packet_data.clone();
        }

        Ok(Some(PacketRecord {
            header: packet_header,
            hci_header: hci_header,
            l2cap_header: l2cap_header,
            att_header: att_header,
            packet_data_str: std::string::String::from_utf8_lossy(&packet_data).to_string(),
            packet_data: packet_data,
            packet_number: self.packet_count,
            dest_addr: self
                .connection_handles
                .get(&hci_header.hci_handle.handle())
                .cloned()
                .unwrap_or([0; 6]),
        }))
    }

    pub fn get_connection_handles(&self) -> &std::collections::HashMap<u16, [u8; 6]> {
        &self.connection_handles
    }
}

impl Iterator for PacketStream {
    type Item = Result<PacketRecord, BTSnoopError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_packet() {
            Ok(Some(packet)) => Some(Ok(packet)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

pub fn parse_btsnoop_file(bytes: Vec<u8>) -> Result<BTSnoopFile, BTSnoopError> {
    let mut packet_stream = PacketStream::new(bytes);
    let header = packet_stream.read_header()?;
    let packets = packet_stream.by_ref().collect::<Result<Vec<_>, _>>()?;
    let handle_addr_map = packet_stream.connection_handles;

    Ok(BTSnoopFile {
        header,
        packets,
        handle_addr_map,
    })
}
