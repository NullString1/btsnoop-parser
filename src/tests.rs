#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read, vec};

    use crate::*;

    #[test]
    fn test_get_test_data() -> Result<(), Box<dyn std::error::Error>> {
        let btsnoop_file_path = "btsnoop_hci.log";
        let mut file = File::open(btsnoop_file_path)?;
        let mut buff = [0u8; 4];
        file.read_exact(&mut buff)?;

        Ok(())
    }

    #[test]
    fn test_parse_btsnoop_file() -> Result<(), Box<dyn std::error::Error>> {
        let btsnoop_file_path: &str = "btsnoop_hci.log";
        let bytes: Vec<u8> = std::fs::read(btsnoop_file_path)?;
        let btsnoop_file: BTSnoopFile = parse_btsnoop_file(bytes)?;
        println!("Packet 1: {}", btsnoop_file.packets[0]);
        assert_eq!(btsnoop_file.header.identifier, *b"btsnoop\0");
        assert_eq!(btsnoop_file.header.version, 1);
        Ok(())
    }

    #[test]
    fn test_parse_dummy_file() -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"btsnoop\0");
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&1002u32.to_be_bytes());

        let hci_event = vec![
            0x04, // HCI Event
            0x3E, // HCI_LE_Meta_Event
            0x13, // Parameter Length
            0x0A, // LE_Connection_Complete
            0x00, // Status (success)
            0x06, 0x02, // Handle (0x1234)
            0x00, // Role
            0x00, // Peer Address Type
            0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // First MAC address
        ];

        let mut att_data_packet = vec![
            0x02, // ATT Data
            0x06, 0x02, // Handle (0x1234)
            0x19, 0x00, // Length (0x0000)
            0x15, 0x00, // L2CAP Length (21)
            0x04, 0x00, // L2CAP Channel ID (4)
            0x52, // ATT Command (Write Command)
            0x12, 0x34, // ATT Handle (0x0000)
        ];
        att_data_packet.extend(b"TEST DATA 12345678");

        let add_packet = |data: &mut Vec<u8>, packet: Vec<u8>, timestamp: u64| {
            data.extend_from_slice(&(packet.len() as u32).to_be_bytes()); // Original length
            data.extend_from_slice(&(packet.len() as u32).to_be_bytes()); // Included length
            data.extend_from_slice(&0u32.to_be_bytes()); // Flags
            data.extend_from_slice(&0u32.to_be_bytes()); // Drops
            data.extend_from_slice(&timestamp.to_be_bytes()); // Timestamp
            data.extend_from_slice(&packet); // Packet data
        };

        add_packet(&mut bytes, hci_event.clone(), 0);
        add_packet(&mut bytes, att_data_packet.clone(), 1);

        let btsnoop_file = parse_btsnoop_file(bytes)?;
        println!("Parsed dummy file: {:?}", btsnoop_file);
        assert_eq!(btsnoop_file.header.identifier, *b"btsnoop\0");
        assert_eq!(btsnoop_file.header.version, 1);
        assert_eq!(btsnoop_file.header.data_link_type, 1002);
        assert_eq!(btsnoop_file.packets.len(), 2);
        assert_eq!(btsnoop_file.packets[0].header.original_length, 15);
        assert_eq!(btsnoop_file.packets[0].header.included_length, 15);
        assert_eq!(btsnoop_file.packets[0].header.packet_flags, 0);
        assert_eq!(btsnoop_file.packets[0].header.cumulative_drops, 0);
        assert_eq!(btsnoop_file.packets[0].header.timestamp_milliseconds, 0);
        assert_eq!(
            btsnoop_file.packets[0].hci_header.hci_packet_type,
            HciPacketType::Event
        );
        assert_eq!(btsnoop_file.packets[0].hci_header.hci_handle.bc_flags(), 0);
        assert_eq!(btsnoop_file.packets[0].hci_header.hci_handle.pb_flags(), 0);
        assert_eq!(btsnoop_file.packets[0].packet_number, 1);

        assert_eq!(btsnoop_file.packets[1].header.original_length, 30);
        assert_eq!(btsnoop_file.packets[1].header.included_length, 30);
        assert_eq!(btsnoop_file.packets[1].header.packet_flags, 0);
        assert_eq!(btsnoop_file.packets[1].header.cumulative_drops, 0);
        assert_eq!(btsnoop_file.packets[1].header.timestamp_milliseconds, 1);
        assert_eq!(
            btsnoop_file.packets[1].hci_header.hci_packet_type,
            HciPacketType::ACLData
        );
        assert_eq!(btsnoop_file.packets[1].hci_header.hci_handle.raw(), 0x206);
        assert_eq!(btsnoop_file.packets[1].hci_header.hci_handle.bc_flags(), 0);
        assert_eq!(btsnoop_file.packets[1].hci_header.hci_handle.pb_flags(), 0);
        assert_eq!(btsnoop_file.packets[1].hci_header.data_total_length, 25);
        assert_eq!(
            btsnoop_file.packets[1]
                .l2cap_header
                .as_ref()
                .map(|f| f.length),
            Some(21)
        );
        assert_eq!(
            btsnoop_file.packets[1]
                .l2cap_header
                .as_ref()
                .map(|f| f.channel_id),
            Some(4)
        );
        assert_eq!(
            btsnoop_file.packets[1]
                .att_header
                .as_ref()
                .map(|f| f.command),
            Some(ATTCommand::WriteCommand)
        );
        assert_eq!(
            btsnoop_file.packets[1]
                .att_header
                .as_ref()
                .map(|f| f.handle),
            Some(0x3412)
        );
        assert_eq!(
            btsnoop_file.packets[1]
                .att_header
                .as_ref()
                .map(|f| f.data.len())
                .unwrap_or(0),
            18
        );
        assert_eq!(btsnoop_file.packets[1].packet_number, 2);
        assert!(btsnoop_file.handle_addr_map.contains_key(&518));
        assert_eq!(btsnoop_file.packets[1].mac_address(), "11:22:33:44:55:66");
        assert_eq!(
            btsnoop_file.packets[1].packet_data_str,
            "TEST DATA 12345678"
        );
        Ok(())
    }

    #[test]
    fn profile_performance() {
        // Load test data
        let data = std::fs::read("btsnoop_hci.log").expect("Failed to read test file");
        let file_size = data.len();

        // Measure parsing time
        let start = std::time::Instant::now();
        let result = parse_btsnoop_file(data).expect("Failed to parse file");
        let duration = start.elapsed();

        // Calculate memory usage
        let packets_memory = std::mem::size_of_val(&result.packets[..]);
        let map_memory = std::mem::size_of_val(&result.handle_addr_map)
            + (result.handle_addr_map.len()
                * (std::mem::size_of::<u16>() + std::mem::size_of::<[u8; 6]>()));

        println!("Performance Profile:");
        println!("File size: {} bytes", file_size);
        println!("Packet count: {}", result.packets.len());
        println!("Parse time: {:?}", duration);
        println!(
            "Parse speed: {:.2} MB/s",
            file_size as f64 / 1_048_576.0 / duration.as_secs_f64()
        );
        println!("Memory usage:");
        println!("  - Packets: {} bytes", packets_memory);
        println!("  - Handle map: {} bytes", map_memory);
        println!("  - Total: {} bytes", packets_memory + map_memory);
        println!(
            "Memory efficiency: {:.2} bytes/packet",
            (packets_memory + map_memory) as f64 / result.packets.len() as f64
        );
    }
}
