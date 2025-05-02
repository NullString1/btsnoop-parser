#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

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
        let btsnoop_file_path = "btsnoop_hci.log";
        let bytes = std::fs::read(btsnoop_file_path)?;
        let btsnoop_file = parse_btsnoop_file(bytes)?;
        assert_eq!(btsnoop_file.header.identifier, *b"btsnoop\0");
        assert_eq!(btsnoop_file.header.version, 1);
        Ok(())
    }

    #[test]
    fn test_parse_att_packet() -> Result<(), Box<dyn std::error::Error>> {
        let btsnoop_file_path = "btsnoop_hci.log";
        let file = std::fs::read(btsnoop_file_path)?;
        let btsnoop_file = parse_btsnoop_file(file)?;

        let packet = btsnoop_file
            .packets
            .iter()
            .filter(|packet| packet.packet_number == 18650)
            .next()
            .unwrap_or_else(|| {
                println!("File: {:?}", btsnoop_file);
                panic!("Test packet not found in btsnoop file");
            });
        println!("Packet: {:?}", packet);
        assert_eq!(packet.header.original_length, 30);
        assert_eq!(packet.header.included_length, 30);
        assert_eq!(packet.header.packet_flags, 0);
        assert_eq!(packet.header.cumulative_drops, 0);
        assert_eq!(packet.header.timestamp_milliseconds, 63898107346213779);
        assert_eq!(packet.hci_header.hci_packet_type, HciPacketType::ACLData);
        assert_eq!(packet.hci_header.hci_handle.raw(), 0x206);
        assert_eq!(packet.hci_header.hci_handle.bc_flags(), 0);
        assert_eq!(packet.hci_header.hci_handle.pb_flags(), 0);
        assert_eq!(packet.hci_header.hci_handle.handle(), 0x206);
        assert_eq!(packet.hci_header.data_total_length, 25);
        assert_eq!(packet.l2cap_header.as_ref().map(|f| f.length), Some(21));
        assert_eq!(packet.l2cap_header.as_ref().map(|f| f.channel_id), Some(4));
        assert_eq!(packet.att_header.as_ref().map(|f| f.command), Some(ATTCommand::WriteCommand));
        assert_eq!(packet.att_header.as_ref().map(|f| f.handle), Some(64));
        assert!(packet.att_header.as_ref().map(|f| f.data.len()).unwrap_or(0) > 5);
        assert_eq!(packet.packet_number, 18650);
        assert!(btsnoop_file.handle_addr_map.contains_key(&512));
        assert_eq!(packet.mac_address(), "d4:f9:8d:20:95:a6");
        println!("Parsed packet: {:?}", packet);
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
        let map_memory = std::mem::size_of_val(&result.handle_addr_map) + 
                        (result.handle_addr_map.len() * (std::mem::size_of::<u16>() + std::mem::size_of::<[u8; 6]>()));
        
        println!("Performance Profile:");
        println!("File size: {} bytes", file_size);
        println!("Packet count: {}", result.packets.len());
        println!("Parse time: {:?}", duration);
        println!("Parse speed: {:.2} MB/s", file_size as f64 / 1_048_576.0 / duration.as_secs_f64());
        println!("Memory usage:");
        println!("  - Packets: {} bytes", packets_memory);
        println!("  - Handle map: {} bytes", map_memory);
        println!("  - Total: {} bytes", packets_memory + map_memory);
        println!("Memory efficiency: {:.2} bytes/packet", (packets_memory + map_memory) as f64 / result.packets.len() as f64);
    }
}
