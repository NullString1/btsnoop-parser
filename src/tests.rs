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
        let packet = btsnoop_file.packets.first().unwrap_or_else(|| {
            panic!("No packets found in the btsnoop file");
        });
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
        assert_eq!(packet.l2cap_header.length, 21);
        assert_eq!(packet.l2cap_header.channel_id, 4);
        assert_eq!(packet.att_header.command, ATTCommand::WriteCommand);
        assert_eq!(packet.att_header.handle, 64);
        assert!(packet.att_header.data.len() > 5);
        assert_eq!(packet.packet_number, 18650);
        assert!(btsnoop_file.handle_addr_map.contains_key(&512));
        assert_eq!(
            btsnoop_file.handle_addr_map.get(&512).unwrap(),
            &[242, 41, 45, 141, 249, 212]
        );
        assert_eq!(packet.mac_address(), "d4:f9:8d:20:95:a6");
        println!("Parsed packet: {}", packet);
        Ok(())
    }
}
