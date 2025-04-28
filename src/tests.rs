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
        let file = File::open(btsnoop_file_path)?;
        let btsnoop_file = parse_btsnoop_file(file)?;
        assert_eq!(btsnoop_file.header.identifier, *b"btsnoop\0");
        assert_eq!(btsnoop_file.header.version, 1);
        Ok(())
    }

    #[test]
    fn test_parse_att_packet() -> Result<(), Box<dyn std::error::Error>> {
        let btsnoop_file_path = "btsnoop_hci.log";
        let file = File::open(btsnoop_file_path)?;
        let btsnoop_file = parse_btsnoop_file(file)?;
        let packet = btsnoop_file.packets.first().unwrap_or_else(|| {
            panic!("No packets found in the btsnoop file");
        });
        assert_eq!(packet.header.original_length, 30);
        assert_eq!(packet.header.included_length, 30);
        assert_eq!(packet.header.packet_flags, 0);
        assert_eq!(packet.header.cumulative_drops, 0);
        assert_eq!(packet.header.timestamp_microseconds, 63898107346213779);
        assert_eq!(packet.hci_header.hci_packet_type, HciPacketType::ACLData);
        assert_eq!(packet.hci_header.command, 1538);
        assert_eq!(packet.hci_header.data_total_length, 25);
        assert_eq!(packet.l2cap_header.length, 21);
        assert_eq!(packet.l2cap_header.channel_id, 4);
        assert_eq!(packet.att_header.command, ATTCommand::WriteCommand);
        assert_eq!(packet.att_header.handle, 64);
        assert!(packet.att_header.data.len() > 5);
        assert_eq!(packet.packet_number, 18650);
        Ok(())
    }
}
