# BTSnoop Parser

<!-- PROJECT SHIELDS -->
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

<!-- PROJECT LOGO -->
<div align="center">
  <h3 align="center">BTSnoop Parser</h3>

  <p align="center">
    A Rust library for parsing Bluetooth HCI snoop logs
    <br />
    <a href="#documentation"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/yourusername/btsnoop-parser/issues">Report Bug</a>
    ·
    <a href="https://github.com/yourusername/btsnoop-parser/issues">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#about-the-project">About The Project</a></li>
    <li><a href="#features">Features</a></li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#supported-packet-types">Supported Packet Types</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
  </ol>
</details>

## About The Project

BTSnoop Parser is a Rust library designed for parsing and analyzing Bluetooth HCI (Host Controller Interface) snoop logs. It's particularly useful for debugging and reverse engineering Bluetooth LE communications on Android devices and other platforms that generate btsnoop log files.

## Features

✨ **Complete Packet Analysis**
- Parse standard BTSnoop file format
- Support for multiple HCI packet types
- Detailed packet header information
- Connection handle tracking
- Timestamp and sequence tracking

🔍 **Comprehensive Protocol Support**
- HCI (Host Controller Interface)
- L2CAP (Logical Link Control and Adaptation Protocol)
- ATT (Attribute Protocol)

🔄 **Format Support**
- Android-compatible output
- BTSnoop Version 1 

## Getting Started

### Prerequisites

- Rust toolchain (latest stable version)
- For Android builds:
  - Android NDK (`cargo-ndk` recommended for ease of use)
  - aarch64-linux-android target

### Installation

1. Add to your Cargo.toml:
```toml
[dependencies]
btsnoop_parser = "1.0.0"
```
or 
```bash
cargo add btsnoop_parser
```c

2. Build for desktop:
```bash
cargo build --release
```

For Android:
```bash
cargo build --target aarch64-linux-android --release
```
or
```bash
cargo ndk -t arm64-v8a -o /path/to/jniLibs build --release
```

## Usage
Note: tests [test_get_test_data, test_parse_btsnoop_file, profile_performance] will fail without a valid `btsnoop_hci.log` file. This can be ignored

```rust
use btsnoop_parser::PacketStream;

let btsnoop_file_path: &str = "btsnoop_hci.log";
let bytes: Vec<u8> = std::fs::read(btsnoop_file_path)?;
let btsnoop_file: BTSnoopFile = parse_btsnoop_file(bytes)?;

println!("Packet 1: {}", btsnoop_file.packets[0]);
```

For Android: (See [BTLeTool](https://github.com/nullstring1/BTLeTool) for complete example)

In one.nullstring.btsnoop_parser.BTSnoopParser:
```Java
public class BTSnoopParser {
    static {
        System.loadLibrary("btsnoop_parser");
    }
    private static native String parse(byte[] bytes, boolean write_and_notify_only, boolean sort_by_timestamp);
    public static native void log(String text);

    public static BTSnoopFile parseBTSnoopFile(byte[] bytes) {
        String parsedData = parse(bytes, true, true);
        Gson gson = new Gson();
        return gson.fromJson(parsedData, BTSnoopFile.class);
    }
}
```
In other class:
```Java
BTSnoopFile result = BTSnoopParser.parseBTSnoopFile(bytes);
```

## Supported Packet Types

### HCI Packet Types
- Commands (0x01) - No parsing yet
- Events (0x04) - Currently only parsed for connection handle tracking to display MAC address of packets
- ACL Data (0x02) - Parsed to show GATT messages
- SCO Data (0x03) - No parsing yet

### ATT Commands
- Write Command (0x52) - Parsed as writing to GATT characteristic
- Signed Write Command (0xD2) - No parsing yet
- Prepare Write Request (0x16) - No parsing yet
- Prepare Write Response (0x17) - No parsing yet
- Execute Write Request (0x18) - No parsing yet
- Execute Write Response (0x19) - No parsing yet
- Handle Value Notification (0x1B) - Parsed as message back from other device
- Handle Value Indication (0x1D) - No parsing yet
- Handle Value Confirmation (0x1E) - No parsing yet

### Packet Information Fields
- Original and included length
- Packet flags
- Cumulative drops
- Timestamp in milliseconds
- HCI packet type and handle
- L2CAP information (for ACL Data packets)
- ATT command details
- Destination address
- Raw packet data

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

<!-- MARKDOWN LINKS & IMAGES -->
[issues-shield]: https://img.shields.io/github/issues/nullstring1/btsnoop-parser.svg?style=for-the-badge
[issues-url]: https://github.com/nullstring1/btsnoop-parser/issues
[license-shield]: https://img.shields.io/github/license/nullstring1/btsnoop-parser.svg?style=for-the-badge
[license-url]: https://github.com/nullstring1/btsnoop-parser/blob/master/LICENSE
