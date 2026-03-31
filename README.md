# gtap

A lightweight command-line packet capture and analysis utility written in Go. Capture live network traffic, read pcap files, apply filters, and display data in multiple formats.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Filters](#filters)
- [License](#license)

## Features

- **Live packet capture** from all or specific network interfaces
- **BPF filtering** to capture only relevant packets
- **Pcap file support** for reading and writing packet data
- **Multiple output formats**: summary view and hex dumps
- **Promiscuous and monitor modes** for advanced packet capture
- **Scriptable CLI** with sensible defaults

## Requirements

- **Go** 1.18 or higher
- **libpcap** development headers:
  - Debian/Ubuntu: `libpcap-dev`
  - Fedora/CentOS: `libpcap-devel`
  - macOS: `libpcap` (via Homebrew)

## Installation

### From Source

```sh
git clone https://github.com/yourusername/gtap.git
cd gtap
go build -o gtap .

#OR install to path
sudo make install
```

## Usage

```
gtap [OPTIONS]
```

By default, `gtap` captures all packets from all available network interfaces.

### Options

| Flag        | Description                                       |
| ----------- | ------------------------------------------------- |
| `-i`        | Capture from specific interface (e.g., `-i eth0`) |
| `-f`        | Apply BPF filter (e.g., `-f "tcp port 80"`)       |
| `-p`        | Enable promiscuous mode                           |
| `-m`        | Enable monitor mode                               |
| `--read`    | Read packets from pcap file                       |
| `--write`   | Save captured packets to pcap file                |
| `--summary` | Display packet summary (default)                  |
| `--hex`     | Display packet data as hex dump                   |

## Examples

**Capture all packets:**

```sh
gtap
```

**Capture from eth0 in promiscuous mode and save:**

```sh
gtap -i eth0 -p --write capture.pcap
```

**Read and analyze a pcap file:**

```sh
gtap --read capture.pcap --summary
```

**Display hex dump of captured packets:**

```sh
gtap --read capture.pcap --hex
```

**Capture only HTTP traffic:**

```sh
gtap -f "tcp port 80" --summary
```

**Capture HTTPS traffic from a specific interface:**

```sh
gtap -i eth0 -f "tcp port 443" --write secure.pcap
```

## Filters

BPF (Berkeley Packet Filter) syntax is supported. Common examples:

- `tcp port 80` - HTTP traffic
- `udp port 53` - DNS queries
- `ip src 192.168.1.1` - Traffic from specific IP
- `icmp` - ICMP packets (ping)
- `tcp and dst port 22` - SSH traffic

## License

MIT License. See [LICENSE](LICENSE) for details.

---

Powered by [Google's gopacket](https://github.com/google/gopacket)
