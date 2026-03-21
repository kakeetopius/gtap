# gtap

**gtap** is a simple command-line utility for capturing, decoding, and displaying network packet data. It supports live capture from network interfaces, reading from pcap files, filtering, and multiple output formats.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Requirements

- Go 1.18 or higher
- Linux or macOS (Windows support may vary)
- Git (for cloning the repository)

## Features

- Capture packets from all or specific network interfaces
- Apply BPF-style filters to captured packets
- Support for promiscuous and monitor modes
- Save captured packets to a pcap file or read from one
- Output packet data as a summary or hex dump
- Simple, scriptable CLI interface

## Usage

```sh
gtap [OPTIONS]
```

If no options are given, `gtap` by default captures all packets from all available network interfaces.

## Examples

Capture all packets from all interfaces:

```sh
gtap
```

Capture packets from interface `eth0` in promiscuous mode and save to `capture.pcap`:

```sh
gtap -i eth0 -p --write capture.pcap
```

Read packets from a pcap file and display as a hex dump:

```sh
gtap --read capture.pcap --hex
```

Capture only HTTP packets using a filter:

```sh
gtap -f "tcp port 80"
```

## Installation

Clone the repository and build with Go:

```sh
git clone https://github.com/yourusername/gtap.git
cd gtap

go build -o gtap .
#OR to install to PATH
sudo make install
```

## License

MIT License. See [LICENSE](LICENSE) for details.
--

<footer>Powered by [Google's gopacket](https://github.com/google/gopacket)</footer>
