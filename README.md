# GoNetSniff++

> A Golang-based Real-Time Network Scanner & Packet Sniffer for Total Local Network Surveillance

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/user/gonetsniff)](https://goreportcard.com/report/github.com/user/gonetsniff)
[![Go Version](https://img.shields.io/github/go-mod/go-version/user/gonetsniff)](https://github.com/user/gonetsniff)

## Project Overview

GoNetSniff++ is a **full-featured, real-time network scanning and traffic monitoring tool**, written in **Golang**, designed for **cybersecurity researchers**, **penetration testers**, and **ethical hackers**.

It scans **all local networks**, detects **all connected devices**, and captures **live traffic**, including DNS queries, HTTP requests, and other protocol activities.

Think of it like a lightweight Wireshark + Nmap + Bettercap combo... but in Golang 

![GoNetSniff++ Screenshot](https://via.placeholder.com/800x450.png?text=GoNetSniff%2B%2B+Screenshot)

## Core Features

- **Device Discovery**: Find every device connected to any local network (Wi-Fi or LAN)
- **Traffic Analysis**: Capture and analyze all traffic (DNS, HTTP, TLS SNI)
- **Real-time Monitoring**: View source IP, destination IP, MAC address, queried domain, and protocol info
- **Multi-Network Support**: Identify devices across multiple subnets
- **Gateway Detection**: Automatically identify network gateways and routers
- **Device Classification**: Attempt to identify device types (PC, mobile, IoT, etc.)
- **Network Summary**: Get a quick overview of all devices on your network
- **Bandwidth Monitoring**: Track data usage per device in real-time
- **Protocol Analysis**: Identify and analyze protocols used by each device
- **GeoIP Location**: Map IP addresses to geographic locations
- **Packet Capture**: Save network traffic to PCAP files for later analysis
- **Device Fingerprinting**: Identify devices based on their network behavior patterns
- **Unique Device Identification**: Classify devices with confidence scores based on their network signatures
- **ARP Spoofing**: Perform man-in-the-middle attacks using ARP poisoning
- **DNS Spoofing**: Redirect DNS queries to specified IP addresses
- **MITM Proxy**: Intercept and modify HTTP/HTTPS traffic

## Key Components

1. **Multi-Network ARP + Subnet Scanning**
   - Scans all network interfaces
   - Identifies all reachable subnets
   - Lists IP/MAC for each connected device

2. **DNS Sniffing (Port 53 UDP)**
   - Captures DNS requests in real-time
   - Shows source, destination, and queried domains

3. **HTTP Request Tracking**
   - Parses HTTP GET/POST requests
   - Shows visited domains and IPs

4. **TLS SNI Logging (HTTPS Insight)**
   - Captures TLS handshake to extract SNI field
   - See which domain is being accessed even via HTTPS

5. **Gateway Detection**
   - Identifies network gateways and routers
   - Shows default gateway for each interface

6. **Enhanced Device Discovery**
   - Port scanning to identify device types
   - Hostname resolution when available
   - Device type classification

7. **Bandwidth Monitoring**
   - Tracks data usage per device
   - Shows upload and download rates in real-time
   - Aggregates total network bandwidth usage

8. **Protocol Analysis**
   - Identifies protocols used by each device
   - Tracks connection statistics
   - Shows top protocols by data volume

9. **GeoIP Location**
   - Maps external IP addresses to geographic locations
   - Shows country, city, and ISP information
   - Caches results to minimize API usage

10. **Packet Capture**
    - Saves network traffic to PCAP files
    - Supports file rotation and BPF filtering
    - Compatible with Wireshark and other analysis tools

11. **Device Fingerprinting**
    - Identifies devices based on TCP/IP stack behavior
    - Analyzes HTTP User-Agent strings
    - Detects operating systems and device types

12. **Unique Device Identification**
    - Creates unique device signatures based on network behavior
    - Classifies devices with confidence scores
    - Tracks devices even when IP addresses change

13. **ARP Spoofing**
    - Performs man-in-the-middle attacks using ARP poisoning
    - Redirects traffic through the attacker machine
    - Enables traffic interception between targets and gateway

14. **DNS Spoofing**
    - Redirects DNS queries to specified IP addresses
    - Supports multiple DNS record types (A, AAAA, CNAME, etc.)
    - Can spoof all domains or specific ones

15. **MITM Proxy**
    - Intercepts HTTP/HTTPS traffic
    - Allows viewing and modifying requests/responses
    - Supports content injection and SSL stripping

## Project Structure

```
gonetsniff/
├── cmd/
│   └── main.go              # Main entrypoint
├── internal/
│   ├── analyzer/            # Protocol analysis
│   │   └── protocol_analyzer.go
│   ├── arp/                 # Network scanning (ARP)
│   │   └── scanner.go
│   ├── bandwidth/           # Bandwidth monitoring
│   │   └── monitor.go
│   ├── capture/             # Packet capture
│   │   └── pcap.go
│   ├── display/             # Terminal UI
│   │   └── summary.go
│   ├── dns/                 # DNS sniffing
│   │   └── sniffer.go
│   ├── fingerprint/         # Device fingerprinting
│   │   └── device_fingerprinter.go
│   ├── gateway/             # Gateway detection
│   │   └── detector.go
│   ├── geoip/               # IP geolocation
│   │   └── locator.go
│   ├── http/                # HTTP tracker
│   │   └── parser.go
│   ├── interfaces/          # Network interface handling
│   │   └── discover.go
│   ├── mitm/                # Man-in-the-middle proxy
│   │   └── proxy.go
│   ├── scanner/             # Enhanced network scanning
│   │   └── network_scanner.go
│   ├── spoof/               # Network spoofing
│   │   ├── arp_spoofer.go
│   │   └── dns_spoofer.go
│   ├── tls/                 # TLS SNI extraction
│   │   └── sni.go
│   ├── uniqueid/            # Unique device identification
│   │   └── device_classifier.go
│   └── utils/               # Utility functions
│       └── logger.go
└── README.md                # This file
```

## Requirements

- Golang 1.16 or higher
- Root/Admin privileges (required for packet capture)
- libpcap development files

### Ubuntu/Debian
```bash
sudo apt-get install libpcap-dev
```

### CentOS/RHEL
```bash
sudo yum install libpcap-devel
```

### macOS
```bash
brew install libpcap
```

## Installation

### From Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/gonetsniff.git
cd gonetsniff
```

2. Build the project:
```bash
go build -o gonetsniff ./cmd/main.go
```

3. Run with root privileges:
```bash
sudo ./gonetsniff
```

### Using Go Install

```bash
go install github.com/yourusername/gonetsniff@latest
sudo $(go env GOPATH)/bin/gonetsniff
```

## Usage Examples

### Basic Usage

```bash
sudo ./gonetsniff
```

This will start GoNetSniff++ with default settings, scanning all available network interfaces.

### With GeoIP Location

```bash
sudo ./gonetsniff --geo
```

Enables GeoIP location service to map IP addresses to geographic locations.

### With Packet Capture

```bash
sudo ./gonetsniff --capture --capture-file=/tmp/network.pcap
```

Captures network traffic and saves it to the specified PCAP file.

### With ARP Spoofing

```bash
sudo ./gonetsniff --arp-spoof --arp-iface=eth0 --arp-gateway=192.168.1.1 --arp-targets=192.168.1.100,192.168.1.101
```

Performs ARP spoofing to intercept traffic between the specified targets and the gateway.

### With DNS Spoofing

```bash
sudo ./gonetsniff --dns-spoof --dns-iface=eth0
```

Enables DNS spoofing on the specified interface. You can add DNS mappings programmatically.

### With MITM Proxy

```bash
sudo ./gonetsniff --mitm --mitm-port=8080
```

Starts a MITM proxy on port 8080 to intercept HTTP/HTTPS traffic.

### With Device Identification

```bash
sudo ./gonetsniff --device-id
```

Enables unique device identification to classify devices based on their network behavior.

### Full-Featured Mode

```bash
sudo ./gonetsniff --geo --geo-key=your_api_key --capture --capture-file=/tmp/network.pcap --capture-iface=eth0 --device-id --arp-spoof --arp-iface=eth0 --arp-gateway=192.168.1.1 --arp-targets=192.168.1.100
```

Runs GoNetSniff++ with all features enabled, using a specific API key for GeoIP, capturing packets on the eth0 interface, and performing ARP spoofing against a target.

## Command Line Options

| Option | Description |
|--------|-------------|
| `--geo` | Enable GeoIP location service |
| `--geo-key` | API key for GeoIP service (optional) |
| `--capture` | Enable packet capture to PCAP file |
| `--capture-file` | Path to save PCAP capture file (default: ./capture.pcap) |
| `--capture-iface` | Interface to capture packets on (default: first available) |
| `--arp-spoof` | Enable ARP spoofing (MITM) |
| `--arp-iface` | Interface to use for ARP spoofing |
| `--arp-targets` | Target IPs for ARP spoofing (comma-separated) |
| `--arp-gateway` | Gateway IP for ARP spoofing |
| `--dns-spoof` | Enable DNS spoofing |
| `--dns-iface` | Interface to use for DNS spoofing |
| `--mitm` | Enable MITM HTTP/HTTPS proxy |
| `--mitm-port` | Port to use for MITM proxy (default: 8080) |
| `--device-id` | Enable unique device identification |

## Permissions

This tool requires **root/admin privileges** to capture packets, similar to Wireshark. It will automatically request elevated privileges on startup.

## Example Output

```
 GoNetSniff++ Network Activity Monitor 

 Network Summary:
   Total Devices: 12 | Gateways: 1 | Routers: 2 | PCs: 5 | Mobile: 3 | IoT: 1 | Unknown: 0

 Network Traffic:
   Total Received: 1.25 GB | Rate: 2.5 MB/s
   Total Sent: 350.5 MB | Rate: 750 KB/s

 Network Gateways:
   • 192.168.1.1 | MAC: 00:11:22:33:44:55 | Router/Gateway | ↓1.2 MB/s ↑350 KB/s

 Connected Devices:
   • 192.168.1.100 | MAC: aa:bb:cc:dd:ee:ff | Windows PC | ↓950 KB/s ↑120 KB/s
     ↳ Ports: 80 (HTTP), 443 (HTTPS), 22 (SSH)
     ↳ Protocols: TCP (15.5 MB), UDP (2.3 MB), HTTP (8.2 MB)
     ↳ google.com [DNS, HTTPS]
     ↳ github.com [DNS, HTTPS]
     ↳ stackoverflow.com [DNS, HTTPS]
   • 192.168.1.101 | MAC: 11:22:33:44:55:66 | Android Phone | San Francisco, US | Comcast | ↓350 KB/s ↑85 KB/s
     ↳ Ports: 80 (HTTP), 443 (HTTPS)
     ↳ Protocols: TCP (5.2 MB), HTTPS (4.8 MB)
     ↳ instagram.com [DNS, HTTPS]
     ↳ facebook.com [DNS, HTTPS]
     ↳ ... and 15 more sites
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Legal Disclaimer

This tool is intended for **educational and ethical purposes only**. Only use it on networks you own or have explicit permission to monitor. Unauthorized network monitoring may be illegal in your jurisdiction.

The ARP spoofing, DNS spoofing, and MITM proxy features are particularly sensitive and should only be used in controlled environments with proper authorization. Misuse of these features may violate laws and regulations.

## Authors

- **Your Name** - *Initial work* - [YourGitHub](https://github.com/yourusername)

## Acknowledgments

- [gopacket](https://github.com/google/gopacket) - The amazing packet processing library for Go
- [cobra](https://github.com/spf13/cobra) - A Commander for modern Go CLI interactions
- [logrus](https://github.com/sirupsen/logrus) - Structured, pluggable logging for Go
- [miekg/dns](https://github.com/miekg/dns) - DNS library in Go
