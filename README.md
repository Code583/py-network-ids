# Simple Py-IDS (Intrusion Detection System)

A lightweight network traffic analyzer built with Python and Scapy. This tool monitors real-time network traffic to detect insecure protocols and potential reconnaissance activities (Port Scanning).

## 🚀 Features

- **Protocol Monitoring**: Identifies unencrypted and insecure traffic (HTTP, Telnet, FTP).
- **Scanning Detection**: Tracks SYN flags to identify potential port scanning attempts from a single source IP.
- **Automated Logging**: Saves all alerts into an `alerts_network.log` file, making it ready for SIEM integration (like Splunk or ELK).
- **Lightweight**: Optimized to run with minimal CPU and RAM usage.

## 🛠️ Requirements

- Python 3.x
- Scapy Library (`pip install scapy`)
- Administrative/Root privileges (Required for packet sniffing)

## 💻 How to Use

1. Clone this repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/simple-py-ids.git](https://github.com/YOUR_USERNAME/simple-py-ids.git)
