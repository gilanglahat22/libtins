#!/bin/bash

# Define variables you might want to change
PROJECT_NAME="Network Packet Monitor"
GITHUB_USERNAME="your-username"
CURRENT_YEAR=$(date +"%Y")

# Create README.md file
cat > README.md << EOF
# ${PROJECT_NAME}

A network packet monitoring tool built using libtins library that captures and displays network packets, showing source IP, destination IP, protocol, source port, and destination port information.

## Overview

This tool monitors network traffic on a specified interface and displays the key packet information in a tabular format. It utilizes the libtins C++ library for packet sniffing and analysis.

## Features

- Captures network packets in real-time
- Displays source IP, destination IP, protocol, source port, and destination port
- Identifies common protocols (HTTP, HTTPS, DNS, etc.)
- Supports packet filtering using BPF syntax
- Shows packets from all devices on the network segment (promiscuous mode)
- Lists available network interfaces

## Prerequisites

- Linux-based operating system (Ubuntu, Debian, etc.)
- C++ compiler (g++)
- libtins library
- libpcap development files
- Root/sudo privileges (required for packet capture)

## Installation

### 1. Install required dependencies

\`\`\`bash
sudo apt update
sudo apt install build-essential libpcap-dev
\`\`\`

### 2. Install libtins

There are two ways to install libtins:

#### Option A: Install via package manager (recommended for beginners)

\`\`\`bash
sudo apt install libtins-dev
\`\`\`

#### Option B: Build from source (for latest version)

\`\`\`bash
git clone https://github.com/mfontanini/libtins.git
cd libtins
mkdir build
cd build
cmake ../
make
sudo make install
sudo ldconfig
\`\`\`

### 3. Compile the packet monitor

\`\`\`bash
g++ packet_monitor.cpp -o packet_monitor -std=c++11 -ltins -lpthread
\`\`\`

## Usage

### Basic usage

\`\`\`bash
sudo ./packet_monitor <interface>
\`\`\`

Replace \`<interface>\` with your network interface name (e.g., eth0, wlan0).

### List available interfaces

\`\`\`bash
sudo ./packet_monitor -l
\`\`\`

### Apply filters

\`\`\`bash
sudo ./packet_monitor <interface> "filter expression"
\`\`\`

Example filters:
- HTTP and HTTPS traffic: \`"tcp port 80 or tcp port 443"\`
- Traffic to/from specific host: \`"host 192.168.1.100"\`
- Only UDP traffic: \`"udp"\`

## Output Format

\`\`\`
SOURCE IP            SRC_PORT               DESTINATION IP DST_PORT PROTOCOL  
----------------------------------------------------------------------
192.168.1.100        52134                 142.250.180.78    443   HTTPS    
192.168.1.1          53                     192.168.1.100    60456  DNS     
192.168.1.100        48772                  192.168.1.1      53     DNS     
\`\`\`

## Understanding the Output

- **SOURCE IP**: The IP address of the packet sender
- **SRC_PORT**: The source port number (only for TCP/UDP)
- **DESTINATION IP**: The IP address of the packet recipient
- **DST_PORT**: The destination port number (only for TCP/UDP)
- **PROTOCOL**: The identified protocol (TCP, UDP, HTTP, HTTPS, DNS, etc.)

## Troubleshooting

### "Error opening interface"
- Make sure you're running with sudo/root privileges
- Verify that the interface name is correct (use \`-l\` to list interfaces)
- Check if the interface is up and running

### No packets appearing
- Generate some traffic (e.g., open a web browser)
- Try a different interface
- Check if your network setup allows promiscuous mode

### Compilation errors
- Make sure libtins is properly installed
- Check that you have the required development libraries installed

## Network Capture Notes

- On switched networks, you'll typically only see:
  - Traffic to/from your machine
  - Broadcast traffic
  - Multicast traffic

- To capture all traffic between all devices, you need:
  - A hub-based network (rare nowadays)
  - A network tap
  - A switch configured for port mirroring/SPAN
  - A WiFi adapter in monitor mode (for wireless networks)

## Advanced Usage

### Common BPF Filter Examples

- Only ICMP (ping) traffic: \`"icmp"\`
- Only SSH traffic: \`"tcp port 22"\`
- Ignore specific IP: \`"not host 192.168.1.1"\`
- Multiple criteria: \`"tcp port 80 and host 192.168.1.100"\`

## License

This project is released under the MIT License.

Copyright (c) ${CURRENT_YEAR} ${GITHUB_USERNAME}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Acknowledgements

This tool is built using the [libtins library](https://github.com/mfontanini/libtins), a high-level, multiplatform C++ network packet crafting and sniffing library.
EOF

echo "README.md has been generated!"