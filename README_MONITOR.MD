#!/bin/bash

# Define variables you might want to change
PROJECT_NAME="Distributed Network Packet Monitor"
GITHUB_USERNAME="your-username"
CURRENT_YEAR=$(date +"%Y")

# Create README.md file
cat > README.md << EOF
# ${PROJECT_NAME}

A distributed network monitoring system consisting of two components:
1. **Packet Agent** - Runs on target computers to capture network packets
2. **Packet Monitor Server** - Collects and displays packet data from multiple agents

This system allows you to monitor network traffic from multiple computers without special network hardware or configuration.

## Overview

The Distributed Network Packet Monitor provides a client-server architecture for network traffic monitoring:

- **Packet Agents** run on the computers you want to monitor
- **Packet Monitor Server** runs on a central monitoring computer
- Packet metadata is transmitted over a TCP connection
- The system only transmits packet headers/metadata (not packet payload)

## Features

- Monitor multiple computers from a central location
- Real-time packet capture and display
- Statistics on protocols, IP addresses, and ports
- Colorized output for different protocols
- Automatic reconnection if connection is lost
- Optional logging to file
- Works across different networks (LAN/WAN)

## Prerequisites

### For Both Monitor and Agent Computers

- Linux-based operating system (Ubuntu, Debian, etc.)
- C++ compiler (g++)
- Network connectivity between computers

### For Agent Computers (Additional)

- libtins library
- libpcap development files
- Root/sudo privileges (required for packet capture)

## Installation

### 1. Install Dependencies

#### On Monitor Computer
\`\`\`bash
sudo apt update
sudo apt install g++ build-essential
\`\`\`

#### On Agent Computers
\`\`\`bash
sudo apt update
sudo apt install g++ build-essential libpcap-dev
sudo apt install libtins-dev
\`\`\`

If libtins is not available in your repositories, you can build from source:
\`\`\`bash
git clone https://github.com/mfontanini/libtins.git
cd libtins
mkdir build && cd build
cmake ../
make
sudo make install
sudo ldconfig
\`\`\`

### 2. Setup Files

#### On Monitor Computer
1. Save the \`packet_monitor_server.cpp\` file
2. Compile with:
\`\`\`bash
g++ packet_monitor_server.cpp -o packet_monitor_server -std=c++11 -lpthread
\`\`\`

#### On Agent Computers
1. Save the \`packet_agent.cpp\` file
2. Compile with:
\`\`\`bash
g++ packet_agent.cpp -o packet_agent -std=c++11 -ltins -lpthread
\`\`\`

## Network Configuration

### Determine IP Addresses

1. On the Monitor Computer, find your IP address:
\`\`\`bash
ip addr show
\`\`\`
or
\`\`\`bash
ifconfig
\`\`\`

2. Note your IP address (like 192.168.1.100)

### Configure Firewall (if necessary)

On the Monitor Computer:
\`\`\`bash
# For UFW (Ubuntu)
sudo ufw allow 5500/tcp

# For iptables
sudo iptables -A INPUT -p tcp --dport 5500 -j ACCEPT
\`\`\`

### For Connections Across Different Networks

If your Monitor and Agent computers are on different networks:

1. You'll need to set up port forwarding on your router to direct traffic on port 5500 to your Monitor computer
2. Use your public IP address for the connection
3. Make sure port 5500 is open in any cloud provider firewall if using VMs

## Usage

### Start the Monitor Server

On the Monitor Computer:
\`\`\`bash
./packet_monitor_server
\`\`\`

Options:
\`\`\`bash
./packet_monitor_server [options]
  -p, --port PORT       Listen on port (default: 5500)
  -o, --output FILE     Save packet data to file
  -n, --no-color        Disable colored output
  -s, --no-stats        Disable statistics
  -i, --interval SEC    Statistics display interval (default: 10)
\`\`\`

### Start the Packet Agent(s)

On each Agent Computer:
\`\`\`bash
sudo ./packet_agent eth0 192.168.1.100
\`\`\`
Replace:
- \`eth0\` with the network interface you want to monitor
- \`192.168.1.100\` with the IP address of your Monitor computer

Options:
\`\`\`bash
sudo ./packet_agent <interface> <monitor_ip> [options]
  -p, --port PORT       Specify monitor port (default: 5500)
  -f, --filter FILTER   Set packet filter (BPF syntax)
  -l, --list            List available interfaces and exit
\`\`\`

## Output Format

The Monitor Server displays packet information in the following format:

\`\`\`
TIMESTAMP             SOURCE               DESTINATION          PROTOCOL   SIZE       AGENT
--------------------------------------------------------------------------------------------
2025-05-16 15:42:01   192.168.1.101:52134  142.250.180.78:443   HTTPS      1.4 KB     laptop1
2025-05-16 15:42:02   192.168.1.102:48772  192.168.1.1:53       DNS        134 B      desktop2
2025-05-16 15:42:03   192.168.1.103:58788  35.224.170.84:443    HTTPS      2.7 KB     server1
\`\`\`

## Packet Filtering

You can apply filters to the Packet Agent using Berkeley Packet Filter (BPF) syntax:

\`\`\`bash
sudo ./packet_agent eth0 192.168.1.100 -f "tcp port 80 or tcp port 443"
\`\`\`

Common filter examples:
- HTTP/HTTPS traffic: \`"tcp port 80 or tcp port 443"\`
- DNS traffic: \`"udp port 53"\`
- Traffic to/from a specific host: \`"host 192.168.1.5"\`
- Only TCP traffic: \`"tcp"\`
- Exclude certain traffic: \`"not port 22"\`

## Troubleshooting

### Connection Issues

If the Agent cannot connect to the Monitor:

1. Verify the Monitor is running
2. Check that the IP address is correct
3. Ensure port 5500 is open in firewalls
4. Test basic connectivity: \`ping <monitor-ip>\`
5. Test TCP connectivity: \`nc -v <monitor-ip> 5500\`

### No Packets Displayed

If no packets are being displayed:

1. Make sure the Agent is running with sudo/root privileges
2. Verify the interface name is correct (use \`-l\` to list interfaces)
3. Check if there is any active network traffic on the target computer
4. Try using a different interface if multiple are available

### Agent Keeps Disconnecting

If the Agent disconnects frequently:

1. Check network stability between the computers
2. Firewall might be timing out the connection
3. The Monitor computer might be under heavy load

## Security Considerations

- The system only transmits packet metadata, not packet contents
- Both components use regular TCP connections without encryption
- For sensitive environments, consider running over SSH tunnels
- Only install the Agent on computers you have permission to monitor

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