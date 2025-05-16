#include <tins/tins.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <csignal>
#include <atomic>

using namespace Tins;
using namespace std;

atomic<bool> running(true);

// Signal handler to stop capture gracefully
void signal_handler(int signal) {
    cout << "\nReceived interrupt signal. Stopping capture..." << endl;
    running = false;
}

// Callback function to process packets
bool packet_handler(const PDU& pdu) {
    if (!running) return false;  // Stop if signal received
    
    // Initialize packet details
    string src_ip = "-";
    string dst_ip = "-";
    string protocol = "-";
    int src_port = 0;
    int dst_port = 0;
    
    // Extract IP layer information (IPv4)
    if (const IP* ip = pdu.find_pdu<IP>()) {
        src_ip = ip->src_addr().to_string();
        dst_ip = ip->dst_addr().to_string();
        
        // Determine protocol
        switch (ip->protocol()) {
            case 6:   // TCP
                protocol = "TCP";
                if (const TCP* tcp = pdu.find_pdu<TCP>()) {
                    src_port = tcp->sport();
                    dst_port = tcp->dport();
                    
                    // Identify common protocols by port
                    if (dst_port == 80 || src_port == 80) protocol = "HTTP";
                    else if (dst_port == 443 || src_port == 443) protocol = "HTTPS";
                    else if (dst_port == 22 || src_port == 22) protocol = "SSH";
                    else if (dst_port == 53 || src_port == 53) protocol = "DNS(TCP)";
                }
                break;
                
            case 17:  // UDP
                protocol = "UDP";
                if (const UDP* udp = pdu.find_pdu<UDP>()) {
                    src_port = udp->sport();
                    dst_port = udp->dport();
                    
                    // Identify common protocols by port
                    if (dst_port == 53 || src_port == 53) protocol = "DNS";
                    else if (dst_port == 67 || dst_port == 68) protocol = "DHCP";
                }
                break;
                
            case 1:   // ICMP
                protocol = "ICMP";
                break;
                
            default:
                protocol = "IP:" + to_string(ip->protocol());
        }
    }
    // Extract IP layer information (IPv6)
    else if (const IPv6* ipv6 = pdu.find_pdu<IPv6>()) {
        src_ip = ipv6->src_addr().to_string();
        dst_ip = ipv6->dst_addr().to_string();
        
        // Determine protocol
        switch (ipv6->next_header()) {
            case 6:   // TCP
                protocol = "TCP";
                if (const TCP* tcp = pdu.find_pdu<TCP>()) {
                    src_port = tcp->sport();
                    dst_port = tcp->dport();
                    
                    // Identify common protocols by port
                    if (dst_port == 80 || src_port == 80) protocol = "HTTP";
                    else if (dst_port == 443 || src_port == 443) protocol = "HTTPS";
                }
                break;
                
            case 17:  // UDP
                protocol = "UDP";
                if (const UDP* udp = pdu.find_pdu<UDP>()) {
                    src_port = udp->sport();
                    dst_port = udp->dport();
                    
                    // Identify common protocols by port
                    if (dst_port == 53 || src_port == 53) protocol = "DNS";
                }
                break;
                
            case 58:  // ICMPv6
                protocol = "ICMPv6";
                break;
                
            default:
                protocol = "IPv6:" + to_string(ipv6->next_header());
        }
    }
    // Check for ARP layer
    else if (const ARP* arp = pdu.find_pdu<ARP>()) {
        protocol = "ARP";
        src_ip = arp->sender_ip_addr().to_string();
        dst_ip = arp->target_ip_addr().to_string();
    }
    
    // Print packet information in a clean format
    cout << left << setw(20) << src_ip << " ";
    cout << setw(7) << src_port << " ";
    cout << right << setw(20) << dst_ip << " ";
    cout << setw(7) << dst_port << " ";
    cout << left << setw(10) << protocol;
    cout << endl;
    
    return running;  // Continue capturing if still running
}

// Display network interfaces
void show_interfaces() {
    cout << "Available Network Interfaces:" << endl;
    cout << "-----------------------------" << endl;
    
    vector<NetworkInterface> interfaces = NetworkInterface::all();
    for (const NetworkInterface& iface : interfaces) {
        cout << "- " << iface.name() << endl;
    }
    cout << endl;
}

int main(int argc, char* argv[]) {
    // Register signal handler
    signal(SIGINT, signal_handler);
    
    // Display help if needed
    if (argc < 2 || string(argv[1]) == "-h" || string(argv[1]) == "--help") {
        cout << "Network Packet Monitor" << endl;
        cout << "Usage: " << argv[0] << " <interface> [filter]" << endl;
        cout << "Options:" << endl;
        cout << "  -l, --list       List available network interfaces and exit" << endl;
        cout << endl;
        cout << "Examples:" << endl;
        cout << "  " << argv[0] << " eth0" << endl;
        cout << "  " << argv[0] << " wlan0 \"tcp port 80 or tcp port 443\"" << endl;
        return 0;
    }
    
    // Check if user just wants to list interfaces
    if (string(argv[1]) == "-l" || string(argv[1]) == "--list") {
        show_interfaces();
        return 0;
    }
    
    string interface = argv[1];
    string filter;
    
    // Check if filter is provided
    if (argc > 2) {
        filter = argv[2];
    }
    
    try {
        // Configure sniffer
        SnifferConfiguration config;
        config.set_promisc_mode(true);       // Capture all packets, not just those addressed to this host
        
        if (!filter.empty()) {
            config.set_filter(filter);
            cout << "Using filter: " << filter << endl;
        }
        
        // Create sniffer
        cout << "Starting packet capture on interface " << interface << endl;
        cout << "Press Ctrl+C to stop capture" << endl;
        cout << endl;
        
        // Print header
        cout << left << setw(20) << "SOURCE IP" << " ";
        cout << setw(7) << "SRC_PORT" << " ";
        cout << right << setw(20) << "DESTINATION IP" << " ";
        cout << setw(7) << "DST_PORT" << " ";
        cout << left << setw(10) << "PROTOCOL";
        cout << endl;
        
        // Print separator line
        cout << string(70, '-') << endl;
        
        // Start capture
        Sniffer sniffer(interface, config);
        sniffer.sniff_loop(packet_handler);
        
    } catch (exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        
        cerr << "\nTroubleshooting:" << endl;
        cerr << "1. Make sure you're running as root/sudo" << endl;
        cerr << "2. Verify the interface name is correct (use -l to list interfaces)" << endl;
        cerr << "3. Check if the interface is up and running" << endl;
        
        return 1;
    }
    
    return 0;
}