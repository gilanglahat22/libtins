#include <tins/tins.h>
#include <iostream>
#include <iomanip>

using namespace Tins;
using namespace std;

// Protocol numbers defined directly
namespace Protocol {
    const uint8_t TCP = 6;
    const uint8_t UDP = 17;
    const uint8_t ICMP = 1;
    const uint8_t ICMPv6 = 58;
}

// Callback function to process packets
bool packet_handler(const PDU& pdu) {
    // Print raw packet info
    cout << "Got packet! PDU type: " << pdu.pdu_type() << endl;
    
    // Try to extract Ethernet first (usually the lowest layer)
    if (const EthernetII* eth = pdu.find_pdu<EthernetII>()) {
        cout << "Ethernet: " << eth->src_addr() << " -> " << eth->dst_addr() << endl;
    }
    
    // Check for IP layer
    if (const IP* ip = pdu.find_pdu<IP>()) {
        cout << "IPv4: " << ip->src_addr() << " -> " << ip->dst_addr() 
             << " (Proto: " << (int)ip->protocol() << ")" << endl;
        
        // Check for TCP layer
        if (const TCP* tcp = pdu.find_pdu<TCP>()) {
            cout << "TCP: Port " << tcp->sport() << " -> " << tcp->dport() << endl;
        }
        // Check for UDP layer
        else if (const UDP* udp = pdu.find_pdu<UDP>()) {
            cout << "UDP: Port " << udp->sport() << " -> " << udp->dport() << endl;
        }
        // Check for ICMP layer
        else if (const ICMP* icmp = pdu.find_pdu<ICMP>()) {
            cout << "ICMP Type: " << (int)icmp->type() << ", Code: " << (int)icmp->code() << endl;
        }
    }
    // Check for IPv6 layer
    else if (const IPv6* ipv6 = pdu.find_pdu<IPv6>()) {
        cout << "IPv6: " << ipv6->src_addr() << " -> " << ipv6->dst_addr() 
             << " (Next Header: " << (int)ipv6->next_header() << ")" << endl;
        
        // Similar checks for upper layers as with IPv4
        if (const TCP* tcp = pdu.find_pdu<TCP>()) {
            cout << "TCP: Port " << tcp->sport() << " -> " << tcp->dport() << endl;
        }
        else if (const UDP* udp = pdu.find_pdu<UDP>()) {
            cout << "UDP: Port " << udp->sport() << " -> " << udp->dport() << endl;
        }
    }
    
    cout << "-----------------------------" << endl;
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <interface>" << endl;
        return 1;
    }
    
    try {
        // Create a sniffer in promiscuous mode
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_immediate_mode(true);  // Try to process packets immediately
        
        // Create a more verbose output about what's happening
        cout << "Starting capture on interface: " << argv[1] << endl;
        cout << "Using promiscuous mode: Yes" << endl;
        cout << "Waiting for packets..." << endl;
        
        Sniffer sniffer(argv[1], config);
        
        // Start the packet capture loop
        sniffer.sniff_loop(packet_handler);
    }
    catch (exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        
        // Add extra info for troubleshooting
        cerr << "Make sure:" << endl;
        cerr << " - You're running with sudo/root privileges" << endl;
        cerr << " - The interface name is correct" << endl;
        cerr << " - The interface is up (check with 'ip link set " << argv[1] << " up')" << endl;
        cerr << " - Try installing libpcap-dev if not already installed" << endl;
        
        return 1;
    }
    
    return 0;
}