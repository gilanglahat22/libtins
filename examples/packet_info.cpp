#include <tins/tins.h>
#include <iostream>

using namespace Tins;
using namespace std;

// Callback function to process packets
bool packet_handler(const PDU& pdu) {
    // Check if the packet has IP layer
    if (pdu.pdu_type() == PDU::IP || pdu.pdu_type() == PDU::IPv6) {
        // Extract IP layer
        const IP* ip = pdu.find_pdu<IP>();
        const IPv6* ipv6 = pdu.find_pdu<IPv6>();
        
        string src_ip, dst_ip;
        string protocol = "Other";
        uint16_t src_port = 0, dst_port = 0;
        
        // Get IP addresses
        if (ip) {
            src_ip = ip->src_addr().to_string();
            dst_ip = ip->dst_addr().to_string();
            
            // Determine protocol
            if (ip->protocol() == Tins::Constants::IP::PROTO_TCP) {
                protocol = "TCP";
                // Extract TCP layer
                if (const TCP* tcp = pdu.find_pdu<TCP>()) {
                    src_port = tcp->sport();
                    dst_port = tcp->dport();
                }
            }
            else if (ip->protocol() == Tins::Constants::IP::PROTO_UDP) {
                protocol = "UDP";
                // Extract UDP layer
                if (const UDP* udp = pdu.find_pdu<UDP>()) {
                    src_port = udp->sport();
                    dst_port = udp->dport();
                }
            }
            else if (ip->protocol() == Tins::Constants::IP::PROTO_ICMP) {
                protocol = "ICMP";
            }
        }
        else if (ipv6) {
            src_ip = ipv6->src_addr().to_string();
            dst_ip = ipv6->dst_addr().to_string();
            
            // Handle IPv6 protocols
            if (ipv6->next_header() == Tins::Constants::IP::PROTO_TCP) {
                protocol = "TCP";
                // Extract TCP layer
                if (const TCP* tcp = pdu.find_pdu<TCP>()) {
                    src_port = tcp->sport();
                    dst_port = tcp->dport();
                }
            }
            else if (ipv6->next_header() == Tins::Constants::IP::PROTO_UDP) {
                protocol = "UDP";
                // Extract UDP layer
                if (const UDP* udp = pdu.find_pdu<UDP>()) {
                    src_port = udp->sport();
                    dst_port = udp->dport();
                }
            }
            else if (ipv6->next_header() == Tins::Constants::IP::PROTO_ICMPV6) {
                protocol = "ICMPv6";
                // You can extract specific ICMPv6 information if needed
                if (const ICMPv6* icmpv6 = pdu.find_pdu<ICMPv6>()) {
                    // For ICMPv6, there are no ports, but you can get the type and code
                    cout << "ICMPv6 Type: " << (int)icmpv6->type() << endl;
                    cout << "ICMPv6 Code: " << (int)icmpv6->code() << endl;
                }
            }
            // Check for IPv6 extension headers
            else if (ipv6->next_header() == Tins::Constants::IP::PROTO_FRAGMENT ||
                     ipv6->next_header() == Tins::Constants::IP::PROTO_ROUTING ||
                     ipv6->next_header() == Tins::Constants::IP::PROTO_DSTOPT ||
                     ipv6->next_header() == Tins::Constants::IP::PROTO_HOPOPT) {
                protocol = "IPv6-Ext";
                // For extension headers, you can add specific handling if needed
            }
        }
        
        // Print the extracted information
        cout << "Source IP: " << src_ip << endl;
        cout << "Destination IP: " << dst_ip << endl;
        cout << "Protocol: " << protocol << endl;
        
        if (src_port > 0 || dst_port > 0) {
            cout << "Source Port: " << src_port << endl;
            cout << "Destination Port: " << dst_port << endl;
        }
        
        cout << "-----------------------------" << endl;
    }
    
    // Return true to keep capturing packets
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <interface>" << endl;
        return 1;
    }
    
    try {
        // Create a sniffer on the specified interface
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        Sniffer sniffer(argv[1], config);
        
        // Start the packet capture loop
        cout << "Starting packet capture on interface " << argv[1] << "..." << endl;
        cout << "Press Ctrl+C to stop." << endl;
        sniffer.sniff_loop(packet_handler);
    }
    catch (exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }
    
    return 0;
}