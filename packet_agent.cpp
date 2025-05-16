#include <tins/tins.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <csignal>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>

using namespace Tins;
using namespace std;

// Configuration
struct AgentConfig {
    string interface;       // Network interface to monitor
    string monitor_ip;      // IP address of the monitor server
    int monitor_port = 5500;// Port to connect to monitor
    string bpf_filter;      // BPF filter
    int reconnect_delay = 5;// Seconds to wait before reconnection attempt
    bool promiscuous = true;// Enable promiscuous mode
};

// Globals
atomic<bool> running(true);
int client_socket = -1;
mutex socket_mutex;

// Signal handler
void signal_handler(int signal) {
    cout << "Received signal " << signal << ". Stopping agent..." << endl;
    running = false;
}

// Connect to monitor server
bool connect_to_monitor(const AgentConfig& config) {
    lock_guard<mutex> lock(socket_mutex);
    
    // Close existing socket if open
    if (client_socket >= 0) {
        close(client_socket);
    }
    
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        cerr << "Error creating socket" << endl;
        return false;
    }
    
    // Set up server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.monitor_port);
    
    // Convert IP address
    if (inet_pton(AF_INET, config.monitor_ip.c_str(), &server_addr.sin_addr) <= 0) {
        cerr << "Invalid monitor IP address: " << config.monitor_ip << endl;
        close(client_socket);
        client_socket = -1;
        return false;
    }
    
    // Connect to server
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Connection to monitor failed" << endl;
        close(client_socket);
        client_socket = -1;
        return false;
    }
    
    cout << "Connected to monitor at " << config.monitor_ip << ":" << config.monitor_port << endl;
    
    // Send device information
    string hostname = "unknown";
    char buffer[256];
    if (gethostname(buffer, sizeof(buffer)) == 0) {
        hostname = buffer;
    }
    
    ostringstream device_info;
    device_info << "AGENT_INFO|" << hostname << "|" << config.interface;
    
    string info = device_info.str();
    send(client_socket, info.c_str(), info.size(), 0);
    
    return true;
}

// Reconnection thread
void reconnect_thread(const AgentConfig& config) {
    while (running) {
        if (client_socket < 0) {
            cout << "Attempting to connect to monitor..." << endl;
            if (connect_to_monitor(config)) {
                cout << "Connection established" << endl;
            } else {
                cout << "Connection failed. Retrying in " << config.reconnect_delay << " seconds..." << endl;
            }
        }
        
        // Sleep before next attempt
        for (int i = 0; i < config.reconnect_delay && running; ++i) {
            this_thread::sleep_for(chrono::seconds(1));
        }
    }
}

// Send packet data to monitor
void send_packet_data(const string& packet_data) {
    lock_guard<mutex> lock(socket_mutex);
    
    if (client_socket >= 0) {
        string data = packet_data + "\n";
        ssize_t sent = send(client_socket, data.c_str(), data.size(), 0);
        
        if (sent < 0) {
            cerr << "Error sending data to monitor" << endl;
            close(client_socket);
            client_socket = -1;
        }
    }
}

// Packet handler callback
bool packet_handler(const PDU& pdu) {
    if (!running) return false;
    
    // Skip processing if not connected to monitor
    if (client_socket < 0) {
        return running;
    }
    
    // Initialize packet details
    string src_ip = "-";
    string dst_ip = "-";
    string protocol = "Unknown";
    int src_port = 0;
    int dst_port = 0;
    size_t packet_size = pdu.size();
    
    // Get timestamp
    auto now = chrono::system_clock::now();
    time_t now_c = chrono::system_clock::to_time_t(now);
    tm *now_tm = localtime(&now_c);
    
    char time_buffer[64];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", now_tm);
    string timestamp(time_buffer);
    
    // Extract IP layer (IPv4)
    if (const IP* ip = pdu.find_pdu<IP>()) {
        src_ip = ip->src_addr().to_string();
        dst_ip = ip->dst_addr().to_string();
        
        // Determine protocol
        switch (ip->protocol()) {
            case 6: // TCP
                protocol = "TCP";
                if (const TCP* tcp = pdu.find_pdu<TCP>()) {
                    src_port = tcp->sport();
                    dst_port = tcp->dport();
                    
                    // Identify common application protocols
                    if (dst_port == 80 || src_port == 80) {
                        protocol = "HTTP";
                    } else if (dst_port == 443 || src_port == 443) {
                        protocol = "HTTPS";
                    } else if (dst_port == 22 || src_port == 22) {
                        protocol = "SSH";
                    }
                }
                break;
                
            case 17: // UDP
                protocol = "UDP";
                if (const UDP* udp = pdu.find_pdu<UDP>()) {
                    src_port = udp->sport();
                    dst_port = udp->dport();
                    
                    // Identify common UDP protocols
                    if (dst_port == 53 || src_port == 53) {
                        protocol = "DNS";
                    } else if (dst_port == 67 || dst_port == 68) {
                        protocol = "DHCP";
                    }
                }
                break;
                
            case 1: // ICMP
                protocol = "ICMP";
                break;
                
            default:
                protocol = "IP:" + to_string(ip->protocol());
        }
    }
    // Extract IP layer (IPv6)
    else if (const IPv6* ipv6 = pdu.find_pdu<IPv6>()) {
        src_ip = ipv6->src_addr().to_string();
        dst_ip = ipv6->dst_addr().to_string();
        
        // Similar protocol determination for IPv6
        switch (ipv6->next_header()) {
            case 6: // TCP
                protocol = "TCP";
                if (const TCP* tcp = pdu.find_pdu<TCP>()) {
                    src_port = tcp->sport();
                    dst_port = tcp->dport();
                    
                    if (dst_port == 80 || src_port == 80) {
                        protocol = "HTTP";
                    } else if (dst_port == 443 || src_port == 443) {
                        protocol = "HTTPS";
                    }
                }
                break;
                
            case 17: // UDP
                protocol = "UDP";
                if (const UDP* udp = pdu.find_pdu<UDP>()) {
                    src_port = udp->sport();
                    dst_port = udp->dport();
                    
                    if (dst_port == 53 || src_port == 53) {
                        protocol = "DNS";
                    }
                }
                break;
                
            case 58: // ICMPv6
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
    
    // Prepare packet data to send
    ostringstream packet_data;
    packet_data << "PACKET|" 
                << timestamp << "|"
                << src_ip << "|" 
                << src_port << "|" 
                << dst_ip << "|" 
                << dst_port << "|" 
                << protocol << "|" 
                << packet_size;
    
    // Send packet data to monitor
    send_packet_data(packet_data.str());
    
    return running;
}

// Show available interfaces
void show_interfaces() {
    cout << "Available Network Interfaces:" << endl;
    cout << "-----------------------------" << endl;
    
    vector<NetworkInterface> interfaces = NetworkInterface::all();
    for (const auto& iface : interfaces) {
        cout << "- " << iface.name();
        
        try {
            auto info = iface.info();
            
            // Show IP addresses
            if (!info.ip_addresses.empty()) {
                cout << " (IP: ";
                cout << info.ip_addresses[0].to_string();
                for (size_t i = 1; i < info.ip_addresses.size(); ++i) {
                    cout << ", " << info.ip_addresses[i].to_string();
                }
                cout << ")";
            }
        } catch (exception& ex) {
            cout << " (Error getting info: " << ex.what() << ")";
        }
        
        cout << endl;
    }
    cout << endl;
}

// Parse command line arguments
void parse_arguments(int argc, char* argv[], AgentConfig& config) {
    if (argc < 3) {
        cout << "Packet Agent - Send network packets to a monitoring server" << endl;
        cout << "Usage: " << argv[0] << " <interface> <monitor_ip> [options]" << endl;
        cout << "Options:" << endl;
        cout << "  -p, --port PORT       Specify monitor port (default: 5500)" << endl;
        cout << "  -f, --filter FILTER   Set packet filter (BPF syntax)" << endl;
        cout << "  -l, --list            List available interfaces and exit" << endl;
        exit(1);
    }
    
    config.interface = argv[1];
    config.monitor_ip = argv[2];
    
    // Process additional options
    for (int i = 3; i < argc; ++i) {
        string arg = argv[i];
        
        if (arg == "-l" || arg == "--list") {
            show_interfaces();
            exit(0);
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            config.monitor_port = atoi(argv[++i]);
        } else if ((arg == "-f" || arg == "--filter") && i + 1 < argc) {
            config.bpf_filter = argv[++i];
        }
    }
}

int main(int argc, char* argv[]) {
    // Register signal handler
    signal(SIGINT, signal_handler);
    
    // Default configuration
    AgentConfig config;
    parse_arguments(argc, argv, config);
    
    // Start reconnection thread
    thread reconnect(reconnect_thread, config);
    
    try {
        // Configure sniffer
        SnifferConfiguration sniffer_config;
        sniffer_config.set_promisc_mode(config.promiscuous);
        
        // Set packet filter if specified
        if (!config.bpf_filter.empty()) {
            sniffer_config.set_filter(config.bpf_filter);
            cout << "Using filter: " << config.bpf_filter << endl;
        }
        
        // Create sniffer
        cout << "Starting packet agent on interface " << config.interface << endl;
        cout << "Sending packet data to " << config.monitor_ip << ":" << config.monitor_port << endl;
        cout << "Press Ctrl+C to stop" << endl;
        
        Sniffer sniffer(config.interface, sniffer_config);
        
        // Start packet capture
        sniffer.sniff_loop(packet_handler);
        
        // Wait for reconnection thread to finish
        reconnect.join();
        
        // Close socket
        if (client_socket >= 0) {
            close(client_socket);
        }
        
    } catch (exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        
        cerr << "\nTroubleshooting:" << endl;
        cerr << "1. Make sure you're running with root/sudo privileges" << endl;
        cerr << "2. Verify the interface name is correct (use -l to list interfaces)" << endl;
        cerr << "3. Check that libpcap and libtins are properly installed" << endl;
        cerr << "4. Ensure the monitor server is running and accessible" << endl;
        
        running = false;
        reconnect.join();
        return 1;
    }
    
    return 0;
}