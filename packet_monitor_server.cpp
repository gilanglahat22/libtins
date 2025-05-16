#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include <atomic>
#include <csignal>
#include <ctime>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <chrono>

using namespace std;

// Monitor configuration
struct MonitorConfig {
    int listen_port = 5500;
    string output_file;
    bool color_output = true;
    bool show_stats = true;
    int stats_interval = 10;
    int max_connections = 10;
};

// Connected agent information
struct AgentInfo {
    int socket;
    string hostname;
    string interface;
    string address;
    time_t connected_time;
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
};

// Packet data structure
struct PacketData {
    string timestamp;
    string src_ip;
    int src_port;
    string dst_ip;
    int dst_port;
    string protocol;
    size_t size;
    string agent_hostname;
};

// Statistics
struct Stats {
    map<string, uint64_t> protocol_count;
    map<string, uint64_t> ip_packet_count;
    map<string, uint64_t> ip_byte_count;
    map<int, uint64_t> port_count;
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    
    mutex stats_mutex;
};

// Globals
atomic<bool> running(true);
vector<AgentInfo> agents;
mutex agents_mutex;
Stats stats;
ofstream output_file;

// ANSI color codes
namespace Color {
    const string RESET   = "\033[0m";
    const string RED     = "\033[31m";
    const string GREEN   = "\033[32m";
    const string YELLOW  = "\033[33m";
    const string BLUE    = "\033[34m";
    const string MAGENTA = "\033[35m";
    const string CYAN    = "\033[36m";
    const string WHITE   = "\033[37m";
    const string BOLD    = "\033[1m";
}

// Signal handler
void signal_handler(int signal) {
    cout << "\nReceived signal " << signal << ". Stopping monitor..." << endl;
    running = false;
}

// Get timestamp
string get_timestamp() {
    auto now = chrono::system_clock::now();
    time_t now_c = chrono::system_clock::to_time_t(now);
    tm *now_tm = localtime(&now_c);
    
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", now_tm);
    return string(buffer);
}

// Pretty format for bytes
string format_size(size_t bytes) {
    const char* suffixes[] = {"B", "KB", "MB", "GB"};
    int suffix_index = 0;
    double size = bytes;
    
    while (size >= 1024 && suffix_index < 3) {
        size /= 1024;
        suffix_index++;
    }
    
    ostringstream oss;
    oss << fixed << setprecision(suffix_index > 0 ? 1 : 0) << size << " " << suffixes[suffix_index];
    return oss.str();
}

// Parse a line of packet data from agent
bool parse_packet_data(const string& line, PacketData& packet, string agent_hostname) {
    vector<string> parts;
    stringstream ss(line);
    string part;
    
    while (getline(ss, part, '|')) {
        parts.push_back(part);
    }
    
    if (parts.size() < 8 || parts[0] != "PACKET") {
        return false;
    }
    
    packet.timestamp = parts[1];
    packet.src_ip = parts[2];
    packet.src_port = atoi(parts[3].c_str());
    packet.dst_ip = parts[4];
    packet.dst_port = atoi(parts[5].c_str());
    packet.protocol = parts[6];
    packet.size = stoul(parts[7]);
    packet.agent_hostname = agent_hostname;
    
    return true;
}

// Process data from an agent
void process_agent_data(int agent_index, const string& data) {
    AgentInfo& agent = agents[agent_index];
    
    // Check if it's agent info
    if (data.substr(0, 10) == "AGENT_INFO") {
        vector<string> parts;
        stringstream ss(data);
        string part;
        
        while (getline(ss, part, '|')) {
            parts.push_back(part);
        }
        
        if (parts.size() >= 3) {
            agent.hostname = parts[1];
            agent.interface = parts[2];
            
            cout << "Agent connected: " << agent.hostname 
                 << " (" << agent.address << ") monitoring interface " 
                 << agent.interface << endl;
        }
        return;
    }
    
    // Process packet data
    PacketData packet;
    if (parse_packet_data(data, packet, agent.hostname)) {
        // Update agent statistics
        agent.packet_count++;
        agent.byte_count += packet.size;
        
        // Update global statistics
        {
            lock_guard<mutex> lock(stats.stats_mutex);
            stats.total_packets++;
            stats.total_bytes += packet.size;
            stats.protocol_count[packet.protocol]++;
            stats.ip_packet_count[packet.src_ip]++;
            stats.ip_byte_count[packet.src_ip] += packet.size;
            
            if (packet.src_port > 0) stats.port_count[packet.src_port]++;
            if (packet.dst_port > 0) stats.port_count[packet.dst_port]++;
        }
        
        // Format the output
        ostringstream output;
        output << left << setw(22) << packet.timestamp;
        output << setw(18) << packet.src_ip;
        if (packet.src_port > 0) {
            output << ":" << setw(5) << left << packet.src_port;
        } else {
            output << "     ";
        }
        
        output << " → " << setw(18) << packet.dst_ip;
        if (packet.dst_port > 0) {
            output << ":" << setw(5) << left << packet.dst_port;
        } else {
            output << "     ";
        }
        
        output << " | " << setw(10) << left << packet.protocol;
        output << " | " << setw(10) << right << format_size(packet.size);
        output << " | " << packet.agent_hostname;
        
        string output_str = output.str();
        
        // Print to console with colors
        if (MonitorConfig().color_output) {
            string color;
            if (packet.protocol == "HTTP" || packet.protocol == "HTTPS") {
                color = Color::GREEN;
            } else if (packet.protocol == "DNS") {
                color = Color::CYAN;
            } else if (packet.protocol == "ICMP" || packet.protocol == "ICMPv6") {
                color = Color::YELLOW;
            } else if (packet.protocol == "ARP") {
                color = Color::MAGENTA;
            } else if (packet.protocol.find("TCP") != string::npos) {
                color = Color::BLUE;
            } else if (packet.protocol.find("UDP") != string::npos) {
                color = Color::RED;
            } else {
                color = Color::WHITE;
            }
            
            cout << color << output_str << Color::RESET << endl;
        } else {
            cout << output_str << endl;
        }
        
        // Save to file if enabled
        if (output_file.is_open()) {
            output_file << output_str << endl;
        }
    }
}

// Print statistics
void print_statistics() {
    // Take a snapshot of stats to avoid race conditions
    map<string, uint64_t> protocol_count;
    map<string, uint64_t> ip_packet_count;
    map<string, uint64_t> ip_byte_count;
    map<int, uint64_t> port_count;
    uint64_t total_packets;
    uint64_t total_bytes;
    
    {
        lock_guard<mutex> lock(stats.stats_mutex);
        protocol_count = stats.protocol_count;
        ip_packet_count = stats.ip_packet_count;
        ip_byte_count = stats.ip_byte_count;
        port_count = stats.port_count;
        total_packets = stats.total_packets;
        total_bytes = stats.total_bytes;
    }
    
    cout << "\n===== Network Monitor Statistics =====" << endl;
    cout << "Total Packets: " << total_packets << endl;
    cout << "Total Data: " << format_size(total_bytes) << endl;
    
    // Connected agents
    {
        lock_guard<mutex> lock(agents_mutex);
        cout << "\nConnected Agents (" << agents.size() << "):" << endl;
        for (const auto& agent : agents) {
            cout << "  " << agent.hostname << " (" << agent.address << ") - " 
                 << agent.packet_count << " packets, " 
                 << format_size(agent.byte_count) << endl;
        }
    }
    
    // Protocol statistics
    cout << "\nTop Protocols:" << endl;
    vector<pair<string, uint64_t>> protocol_vec(protocol_count.begin(), protocol_count.end());
    sort(protocol_vec.begin(), protocol_vec.end(), 
         [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (size_t i = 0; i < min(size_t(5), protocol_vec.size()); ++i) {
        cout << "  " << setw(10) << left << protocol_vec[i].first << ": " 
             << protocol_vec[i].second << " packets";
        if (total_packets > 0) {
            cout << " (" << fixed << setprecision(1) 
                 << (protocol_vec[i].second * 100.0 / total_packets) << "%)";
        }
        cout << endl;
    }
    
    // IP address statistics
    cout << "\nTop Source IPs:" << endl;
    vector<pair<string, uint64_t>> ip_vec(ip_packet_count.begin(), ip_packet_count.end());
    sort(ip_vec.begin(), ip_vec.end(), 
         [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (size_t i = 0; i < min(size_t(5), ip_vec.size()); ++i) {
        cout << "  " << setw(18) << left << ip_vec[i].first << ": " 
             << ip_vec[i].second << " packets, "
             << format_size(ip_byte_count[ip_vec[i].first]) << endl;
    }
    
    // Port statistics
    cout << "\nTop Ports:" << endl;
    vector<pair<int, uint64_t>> port_vec(port_count.begin(), port_count.end());
    sort(port_vec.begin(), port_vec.end(), 
         [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (size_t i = 0; i < min(size_t(5), port_vec.size()); ++i) {
        string port_service = to_string(port_vec[i].first);
        // Add known service names for common ports
        if (port_vec[i].first == 80) port_service += " (HTTP)";
        else if (port_vec[i].first == 443) port_service += " (HTTPS)";
        else if (port_vec[i].first == 53) port_service += " (DNS)";
        else if (port_vec[i].first == 22) port_service += " (SSH)";
        
        cout << "  Port " << setw(15) << left << port_service << ": " 
             << port_vec[i].second << " uses" << endl;
    }
    
    cout << endl;
}

// Handle agent connections and data
void handle_agents(int server_socket, const MonitorConfig& config) {
    fd_set read_fds, master_fds;
    FD_ZERO(&master_fds);
    FD_SET(server_socket, &master_fds);
    
    int max_fd = server_socket;
    
    // For reading data from clients
    char buffer[4096];
    vector<string> incomplete_data(config.max_connections + 1);
    
    while (running) {
        // Copy the master set to read_fds
        read_fds = master_fds;
        
        // Set up timeout
        struct timeval timeout;
        timeout.tv_sec = 1;  // 1 second timeout for clean exit
        timeout.tv_usec = 0;
        
        // Wait for activity on any socket
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            cerr << "Select error: " << strerror(errno) << endl;
            break;
        }
        
        // Check for new connections
        if (FD_ISSET(server_socket, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            
            int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);
            if (client_socket >= 0) {
                // Add to agents list
                AgentInfo agent;
                agent.socket = client_socket;
                agent.address = inet_ntoa(client_addr.sin_addr);
                agent.connected_time = time(NULL);
                
                {
                    lock_guard<mutex> lock(agents_mutex);
                    agents.push_back(agent);
                }
                
                // Add to master set
                FD_SET(client_socket, &master_fds);
                if (client_socket > max_fd) {
                    max_fd = client_socket;
                }
                
                cout << "New connection from " << agent.address << endl;
            }
        }
        
        // Check data from agents
        {
            lock_guard<mutex> lock(agents_mutex);
            
            for (size_t i = 0; i < agents.size(); ++i) {
                int client_socket = agents[i].socket;
                
                if (FD_ISSET(client_socket, &read_fds)) {
                    // Receive data
                    memset(buffer, 0, sizeof(buffer));
                    int bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
                    
                    if (bytes_read <= 0) {
                        // Connection closed or error
                        cout << "Agent disconnected: " << agents[i].hostname 
                             << " (" << agents[i].address << ")" << endl;
                        
                        close(client_socket);
                        FD_CLR(client_socket, &master_fds);
                        
                        // Remove from agents list
                        agents.erase(agents.begin() + i);
                        i--; // Adjust index
                    } else {
                        // Process received data
                        buffer[bytes_read] = '\0';
                        string data = incomplete_data[i] + buffer;
                        
                        // Process complete lines
                        size_t pos = 0;
                        while ((pos = data.find('\n')) != string::npos) {
                            string line = data.substr(0, pos);
                            data = data.substr(pos + 1);
                            
                            // Process the complete line
                            process_agent_data(i, line);
                        }
                        
                        // Save any incomplete data
                        incomplete_data[i] = data;
                    }
                }
            }
        }
    }
}

// Parse command line arguments
void parse_arguments(int argc, char* argv[], MonitorConfig& config) {
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            cout << "Packet Monitor Server - Receive and display network packets from agents" << endl;
            cout << "Usage: " << argv[0] << " [options]" << endl;
            cout << "Options:" << endl;
            cout << "  -p, --port PORT       Listen on port (default: 5500)" << endl;
            cout << "  -o, --output FILE     Save packet data to file" << endl;
            cout << "  -n, --no-color        Disable colored output" << endl;
            cout << "  -s, --no-stats        Disable statistics" << endl;
            cout << "  -i, --interval SEC    Statistics display interval (default: 10)" << endl;
            exit(0);
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            config.listen_port = atoi(argv[++i]);
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            config.output_file = argv[++i];
        } else if (arg == "-n" || arg == "--no-color") {
            config.color_output = false;
        } else if (arg == "-s" || arg == "--no-stats") {
            config.show_stats = false;
        } else if ((arg == "-i" || arg == "--interval") && i + 1 < argc) {
            config.stats_interval = atoi(argv[++i]);
        }
    }
}

int main(int argc, char* argv[]) {
    // Register signal handler
    signal(SIGINT, signal_handler);
    
    // Default configuration
    MonitorConfig config;
    parse_arguments(argc, argv, config);
    
    // Open output file if specified
    if (!config.output_file.empty()) {
        output_file.open(config.output_file);
        if (!output_file.is_open()) {
            cerr << "Error: Could not open output file '" << config.output_file << "'" << endl;
            return 1;
        }
    }
    
    // Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        cerr << "Error creating server socket" << endl;
        return 1;
    }
    
    // Set socket options for reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Error setting socket options" << endl;
        close(server_socket);
        return 1;
    }
    
    // Bind socket to port
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config.listen_port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Error binding server socket to port " << config.listen_port << endl;
        close(server_socket);
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, config.max_connections) < 0) {
        cerr << "Error listening on server socket" << endl;
        close(server_socket);
        return 1;
    }
    
    cout << "Packet Monitor Server started" << endl;
    cout << "Listening for agent connections on port " << config.listen_port << endl;
    
    if (!config.output_file.empty()) {
        cout << "Saving packet data to '" << config.output_file << "'" << endl;
    }
    
    cout << "Press Ctrl+C to stop" << endl << endl;
    
    // Print column headers
    cout << left << setw(22) << "TIMESTAMP";
    cout << setw(24) << "SOURCE";
    cout << setw(24) << "DESTINATION";
    cout << setw(11) << "PROTOCOL";
    cout << setw(11) << "SIZE";
    cout << "AGENT" << endl;
    
    cout << string(100, '-') << endl;
    
    // Create statistics thread
    thread stats_thread;
    if (config.show_stats) {
        stats_thread = thread([&config]() {
            while (running) {
                for (int i = 0; i < config.stats_interval && running; ++i) {
                    this_thread::sleep_for(chrono::seconds(1));
                }
                
                if (running && stats.total_packets > 0) {
                    print_statistics();
                }
            }
        });
    }
    
    // Handle agent connections
    handle_agents(server_socket, config);
    
    // Wait for statistics thread
    if (config.show_stats && stats_thread.joinable()) {
        stats_thread.join();
    }
    
    // Clean up
    close(server_socket);
    
    if (output_file.is_open()) {
        output_file.close();
    }
    
    // Close any open agent connections
    {
        lock_guard<mutex> lock(agents_mutex);
        for (const auto& agent : agents) {
            close(agent.socket);
        }
    }
    
    cout << "\nPacket Monitor Server stopped" << endl;
    
    return 0;
}