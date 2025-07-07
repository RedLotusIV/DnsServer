#include "../includes/DnsServer.hpp"
#include "../includes/DnsParser.hpp"
#include <stdexcept>
#include <iostream>
#include <sys/socket.h>
#include <cerrno>
#include <cstring>
#include <map>
#include <fstream>

DnsServer::DnsServer(const std::string& ip, int port)
    : server_ip(ip), server_port(port), socket_fd(-1), epoll_fd(-1), is_running(false), events(10) {
    // init address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
        throw std::runtime_error("invalid ip " + ip);
    }
    // load zone data
    if (!load_zone_file("rules/root.zone.txt")) {
        std::cerr << "warning no data" << std::endl;
    }
}

DnsServer::~DnsServer() {
    stop();
}

void DnsServer::start() {
    // create udp socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
    }
    
    // set socket to non-blocking
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags < 0) {
        close(socket_fd);
        throw std::runtime_error("Failed to get socket flags: " + std::string(strerror(errno)));
    }
    
    if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(socket_fd);
        throw std::runtime_error("Failed to set socket to non-blocking: " + std::string(strerror(errno)));
    }
    
    // allow socket reuse
    int reuse = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        close(socket_fd);
        throw std::runtime_error("Failed to set socket reuse: " + std::string(strerror(errno)));
    }
    
    // bind socket
    if (bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(socket_fd);
        throw std::runtime_error("Failed to bind socket: " + std::string(strerror(errno)));
    }
    
    // create epoll instance
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        close(socket_fd);
        throw std::runtime_error("Failed to create epoll instance: " + std::string(strerror(errno)));
    }
    
    // add socket to epoll
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET; // edge-triggered mode
    event.data.fd = socket_fd;
    
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &event) < 0) {
        close(socket_fd);
        close(epoll_fd);
        throw std::runtime_error("Failed to add socket to epoll: " + std::string(strerror(errno)));
    }
    
    is_running = true;
    std::cout << "DNS Server started on " << server_ip << ":" << server_port << " (epoll mode)" << std::endl;
}

void DnsServer::stop() {
    if (is_running) {
        is_running = false;
        
        if (epoll_fd >= 0) {
            close(epoll_fd);
            epoll_fd = -1;
        }
        
        if (socket_fd >= 0) {
            close(socket_fd);
            socket_fd = -1;
        }
        
        std::cout << "DNS Server stopped" << std::endl;
    }
}

void DnsServer::run() {
    if (!is_running) {
        throw std::runtime_error("Server is not running. Call start() first.");
    }
    
    std::cout << "DNS Server running with epoll, waiting for requests..." << std::endl;
    
    while (is_running) {
        int num_events = epoll_wait(epoll_fd, events.data(), events.size(), -1);

        // continue loop
        if (num_events < 0) {
            if (errno == EINTR) {
                continue; // Interrupted by signal, continue
                // interrupted by signal
            }
            std::cerr << "epoll_wait error: " << strerror(errno) << std::endl;
            break;
        }
        
        for (int i = 0; i < num_events; ++i) {
            if (events[i].data.fd == socket_fd) {
                // handle dns requests
                while (true) {
                    char buffer[512];
                    sockaddr_in client_addr;
                    socklen_t addr_len = sizeof(client_addr);
                    
                    ssize_t bytes_received = recvfrom(socket_fd, buffer, sizeof(buffer), 0,
                                                    (sockaddr*)&client_addr, &addr_len);
                    
                    if (bytes_received < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            // no more data

                            break;
                        }
                        std::cerr << "Error receiving data: " << strerror(errno) << std::endl;
                        break;
                    }

                    if (bytes_received == 0) {
                        // connection closed
                        break;
                    }
                    
                    handle_dns_request(buffer, bytes_received, client_addr);
                }
            }
        }
    }
}

void DnsServer::handle_dns_request(const char* buffer, size_t size, const sockaddr_in& client_addr) {
    std::cout << "\n=== Received DNS Request ===" << std::endl;
    std::cout << "From: " << inet_ntoa(client_addr.sin_addr)
              << ":" << ntohs(client_addr.sin_port) << std::endl;
    std::cout << "Size: " << size << " bytes" << std::endl;
    
    // Print first few bytes of request for debugging
    // print first few bytes of request
    std::cout << "Raw data (hex): ";
    for (size_t i = 0; i < std::min(size, static_cast<size_t>(32)); i++) {
        printf("%02x ", (unsigned char)buffer[i]);
        if ((i + 1) % 16 == 0) std::cout << std::endl << "                ";
    }
    std::cout << std::endl;
    
    // Parse DNS request
    // parse dns request
    DnsParser parser;
    if (parser.parse(buffer, size)) {
        std::cout << "DNS packet parsed successfully!" << std::endl;
        parser.print_debug();
        
        // process each question
        if (parser.has_questions()) {
            const auto& questions = parser.get_questions();
            for (const auto& question : questions) {
                std::cout << "\nProcessing query for: " << question.qname << std::endl;
                std::cout << "Query type: " << question.qtype << ", Class: " << question.qclass << std::endl;
                
                // handle a/aaaa records
                if ((question.qtype == 1 || question.qtype == 28) && question.qclass == 1) {
                    // generate dns response
                    std::vector<uint8_t> response = build_dns_response(buffer, size, parser);

                    if (!response.empty()) {
                        std::string response_str(response.begin(), response.end());
                        send_response(client_addr, response_str);
                    }
                } else {
                    std::cout << "Unsupported query type/class - ignoring" << std::endl;
                }
            }
        }
    } else {
        std::cout << "Failed to parse DNS packet" << std::endl;
    }
    
    std::cout << "=============================" << std::endl;
}

void DnsServer::send_response(const sockaddr_in& client_addr, const std::string& response) {
    ssize_t bytes_sent = sendto(socket_fd, response.c_str(), response.length(), 0,
                               (sockaddr*)&client_addr, sizeof(client_addr));
    
    if (bytes_sent < 0) {
        std::cerr << "Error sending response: " << strerror(errno) << std::endl;
    } else {
        std::cout << "Sent response (" << bytes_sent << " bytes) to "
                  << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;
    }
}

std::vector<uint8_t> DnsServer::build_dns_response(const char* request_buffer, size_t request_size, const DnsParser& parser) {
    std::vector<uint8_t> response;
    
    if (!parser.has_questions()) {
        std::cerr << "No questions found in DNS request" << std::endl;
        return response;
    }
    
    const auto& questions = parser.get_questions();
    const auto& first_question = questions[0]; // handle first question only
    
    // get ip for domain
    std::string ip = get_ip_for_domain(first_question.qname);
    if (ip.empty()) {
        std::cout << "No record configured for domain: " << first_question.qname << std::endl;
        return response;
    }

    // convert ip string to network byte order
    struct in_addr addr;
    if (inet_aton(ip.c_str(), &addr) == 0) {
        std::cerr << "Invalid IP address: " << ip << std::endl;
        return response;
    }
    
    std::cout << "Generating DNS response for " << first_question.qname << " -> " << ip << std::endl;
    
    // 1. Build Response Header (12 bytes)
    DnsHeader response_header;
    response_header.id = parser.get_raw_id();  // Use raw network byte order ID
    
    // Set response flags: QR=1, AA=1, RD=copy from request, RA=0, RCODE=0
    uint16_t flags = 0x8180;  // 1000 0001 1000 0000 (QR=1, AA=1, RD=1, RA=0, RCODE=0)
    if (!parser.is_recursion_desired()) {
        flags &= ~0x0100;  // Clear RD bit if not set in request
    }
    response_header.flags = htons(flags);
    
    response_header.qdcount = htons(1);    // 1 question (copied from request)
    response_header.ancount = htons(1);    // 1 answer
    response_header.nscount = htons(0);    // 0 authority records
    response_header.arcount = htons(0);    // 0 additional records
    
    // Add header to response
    response.resize(sizeof(DnsHeader));
    memcpy(response.data(), &response_header, sizeof(DnsHeader));
    
    // 2. Copy Question Section from request
    // Find where question section starts (after header) and ends
    size_t question_start = sizeof(DnsHeader);
    size_t question_end = question_start;
    
    // Parse domain name to find end of question section
    while (question_end < request_size) {
        uint8_t length = (uint8_t)request_buffer[question_end];
        if (length == 0) {
            question_end += 1; // Skip null terminator
            question_end += 4; // Skip QTYPE (2 bytes) + QCLASS (2 bytes)
            break;
        }
        if ((length & 0xC0) == 0xC0) {
            question_end += 2; // Skip compression pointer
            question_end += 4; // Skip QTYPE + QCLASS
            break;
        }
        question_end += 1 + length; // Skip length byte + label
    }
    
    // Copy question section
    size_t question_size = question_end - question_start;
    size_t current_pos = response.size();
    response.resize(current_pos + question_size);
    memcpy(response.data() + current_pos, request_buffer + question_start, question_size);
    
    // 3. Build Answer Section
    // Answer RR format:
    // NAME (2 bytes) - pointer to domain name in question
    // TYPE (2 bytes) - record type
    // CLASS (2 bytes) - record class
    // TTL (4 bytes)
    // RDLENGTH (2 bytes)
    // RDATA (4 or 16 bytes)
    
    current_pos = response.size();
    {
        // Prepare record header
        uint16_t type_val = first_question.qtype;  // 1=A, 28=AAAA
        uint16_t class_val = first_question.qclass; // 1=IN
        uint32_t ttl = 60;
        
        // Determine RDLENGTH
        uint16_t rdlength = (type_val == 28 ? 16 : 4);
        
        // Reserve space
        size_t rr_size = 2+2+2+4+2 + rdlength;
        response.resize(current_pos + rr_size);
        uint8_t* answer_ptr = response.data() + current_pos;
        
        // NAME pointer: use explicit big-endian bytes for 0xC00C
        answer_ptr[0] = 0xC0;
        answer_ptr[1] = 0x0C;
        answer_ptr += 2;
        
        // TYPE
        uint16_t ntype = htons(type_val);
        memcpy(answer_ptr, &ntype, 2);
        answer_ptr += 2;
        
        // CLASS
        uint16_t nclass = htons(class_val);
        memcpy(answer_ptr, &nclass, 2);
        answer_ptr += 2;
        
        // TTL
        uint32_t nttl = htonl(ttl);
        memcpy(answer_ptr, &nttl, 4);
        answer_ptr += 4;
        
        // RDLENGTH
        uint16_t nrdlen = htons(rdlength);
        memcpy(answer_ptr, &nrdlen, 2);
        answer_ptr += 2;
        
        // RDATA
        if (type_val == 28) {
            // IPv6
            struct in6_addr addr6;
            if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
                memcpy(answer_ptr, &addr6, 16);
            } else {
                memset(answer_ptr, 0, 16);
            }
        } else {
            // IPv4: use converted addr.s_addr (network byte order)
            memcpy(answer_ptr, &addr.s_addr, 4);
        }
    }
    
    std::cout << "Built DNS response (" << response.size() << " bytes) for " 
              << first_question.qname << " -> " << ip << std::endl;
    
    return response;
}

std::string DnsServer::get_ip_for_domain(const std::string& domain) {
    // Lookup in member map
    auto it = records.find(domain);
    if (it != records.end()) {
        return it->second;
    }
    // Check subdomain
    for (const auto& pair : records) {
        if (domain.size() > pair.first.size() + 1 &&
            domain.compare(domain.size() - pair.first.size(), pair.first.size(), pair.first) == 0) {
            return pair.second;
        }
    }
    return "";
}

void DnsServer::append_answer_record(std::vector<uint8_t>& response, const std::string& domain, uint32_t ip_address, uint32_t ttl) {
    // This method can be used for more complex response building
    // For now, it's implemented in build_dns_response
    (void)response; (void)domain; (void)ip_address; (void)ttl; // Suppress unused warnings
} 

// Getters
std::string DnsServer::get_server_ip() const {
    return server_ip;
}

int DnsServer::get_server_port() const {
    return server_port;
}

int DnsServer::get_socket_fd() const {
    return socket_fd;
}

bool DnsServer::is_server_running() const {
    return is_running;
}

bool DnsServer::load_zone_file(const std::string& filename) {
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Failed to open zone file: " << filename << std::endl;
        return false;
    }
    std::string domain, ip;
    while (infile >> domain >> ip) {
        records[domain] = ip;
    }
    std::cout << "Loaded " << records.size() << " records from " << filename << std::endl;
    return true;
}