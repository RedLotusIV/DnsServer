#pragma once

#include <iostream>
#include <string>
#include <map>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <sys/epoll.h>
#include <fcntl.h>
#include <vector>
#include "DnsParser.hpp"

class DnsServer
{
	private:
		std::string server_ip;
		int server_port;
		int socket_fd;
		int epoll_fd;
		bool is_running;
		sockaddr_in server_addr;
		std::vector<epoll_event> events;
		std::map<std::string, std::string> records;  // domain -> ip mapping
	public:
		// constructors and destructor
		DnsServer() = delete;
		DnsServer(const std::string& ip, int port);
		~DnsServer();
		DnsServer(const DnsServer&) = delete;
		DnsServer& operator=(const DnsServer&) = delete;

		// member functions
		void start();
		void stop();
		void run();
		void handle_dns_request(const char* buffer, size_t size, const sockaddr_in& client_addr);
		void send_response(const sockaddr_in& client_addr, const std::string& response);
		
		// dns response generation
		std::vector<uint8_t> build_dns_response(const char* request_buffer, size_t request_size, const DnsParser& parser);
		std::string get_ip_for_domain(const std::string& domain);
		void append_answer_record(std::vector<uint8_t>& response, const std::string& domain, uint32_t ip_address, uint32_t ttl = 60);
		
		// zone file loading
		bool load_zone_file(const std::string& filename);
		
		// getters
		std::string get_server_ip() const;
		int get_server_port() const;
		int get_socket_fd() const;
		bool is_server_running() const;
};