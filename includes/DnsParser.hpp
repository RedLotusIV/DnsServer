#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>

struct DnsHeader {
    uint16_t id;        // transaction id
    uint16_t flags;     // flags (qr, opcode, aa, tc, rd, ra, z, rcode)
    uint16_t qdcount;   // number of questions
    uint16_t ancount;   // number of answers
    uint16_t nscount;   // number of authority records
    uint16_t arcount;   // number of additional records
};

struct DnsQuestion {
    std::string qname;  // domain name
    uint16_t qtype;     // query type
    uint16_t qclass;    // query class
};

class DnsParser {
	private:
		DnsHeader header;
		std::vector<DnsQuestion> questions;
		bool is_parsed;
		size_t current_offset;
		
		// Helper methods for parsing
		std::string parse_domain_name(const char* buffer, size_t buffer_size, size_t& offset);
		bool parse_header(const char* buffer, size_t size);
		bool parse_questions(const char* buffer, size_t size);
		
	public:
		DnsParser() : is_parsed(false), current_offset(0) {}
		~DnsParser() = default;
		DnsParser(const DnsParser&) = delete;
		DnsParser& operator=(const DnsParser&) = delete;
		
		// main parse method
		bool parse(const char* buffer, size_t size);
		
		// reset for new packet
		void reset();
		
		// header getters
		uint16_t get_id() const { return ntohs(header.id); }
		uint16_t get_raw_id() const { return header.id; }
		uint16_t get_flags() const { return ntohs(header.flags); }
		uint16_t get_qdcount() const { return ntohs(header.qdcount); }
		uint16_t get_ancount() const { return ntohs(header.ancount); }
		uint16_t get_nscount() const { return ntohs(header.nscount); }
		uint16_t get_arcount() const { return ntohs(header.arcount); }
		
		// flag bit getters
		bool is_query() const { return (ntohs(header.flags) & 0x8000) == 0; }
		bool is_response() const { return (ntohs(header.flags) & 0x8000) != 0; }
		uint8_t get_opcode() const { return (ntohs(header.flags) >> 11) & 0x0F; }
		bool is_authoritative() const { return (ntohs(header.flags) & 0x0400) != 0; }
		bool is_truncated() const { return (ntohs(header.flags) & 0x0200) != 0; }
		bool is_recursion_desired() const { return (ntohs(header.flags) & 0x0100) != 0; }
		bool is_recursion_available() const { return (ntohs(header.flags) & 0x0080) != 0; }
		uint8_t get_rcode() const { return ntohs(header.flags) & 0x0F; }
		
		// question getters
		const std::vector<DnsQuestion>& get_questions() const { return questions; }
		bool has_questions() const { return !questions.empty(); }
		
		// status
		bool is_valid() const { return is_parsed; }
		
		// debug output
		void print_debug() const;
};