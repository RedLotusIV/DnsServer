#include "../includes/DnsParser.hpp"
#include <iostream>
#include <iomanip>

bool DnsParser::parse(const char* buffer, size_t size) {
    reset();
    
    if (size < 12) {
        std::cerr << "dns packet too small (< 12 bytes)" << std::endl;
        return false;
    }
    
    // parse header
    if (!parse_header(buffer, size)) {
        std::cerr << "failed to parse dns header" << std::endl;
        return false;
    }
    
    // parse questions if any
    if (get_qdcount() > 0) {
        if (!parse_questions(buffer, size)) {
            std::cerr << "failed to parse dns questions" << std::endl;
            return false;
        }
    }
    
    is_parsed = true;
    return true;
}

void DnsParser::reset() {
    memset(&header, 0, sizeof(header));
    questions.clear();
    is_parsed = false;
    current_offset = 0;
}

bool DnsParser::parse_header(const char* buffer, size_t size) {
    if (size < sizeof(DnsHeader)) {
        return false;
    }
    
    // copy header
    memcpy(&header, buffer, sizeof(DnsHeader));
    current_offset = sizeof(DnsHeader);
    
    return true;
}

bool DnsParser::parse_questions(const char* buffer, size_t size) {
    uint16_t question_count = get_qdcount();
    
    for (uint16_t i = 0; i < question_count; i++) {
        if (current_offset >= size) {
            std::cerr << "buffer overflow while parsing questions" << std::endl;
            return false;
        }
        
        DnsQuestion question;
        
        // parse domain name
        question.qname = parse_domain_name(buffer, size, current_offset);
        if (question.qname.empty()) {
            std::cerr << "failed to parse domain name for question" << std::endl;
            return false;
        }
        
        // check bounds for qtype/qclass
        if (current_offset + 4 > size) {
            std::cerr << "buffer overflow while parsing question type/class" << std::endl;
            return false;
        }
        
        // parse qtype
        question.qtype = ntohs(*(uint16_t*)(buffer + current_offset));
        current_offset += 2;
        
        // parse qclass
        question.qclass = ntohs(*(uint16_t*)(buffer + current_offset));
        current_offset += 2;
        
        questions.push_back(question);
    }
    
    return true;
}

std::string DnsParser::parse_domain_name(const char* buffer, size_t buffer_size, size_t& offset) {
    std::string domain_name;
    size_t original_offset = offset;
    bool jumped = false;
    size_t max_jumps = 10; // prevent infinite loops
    size_t jump_count = 0;
    
    while (offset < buffer_size) {
        uint8_t length = (uint8_t)buffer[offset];
        
        // check compression pointer
        if ((length & 0xC0) == 0xC0) {
            if (offset + 1 >= buffer_size) {
                std::cerr << "buffer overflow while parsing compressed domain name" << std::endl;
                return "";
            }
            
            // handle compression pointer
            uint16_t pointer = ((length & 0x3F) << 8) | (uint8_t)buffer[offset + 1];
            
            if (pointer >= buffer_size) {
                std::cerr << "invalid compression pointer" << std::endl;
                return "";
            }
            
            if (!jumped) {
                original_offset = offset + 2; // remember continuation
                jumped = true;
            }
            
            offset = pointer;
            jump_count++;
            
            if (jump_count > max_jumps) {
                std::cerr << "too many compression jumps" << std::endl;
                return "";
            }
            
            continue;
        }
        
        // check end of name
        if (length == 0) {
            offset++;
            break;
        }
        
        // check label length
        if (length > 63) {
            std::cerr << "invalid label length" << std::endl;
            return "";
        }
        
        // check buffer bounds
        if (offset + 1 + length > buffer_size) {
            std::cerr << "buffer overflow while parsing domain label" << std::endl;
            return "";
        }
        
        // add dot separator
        if (!domain_name.empty()) {
            domain_name += ".";
        }
        
        // copy label
        domain_name.append(buffer + offset + 1, length);
        offset += 1 + length;
    }
    
    // restore offset after jump
    if (jumped) {
        offset = original_offset;
    }
    
    return domain_name;
}

void DnsParser::print_debug() const {
    if (!is_parsed) {
        std::cout << "dns packet not parsed" << std::endl;
        return;
    }
    
    std::cout << "=== DNS Packet Debug ===" << std::endl;
    std::cout << "Header:" << std::endl;
    std::cout << "  ID: 0x" << std::hex << get_id() << std::dec << " (" << get_id() << ")" << std::endl;
    std::cout << "  Flags: 0x" << std::hex << get_flags() << std::dec << std::endl;
    std::cout << "    QR: " << (is_response() ? "Response" : "Query") << std::endl;
    std::cout << "    Opcode: " << (int)get_opcode() << std::endl;
    std::cout << "    AA: " << (is_authoritative() ? "Yes" : "No") << std::endl;
    std::cout << "    TC: " << (is_truncated() ? "Yes" : "No") << std::endl;
    std::cout << "    RD: " << (is_recursion_desired() ? "Yes" : "No") << std::endl;
    std::cout << "    RA: " << (is_recursion_available() ? "Yes" : "No") << std::endl;
    std::cout << "    RCODE: " << (int)get_rcode() << std::endl;
    std::cout << "  Questions: " << get_qdcount() << std::endl;
    std::cout << "  Answers: " << get_ancount() << std::endl;
    std::cout << "  Authority: " << get_nscount() << std::endl;
    std::cout << "  Additional: " << get_arcount() << std::endl;
    
    if (has_questions()) {
        std::cout << "Questions:" << std::endl;
        for (size_t i = 0; i < questions.size(); i++) {
            const auto& q = questions[i];
            std::cout << "  " << (i + 1) << ". " << q.qname << std::endl;
            std::cout << "     Type: " << q.qtype << " (";
            switch (q.qtype) {
                case 1: std::cout << "A"; break;
                case 2: std::cout << "NS"; break;
                case 5: std::cout << "CNAME"; break;
                case 6: std::cout << "SOA"; break;
                case 12: std::cout << "PTR"; break;
                case 15: std::cout << "MX"; break;
                case 16: std::cout << "TXT"; break;
                case 28: std::cout << "AAAA"; break;
                default: std::cout << "Unknown"; break;
            }
            std::cout << ")" << std::endl;
            std::cout << "     Class: " << q.qclass << " (";
            switch (q.qclass) {
                case 1: std::cout << "IN"; break;
                case 3: std::cout << "CH"; break;
                case 4: std::cout << "HS"; break;
                default: std::cout << "Unknown"; break;
            }
            std::cout << ")" << std::endl;
        }
    }
    
    std::cout << "=========================" << std::endl;
}
