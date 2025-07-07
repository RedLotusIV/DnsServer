#include "../includes/DnsServer.hpp"
#include "../includes/DnsParser.hpp"
#include <iostream>
#include <signal.h>

// global server instance for signal handling
DnsServer* g_server = nullptr;

// setup signal handlers for graceful shutdown
void signal_handler(int signal) {
    if (g_server) {
        std::cout << "\nReceived signal " << signal << ", shutting down server..." << std::endl;
        g_server->stop();
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    // setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    try {
        // create dns server
        DnsServer dnsServer("127.0.0.1", 53);
        g_server = &dnsServer;
        
        // start server
        dnsServer.start();
        
        // run server event loop
        dnsServer.run();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
