# DNS Server

A simple non-blocking, epoll-based DNS server in C++23. It listens for DNS A and AAAA queries, responds with configured IPs, and uses DNS compression pointers for efficiency. (as i was working on a school project called Webserv, i got slightly interested un the idea of a DNS server)
## Features
- non-blocking UDP server using epoll
- parses DNS queries (A and AAAA)
- loads domain→IP mappings from `rules/root.zone.txt`
- generates valid DNS responses with question and answer sections
- minimal lowercase comments and clean C++23 code

## Prerequisites
- Linux with epoll support
- g++ (C++23) or compatible compiler
- make

## Project Structure
```
Makefile
includes/      ← public headers
src/           ← source files
rules/root.zone.txt ← zone file with domain→IP entries
logs/          ← (optional) logs output directory
tests/         ← unit tests (if any)
```

## Build
```bash
# build optimized binary
make

## Run
```bash
# default binds to port 53 (requires sudo/root)
sudo ./dnsserver

# or use non-root port
./dnsserver 127.0.0.1 1053
```