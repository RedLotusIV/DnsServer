# DNS Server

A simple non-blocking, epoll-based DNS server in C++. It listens for DNS A and AAAA queries, responds with configured IPs, and uses DNS compression pointers for efficiency. (as i was working on a school project called Webserv, i got slightly interested un the idea of a DNS server)
## Features
- non-blocking UDP server using epoll
- parses DNS queries (A and AAAA)
- loads domain→IP mappings from `rules/root.zone.txt`
- generates valid DNS responses with question and answer sections
- minimal lowercase comments

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
./dnsserver

```

## Configuration
Edit `rules/root.zone.txt` to add or modify fake DNS mappings:
```
domain.com 1.2.3.4
example.org 2001:db8::1
```

## Logging
Currently logs to stdout/stderr. Future support may include file-based logging under `logs/`.

## License
MIT License. See LICENSE file (or add your own).