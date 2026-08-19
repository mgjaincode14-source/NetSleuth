# Phase 1: Networking Fundamentals & Setup

Welcome to **Phase 1** of NetSleuth AI! This document provides the fundamental networking concepts required to understand how real-time network sniffing, packet parsing, and threat detection work under the hood.

---

## 📚 1. Core Networking Concepts

### 1.1 What is a Packet?
A **network packet** is a formatted unit of data transmitted over a packet-switched network. A packet consists of two main parts:
- **Header**: Contains metadata required to route and deliver the packet (source/destination addresses, protocol, length, sequence numbers, checksums).
- **Payload**: The actual data being transported (e.g., HTML text, image bytes, DNS query string).

```
┌──────────────────────────────────────────────────────────┐
│                      Ethernet Frame                      │
├─────────────────┬────────────────────────────────────────┤
│ Ethernet Header │               IP Packet                │
│ (MAC Addresses) ├───────────┬────────────────────────────┤
│                 │ IP Header │       TCP/UDP Segment      │
│                 │ (IP Addr) ├────────────┬───────────────┤
│                 │           │ TCP Header │  Application  │
│                 │           │  (Ports)   │ Payload Data  │
└─────────────────┴───────────┴────────────┴───────────────┘
```

---

### 1.2 MAC Address vs. IP Address

| Feature | MAC Address (Media Access Control) | IP Address (Internet Protocol) |
|---|---|---|
| **Layer** | Data Link Layer (Layer 2) | Network Layer (Layer 3) |
| **Scope** | Local Network (LAN / same broadcast domain) | Global / Routed Network (LAN & Internet) |
| **Format** | 48-bit hex (e.g., `40:c2:ba:60:e5:9e`) | 32-bit IPv4 (`192.168.1.1`) or 128-bit IPv6 |
| **Purpose** | Direct hardware communication on local switch/Wi-Fi | Logical routing between networks |

---

### 1.3 TCP vs. UDP (Transport Layer 4)

#### **TCP (Transmission Control Protocol)**
- **Connection-Oriented**: Requires a 3-Way Handshake before sending data (`SYN` ➔ `SYN-ACK` ➔ `ACK`).
- **Reliable**: Guarantees delivery via packet acknowledgment and retransmissions.
- **Ordered**: Packets arrive in sequence.
- **Flags**:
  - `SYN` (Synchronize): Initiates connection.
  - `ACK` (Acknowledgment): Confirms receipt.
  - `FIN` (Finish): Gracefully closes connection.
  - `RST` (Reset): Abruptly aborts connection.
  - `PSH` (Push): Informs receiver to push data immediately to application.
  - `URG` (Urgent): Priority data.

#### **UDP (User Datagram Protocol)**
- **Connectionless**: No handshake; send and forget.
- **Unreliable / Fast**: No acknowledgments or retries.
- **Use Cases**: Video streaming, VoIP, Gaming, DNS queries.

---

### 1.4 Ports & Common Services

A **port number** (0 - 65535) identifies a specific process or application running on an IP address.

| Port | Protocol | Service | Description |
|---|---|---|---|
| **21** | TCP | FTP | File Transfer Protocol |
| **22** | TCP | SSH | Secure Shell Remote Login |
| **25** | TCP | SMTP | Simple Mail Transfer Protocol |
| **53** | UDP/TCP | DNS | Domain Name System |
| **80** | TCP | HTTP | HyperText Transfer Protocol (Unencrypted) |
| **443** | TCP | HTTPS | HTTP Secure (TLS/SSL Encrypted) |
| **3306**| TCP | MySQL | Database Service |
| **8080**| TCP | HTTP-Alt| Common Web Dev Server |

---

### 1.5 DNS (Domain Name System)
DNS translates human-readable hostnames (e.g. `example.com`) into IP addresses (`93.184.216.34`).
- **Record Types**:
  - `A`: Hostname to IPv4
  - `AAAA`: Hostname to IPv6
  - `CNAME`: Canonical Name (Alias)
  - `MX`: Mail Exchange server
  - `TXT`: Arbitrary text (SPF, DKIM, verification)

---

### 1.6 HTTP vs. HTTPS
- **HTTP (Port 80)**: Plaintext application protocol (`GET /index.html HTTP/1.1`). Payloads and credentials can be inspected directly in raw packets.
- **HTTPS (Port 443)**: Encrypted via TLS (Transport Layer Security). Packet headers (IP, Port, TCP flags) are visible to sniffers, but payloads are encrypted. NetSleuth AI can analyze TLS handshake metadata (Server Name Indication / SNI) and flow statistics.

---

## 🛠️ 2. Environment Verification

To verify that your Python virtual environment and networking dependencies are properly installed:

```bash
# Activate virtual environment
source ../venv/bin/activate

# Run environment verification test
python test_environment.py
```
