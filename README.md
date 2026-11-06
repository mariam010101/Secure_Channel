# Secure Inline Communication Channel

A Linux-based prototype of a secure communication channel that protects TCP payloads using authenticated encryption and Diffie–Hellman key exchange.

## Overview

This project implements a secure communication mechanism between two endpoints connected through two intermediate Linux devices.

The objective is to protect TCP application data against unauthorized reading and modification while preserving the original IPv4 and TCP headers.

The proposed network architecture is:

```text
PC1  →  Device1  →  Device2  →  PC2
          |           |
       Encrypt     Decrypt
```

Device1 encrypts the TCP payload before forwarding it, while Device2 decrypts the payload before delivering it to the destination endpoint.

The implementation focuses on low-level network packet processing, cryptographic operations, and secure communication principles.

## Project Objectives

- Establish a shared cryptographic secret using Diffie–Hellman key exchange.
- Encrypt TCP payloads using AES-256-GCM.
- Authenticate encrypted data to detect unauthorized modifications.
- Preserve the original IPv4 and TCP headers.
- Append the authentication tag to the encrypted payload.
- Use unique nonces for encryption operations.
- Support bidirectional TCP communication.
- Process selected TCP traffic transparently within an inline network topology.

## Technologies Used

| Technology | Purpose |
|---|---|
| C | Low-level implementation |
| Linux | Networking environment |
| OpenSSL | Cryptographic operations |
| X25519 | Diffie–Hellman key exchange |
| HKDF-SHA-256 | Session key derivation |
| AES-256-GCM | Authenticated encryption |
| IPv4 / TCP | Network packet processing |
| NFQUEUE | Linux packet interception |
| Network namespaces | Network topology simulation |
| GCC | Compilation and testing |
| Git / GitHub | Version control |

## Architecture

### 1. Key Exchange

The project uses X25519, an elliptic-curve Diffie–Hellman key exchange mechanism, to establish a shared secret between the two intermediate devices.

The shared secret is processed through HKDF-SHA-256 to derive an AES-256 session key.

Both devices independently derive the same session key without transmitting the resulting key directly.

### 2. Encryption and Authentication

AES-256-GCM is used to encrypt and authenticate TCP payload data.

The encryption process:
1. Receives an IPv4/TCP packet.
2. Parses the IPv4 and TCP headers.
3. Extracts the TCP payload.
4. Encrypts the payload using AES-256-GCM.
5. Generates an authentication tag of 16 bytes.
6. Preserves the original network and transport headers.

### 3. Packet Processing

The packet parser validates:
- IPv4 version and header length.
- IPv4 total packet length.
- TCP protocol identification.
- TCP header length.
- Packet boundaries.
- Fragmentation status.

Only TCP packets are accepted by the secure packet processing module. IPv4 and TCP headers remain unencrypted.

### 4. Decryption

The receiving device uses the corresponding session key and nonce to decrypt the encrypted TCP payload.

AES-GCM authentication is verified during decryption. If authentication fails, the packet must not be treated as successfully decrypted.

## Network Topology

The project uses four Linux network namespaces to simulate communication between two endpoints through two intermediate devices.

```text
PC1                Device1              Device2                PC2
10.10.1.2          10.10.1.1            10.10.2.2              10.10.3.2
   |                   |                     |                      |
   | p1                | d1a                 | d2a                  | p2
   +-------------------+                     +----------------------+
                       | d1b             d2a |
                       | 10.10.2.1       10.10.2.2
                       +---------------------+
```

Interface and address configuration:

| Connection | Interface | IP address |
|---|---|---|
| PC1 – Device1 | p1 / d1a | 10.10.1.2 / 10.10.1.1 |
| Device1 – Device2 | d1b / d2a | 10.10.2.1 / 10.10.2.2 |
| Device2 – PC2 | d2b / p2 | 10.10.3.1 / 10.10.3.2 |

IP forwarding and routing are configured on the intermediate devices to enable end-to-end connectivity.

## Project Structure

```text
Secure_Channel/
│
├── src/
│   ├── common/
│   │   ├── packet_parser.c
│   │   ├── packet_parser.h
│   │   ├── secure_packet.c
│   │   └── secure_packet.h
│   │
│   ├── crypto/
│   │   ├── aes_gcm.c
│   │   ├── aes_gcm.h
│   │   ├── key_exchange.c
│   │   └── key_exchange.h
│   │
│   └── demo/
│       ├── generate_session_keys.c
│       └── packet_interceptor_demo.c
│
├── tests/
│   ├── test_aes_gcm.c
│   ├── test_key_exchange.c
│   ├── test_packet_parser.c
│   ├── test_secure_packet.c
│   └── test_secure_channel.c
│
├── .gitignore
└── README.md
```

## Testing

The project includes five independent test programs covering its main components.

| Test | Description |
|---|---|
| `test_key_exchange` | Verifies shared secret and key derivation |
| `test_aes_gcm` | Tests AES-GCM encryption, decryption, and authentication |
| `test_packet_parser` | Tests IPv4/TCP packet parsing and validation |
| `test_secure_packet` | Tests TCP payload encryption and decryption |
| `test_secure_channel` | Tests secure channel functionality |

All five test executables were successfully executed, and **all tests passed**.

The network namespace topology, routing configuration, IP forwarding, and connectivity between the endpoints were also verified.

## Security Considerations

The implementation follows several important security principles:

- Authenticated encryption using AES-GCM.
- X25519-based shared secret establishment.
- HKDF-based session key derivation.
- Nonce uniqueness requirements for AES-GCM.
- Integrity verification through authentication tags.
- Separation of packet headers and application payload.
- Input validation during packet parsing.

The implementation does not encrypt IPv4 or TCP headers, does not process UDP traffic, and does not introduce a custom packet header.

## Current Implementation Status

| Component | Status |
|---|---|
| X25519 key exchange | Implemented and tested |
| HKDF-SHA-256 key derivation | Implemented and tested |
| AES-256-GCM encryption | Implemented and tested |
| AES-GCM authentication | Implemented and tested |
| IPv4/TCP packet parser | Implemented and tested |
| Secure TCP packet processing | Implemented and tested |
| Session key generation | Implemented |
| Linux network namespace topology | Configured and verified |
| Routing and IP forwarding | Configured and verified |
| NFQUEUE packet interception demo | Demonstration scaffold |

The current packet interception demonstration provides the NFQUEUE integration point. Full integration of encryption and decryption into the live inline forwarding path remains separate from the independently tested cryptographic and packet-processing modules.

## Limitations

- Only IPv4/TCP traffic is supported.
- UDP traffic is not supported.
- IPv4 and TCP headers remain unencrypted.
- The prototype does not implement a complete production-grade key management or authentication infrastructure.
- Full live inline encryption/decryption integration is not yet complete.

## Conclusion

This project demonstrates the implementation of essential components of a secure TCP communication mechanism using low-level C programming, applied cryptography, and Linux networking.

It combines key exchange, authenticated encryption, packet parsing, and network namespace simulation to explore how secure communication can be implemented at the network packet-processing level.

---

**Author:** Mariam Ghevondyan

**Project:** Secure Inline Communication Channel

**Repository:** [Secure_Channel](https://github.com/mariam010101/Secure_Channel)
