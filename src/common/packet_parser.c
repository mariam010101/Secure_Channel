#include "packet_parser.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

ParseResult parse_tcp_packet(
    unsigned char *packet,
    size_t packet_length,
    ParsedPacket *result
) {

    if (packet == NULL || result == NULL) {
        return PARSE_ERROR_NULL_PACKET;
    }

    memset(result, 0, sizeof(ParsedPacket));

    // Check minimum IPv4 header size
    if (packet_length < sizeof(struct iphdr)) {
        return PARSE_ERROR_INVALID_IP_HEADER;
    }

    struct iphdr ip;

    memcpy(&ip, packet, sizeof(ip));

    // Check IPv4 version
    if (ip.version != 4 || ip.ihl < 5) {
        return PARSE_ERROR_INVALID_IP_HEADER;
    }

    size_t ip_header_length = ip.ihl * 4;

    // Check that the complete IP header exists
    if (packet_length < ip_header_length) {
        return PARSE_ERROR_INVALID_IP_HEADER;
    }

    uint16_t total_length = ntohs(ip.tot_len);

    // Validate total IP packet length
    if (total_length < ip_header_length ||
        total_length > packet_length) {

        return PARSE_ERROR_INVALID_IP_LENGTH;
    }

    // Only TCP packets are supported
    if (ip.protocol != IPPROTO_TCP) {
        return PARSE_ERROR_NOT_TCP;
    }

    // Reject fragmented IPv4 packets
    uint16_t fragment = ntohs(ip.frag_off);

    if (fragment & (IP_MF | IP_OFFMASK)) {
        return PARSE_ERROR_FRAGMENTED_PACKET;
    }

    // Check minimum TCP header size
    if (total_length < ip_header_length + sizeof(struct tcphdr)) {
        return PARSE_ERROR_INVALID_TCP_HEADER;
    }

    struct tcphdr tcp;

    memcpy(
        &tcp,
        packet + ip_header_length,
        sizeof(tcp)
    );

    // Calculate TCP header length
    size_t tcp_header_length = tcp.doff * 4;

    if (tcp.doff < 5 ||
        tcp_header_length > total_length - ip_header_length) {

        return PARSE_ERROR_INVALID_TCP_HEADER;
    }

    // Calculate payload position
    size_t payload_offset =
        ip_header_length + tcp_header_length;

    // Calculate payload size
    size_t payload_length =
        total_length - payload_offset;

    // Store extracted information
    memcpy(&result->source_ip, &ip.saddr, sizeof(result->source_ip));
    memcpy(&result->destination_ip, &ip.daddr, sizeof(result->destination_ip));

    result->source_port = ntohs(tcp.source);
    result->destination_port = ntohs(tcp.dest);

    result->ip_header_length = ip_header_length;
    result->tcp_header_length = tcp_header_length;

    result->payload_offset = payload_offset;
    result->payload_length = payload_length;

    result->total_length = total_length;

    result->payload = packet + payload_offset;

    return PARSE_SUCCESS;
}