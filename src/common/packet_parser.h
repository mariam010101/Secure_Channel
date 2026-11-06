#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

typedef struct {

    struct in_addr source_ip;
    struct in_addr destination_ip;

    uint16_t source_port;
    uint16_t destination_port;

    size_t ip_header_length;
    size_t tcp_header_length;

    size_t payload_offset;
    size_t payload_length;

    uint16_t total_length;

    unsigned char *payload;

} ParsedPacket;

typedef enum {

    PARSE_SUCCESS = 0,
    PARSE_ERROR_NULL_PACKET,
    PARSE_ERROR_INVALID_IP_HEADER,
    PARSE_ERROR_INVALID_IP_LENGTH,
    PARSE_ERROR_NOT_TCP,
    PARSE_ERROR_FRAGMENTED_PACKET,
    PARSE_ERROR_INVALID_TCP_HEADER

} ParseResult;

ParseResult parse_tcp_packet(
    unsigned char *packet,
    size_t packet_length,
    ParsedPacket *result
);

#endif