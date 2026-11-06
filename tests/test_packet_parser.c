#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "../src/common/packet_parser.h"

#define TEST_PACKET_SIZE 54

unsigned char packet[TEST_PACKET_SIZE];

void create_test_packet(void)
{
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;

    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(TEST_PACKET_SIZE);
    ip->protocol = IPPROTO_TCP;

    inet_pton(AF_INET, "10.10.1.2", &ip->saddr);
    inet_pton(AF_INET, "10.10.3.2", &ip->daddr);

    struct tcphdr *tcp =
        (struct tcphdr *)(packet + 20);

    tcp->source = htons(12345);
    tcp->dest = htons(5000);
    tcp->doff = 5;

    memcpy(packet + 40, "Hello from PC1", 14);
}

void test_valid_packet(void)
{
    create_test_packet();

    ParsedPacket result;

    ParseResult status = parse_tcp_packet(
        packet,
        sizeof(packet),
        &result
    );

    printf("\nTEST 1: Valid TCP packet\n");

    if (status == PARSE_SUCCESS &&
        result.source_port == 12345 &&
        result.destination_port == 5000 &&
        result.payload_offset == 40 &&
        result.payload_length == 14 &&
        memcmp(result.payload, "Hello from PC1", 14) == 0) {

        printf("PASS\n");

    } else {
        printf("FAIL\n");
    }
}

void test_invalid_ip_header(void)
{
    ParsedPacket result;

    ParseResult status = parse_tcp_packet(
        packet,
        10,
        &result
    );

    printf("\nTEST 2: Invalid IPv4 header\n");

    printf("%s\n",
        status == PARSE_ERROR_INVALID_IP_HEADER
        ? "PASS" : "FAIL");
}

void test_non_tcp_packet(void)
{
    create_test_packet();

    struct iphdr *ip = (struct iphdr *)packet;

    ip->protocol = IPPROTO_UDP;

    ParsedPacket result;

    ParseResult status = parse_tcp_packet(
        packet,
        sizeof(packet),
        &result
    );

    printf("\nTEST 3: Non-TCP packet\n");

    printf("%s\n",
        status == PARSE_ERROR_NOT_TCP
        ? "PASS" : "FAIL");
}

void test_fragmented_packet(void)
{
    create_test_packet();

    struct iphdr *ip = (struct iphdr *)packet;

    ip->frag_off = htons(IP_MF);

    ParsedPacket result;

    ParseResult status = parse_tcp_packet(
        packet,
        sizeof(packet),
        &result
    );

    printf("\nTEST 4: Fragmented IPv4 packet\n");

    printf("%s\n",
        status == PARSE_ERROR_FRAGMENTED_PACKET
        ? "PASS" : "FAIL");
}

void test_invalid_tcp_header(void)
{
    create_test_packet();

    struct tcphdr *tcp =
        (struct tcphdr *)(packet + 20);

    tcp->doff = 4;

    ParsedPacket result;

    ParseResult status = parse_tcp_packet(
        packet,
        sizeof(packet),
        &result
    );

    printf("\nTEST 5: Invalid TCP header\n");

    printf("%s\n",
        status == PARSE_ERROR_INVALID_TCP_HEADER
        ? "PASS" : "FAIL");
}

void test_empty_payload(void)
{
    create_test_packet();

    struct iphdr *ip = (struct iphdr *)packet;

    ip->tot_len = htons(40);

    ParsedPacket result;

    ParseResult status = parse_tcp_packet(
        packet,
        40,
        &result
    );

    printf("\nTEST 6: Empty TCP payload\n");

    printf("%s\n",
        status == PARSE_SUCCESS &&
        result.payload_length == 0
        ? "PASS" : "FAIL");
}

int main(void)
{
    printf("================================\n");
    printf("     TCP PACKET PARSER TESTS\n");
    printf("================================\n");

    test_valid_packet();
    test_invalid_ip_header();
    test_non_tcp_packet();
    test_fragmented_packet();
    test_invalid_tcp_header();
    test_empty_payload();

    printf("\n================================\n");

    return 0;
}