#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

#define ICMP_BUFSIZE IP_PAYLOAD_SIZE_MAX


// ICMP Header (Message-specific fields are treated as 32bit value.)
struct icmp_hdr{
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint32_t values;
};

// Echo/EchoReply (Cast the message to this structure when the message type is determined.)
struct icmp_echo{
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint16_t id;
    uint16_t seq;
};

static char* icmp_type_ntoa(uint8_t type) {
    switch (type) {
    case ICMP_TYPE_ECHOREPLY:
        return "EchoReply";
    case ICMP_TYPE_DEST_UNREACH:
        return "DestinationUnreachable";
    case ICMP_TYPE_SOURCE_QUENCH:
        return "SourceQuench";
    case ICMP_TYPE_REDIRECT:
        return "Redirect";
    case ICMP_TYPE_ECHO:
        return "Echo";
    case ICMP_TYPE_TIME_EXCEEDED:
        return "TimeExceeded";
    case ICMP_TYPE_PARAM_PROBLEM:
        return "ParameterProblem";
    case ICMP_TYPE_TIMESTAMP:
        return "Timestamp";
    case ICMP_TYPE_TIMESTAMPREPLY:
        return "TimestampReply";
    case ICMP_TYPE_INFO_REQUEST:
        return "InformationRequest";
    case ICMP_TYPE_INFO_REPLY:
        return "InformationReply";
    }
    return "Unknown";
}

static void icmp_dump(const uint8_t *data, size_t len){
    struct icmp_hdr *hdr;
    struct icmp_echo *echo;

    flockfile(stderr);
    hdr = (struct icmp_hdr *)data;
    fprintf(stderr, "       type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
    fprintf(stderr, "       code: %u\n", hdr->code);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));

    switch (hdr->type) {
    case ICMP_TYPE_ECHOREPLY:
    case ICMP_TYPE_ECHO:
        echo = (struct icmp_echo *)hdr;
        fprintf(stderr, "         id: %u\n", ntoh16(echo->id));
        fprintf(stderr, "        seq: %u\n", ntoh16(echo->seq));
        break;
    default:
        fprintf(stderr, "     values: 0x%08x\n", ntoh32(hdr->values));
        break;
    }

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

void icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface){
    struct icmp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    hdr = (struct icmp_hdr*)data;

    if(len < ICMP_HDR_SIZE){
        errorf("data length shorter than ICMP Header size");
        return;
    }

    uint16_t sum = cksum16((uint16_t*)data, len, 0);
    if(sum != 0){
        errorf("check sum doesn't match at icmp");
        return;
    }

    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)),len);
    icmp_dump(data, len);

    switch (hdr->type){
        case ICMP_TYPE_ECHO:
            if(dst != iface->unicast){
                /* message addressed to broadcast address. */
                /* responds with the address of the received interface. */
                dst = iface->unicast;
            }
            // Swap the source(src) and destination(dst).
            icmp_output(ICMP_TYPE_ECHOREPLY, hdr->code, hdr->values, (uint8_t*)(hdr+1), len - ICMP_HDR_SIZE, dst, src);
            break;
        default:
            /* ignore */
            break;
    }
}

// Creation of ICMP Message and call ip_output():ip.c
int icmp_output(uint8_t type, uint8_t code, uint32_t values, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst){
    uint8_t buf[ICMP_BUFSIZE];
    struct icmp_hdr *hdr;
    size_t msg_len; // Length of ICMP Message (Header + Data)
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    hdr = (struct icmp_hdr*)buf;
    msg_len = ICMP_HDR_SIZE + len;

    // Create ICMP Message
    hdr->type = type;
    hdr->code = code;
    hdr->sum = 0; //Since address area of "sum" will also be used to calculate checksum with cksum16()
    hdr->values = values; // "values" is already in network byte order
    memcpy(hdr+1, data, len);

    // Check Sum should be calculated after all of the contents are filled.
    hdr->sum = cksum16((uint16_t*)hdr, msg_len, 0);

    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), msg_len);
    icmp_dump((uint8_t *)hdr, msg_len);

    return ip_output(IP_PROTOCOL_ICMP, buf, msg_len, src, dst);
}


int icmp_init(void){
    if(ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input)<0){
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}
