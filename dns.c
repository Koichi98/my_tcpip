#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "net.h"
#include "util.h"
#include "ip.h"
#include "udp.h"
#include "dns.h"

static void dns_dump(const uint8_t *data, size_t len){
    struct dns_header* hdr;
    hdr = (struct dns_header*)data;
    flockfile(stderr);
    fprintf(stderr, "       id: %u\n",ntoh16(hdr->id));
    fprintf(stderr, "       flags: %u\n",ntoh16(hdr->flags));
    fprintf(stderr, "       qdcount: %u\n",ntoh16(hdr->qdcount));
    fprintf(stderr, "       ancount: %u\n",ntoh16(hdr->ancount));
    fprintf(stderr, "       nscount: %u\n",ntoh16(hdr->nscount));
    fprintf(stderr, "       arcount: %u\n",ntoh16(hdr->arcount));

#ifdef HEXDUMP
    flockfile(stderr);
    hexdump(stderr, data, len);
    funlockfile(stderr);
#endif
}

int dns_query(int soc, const char name[], struct udp_endpoint* foreign){
    uint8_t buf[1024];
    struct dns_header hdr;
    int count = 0;

    hdr.id = 0;
    hdr.flags = (0<<15) + (0<<11) + (0<<10) + (0<<9) + (1<<8) + (0<<7) + (0<<4) + 0;
    hdr.qdcount = hton16(1); // Convert to network byte order
    hdr.ancount = 0;
    hdr.nscount = 0;
    hdr.arcount = 0;

    memcpy(buf, &hdr, sizeof(hdr));

    count += sizeof(hdr);

    // example.com
    // 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
    // A IN
    // 00 01 00 01    

    //uint8_t qname_type_class[] = {7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1};
    //int size = sizeof(qname_type_class) / sizeof(uint8_t);
    //memcpy(buf+count, qname_type_class, size);
    //count += size;

    int i = 0;
    int label_len = 0;
    int pointer = 0;
    while(1){
        if(name[i] == '.' || name[i] == '\0') {
            // Set the length of the next label
            buf[sizeof(hdr)+pointer] = label_len;
            pointer ++;
            // Set the value of the label itself
            memcpy(buf+sizeof(hdr)+pointer, &name[i-label_len], label_len);
            pointer += label_len;

            label_len = 0;
            if(name[i] == '\0'){
                buf[sizeof(hdr)+pointer] = 0;
                pointer++;
                break;
            }
        }else{
            label_len++;
        }
        i++;
    }

    buf[sizeof(hdr)+pointer] = 0;
    buf[sizeof(hdr)+pointer+1] = 1;
    buf[sizeof(hdr)+pointer+2] = 0;
    buf[sizeof(hdr)+pointer+3] = 1;



    //hexdump(stderr, buf, count);
    hexdump(stderr, buf, sizeof(hdr)+pointer+4);
    //printf("count:%d\n",count);
    count = sizeof(hdr) + pointer + 4;
    if (udp_sendto(soc, buf, count, foreign) == -1) {
    //if (udp_sendto(soc, buf, count, foreign) == -1) {
        errorf("udp_sendto() failure");
        return -1;
    }
    sleep(1);
    if (udp_sendto(soc, buf, count, foreign) == -1) {
        errorf("udp_sendto() failure");
        return -1;
    }
    return 0;
}

int dns_recv_response(int soc, struct my_hostent* hostent, struct udp_endpoint* foreign){
    uint8_t recvbuf[1024];
    ssize_t len;
    struct dns_header* recvhdr;

    len = udp_recvfrom(soc, recvbuf, 1024, foreign);
    recvhdr = (struct dns_header*)recvbuf;
    dns_dump(recvbuf, len);

    return 0;
}

struct my_hostent* my_gethostbyname(const char* name){
    int soc;
    struct udp_endpoint* foreign;
    struct my_hostent* hostent;

    foreign = calloc(1,sizeof(*foreign));
    udp_endpoint_pton(DNS_SERVER_ADDR, foreign);
    soc = udp_open();
    if (soc == -1) {
        errorf("udp_open() failure");
        return NULL;
    }

    dns_query(soc, name, foreign);

    hostent = calloc(1, sizeof(*hostent));
    dns_recv_response(soc, hostent, foreign);

    udp_close(soc);

    return hostent;
}