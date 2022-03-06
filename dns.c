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
    uint16_t flags;
    flockfile(stderr);
    fprintf(stderr, "       id: %u\n",ntoh16(hdr->id));
    //fprintf(stderr, "       flags: %u\n",ntoh16(hdr->flags));
    flags = ntoh16(hdr->flags);
    fprintf(stderr, "       QR: %u\n", (flags>>15)&0x1);
    fprintf(stderr, "       Opcode: %u\n", (flags>>11)&0xf);
    fprintf(stderr, "       AA: %u\n", (flags>>10)&0x1);
    fprintf(stderr, "       TC: %u\n", (flags>>9)&0x1);
    fprintf(stderr, "       RD: %u\n", (flags>>8)&0x1);
    fprintf(stderr, "       RA: %u\n", (flags>>7)&0x1);
    fprintf(stderr, "       Z: %u\n", (flags>>4)&0x7);
    fprintf(stderr, "       RCODE: %u\n", (flags)&0xf);
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

    // QTYPE:A 00 01
    buf[sizeof(hdr)+pointer] = 0;
    buf[sizeof(hdr)+pointer+1] = 1;
    // QCLASS:IN 00 01
    buf[sizeof(hdr)+pointer+2] = 0;
    buf[sizeof(hdr)+pointer+3] = 1;


    //hexdump(stderr, buf, count);
    hexdump(stderr, buf, sizeof(hdr)+pointer+4);
    //printf("count:%d\n",count);
    count = sizeof(hdr) + pointer + 4;

    // These two accesses are to achieve arp resolve.
    if (udp_sendto(soc, buf, count, foreign) == -1) {
    //if (udp_sendto(soc, buf, count, foreign) == -1) {
        errorf("udp_sendto() failure");
        return -1;
    }
    usleep(5000);
    if (udp_sendto(soc, buf, count, foreign) == -1) {
        errorf("udp_sendto() failure");
        return -1;
    }
    usleep(5000);

    // Actual sending operation
    if (udp_sendto(soc, buf, count, foreign) == -1) {
        errorf("udp_sendto() failure");
        return -1;
    }
    return 0;
}



int dns_recv_response(int soc, struct my_hostent* hostent, struct udp_endpoint* foreign){
    uint8_t recvbuf[1024]; // TODO: Check the maximum size of the DNS packet
    ssize_t len;
    struct dns_header* recvhdr;
    int position;

    len = udp_recvfrom(soc, recvbuf, 1024, foreign);
    recvhdr = (struct dns_header*)recvbuf;
    dns_dump(recvbuf, len);

    // Question section 
    // Assumes qdcount == 1.
    char* question;
    char qname[1024]; // TODO: Check the maximum size of the domain name
    uint8_t label_len;
    uint16_t qdcount = ntoh16(recvhdr->qdcount);
    uint16_t qtype;
    uint16_t qclass;
    int i = 0;
    position = 0;
    question = (char*)(recvhdr+1);
    if(qdcount>0){
        while(1){
            label_len = question[position];
            position++;
            if(label_len == 0){ // Route 
                qname[i-1] = '\0'; // Overwrite the period ('.')
                break;
            }
            memcpy(qname+i, &question[position], label_len);
            i += label_len;
            position += label_len;
            qname[i] = '.';
            i++;
        }
        printf("qnname:%s\n",qname);
        //// Check if the qname matches
        //if(strcmp() != 0){
        //

        // QTYPE
        qtype = ntoh16(*(uint16_t*)(question+position));
        printf("qtype:%d\n",qtype);
        if(qtype!= 1){
            errorf("not ipv4 address :type is not A");
            return -1;
        }
        position += sizeof(qtype);
        // QCLASS
        qclass = ntoh16(*(uint16_t*)(question+position));
        if(qclass != 1){
            errorf("not ipv4 address :class is not IN");
            return -1;
        }
        position += sizeof(qclass);

        qdcount--;
    }
    printf("position:%d\n",position);

    // Answers
    char* answer;
    answer = question+position;
    char name[1024]; 
    // Assumes qdcount == 1.
    uint16_t ancount = ntoh16(recvhdr->ancount);
    uint16_t two_octet;
    uint16_t offset;
    uint16_t type;
    uint16_t class;
    uint16_t rdlength;
    char* rdata;
    position = 0;
    while(ancount>0){
        // NAME 
        two_octet = ntoh16(*(uint16_t*)(answer+position));
        // Check for message compression
        if(((two_octet>>14)&0x3) == 0x3){ // If compressed
            offset = two_octet & 0x3fff;
            position += sizeof(two_octet);
        }else{ 
            // TODO
        }

        // TYPE
        type = ntoh16(*(uint16_t*)(answer+position));
        if(type!= 1){
            errorf("not ipv4 address :type is not A");
            return -1;
        }
        position += sizeof(type);
        // CLASS
        class = ntoh16(*(uint16_t*)(answer+position));
        if(class != 1){
            errorf("not ipv4 address :class is not IN");
            return -1;
        }
        position += sizeof(class);
        //TTL
        position += sizeof(uint32_t);
        // RDLENGTH
        rdlength = ntoh16(*(uint16_t*)(answer+position));
        if(rdlength != 4){
            errorf("not ipv4 address: rdlength is not 4");
            return -1;
        }
        position += sizeof(rdlength);
        // RDATA
        rdata = answer+position;
        //ip_addr_ntop(*rdata, addr, sizeof(addr));
        position += sizeof(uint32_t);

        hostent->h_name = name;
        hostent->h_alias = NULL;
        hostent->h_addrtype = 2; // linux/socket.h: #define AF_INET 2
        hostent->h_length = 4; 
        hostent->h_addr = rdata;

        ancount--;
    }
    

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