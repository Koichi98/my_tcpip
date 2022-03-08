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

struct udp_endpoint* server_addr;
struct dns_host* hosts;

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


int question_create(uint8_t question[], const char name[], uint16_t qtype, uint16_t qclass){
    int i = 0;
    int label_len = 0;
    int position = 0;
    while(1){
        if(name[i] == '.' || name[i] == '\0') {
            // Set the length of the next label
            question[position] = label_len;
            position++;
            // Set the value of the label itself
            memcpy(question+position, &name[i-label_len], label_len);
            position += label_len;

            label_len = 0;
            if(name[i] == '\0'){
                question[position] = 0;
                position++;
                break;
            }
        }else{
            label_len++;
        }
        i++;
    }

    // QTYPE:A 00 01
    uint16_t* question_qtype = (uint16_t*)(question + position);
    *question_qtype = hton16(qtype);
    position += 2;
    // QCLASS:IN 00 01
    uint16_t* question_qclass = (uint16_t*)(question + position);
    *question_qclass = hton16(qclass);
    position += 2;

    return position;
}


int dns_query(int soc, const char name[], struct udp_endpoint* foreign){
    uint8_t buf[1024];
    struct dns_header hdr;
    uint16_t qtype;
    uint16_t qclass;
    int question_len;
    int count;

    // Set the header values
    hdr.id = 0;
    hdr.flags = hton16((0<<15) + (0<<11) + (0<<10) + (0<<9) + (1<<8) + (0<<7) + (0<<4) + 0);
    hdr.qdcount = hton16(1); // Convert to network byte order
    hdr.ancount = 0;
    hdr.nscount = 0;
    hdr.arcount = 0;

    memcpy(buf, &hdr, sizeof(hdr));

    qtype = 1;
    qclass = 1;
    question_len = question_create(buf+sizeof(hdr), name, qtype, qclass);

    count = sizeof(hdr) + question_len;
    hexdump(stderr, buf, count);

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

int parse_name(char name[], char section[], char full_message[]){
    int i = 0;  // position in the "name[]"
    int count = 0; // position in the "section[]"
    uint8_t label_len;
    uint16_t offset; 
    char* buf;
    int compressed = 0;
    int position;

    buf = section;
    position = 0;
    while(1){
        label_len = buf[position];
        position++;
        if(label_len == 0){ // End of the name data
            name[i-1] = '\0';
            break;
        }else if((label_len&0xc0) == 0xc0){ // Compressed
            offset = hton16(*(uint16_t*)(buf+position-1)) & 0x3fff; // Take out the offset pointer as a 16 bits integer
            buf = &full_message[offset];
            compressed = 1;
            count = sizeof(uint16_t);
            position = 0;
        }else{ // Label
            memcpy(name+i, &buf[position], label_len);
            i += label_len;
            position += label_len;
            name[i] = '.';
            i++;
        }
    }

    if(!compressed){
        count = position; 
    }

    return count;
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
    uint16_t qdcount = ntoh16(recvhdr->qdcount);
    uint16_t qtype;
    uint16_t qclass;
    position = 0; // position in "question"
    question = (char*)(recvhdr+1);
    if(qdcount>0){
        position += parse_name(qname, question, (char*)recvbuf);

        // Check if the qname matches with the requested "name"
        //if(strcmp() != 0){
        //

        // QTYPE
        qtype = ntoh16(*(uint16_t*)(question+position));
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

    // Answers
    char* answer;
    answer = question+position;
    char name[1024]; 
    // Assumes qdcount == 1.
    uint16_t ancount = ntoh16(recvhdr->ancount);
    uint16_t type;
    uint16_t class;
    uint16_t rdlength;
    char* rdata;
    position = 0;
    char* h_addr[ancount+1]; // To set the NULL pointer at the last.
    h_addr[ancount] = NULL;
    int count = 0;
    while(ancount>0){
        // DNAME
        position += parse_name(name, answer, (char*)recvbuf);

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
        h_addr[count] = rdata;

        ancount--;
        count++;
    }

    hostent->h_addr = h_addr;
    

    return 0;
}

struct dns_host* dns_select(const char* name){
    struct dns_host* host;

    for(host=hosts;host!=NULL;host=host->next){
        if(strcmp(name, host->h_name) == 0){
            return host;
        }
    }
    return NULL;
}

struct my_hostent* my_gethostbyname(const char* name){
    int soc;
    struct my_hostent* hostent;
    struct dns_host* host;

    hostent = calloc(1, sizeof(*hostent));
    if(!hostent){
        errorf("calloc() failure");
        return NULL;
    }

    host = dns_select(name); // Look up the "hosts" list by using "name" as a key.
    if(host){ // If the requested "name" was statically defined.
        hostent->h_name = host->h_name;
        char* h_addr[2];
        h_addr[0] = (char*)&host->h_addr;
        h_addr[1] = NULL;
        hostent->h_addr = h_addr;
        return hostent;
    }

    soc = udp_open();
    if (soc == -1) {
        errorf("udp_open() failure");
        return NULL;
    }

    dns_query(soc, name, server_addr);

    dns_recv_response(soc, hostent, server_addr);

    udp_close(soc);

    return hostent;
}

int dns_host_register(char* h_name, char* h_addr){
    struct dns_host* host;

    host = calloc(1, sizeof(*host));
    if(!host){
        errorf("calloc() failure");
        return -1;
    }

    // Set the value 
    host->h_name = h_name;
    ip_addr_pton(h_addr, &host->h_addr);
    // Add to the head of the "hosts"
    host->next = hosts;
    hosts = host;

    return 0;
}

int dns_init(){

    server_addr = calloc(1,sizeof(*server_addr));
    if(!server_addr){
        errorf("calloc() failure");
        return -1;
    }
    // Set the DNS cache server IP address.
    udp_endpoint_pton(DNS_SERVER_ADDR, server_addr);

    return 0;
}