#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stddef.h>

#include "ip.h"
#include "udp.h"

#define DNS_SERVER_ADDR "192.0.2.1:53"

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct my_hostent{
    char* h_name;
    char* h_alias;
    int h_addrtype;
    int h_length;
    char* h_addr;
};

struct dns_host{
    struct dns_host* next;
    char* h_name;
    ip_addr_t h_addr;
};


/* Create question section and return the size of the question section. */
int question_create(uint8_t question[], const char name[], uint16_t qtype, uint16_t qclass);

/* Create dns message and call udp_sendto().
    RETURN VALUE: On success, zero is returned.  On error, -1 is returned. */
int dns_query(int soc, const char* name, struct udp_endpoint* foreign);

/* Call udp_recvfrom() and set the value to the hostent structure from the parsed message.
    RETURN VALUE: On success, zero is returned.  On error, -1 is returned. */
int dns_recv_response(int soc,struct my_hostent* hostent, struct udp_endpoint* foreign);

struct dns_host* dns_select(const char* name);

/* Open socket and call dns_query() and dns_recv_response();
     RETURN VALUE: Hostent structure or a null pointer if an error occurs. */
extern struct my_hostent* my_gethostbyname(const char* name);

/* Register a pair of host name and the IP address to perform name resolution statically. */
extern int dns_host_register(char* h_name, char* h_addr);

extern int dns_init();

#endif