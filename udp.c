#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <pthread.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_SIZE 16

#define UDP_PCB_STATE_FREE    0
#define UDP_PCB_STATE_OPEN    1
#define UDP_PCB_STATE_CLOSING 2

/* see https://tools.ietf.org/html/rfc6335 */
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

struct pseudo_hdr{
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct udp_hdr{
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

struct udp_pcb {
     int state;
     struct udp_endpoint local;
     struct queue_head queue; /* receive queue */
     int wait; /* number of wait for cond */
     pthread_cond_t cond;
 };
 
 /* NOTE: the data follows immediately after the structure */
 struct udp_queue_entry {
     struct udp_endpoint foreign;
     uint16_t len;
 };
 
 static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
 static struct udp_pcb pcbs[UDP_PCB_SIZE];

int udp_endpoint_pton(char *p, struct udp_endpoint *n){
    char *sep;
    char addr[IP_ADDR_STR_LEN] = {};
    long int port;

    sep = strrchr(p, ':');
    if (!sep) {
        return -1;
    }
    memcpy(addr, p, sep - p);
    if (ip_addr_pton(addr, &n->addr) == -1) {
        return -1;
    }
    port = strtol(sep+1, NULL, 10);
    if (port <= 0 || port > UINT16_MAX) {
        return -1;
    }
    n->port = hton16(port);
    return 0;
}

char* udp_endpoint_ntop(struct udp_endpoint *n, char *p, size_t size){
    size_t offset;

    ip_addr_ntop(n->addr, p, size);
    offset = strlen(p);
    snprintf(p + offset, size - offset, ":%d", ntoh16(n->port));
    return p;
}

static void udp_dump(const uint8_t *data, size_t len){
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

  /*
* UDP Protocol Control Block (PCB)
*
* NOTE: UDP PCB functions must be called after mutex locked
  */

// Look for free pcb and return.
static struct udp_pcb* udp_pcb_alloc(void){
    struct udp_pcb* pcb;

    for(pcb=pcbs;pcb<tailof(pcbs);pcb++){
        if(pcb->state == UDP_PCB_STATE_FREE){
            pcb->state = UDP_PCB_STATE_OPEN;
            pthread_cond_init(&pcb->cond, NULL);
            return pcb;
        }
    }
    /* Free pcb not found */
    return NULL;
}

static void udp_pcb_release(struct udp_pcb *pcb){
    struct queue_entry* entry;

    pcb->state = UDP_PCB_STATE_CLOSING;
    if(pcb->wait){
        pthread_cond_broadcast(&pcb->cond);
        return;
    }

    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;
    // Empty the queue.
    while((entry = queue_pop(&pcb->queue)) != NULL){
        free(entry);
    }
    pthread_cond_destroy(&pcb->cond);
}

static struct udp_pcb* udp_pcb_select(ip_addr_t addr, uint16_t port){
    struct udp_pcb* pcb;

    for(pcb=pcbs;pcb<tailof(pcbs);pcb++){
        if(pcb->state == UDP_PCB_STATE_OPEN){
            if((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port){
                return pcb;
            }
        }
    }
    /* Corresponding pcb not found */
    return NULL;
}

static struct udp_pcb* udp_pcb_get(int id){
    struct udp_pcb* pcb;

    if(id < 0 || id > (int)countof(pcbs)){
        /* out of range */
        return NULL;
    }

    pcb = &pcbs[id];
    if(pcb->state != UDP_PCB_STATE_OPEN){
        return NULL;
    }
    return pcb;
}

static int udp_pcb_id(struct udp_pcb *pcb){
    return indexof(pcbs,pcb);
}

static struct udp_queue_entry* udp_pcb_queue_pop(struct udp_pcb *pcb){
    struct net_interrupt_ctx *ctx;
    struct udp_queue_entry* entry;
    struct timespec timeout;
    

    ctx = net_interrupt_subscribe();
    while(!net_interrupt_occurred(ctx)){
        entry = (struct udp_queue_entry*)queue_pop(&pcb->queue);
        if(entry){
            break;
        }
        clock_gettime(CLOCK_REALTIME, &timeout);
        timespec_add_nsec(&timeout, 100000000); /* 100ms */
        pcb->wait++;
        pthread_cond_timedwait(&pcb->cond, &mutex, &timeout);
        pcb->wait--;

    }
    net_interrupt_unsubscribe(ctx);
    return entry;
}

static void udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface){
    struct pseudo_hdr pseudo;    
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;


    if(len < sizeof(*hdr)){
        errorf("too short");
        return;
    }

    hdr = (struct udp_hdr*)data;
    if (len != ntoh16(hdr->len)) { /* just to make sure */
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }

    // Set the value of pseudo header to calculate check sum
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);

    // Calculate check sum
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0); // Invert each bit since the cksum16() inverts in its function.
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }

    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
        ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src), ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst), len, len - sizeof(*hdr));
    udp_dump(data, len);

    pthread_mutex_lock(&mutex);
    pcb = udp_pcb_select(dst, hdr->dst);
    if(!pcb){
        /* port is not in use */
        pthread_mutex_unlock(&mutex);
        return;
    }

    entry = calloc(1, sizeof(*entry) + len - sizeof(*hdr)); // Size of entry structure and data itself
    entry->foreign.addr = src;
    entry->foreign.port = hdr->src;
    entry->len = len - sizeof(*hdr);
    memcpy(entry+1, hdr+1, len - sizeof(*hdr));

    queue_push(&pcb->queue, entry);

    pthread_cond_broadcast(&pcb->cond);
    pthread_mutex_unlock(&mutex);
}

ssize_t udp_output(struct udp_endpoint *src, struct udp_endpoint *dst, const  uint8_t *data, size_t len) {
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t total, psum = 0;
    char ep1[UDP_ENDPOINT_STR_LEN];
    char ep2[UDP_ENDPOINT_STR_LEN];

    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
        errorf("too long");
        return -1;
    }

    total = sizeof(*hdr) + len;

    // Set the value of pseudo header to calculate check sum
    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0); // Invert each bit since the cksum16() inverts in its function.

    // Set the value of udp header
    hdr = (struct udp_hdr *)buf;
    hdr->src = src->port;
    hdr->dst = dst->port;
    hdr->len = hton16(total);
    hdr->sum = 0;
    memcpy(hdr+1, data, len);
    hdr->sum = cksum16((uint16_t*)hdr, total, psum);

    debugf("%s => %s, len=%zu (payload=%zu)", udp_endpoint_ntop(src, ep1, sizeof(ep1)), udp_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
    udp_dump((uint8_t *)hdr, total);

    return ip_output(IP_PROTOCOL_UDP, buf, total, src->addr, dst->addr);
}

/*
 * UDP User Commands
 */

// Allocate the pcb and return the id.
int udp_open(void){
    struct udp_pcb* pcb;

    pcb = udp_pcb_alloc();
    if(!pcb){
        errorf("udp_pcb_alloc() failure");
        return -1;
    }

    return udp_pcb_id(pcb);
}


int udp_close(int id){
    struct udp_pcb* pcb;

    pcb = udp_pcb_get(id);
    if(!pcb){
        errorf("udp_pcb_get() failure");
        return -1;
    }

    udp_pcb_release(pcb);

    return 0;
}

int udp_bind(int id, struct udp_endpoint *local){
    struct udp_pcb *pcb;
    char ep1[UDP_ENDPOINT_STR_LEN];

    pthread_mutex_lock(&mutex);

    pcb = udp_pcb_get(id);
    if(udp_pcb_select(local->addr, local->port)){
        errorf("binded socket already exists.");
        return -1;
    }
    pcb->local = *local;

    debugf("bound, id=%d, local=%s", id, udp_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
    pthread_mutex_unlock(&mutex);
    return 0;
}

ssize_t udp_sendto(int id, uint8_t *data, size_t len, struct udp_endpoint *foreign){
    struct udp_pcb* pcb;
    struct udp_endpoint local;
    struct ip_iface* iface;
    char addr[IP_ADDR_STR_LEN];

    pthread_mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    local.addr = pcb->local.addr;
    // If socket is not binded, get the source IP address from interface
    if(local.addr == IP_ADDR_ANY){
        iface = ip_route_get_iface(foreign->addr);
        if(!iface){
            errorf("iface not found that can reach foreign address, addr=%s", ip_addr_ntop(foreign->addr, addr, sizeof(addr)));
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        local.addr = iface->unicast;
        debugf("select local address, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
    }

    // If the local port is not set, output an error
    if(!pcb->local.port){
        errorf("local port is required");
        return -1;
    }
    local.port = pcb->local.port;
    pthread_mutex_unlock(&mutex);
    return udp_output(&local, foreign, data, len);
}

ssize_t udp_recvfrom(int id, uint8_t *buf, size_t size, struct udp_endpoint *foreign){
    struct udp_pcb* pcb;
    struct udp_queue_entry* entry;
    ssize_t len;

    pthread_mutex_lock(&mutex);
    pcb = udp_pcb_get(id);

    entry = udp_pcb_queue_pop(pcb);
    if(!entry){
        if(pcb->state == UDP_PCB_STATE_CLOSING){
            udp_pcb_release(pcb);
        }
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    pthread_mutex_unlock(&mutex);

    // Set the source IP address and port if "foreign" is given
    if(foreign){
        *foreign = entry->foreign;
    }

    len = MIN(size, entry->len); /* truncate */
    memcpy(buf, entry+1, len);
    free(entry);
    return len;
}

int udp_init(void){
    if(ip_protocol_register(IP_PROTOCOL_UDP, udp_input)<0){
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}
