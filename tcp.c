#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


#include "net.h"
#include "util.h"
#include "ip.h"
#include "tcp.h"

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE         0
#define TCP_PCB_STATE_CLOSED       1
#define TCP_PCB_STATE_LISTEN       2
#define TCP_PCB_STATE_SYN_SENT     3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED  5
#define TCP_PCB_STATE_FIN_WAIT1    6
#define TCP_PCB_STATE_FIN_WAIT2    7
#define TCP_PCB_STATE_CLOSING      8
#define TCP_PCB_STATE_TIME_WAIT    9
#define TCP_PCB_STATE_CLOSE_WAIT  10
#define TCP_PCB_STATE_LAST_ACK    11

#define TCP_DEFAULT_RTO 200000 /* micro seconds */
#define TCP_RETRANSMIT_DEADLINE 12 /* seconds */

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t off;
    uint8_t flg;
    uint16_t wnd;
    uint16_t sum;
    uint16_t up;
};

struct tcp_segment_info {
    uint32_t seq;
    uint32_t ack;
    uint16_t len;
    uint16_t wnd;
    uint16_t up;
};

struct tcp_pcb {
    int state;
    struct tcp_endpoint local;
    struct tcp_endpoint foreign;
    struct {
        uint32_t nxt;
        uint32_t una;
        uint16_t wnd;
        uint16_t up;
        uint32_t wl1;
        uint32_t wl2;
    } snd;
    uint32_t iss;
    struct {
        uint32_t nxt;
        uint16_t wnd;
        uint16_t up;
    } rcv;
    uint32_t irs;
    uint16_t mtu;
    uint16_t mss;
    uint8_t buf[65535]; /* receive buffer */
    pthread_cond_t cond;
    int wait; /* number of wait for cond */
    struct queue_head queue;
};

struct queue_head queue; /* retransmit queue */

struct tcp_queue_entry {
    struct timeval first;
    struct timeval last;
    unsigned int rto; /* micro seconds */
    uint32_t seq;
    uint8_t flg;
    size_t len;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];



int tcp_endpoint_pton(char *p, struct tcp_endpoint *n){
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

char* tcp_endpoint_ntop(struct tcp_endpoint *n, char *p, size_t size){
    size_t offset;

    ip_addr_ntop(n->addr, p, size);
    offset = strlen(p);
    snprintf(p + offset, size - offset, ":%d", ntoh16(n->port));
    return p;
}

static char* tcp_flg_ntoa(uint8_t flg){
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
        TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}


static void tcp_dump(const uint8_t *data, size_t len){
    struct tcp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct tcp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, "        ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, "        flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
    fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "         up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
* TCP Protocol Control Block (PCB)
*
* NOTE: TCP PCB functions must be called after mutex locked
*/

static struct tcp_pcb* tcp_pcb_alloc(void){
    struct tcp_pcb* pcb;

    for(pcb=pcbs;pcb<tailof(pcbs);pcb++){
        if(pcb->state == TCP_PCB_STATE_FREE){
            pcb->state = TCP_PCB_STATE_CLOSED;
            pthread_cond_init(&pcb->cond, NULL);
            return pcb;
        }
    }
    return NULL;
}

static void tcp_pcb_release(struct tcp_pcb *pcb){
    // If there is a thread waiting to be notified, it cannot be released at this time.
    if(pcb->wait){
        pthread_cond_broadcast(&pcb->cond); // Throw a notification and leave it to other threads to release it.
        return;
    }
    pthread_cond_destroy(&pcb->cond);
    // State would also be FREE
    memset(pcb, 0, sizeof(*pcb));
}

static struct tcp_pcb* tcp_pcb_select(struct tcp_endpoint *local, struct tcp_endpoint *foreign){
    struct tcp_pcb *pcb, *listen_pcb = NULL;

    for(pcb=pcbs;pcb<tailof(pcbs);pcb++){
        if((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port){
            // When checking if it is possible to bind to a local address, it is called without specifying the external address.
            if(!foreign){
                return pcb; 
            }
            // Both local address and external address match
            if(pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port){
                return pcb;
            }
            // LISTENing without specifying an external address, any external address will be matched.
            if(pcb->state == TCP_PCB_STATE_LISTEN){
                if(pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0){
                    listen_pcb = pcb; // Local and external address matches are prioritized, so they are not returned immediately.
                }
            }
        }
    }
    return listen_pcb;
}

static int tcp_pcb_cond_wait(struct tcp_pcb *pcb){
    struct timespec timeout;
    int ret;

    clock_gettime(CLOCK_REALTIME, &timeout);
    timespec_add_nsec(&timeout, 100000000); // 100ms
    pcb->wait++;
    ret = pthread_cond_timedwait(&pcb->cond, &mutex, &timeout);
    pcb->wait--;
    return ret;
}

static struct tcp_pcb* tcp_pcb_get(int id){
    struct tcp_pcb* pcb;

    if(id < 0 || id > (int)countof(pcbs)){
        /* out of range */
        return NULL;
    }

    pcb = &pcbs[id];
    if(pcb->state == TCP_PCB_STATE_FREE){
        return NULL;
    }
    return pcb;
}

static int tcp_pcb_id(struct tcp_pcb *pcb){
    return indexof(pcbs, pcb);
}

static ssize_t tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct tcp_endpoint *local, struct tcp_endpoint *foreign){
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    uint16_t total;
    char ep1[TCP_ENDPOINT_STR_LEN];
    char ep2[TCP_ENDPOINT_STR_LEN];

    hdr = (struct tcp_hdr *)buf;
    total = sizeof(*hdr) + len;

    pseudo.src = local->addr;
    pseudo.dst = foreign->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0); // Invert each bit since the cksum16() inverts in its function.

    hdr->src = local->port;
    hdr->dst = foreign->port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(*hdr) >> 2) << 4;
    hdr->flg = flg;
    hdr->wnd = hton16(wnd);
    hdr->sum = 0; // Since address area of "sum" will also be used to calculate checksum with cksum16()
    hdr->up = 0;
    memcpy(hdr+1, data, len);

    hdr->sum = cksum16((uint16_t*)hdr, total, psum);

    debugf("%s => %s, len=%zu (payload=%zu)",
        tcp_endpoint_ntop(local, ep1, sizeof(ep1)), tcp_endpoint_ntop(foreign, ep2, sizeof(ep2)), total, len);
    tcp_dump((uint8_t *)hdr, total);

    ip_output(IP_PROTOCOL_TCP, buf, total, local->addr, foreign->addr);

    return len;
}

/*
 * TCP Retransmit
 *
 * NOTE: TCP Retransmit functions must be called after mutex locked
 */

static int tcp_retransmit_queue_add(struct tcp_pcb *pcb, uint32_t seq, uint8_t flg, uint8_t *data, size_t len){
    struct tcp_queue_entry *entry;

    entry = calloc(1, sizeof(*entry) + len);
    if (!entry) {
        errorf("calloc() failure");
        return -1;
    }
    entry->rto = TCP_DEFAULT_RTO;
    entry->seq = seq;
    entry->flg = flg;
    entry->len = len;
    memcpy(entry + 1, data, entry->len);
    gettimeofday(&entry->first, NULL);
    entry->last = entry->first; // Copy the same value to the last transmission time
    if (!queue_push(&pcb->queue, entry)) {
        errorf("queue_push() failure");
        free(entry);
        return -1;
    }
    return 0;
}

static void tcp_retransmit_queue_cleanup(struct tcp_pcb *pcb){
    struct tcp_queue_entry *entry;

    while (1) {
        entry = (struct tcp_queue_entry *)queue_peek(&pcb->queue); // Peek at the top entry in the incoming queue
        if (!entry) {
            break;
        }
        if (entry->seq >= pcb->snd.una) { // If no ACK response is received, exit the process.
            break;
        }
        entry = (struct tcp_queue_entry *)queue_pop(&pcb->queue); // If an ACK response is received, take it out of the receive queue.
        debugf("remove, seq=%u, flags=%s, len=%u", entry->seq, tcp_flg_ntoa(entry->flg), entry->len);
        free(entry);
    }
    return;
}

static void tcp_retransmit_queue_emit(void *arg, void *data){

    struct tcp_pcb *pcb;
    struct tcp_queue_entry *entry;
    struct timeval now, diff, timeout;

    pcb = (struct tcp_pcb *)arg;
    entry = (struct tcp_queue_entry *)data;
    gettimeofday(&now, NULL);
    timersub(&now, &entry->first, &diff); // Calculate elapsed time since first transmission
    if (diff.tv_sec >= TCP_RETRANSMIT_DEADLINE) { // If the elapsed time since the first transmission exceeds the deadline, the connection is destroyed.
        pcb->state = TCP_PCB_STATE_CLOSED;
        pthread_cond_broadcast(&pcb->cond);
        return;
    }
    timeout = entry->last;
    timeval_add_usec(&timeout, entry->rto); // Calculate estimated retransmission time
    if (timercmp(&now, &timeout, >)) { // Retransmit TCP segment if it is past the scheduled restransmission time
        tcp_output_segment(entry->seq, pcb->rcv.nxt, entry->flg, pcb->rcv.wnd, (uint8_t *)(entry+1), entry->len, &pcb->local, &pcb->foreign);
        entry->last = now; // Update the last transmisson time 
        entry->rto *= 2; //Set retransmission timeout (time until next retransmission) at twice the value
    }
}



static ssize_t tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len){
    uint32_t seq;

    seq = pcb->snd.nxt;
    if(TCP_FLG_ISSET(flg, TCP_FLG_SYN)){
        seq = pcb->iss; // Use iss (initial send sequence number) because the SYN flag is specified at the first send.
    }
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len) { // Only the segments that consume a sequence number are stored in the retransmission queue (simple ACK segments and RST segments are not included)
        tcp_retransmit_queue_add(pcb, seq, flg, data, len);

    }
    return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign);
}

/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct tcp_endpoint *local, struct tcp_endpoint *foreign){
    struct tcp_pcb *pcb;
    int acceptable = 0;

    pcb = tcp_pcb_select(local, foreign);
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED) {
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            return;
        }

        // Send back RST if something comes to unused port
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
        } else {
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        }
        return;
    }
    /* implemented in the next step */
    switch(pcb->state) {
        case TCP_PCB_STATE_LISTEN:
            /*
            * 1st check for an RST
            */
            if(TCP_FLG_ISSET(flags, TCP_FLG_RST)){
                return;
            }
            /*
            * 2nd check for an ACK
            */
            if(TCP_FLG_ISSET(flags, TCP_FLG_ACK)){
               tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
               return;
            }
            /*
            * 3rd check for an SYN
            */
            if(TCP_FLG_ISSET(flags, TCP_FLG_SYN)){
                /* ignore: security/compartment check */
                /* ignore: precedence check */
                
                pcb->local = *local; // The specific address of both ends is determined.
                pcb->foreign = *foreign;
                pcb->rcv.wnd = sizeof(pcb->buf); // Size of receiving window is determined.
                pcb->rcv.nxt = seg->seq + 1; // Next expecting sequence number.
                pcb->irs = seg->seq; // Store initial receive sequence number.
                pcb->iss = random(); // Determine initial send sequence number.
                tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0); // Send SYN+ACK
                pcb->snd.nxt = pcb->iss + 1; // Next sending sequence number.
                pcb->snd.una = pcb->iss; // The last unreceived ack sequence number.
                pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
                    /* ignore: Note that any other incoming control or data             */
                    /* (combined with SYN) will be processed in the SYN-RECEIVED state, */
                    /* but processing of SYN and ACK  should not be repeated            */
                return;

            }
            /*
            * 4th other text or control
            */

            /* drop segment */
            return;
        case TCP_PCB_STATE_SYN_SENT:
            /*
            * 1st check the ACK bit
            */
            if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
                if (seg->ack <= pcb->iss || seg->ack > pcb->snd.nxt) {
                    tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign); // Send RST if the received ACK is for a sequence number that has not been sent
                    return;
                }
                if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt) { // Accept if it is for a sequence number for which an ACK response has not yet been received
                    acceptable = 1;
                }
            }

            /*
            * 2nd check the RST bit
            */

            /*
            * 3rd check security and precedence (ignore)
            */

            /*
            * 4th check the SYN bit
            */
            if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
                pcb->rcv.nxt = seg->seq + 1;
                pcb->irs = seg->seq;
                if (acceptable) {
                    pcb->snd.una = seg->ack;
                    tcp_retransmit_queue_cleanup(pcb);
                }
                if (pcb->snd.una > pcb->iss) {
                    pcb->state = TCP_PCB_STATE_ESTABLISHED;
                    tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
                    /* NOTE: not specified in the RFC793, but send window initialization required */
                    pcb->snd.wnd = seg->wnd;
                    pcb->snd.wl1 = seg->seq;
                    pcb->snd.wl2 = seg->ack;
                    pthread_cond_broadcast(&pcb->cond);
                    /* ignore: continue processing at the sixth step below where the URG bit is checked */
                    return;
                } else {
                    pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
                    tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
                    /* ignore: If there are other controls or text in the segment, queue them for processing after the ESTABLISHED state has been reached */
                    return;
                }
            }
            /*
            * 5th, if neither of the SYN or RST bits is set then drop the segment and return
            */

            /* drop segment */
            return;
    }
    /*
     * Otherwise
     */

    /*
     * 1st check sequence number
     */
    switch (pcb->state) {
        case TCP_PCB_STATE_SYN_RECEIVED:
        case TCP_PCB_STATE_ESTABLISHED:
            if (!seg->len) {
                if (!pcb->rcv.wnd) {
                    if (seg->seq == pcb->rcv.nxt) {
                        acceptable = 1;
                    }
                } else {
                    if (pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) {
                        acceptable = 1;
                    }
                }
            } else {
                if (!pcb->rcv.wnd) {
                    /* not acceptable */
                } else {
                    if ((pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) ||
                        (pcb->rcv.nxt <= seg->seq + seg->len - 1 && seg->seq + seg->len - 1 < pcb->rcv.nxt + pcb->rcv.wnd)) {
                        acceptable = 1;
                    }
                }
            }

        if (!acceptable) {
            if (!TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
                tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
            }
            return;
        }
    }
    /*
    * In the following it is assumed that the segment is the idealized
    * segment that begins at RCV.NXT and does not exceed the window.
    * One could tailor actual segments to fit this assumption by
    * trimming off any portions that lie outside the window (including
    * SYN and FIN), and only processing further if the segment then
    * begins at RCV.NXT.  Segments with higher begining sequence
    * numbers may be held for later processing.
    */


    /*
     * 2nd check the RST bit
     */

    /*
     * 3rd check security and precedence (ignore)
     */

    /*
     * 4th check the SYN bit
     */

    /*
     * 5th check the ACK field
     */
    if(!TCP_FLG_ISSET(flags, TCP_FLG_ACK)){
        /* drop segment */ 
        return;
    }
    switch(pcb->state){
            case TCP_PCB_STATE_SYN_RECEIVED:
                if(pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt){
                    pcb->state = TCP_PCB_STATE_ESTABLISHED;
                    pthread_cond_broadcast(&pcb->cond); // Notification of a change in PCB status
                }else{
                    tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
                }
            /* fall through */
            case TCP_PCB_STATE_ESTABLISHED:
                // Unreceived ack of the sent data
                if (pcb->snd.una < seg->ack && seg->ack <= pcb->snd.nxt) {
                    pcb->snd.una = seg->ack;
                    tcp_retransmit_queue_cleanup(pcb);


                    /* ignore: Users should receive positive acknowledgments for buffers
                                which have been SENT and fully acknowledged (i.e., SEND buffer should be returned with "ok" response) */
                    if (pcb->snd.wl1 < seg->seq || (pcb->snd.wl1 == seg->seq && pcb->snd.wl2 <= seg->ack)) {
                        pcb->snd.wnd = seg->wnd;
                        pcb->snd.wl1 = seg->seq;
                        pcb->snd.wl2 = seg->ack;
                    }
                // Already received ack
                } else if (seg->ack < pcb->snd.una) {
                    /* ignore */
                // Out of range
                } else if (seg->ack > pcb->snd.nxt) {
                    tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
                    return;
                }
            break;
    }

    /*
     * 6th, check the URG bit (ignore)
     */

    /*
     * 7th, process the segment text
     */
        switch (pcb->state) {
            case TCP_PCB_STATE_ESTABLISHED:
                if (len) {
                    memcpy(pcb->buf + (sizeof(pcb->buf) - pcb->rcv.wnd), data, len);
                    pcb->rcv.nxt = seg->seq + seg->len;
                    pcb->rcv.wnd -= len;
                    tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
                    pthread_cond_broadcast(&pcb->cond);
                }
                break;
        }
    /*
     * 8th, check the FIN bit
     */

    return;
}



static void tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface){
    struct tcp_hdr* hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct tcp_endpoint local, foreign;
    uint16_t hlen;
    struct tcp_segment_info seg;


    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }

    hdr = (struct tcp_hdr*)data;

    // Set the value of pseudo header to calculate check sum
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len);

    // Calculate check sum
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0); // Invert each bit since the cksum16() inverts in its function.
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }

    if(src == IP_ADDR_BROADCAST || dst == IP_ADDR_BROADCAST){
        errorf("broadcast IP adress is used");
        return;
    }

    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
        ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len, len - sizeof(*hdr));
    tcp_dump(data, len);

    local.addr = dst;
    local.port = hdr->dst;
    foreign.addr = src;
    foreign.port = hdr->src;
    hlen = (hdr->off >> 4) << 2;
    seg.seq = ntoh32(hdr->seq);
    seg.ack = ntoh32(hdr->ack);
    seg.len = len - hlen;
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
        seg.len++; /* SYN flag consumes one sequence number */
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        seg.len++; /* FIN flag consumes one sequence number */
    }
    seg.wnd = ntoh16(hdr->wnd);
    seg.up = ntoh16(hdr->up);
    pthread_mutex_lock(&mutex);
    tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
    pthread_mutex_unlock(&mutex);
    return;
}

int tcp_open_rfc793(struct tcp_endpoint *local, struct tcp_endpoint *foreign, int active){
    struct tcp_pcb *pcb;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct net_interrupt_ctx *ctx;
    int state, id;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_alloc();
    if(!pcb){
        errorf("tcp_pcb_alloc() failure");
        pthread_mutex_unlock(&mutex);
        return -1;
    }

    if(active){
        debugf("active open: local=%s:%u, foreign=%s:%u, connecting...",
        ip_addr_ntop(local->addr, addr1, sizeof(addr1)), ntoh16(local->port),
        ip_addr_ntop(foreign->addr, addr2, sizeof(addr2)), ntoh16(foreign->port));
        pcb->local = *local;
        pcb->foreign = *foreign;
        pcb->rcv.wnd = sizeof(pcb->buf);
        pcb->iss = random();
        if (tcp_output(pcb, TCP_FLG_SYN, NULL, 0)<0) {
            errorf("tcp_output() failure");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        pcb->snd.una = pcb->iss;
        pcb->snd.nxt = pcb->iss + 1;
        pcb->state = TCP_PCB_STATE_SYN_SENT;
    }else{
        debugf("passive open: local=%s:%u, waiting for connection...", ip_addr_ntop(local->addr, addr1, sizeof(addr1)), ntoh16(local->port));
        pcb->local = *local;
        if(foreign){
            pcb->foreign = *foreign; // According to the RFC793, it is possible to LISTEN to the specific external addresses (not possible with the socket API).
        }
        pcb->state = TCP_PCB_STATE_LISTEN;
    }
    ctx = net_interrupt_subscribe();
    AGAIN:
        state = pcb->state;
        /* waiting for state changed */
        while(pcb->state == state && !net_interrupt_occurred(ctx)){
            tcp_pcb_cond_wait(pcb);
        }
        // Interrupt occured
        if(pcb->state == state){
            errorf("interrupt");
            net_interrupt_unsubscribe(ctx);
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            pthread_mutex_unlock(&mutex);
            return -1;
        }

        if(pcb->state != TCP_PCB_STATE_ESTABLISHED){
            if(pcb->state == TCP_PCB_STATE_SYN_RECEIVED){
                goto AGAIN;
            }
            errorf("open error: %d", pcb->state);
            net_interrupt_unsubscribe(ctx);
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        net_interrupt_unsubscribe(ctx);
        id = tcp_pcb_id(pcb);
        debugf("connection established: local=%s:%u, foreign=%s:%u",
        ip_addr_ntop(pcb->local.addr, addr1, sizeof(addr1)), ntoh16(pcb->local.port),
        ip_addr_ntop(pcb->foreign.addr, addr2, sizeof(addr2)), ntoh16(pcb->foreign.port));
        pthread_mutex_unlock(&mutex);
        return id;
}

int tcp_close(int id){
    struct tcp_pcb *pcb;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    tcp_output(pcb, TCP_FLG_RST, NULL, 0);
    tcp_pcb_release(pcb);
    pthread_mutex_unlock(&mutex);
    return 0;
}

ssize_t tcp_receive(int id, uint8_t *buf, size_t size){
    struct tcp_pcb *pcb;
    struct net_interrupt_ctx *ctx;
    size_t remain, len;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    ctx = net_interrupt_subscribe();

RETRY:
    switch (pcb->state) {
        case TCP_PCB_STATE_ESTABLISHED:
            remain = sizeof(pcb->buf) - pcb->rcv.wnd;
            if (!remain) { /* no data */
                tcp_pcb_cond_wait(pcb); // Wait for the data to be set in the buffer
                if (net_interrupt_occurred(ctx)) {
                    break;
                }
                goto RETRY;
            }
            break;
        default:
            errorf("unknown state '%u'", pcb->state);
            net_interrupt_unsubscribe(ctx);
            pthread_mutex_unlock(&mutex);
            return -1;
    
    }
    net_interrupt_unsubscribe(ctx);
    len = MIN(size, remain);
    // Copy as much as fits in buf
    memcpy(buf, pcb->buf, len);
    // Shift the memory to delete the copied area.
    memmove(pcb->buf, pcb->buf + len, remain - len);
    pcb->rcv.wnd += len;
    pthread_mutex_unlock(&mutex);

    return len;
}

ssize_t tcp_send(int id, uint8_t *data, size_t len){
    struct tcp_pcb *pcb;
    struct net_interrupt_ctx *ctx;
    ssize_t sent = 0;
    struct ip_iface *iface;
    size_t mss, cap, slen;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    ctx = net_interrupt_subscribe();

RETRY:
   switch (pcb->state) {
        case TCP_PCB_STATE_ESTABLISHED:
            iface = ip_route_get_iface(pcb->foreign.addr);
            if (!iface) {
                errorf("iface not found");
                net_interrupt_unsubscribe(ctx);
                pthread_mutex_unlock(&mutex);
                return -1;
            }
            // Calculate Max Segment Size
            mss = NET_IFACE(iface)->dev->mtu - (IP_HDR_SIZE_MIN + sizeof(struct tcp_hdr));
            while (sent < (ssize_t)len) {
                cap = pcb->snd.wnd - (pcb->snd.nxt - pcb->snd.una);
                // If the receiver's buffer is filled
                if (!cap) {
                    tcp_pcb_cond_wait(pcb);
                    if (net_interrupt_occurred(ctx)) {
                        break;
                    }
                    goto RETRY;
                }
                // Divide and send in the size of mss
                slen = MIN(MIN(mss, len - sent), cap);
                if (tcp_output(pcb, TCP_FLG_ACK | TCP_FLG_PSH, data + sent, slen) == -1) {
                    errorf("tcp_output() failure");
                    net_interrupt_unsubscribe(ctx);
                    pcb->state = TCP_PCB_STATE_CLOSED;
                    tcp_pcb_release(pcb);
                    pthread_mutex_unlock(&mutex);
                    return -1;
                }
                pcb->snd.nxt += slen;
                sent += slen;
            }
            break;
        default:
            errorf("unknown state '%u'", pcb->state);
            net_interrupt_unsubscribe(ctx);
            pthread_mutex_unlock(&mutex);
            return -1;
        }


    net_interrupt_unsubscribe(ctx);
    pthread_mutex_unlock(&mutex);
    return sent;

}

static void tcp_timer(void){
    struct tcp_pcb *pcb;

    pthread_mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_FREE) {
            continue;
        }
        queue_foreach(&pcb->queue, tcp_retransmit_queue_emit, pcb); // Execute tcp_retransmit_queue_emit() for each of the entries of the queue
    }
    pthread_mutex_unlock(&mutex);
}

int tcp_init(void){
    struct timeval interval = {0,100000};

    if(ip_protocol_register(IP_PROTOCOL_TCP, tcp_input)<0){
        errorf("ip_protocol_register() failure");
        return -1;
    }
    if (net_timer_register(interval, tcp_timer) == -1) {
        errorf("net_timer_register() failure");
        return -1;
    }

    return 0; 
}
