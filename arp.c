#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

#define ARP_HRD_ETHER 0x0001

#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

struct arp_hdr{
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
};

struct arp_ether{
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN];
    uint8_t spa[IP_ADDR_LEN];
    uint8_t tha[ETHER_ADDR_LEN];
    uint8_t tpa[IP_ADDR_LEN];
};

static char* arp_opcode_ntoa(uint16_t opcode){
    switch(ntoh16(opcode)){
        case ARP_OP_REQUEST:
            return "Request";
        case ARP_OP_REPLY:
            return "Reply";
    }
    return "Unknown";
}

static void arp_dump(const uint8_t *data, size_t len){
    struct arp_ether *message;
    ip_addr_t spa, tpa;
    char addr[128];

    message = (struct arp_ether*)data;
    flockfile(stderr);
    fprintf(stderr, "       hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, "       pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "       hln: 0x%u\n", message->hdr.hln);
    fprintf(stderr, "       pln: 0x%u\n", message->hdr.pln);
    fprintf(stderr, "        op: %u (%s)\n",  ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
    fprintf(stderr, "       sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    memcpy(&spa, message->spa, sizeof(spa));
    fprintf(stderr, "       spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "       tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    memcpy(&tpa, message->tpa, sizeof(tpa));
    fprintf(stderr, "       tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif 
    funlockfile(stderr);
}

// Create reply frame and call net_device_output()
static int arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst){
    struct arp_hdr* hdr;
    struct arp_ether* reply;

    reply = calloc(1,sizeof(*reply));
    hdr = (struct arp_hdr*)reply;

    // Set the value for arp_hdr
    hdr->hrd = ntoh16(ARP_HRD_ETHER);
    hdr->pro = ntoh16(ARP_PRO_IP);
    hdr->hln = ETHER_ADDR_LEN;
    hdr->pln = IP_ADDR_LEN;
    hdr->op = ntoh16(ARP_OP_REPLY);

    // Set the value for arp_ether other than arp_hdr
    memcpy(reply->sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply->spa, &((struct ip_iface*)iface)->unicast, IP_ADDR_LEN);
    memcpy(reply->tha, tha, ETHER_ADDR_LEN);
    memcpy(reply->tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(*reply));
    arp_dump((uint8_t*)reply, sizeof(*reply));
    
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t*) reply, sizeof(*reply), dst);
}

static void arp_input(const uint8_t *data, size_t len, struct net_device *dev){
    struct arp_ether* msg;
    struct arp_hdr* hdr;
    struct ip_iface* iface;
    ip_addr_t spa,tpa;

    if(len < sizeof(*msg)){
        errorf("too short");
        return;
    }

    msg = (struct arp_ether*)data;
    hdr = (struct arp_hdr*)msg;

    if(ntoh16(hdr->hrd) != ARP_HRD_ETHER || hdr->hln != ETHER_ADDR_LEN){
        return;
    }

    if(ntoh16(hdr->pro) != ARP_PRO_IP || hdr->pln != IP_ADDR_LEN){
        return;
    }

    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);

    iface = (struct ip_iface*)(net_device_get_iface(dev, NET_IFACE_FAMILY_IP));
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));

    char addr[32];
    ip_addr_ntop(iface->unicast,addr,32);
    if(iface && iface->unicast == tpa){
        if(ntoh16(hdr->op) == ARP_OP_REQUEST){
            int ret;
            ret = arp_reply((struct net_iface*)iface, msg->sha, spa, msg->sha);
            if(ret<0){
                errorf("arp_reply() failure");
            }
        }
    }

}

int arp_init(void){
    if(net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input)<0){
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}