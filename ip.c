#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "util.h"
#include "net.h"
#include "ip.h"

struct ip_hdr {
    uint8_t vhl; // Version(4bit) and IP Header(4bit)
    uint8_t tos;
    uint16_t total;
    uint16_t id;
    uint16_t offset; // Flag(3bit) and Flagment Offset(13bit)
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[0];
};

const ip_addr_t IP_ADDR_ANY = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

static struct ip_iface *ifaces;  /* NOTE: if you want to add/delete the entries after net_run(), you need to protect this list with a mutex. */

//Converts the IP address from string to network-ordered integer.
int ip_addr_pton(const char *p, ip_addr_t *n){
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char*)p;
    for(idx = 0; idx < 4; idx++){
        ret = strtol(sp, &ep, 10);
        if(ret < 0 || ret > 255){
            return -1;
        }
        if(ep == sp){
            return -1;
        }
        if((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')){
            return -1;
        }
        ((uint8_t*)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

//Converts the IP address from network-ordered integer to string.
char * ip_addr_ntop(const ip_addr_t n, char *p, size_t size){

    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d",u8[0], u8[1], u8[2], u8[3]);
    return p;
}

void ip_dump(const uint8_t *data, size_t len){
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4; // Upper 4bit of vhl
    hl = hdr->vhl & 0x0f; // Lower 4bit of vhl
    hlen = hl << 2; // IPHeader Length: Multiply it by 4 to make it 8-bit units since the value is stored in 32-bit units.
    fprintf(stderr, "   vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "   tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total); // Swap byte ordering is necessary for multiple bytes value
    fprintf(stderr, "   total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "   id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "   offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff); 
    fprintf(stderr, "   ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->protocol);
    fprintf(stderr, "   sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "   src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "   dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
    #ifdef HEXDUMP
    hexdump(stderr, data, len);
    #endif
    funlockfile(stderr);
}

struct ip_iface* ip_iface_alloc(const char *unicast, const char *netmask){
    struct ip_iface *iface;
    
    iface = calloc(1,sizeof(*iface));
    if(!iface){
        errorf("calloc() failure");
        return NULL;
    }

    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    //Set iface->unicast while converting it from String to Binary
    if(ip_addr_pton(unicast,&iface->unicast)<0){
        errorf("ip_addr_pton() failure: unicast");
        return NULL;
    }

    //Set iface->netmask while converting it from String to Binary
    if(ip_addr_pton(netmask,&iface->netmask)<0){
        errorf("ip_addr_pton() failure: netmask");
        return NULL;
    }

    //Set iface->broadcast 
    iface->broadcast = (iface->unicast & iface->netmask) | (~iface->netmask);

    return iface;
}


/* NOTE: must not be called after net_run() */
int ip_iface_register(struct net_device *dev, struct ip_iface *iface){
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    // Register the interface to the device
    if(net_device_add_iface(dev,(struct net_iface*)iface)<0){
        errorf("net_device_add_iface() failure");
        return -1;
    }

    // Add to the head of the IP interfaces list
    iface->next = ifaces;
    ifaces = iface;

    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
        ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));

    return 0;
}

struct ip_iface* ip_iface_select(ip_addr_t addr){
    struct ip_iface* iface;
    for(iface=ifaces;iface!=NULL;iface=iface->next){
        if(addr == iface->unicast){
            // Return the pointer to the matching interface
            return iface;
        }
    }

    // Return NULL if the matching interface doesn't exist
    return NULL;
}

static void ip_input(const uint8_t *data, size_t len, struct net_device *dev){

    struct ip_hdr *hdr;
    uint16_t offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

    // Error if the length of the input data is shorter then the minimum size of the IP Header
    if(len < IP_HDR_SIZE_MIN){        
        errorf("too short");
        return;
    }
    hdr = (struct ip_hdr *)data; 

    // Error if the version doesn't match with IP_VERSION_IPV4
    uint8_t v;
    v = (hdr->vhl & 0xf0) >> 4; // Upper 4bit of vhl
    if( v != IP_VERSION_IPV4){
        errorf("Not IPv4");
        return;
    }

    // Error if the length of the input data is shorter then the size of the IP Header
    uint8_t hl;
    hl = (hdr->vhl & 0x0f); // Lower 4bit of vhl
    uint8_t hlen;
    hlen = hl << 2; // IPHeader Length: Multiply it by 4 to make it 8-bit units since the value is stored in 32-bit units.
    if(len<hlen){
        errorf("shorter than IP Header");
        return;
    }

    // Error if the length of the input data is shorter than "total"
    size_t total;
    total = ntoh16(hdr->total);
    if(len<total){
        errorf("shorter than total length");
        return;
    }

    //Check Sum
    uint16_t sum = cksum16((uint16_t*)data, hlen, 0);
    if(sum != 0){
        errorf("check sum doesn't match");
        return;
    }

    offset = ntoh16(hdr->offset);
    if(offset & 0x2000 || offset & 0x1fff){
        errorf("fragments does not support");
        return;
    }

    iface = (struct ip_iface*)(net_device_get_iface(dev,NET_IFACE_FAMILY_IP));

    if(iface == NULL){
       errorf("interface not found");
       return;
    }

    if((hdr->dst != iface->unicast) && (hdr->dst != iface->netmask) && (hdr->dst != iface->broadcast)){
        // To other destination
        return;
    }

    //Debug Output
    debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
    ip_dump(data, total);

}

static int ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst){
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};

    if(NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP){
        if(dst == iface->broadcast || dst == IP_ADDR_BROADCAST){
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        }else{
            errorf("arp does not implement");
            return -1;
        }
    }
}

static ssize_t ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset){
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr*)buf;

    debugf("dev=%s, iface=%s, protocol=%u, len=%u", NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);

    // Pass the created IP datagram to the actual function of the device to output
    return ip_output_device(iface, buf, total, dst);
}

ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst){
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint16_t id;

    if(src == IP_ADDR_ANY){
        errorf("rounting does not implement");
        return -1;
    }else{

    }

    // Give an error if the size of the data is bigger than the mtu since fragmentation is not supported.
    if(NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len){
        errorf("too long, dev=%s, mtu=%u < %zu", NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }

    // Call the function to create and output the datagram
    id = ip_generate_id();
    if(ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1){
        errorf("ip_outout_core() failure");
        return -1;
    }

    return len;

}

int ip_init(void){
    //Register IP input functions in the protocol stack
    if(net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1){
        errorf("net_protocol_register failure");
        return -1;
    }
    return 0;
}

