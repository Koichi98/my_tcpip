#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>



#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

#define ARP_HRD_ETHER 0x0001

#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_CACHE_SIZE 32

#define ARP_CACHE_STATE_FREE       0
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED   2
#define ARP_CACHE_STATE_STATIC     3 

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

struct arp_cache{
    unsigned char state;
    ip_addr_t pa;
    uint8_t ha[ETHER_ADDR_LEN];
    struct timeval timestamp;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE];


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

/*
    ARP Cache

    NOTE: ARP Cache functions must be called after mutex locked
*/

static struct arp_cache* arp_cache_alloc(void){
    struct arp_cache *entry, *oldest = NULL;

    for(entry=caches;entry<tailof(caches);entry++){
        // Look for unused (FREE) entry
        if(entry->state == ARP_CACHE_STATE_FREE){
            return entry;
        }
        // Look for the oldest entry simultaneously in case when FREE entry doesn't exist.
        if(!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)){
            oldest = entry;
        }
    }
    
    return oldest;
}

// Return a arp_cache entry with a matching IP address
static struct arp_cache* arp_cache_select(ip_addr_t pa){
    struct arp_cache *cache;
    for(cache=caches;cache<tailof(caches);cache++){
        if(cache->state != ARP_CACHE_STATE_FREE){
            // Having the same IP address
            if(cache->pa == pa){
                return cache;
            }
        }
    }
    return NULL;
}

// Update the cache entry
static struct arp_cache* arp_cache_update(ip_addr_t pa, const uint8_t *ha){
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];


    cache = arp_cache_select(pa);

    // If cache is not found, return NULL.
    if(!cache){
        return NULL;
    }

    // Update the cache information 
    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, sizeof(uint8_t) * ETHER_ADDR_LEN);
    if(gettimeofday(&cache->timestamp,NULL)<0){ // TODO:gettimeofday() isn't recommended. Use clock_gettime()
        errorf("gettimeofday() failure");
        return NULL;
    }

    debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

static struct arp_cache* arp_cache_insert(ip_addr_t pa, const uint8_t *ha){
    struct arp_cache* cache; 
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    // Allcate the cache entry
    cache = arp_cache_alloc();
    if(!cache){
        errorf("arp_cache_alloc() failure");
        return NULL;
    }

    // Set the value of the cache entry
    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, sizeof(uint8_t) * ETHER_ADDR_LEN);
    if(gettimeofday(&cache->timestamp,NULL)<0){ // TODO:gettimeofday() isn't recommended. Use clock_gettime()
        errorf("gettimeofday() failure");
        return NULL;
    }

    debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}


static void arp_cache_delete(struct arp_cache *cache){
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));

    // Delete the cache entry.
    cache->state = ARP_CACHE_STATE_FREE;
    cache->pa = 0;
    memset(cache->ha, 0, sizeof(uint8_t) * ETHER_ADDR_LEN);
    timerclear(&cache->timestamp);
}

// Create the arp request message and call net_device_output()
static int arp_request(struct net_iface* iface, ip_addr_t tpa){
    struct arp_ether* request;
    struct arp_hdr* hdr;

    request = calloc(1,sizeof(*request));
    hdr = (struct arp_hdr*)request;

    // Set the value for arp_hdr
    hdr->hrd = ntoh16(ARP_HRD_ETHER);
    hdr->pro = ntoh16(ARP_PRO_IP);
    hdr->hln = ETHER_ADDR_LEN;
    hdr->pln = IP_ADDR_LEN;
    hdr->op = ntoh16(ARP_OP_REQUEST);

    // Set the value for arp_ether other than arp_hdr
    memcpy(request->sha, iface->dev->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(request->spa, &((struct ip_iface*)iface)->unicast, sizeof(uint8_t) * IP_ADDR_LEN);
    memset(request->tha, 0 , sizeof(uint8_t) * ETHER_ADDR_LEN); /* Set 0 for "tha", since we don't know and are requesting this value. */
    memcpy(request->tpa, &tpa, sizeof(uint8_t) * IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(*request));
    arp_dump((uint8_t *)request, sizeof(*request));
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t*)request, sizeof(*request), iface->dev->broadcast);
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
    memcpy(reply->sha, iface->dev->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(reply->spa, &((struct ip_iface*)iface)->unicast, sizeof(uint8_t) * IP_ADDR_LEN);
    memcpy(reply->tha, tha, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(reply->tpa, &tpa, sizeof(uint8_t) * IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(*reply));
    arp_dump((uint8_t*)reply, sizeof(*reply));
    
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t*) reply, sizeof(*reply), dst);
}

static void arp_input(const uint8_t *data, size_t len, struct net_device *dev){
    struct arp_ether* msg;
    struct arp_hdr* hdr;
    struct ip_iface* iface;
    ip_addr_t spa,tpa;
    int merge = 0;


    if(len < sizeof(*msg)){
        errorf("too short");
        return;
    }

    msg = (struct arp_ether*)data;
    hdr = (struct arp_hdr*)msg;

    // Check the type and length of the device and the protocol
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

    pthread_mutex_lock(&mutex);
    if(arp_cache_update(spa,msg->sha)){
        /* updated */
        merge = 1;
    }
    pthread_mutex_unlock(&mutex);

    if(iface && iface->unicast == tpa){
        // Register as a new cache entry if it is not updated.
        if(!merge){
            pthread_mutex_lock(&mutex);
            arp_cache_insert(spa, msg->sha);
            pthread_mutex_unlock(&mutex);
        }
        // Send reply message if the operation type is "Request"
        if(ntoh16(hdr->op) == ARP_OP_REQUEST){
            int ret;
            ret = arp_reply((struct net_iface*)iface, msg->sha, spa, msg->sha);
            if(ret<0){
                errorf("arp_reply() failure");
            }
        }
    }

}

// Set the hardware address corresponding to the IP address to "ha".
int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha){
    struct arp_cache* cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    // Check the device type and protocol type to make sure 
    if(iface->dev->type != NET_DEVICE_TYPE_ETHERNET){
        debugf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    if(iface->family != NET_IFACE_FAMILY_IP){
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }

    pthread_mutex_lock(&mutex);
    cache = arp_cache_select(pa);
    if(!cache){
        // Allocate a new entry and set the value ( Will be completed by arp_cache_update() in arp_input())
        cache = arp_cache_alloc();
        if(!cache){
            errorf("arp_cache_alloc() failure");
            return -1;
        }
        cache->state = ARP_CACHE_STATE_INCOMPLETE;
        cache->pa = pa;
        if(gettimeofday(&cache->timestamp,NULL)<0){ // TODO:gettimeofday() isn't recommended. Use clock_gettime()
            errorf("gettimeofday() failure");
            return NULL;
        }
        arp_request(iface, pa);
        pthread_mutex_unlock(&mutex);
        debugf("cache not found, pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));
        return ARP_RESOLVE_INCOMPLETE;
    }

    // If the found entry is INCOMPLETE, do arp_request() again just in case there was packet loss.
    if(cache->state == ARP_CACHE_STATE_INCOMPLETE){
        arp_request(iface, pa);
        pthread_mutex_unlock(&mutex);
        return ARP_RESOLVE_INCOMPLETE;
    }


    memcpy(ha, cache->ha, ETHER_ADDR_LEN);
    pthread_mutex_unlock(&mutex);

    debugf("resolved, pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return ARP_RESOLVE_FOUND;
}

int arp_init(void){
    if(net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input)<0){
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}