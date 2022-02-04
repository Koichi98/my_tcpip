#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "net.h"

#define NULL_MTU UINT16_MAX  /*maximum size of IP datagram */

//Initialize "NULL DEVICE" by creating the "net_device" instance
static struct net_device* null_init(void){
    struct net_device *dev;
    dev = net_device_alloc();
    if(!dev){

    }
    dev->type = NET_DEVICE_TYPE_NULL;
    dev->mtu = NULL_MTU;
    dev->hlen = 0; /* non header */
    dev->alen = 0; /*non address*/
    dev->ops = &null_ops;
    if(!net_device_register(dev)){
        errorf("net_device_register() failure");
        return NULL;
    }
    debugf("initialized, dev=%s", dev->name);
    return dev;
}

static int null_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst){
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
}

static struct net_device_ops null_ops = {
    .transmit = null_transmit,
};