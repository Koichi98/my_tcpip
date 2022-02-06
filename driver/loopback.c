#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "net.h"

#define LOOPBACK_MTU UINT16_MAX  /*maximum size of IP datagram */

static int loopback_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst){
    int ret;
    if((ret = net_input_handler(type, data, len, dev)) == -1){
        errorf("net input handler failure, dev=%s, len=%zu", dev, len);
    }
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data,len);
    /*drop data*/
    return ret;
}

static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

//Initialize "LOOPBACK DEVICE" by creating the "net_device" instance
struct net_device* loopback_init(void){
    struct net_device *dev;

    dev = net_device_alloc();
    if(!dev){
        errorf("net_device_alloc() failure");
        return NULL;
    }
    dev->type = NET_DEVICE_TYPE_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;
    dev->hlen = 0; /* non header */
    dev->alen = 0; /*non address*/
    dev->ops = &loopback_ops;
    if(net_device_register(dev) == -1){
        errorf("net_device_register() failure");
        return NULL;
    }
    debugf("initialized, dev=%s", dev->name);
    return dev;
}
