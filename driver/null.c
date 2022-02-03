#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "net.h"

#define NULL_MTU UINT16_MAX  /*maximum size of IP datagram */


static net_device * null_init(void){
    struct net_device *dev;

}

static int null_transmit(){

}

static struct net_device_ops null_ops = {
    .transmit = null_transmit,
};