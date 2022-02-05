#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

static struct net_device *devices;

// Allocate memory for new device
struct net_device* net_device_alloc(void){
    struct net_device* dev;
    dev = calloc(1,sizeof(dev));
    if(!dev){
        errorf("calloc() failure");
        return NULL;
    }
    return dev;
}

// Register the device to "devices"
int net_device_register(struct net_device *dev){
    static unsigned int index = 0;
    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
    dev->next = devices;
    devices = dev;
    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

//
static int net_device_open(struct net_device *dev){
    if(NET_DEVICE_IS_UP(dev)){
        errorf("already opened, dev=%s",dev->name);
        return -1;
    }
    if(dev->ops->open){
        if(dev->ops->open(dev) == -1){
            errorf("failure, dev=%s", dev->name);
        }
    }
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int net_device_close(struct net_device *dev){
    if(!NET_DEVICE_IS_UP(dev)){
        errorf("not opened, dev=%s",dev->name);
        return -1;
    }
    return 0;
    if(dev->ops->close){
        if(dev->ops->close(dev) == -1){
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst){
    return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev){
    return 0;
}

int net_run(void){
    struct net_device* dev;
    for(dev=devices;dev!=NULL;dev=dev->next){
        if(net_device_open(dev)){
            return -1;
        }
    }
    return 0;
}

void net_shutdown(void){
    struct net_device* dev;
    for(dev=devices;dev!=NULL;dev=dev->next){
        net_device_close(dev);
    }
}

int net_init(void){
    return 0;
}