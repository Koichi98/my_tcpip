#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "util.h"
#include "net.h"
#include "ether.h"

#include "ether_tap.h"

#define CLONE_DEVICE "/dev/net/tun"

struct ether_tap{
    char name[IFNAMSIZ];
    int fd;
};

#define PRIV(x) ((struct ether_tap *)x->priv)

static int ether_tap_addr(struct net_device *dev){
    int soc;
    struct ifreq ifr = {}; // Structure used to request/response at ioctl()

    // Open the socket only to execute ioctl() with SIOCGIFHWADDR (Since SIOCGIFHWADDR can only be applied to file descripter opened as a socket)
    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if(soc<0){
        errorf("socket: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name)-1);
    // Get the hardware address
    if(ioctl(soc, SIOCGIFHWADDR, &ifr) < 0){
        errorf("ioctl [SIOCGIFHADDR]: %s, dev=%s", strerror(errno), dev->name);
        close(soc);
        return -1;
    }
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(soc);
    return 0;
}

static int ether_tap_open(struct net_device *dev){
    struct ether_tap *tap;
    struct ifreq ifr = {}; // Structure used to request/response at ioctl()

    tap = PRIV(dev);
    // Open the control device of TUN/TAP
    tap->fd = open(CLONE_DEVICE, O_RDWR);
    if(tap->fd<0){
        errorf("open: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }
    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name)-1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI; // Setting of flags ( IFF_TAP:TAP Mode, IFF_NO_PI:Not adding a header of packet info)

    // Create TAP device 
    if(ioctl(tap->fd, TUNSETIFF, &ifr)<0){ 
        errorf("ioctl [TUNSETIFF]: %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    
    if(memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0){ // If the hardware address is not specified
        if(ether_tap_addr(dev)<0){ // Get and use the hardware address of the TAP device that is visible to OS.
            errorf("ether_tap_addr() failure, dev=%s",dev->name);
            close(tap->fd);
            return -1;
        }
    }
    return 0;
}

static int ether_tap_close(struct net_device *dev){
    close(PRIV(dev)->fd);
    return 0;
}

static ssize_t ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen){
    int ret;
    ret = write(PRIV(dev)->fd, frame, flen);
    printf("flen:%d\n",flen);
    printf("ret:%d\n",ret);
    if (ret<0){
        errorf("write: %s, dev=%s", strerror(errno), dev->name);
    }
    return ret;
}

int ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst){
    return ether_transmit_helper(dev, type, buf, len, dst, ether_tap_write);
}

static ssize_t ether_tap_read(struct net_device *dev, uint8_t *buf, size_t size){
    ssize_t len;

    len = read(PRIV(dev)->fd, buf, size);
    if(len<=0){
        if(len<0 && errno != EINTR){
            errorf("read: %s, dev=%s", strerror(errno), dev->name);
        }
        return -1;
    }
    return len;
}

static int ether_tap_poll(struct net_device *dev){
    struct pollfd pfd;
    int ret;

    pfd.fd = PRIV(dev)->fd;
    pfd.events= POLLIN;
    ret = poll(&pfd, 1, 0); // The third argument specifies timeout value: By setting 0, the timeout occurs immediately if it is not readable 
    switch(ret){
        case -1:
            if(errno != EINTR){
                errorf("poll: %s, dev=%s", strerror(errno), dev->name);
            }
            /* fall through */
        case 0: // Timeout
            return -1;
    }
    return ether_poll_helper(dev, ether_tap_read);
}

static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
    .poll = ether_tap_poll,
};

struct net_device* ether_tap_init(const char *name, const char *addr){
    struct net_device *dev;
    struct ether_tap *tap;

    // Create device
    dev = net_device_alloc();
    if(!dev){
        errorf("net_device_alloc() failure");
        return NULL;
    }

    // Set common parameters of Ethernet device
    ether_setup_helper(dev);
    // Use the hardware address if it is given as argument
    if(addr){
        if(ether_addr_pton(addr, dev->addr) == -1){
            errorf("invalid address, addr=%s",addr);
            return NULL;
        }
    }

    // Set functions for the driver
    dev->ops = &ether_tap_ops;

    // Create and set private data used internally in driver
    tap = calloc(1, sizeof(*tap));
    if(!tap){
        errorf("calloc() failure");
        return NULL;
    }
    strncpy(tap->name, name, sizeof(tap->name)-1);
    tap->fd = -1;
    dev->priv = tap;
    if(net_device_register(dev)<0){
        errorf("net_device_register() failure");
        free(tap);
        return NULL;
    }
    debugf("ethernet device initialized, dev=%s", dev->name);
    return dev;
}
