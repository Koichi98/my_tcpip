/*
The following commands should be exectuted in another terminal.

$ sudo ip route add 192.0.2.0/24 dev tap0
$ sudo ip link set tap0 up
$ ping 192.0.2.2

*/

#define _XOPEN_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "driver/loopback.h"
#include "driver/ether_tap.h"
#include "test.h"


static volatile sig_atomic_t terminate;

static void on_signal(int s){
    (void)s;
    terminate = 1;
}

static int setup(void){
    struct net_device *dev;
    struct ip_iface *iface;

    if(net_init()==-1){
        errorf("net_init() failure");
        return -1;
    }

    dev = loopback_init();
    if(!dev){
        errorf("loopback_init() failure");
        return -1;
    }

    //Create IP Interface 
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if(!iface){
        errorf("ip_iface_alloc() failure");
        return -1;
    }

    //Register IP Interface
    if(ip_iface_register(dev, iface) == -1){
        errorf("ip_iface_register() failure");
        return -1;
    }

    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if(!dev){
        errorf("loopback_init() failure");
        return -1;
    }

    //Create IP Interface 
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if(!iface){
        errorf("ip_iface_alloc() failure");
        return -1;
    }

    //Register IP Interface
    if(ip_iface_register(dev, iface) == -1){
        errorf("ip_iface_register() failure");
        return -1;
    }
    
    if(net_run()==-1){
        errorf("net_run() failure");
        return -1;
    }

    return 0;
}

static void cleanup(void){
    net_shutdown();
}


int main(int argc, char *argv[]){

    ip_addr_t src, dst;
    uint16_t id, seq = 0;
    size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;

    struct sigaction* sigact; 
    sigact = calloc(1,sizeof(*sigact));
    sigact->sa_handler = on_signal;
    sigact->sa_flags = 0; 
    sigaction(SIGINT,sigact,NULL);
    //signal(SIGINT,on_signal);

    if(setup() == -1){
        errorf("setup() failure");
        return -1;
    }

    ip_addr_pton("192.168.2.5", &src);
    ip_addr_pton("192.168.2.155", &dst);
    id = getpid() % UINT16_MAX;

    while(!terminate){
        if (icmp_output(ICMP_TYPE_ECHO, 0, hton32(id << 16 | ++seq), test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
            errorf("icmp_output() failure");
            break;
        }
        sleep(1);
    }

    cleanup();
    return 0;
}
