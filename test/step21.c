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
#include "udp.h"
#include "tcp.h"
#include "driver/loopback.h"
#include "driver/ether_tap.h"
#include "test.h"


static volatile sig_atomic_t terminate;

static void on_signal(int s){
    (void)s;
    terminate = 1;
    net_interrupt();
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

    // Set the default gateway on the routing table
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failure");
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
    struct tcp_endpoint local;
    int id;

    struct sigaction* sigact; 
    sigact = calloc(1,sizeof(*sigact));
    sigact->sa_handler = on_signal;
    sigact->sa_flags = 0; 
    sigaction(SIGINT,sigact,NULL);
    //signal(SIGINT,on_signal);

    signal(SIGINT, on_signal);
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    tcp_endpoint_pton("0.0.0.0:7", &local);
    id = tcp_open_rfc793(&local, NULL, 0);
    if (id == -1) {
        errorf("tcp_open_rfc793() failure");
        return -1;
    }

    while (!terminate) {
        sleep(1);
    }

    tcp_close(id);
    cleanup();
    return 0;

    
}
