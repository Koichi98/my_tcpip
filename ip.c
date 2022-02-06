#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "util.h"
#include "net.h"

static void ip_input(const uint8_t *data, size_t len, struct net_device *dev){
    //Debug Output
    debugf("dev=%s, len=%zu", dev->name, len);
    debugdump(data, len);

}

int ip_init(void){
    //Register IP input functions in the protocol stack
    if(net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1){
        errorf("net_protocol_register failure");
        return -1;
    }
    return 0;
}

