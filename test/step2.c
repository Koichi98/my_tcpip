//#define _XOPEN_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "driver/loopback.h"
#include "test.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s){
    (void)s;
    terminate = 1;
}


int main(int argc, char *argv[]){

    struct net_device *dev;

    /*struct sigaction* sigact; TODO::なぜか"Segmentation fault (コアダンプ)"が起きる
    memset(&sigact, 0, sizeof(sigact));
    sigact->sa_handler = on_signal;
    sigact->sa_flags = 0; 
    sigaction(SIGINT,sigact,NULL);*/
    signal(SIGINT,on_signal);

    //errorf("net_init() failure");
    if(net_init()==-1){
        errorf("net_init() failure");
        return -1;
    }

    dev = loopback_init();
    if(!dev){
        errorf("loopback_init() failure");
        return -1;
    }
    
    if(net_run()==-1){
        errorf("net_run() failure");
        return -1;
    }

    while(!terminate){
        if(net_device_output(dev,0x0800,test_data,sizeof(test_data),NULL)==-1){
            errorf("net_device_output() failure");
            break;
        }
        sleep(1);
    }

    net_shutdown();
    return 0;
}
