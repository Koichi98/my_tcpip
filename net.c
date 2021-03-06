#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>


#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"
#include "udp.h"
#include "tcp.h"

#define NET_THREAD_SLEEP_TIME 1000 /* micro seconds */


struct net_protocol {
    struct net_protocol *next;
    uint16_t type;
    pthread_mutex_t mutex; /*mutex for input queue*/
    struct queue_head queue; /*input queue*/
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

/* NOTE: the data follows immediately after the structure */
struct net_protocol_queue_entry {
    struct net_device *dev;
    size_t len;
};

struct net_timer{
    struct net_timer* next;
    struct timeval interval;
    struct timeval last;
    void (*handler)(void);
};

static struct net_timer *timers;

struct net_interrupt_ctx {
    struct net_interrupt_ctx *prev;
    struct net_interrupt_ctx *next;
    int occurred;
};

static struct {
    struct net_interrupt_ctx *head;
    pthread_mutex_t mutex;
} interrupts;

static volatile sig_atomic_t interrupted;

// Create the net_timer and add to the head of the "timers"
int net_timer_register(struct timeval interval, void (*handler)(void)){
    struct net_timer* timer;
    timer = calloc(1, sizeof(*timer));
    if(!timer){
        return -1;
    }

    // Set the value
    timer->interval = interval;
    if(gettimeofday(&timer->last,NULL)<0){ // TODO:gettimeofday() isn't recommended. Use clock_gettime()
    errorf("gettimeofday() failure");
    return -1;
    }
    timer->handler = handler;

    timer->next = timers;
    timers = timer;

    return 0;
}

static struct net_device *devices;
static struct net_protocol *protocols;

static pthread_t thread;
static volatile sig_atomic_t terminate;

// Allocate memory for new device
struct net_device* net_device_alloc(void){
    struct net_device* dev;
    dev = calloc(1,sizeof(*dev));
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

static int net_device_open(struct net_device *dev){
    if(NET_DEVICE_IS_UP(dev)){
        errorf("already opened, dev=%s",dev->name);
        return -1;
    }
    if(dev->ops->open){
        if(dev->ops->open(dev) == -1){
            errorf("failure, dev=%s", dev->name);
            return -1;
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

int net_device_add_iface(struct net_device *dev, struct net_iface *iface){
    struct net_iface *entry;

    //To make it simple, duplicate registration is not allowed.
    for(entry = dev->ifaces; entry != NULL; entry = entry->next){
        if(entry->family == iface->family){
            errorf("already exists, dev=%s, family=%d", dev->name, entry->family);
            return -1;
        }
    }
    iface->dev = dev;

    // Add to the head of the interfaces list
    iface->next = dev->ifaces;
    dev->ifaces = iface;

    return 0;
}

struct net_iface* net_device_get_iface(struct net_device *dev, int family){
    struct net_iface *iface;

    for(iface=dev->ifaces;iface!=NULL;iface=iface->next){
        if(family == iface->family){
            // Return the pointer to the matching interface
            return iface;
        }
    }

    // Return NULL if the matching interface doesn't exist
    return NULL;

}

int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst){
    if(!NET_DEVICE_IS_UP(dev)){
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    if(len > dev->mtu){
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    if(dev->ops->transmit(dev,type,data,len,dst)==-1){
        errorf("device transmit failure, dev=%s, len=%zu", dev, len);
        return -1;
    };
    return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev){

    struct net_protocol* proto;
    struct net_protocol_queue_entry* entry;
    unsigned int num;

    //Storing in the receive queue of the protocol
    for(proto=protocols;proto!=NULL;proto=proto->next){
        if(proto->type == type){
            //Allocate memory for queue entries, including the data that follows
            entry = calloc(1, sizeof(*entry) + len);
            if(!entry){
                errorf("calloc() failure");
                return -1;
            }

            //Set the values for the entry.
            entry->dev = dev;
            entry->len = len;
            memcpy(entry+1, data, len);

            //Push the entry to the queue
            pthread_mutex_lock(&proto->mutex);
            if(!queue_push(&proto->queue,entry)){
                pthread_mutex_unlock(&proto->mutex);
                errorf("queue_push() failure");
                free(entry);
                return -1;
            }

            //Get the size of the queue after the entry is pushed 
            num = proto->queue.num;
            pthread_mutex_unlock(&proto->mutex);

            debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zu", num, dev->name, type, len);
            debugdump(data, len);
            return 0;
        }
    }
    /* unsupported protocol */
    return 0;
}

int net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev)){
    
    //Check for duplicate registrations
    struct net_protocol* proto;
    for(proto=protocols;proto!=NULL;proto=proto->next){
        if(proto->type == type){
            errorf("protocol already registered, type=0x%04x", type);
            return -1;
        }
    }

    //Allocate memory for struct net_protocol
    struct net_protocol* new_proto;
    new_proto = calloc(1,sizeof(*new_proto));
    if(!new_proto){
        errorf("calloc() failure");
        return -1;
    }

    //Set the values of the new protocol
    new_proto->type = type;
    pthread_mutex_init(&new_proto->mutex, NULL);
    //queue_init(&new_proto->queue);
    new_proto->handler = handler;

    //Add to the head of the protocol list
    new_proto->next = protocols;
    protocols = new_proto;

    infof("registered, type=0x%04x", type);
    return 0;
}

static void* net_thread(void* arg){

    unsigned int count, num;
    struct net_device* dev;
    struct net_protocol* proto;
    struct net_protocol_queue_entry* entry;
    struct net_timer *timer;
    struct timeval now, diff;
    struct net_interrupt_ctx *ctx;

    while(!terminate){

        //Polling for devices
        for(dev=devices;dev!=NULL;dev=dev->next){
            if(dev->ops->poll){ // Skip if the polling function is not defined
                if(dev->ops->poll(dev) == -1){ 
                    count++;
                }
            }
        }

        //Data processing for receive queues of the protocols
        for(proto=protocols;proto!=NULL;proto=proto->next){
            pthread_mutex_lock(&proto->mutex);
            entry = queue_pop(&proto->queue); //Take the entry from the protocol queue
            num = proto->queue.num; //Queue size after the entry is popped 
            pthread_mutex_unlock(&proto->mutex);
            if(!entry){
                continue;
            }
            debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zd", num, entry->dev->name, proto->type, entry->len);
            debugdump((uint8_t *)(entry+1), entry->len);

            proto->handler((uint8_t*)(entry+1), entry->len, entry->dev);
            free(entry);
            count++;
        }

        // Checking "timers" list
        for(timer=timers;timer!=NULL;timer=timer->next){
            gettimeofday(&now, NULL);
            timersub(&now, &timer->last, &diff);
            if(timercmp(&timer->interval, &diff, <) != 0){
                timer->handler();
                gettimeofday(&timer->last, NULL);
                count++;
            }
        }

        // Execute ctx->occured = 1 to each ctx if net_interrupt() is called.
        if (interrupted) {
            debugf("interrupt occurred");
            pthread_mutex_lock(&interrupts.mutex);
            for (ctx = interrupts.head; ctx; ctx = ctx->next) {
                ctx->occurred = 1;
            }
            pthread_mutex_unlock(&interrupts.mutex);
            interrupted = 0;
        }

        //Avoid busy wait
        if(!count){
            usleep(NET_THREAD_SLEEP_TIME);
        }
    }

    return NULL;
}

void net_interrupt(void){
    interrupted = 1;
}

struct net_interrupt_ctx* net_interrupt_subscribe(void){
    struct net_interrupt_ctx *ctx;

    ctx = calloc(1, sizeof(struct net_interrupt_ctx));
    if (!ctx) {
        errorf("calloc() failure");
        return NULL;
    }
    pthread_mutex_lock(&interrupts.mutex);
    if (interrupts.head) {
        ctx->next = interrupts.head;
        interrupts.head->prev = ctx;
    }
    interrupts.head = ctx;
    pthread_mutex_unlock(&interrupts.mutex);
    return ctx;
}

int net_interrupt_occurred(struct net_interrupt_ctx *ctx){
    int occurred;

    pthread_mutex_lock(&interrupts.mutex);
    occurred = ctx->occurred;
    pthread_mutex_unlock(&interrupts.mutex);
    return occurred;
}

int net_interrupt_unsubscribe(struct net_interrupt_ctx *ctx){
    pthread_mutex_lock(&interrupts.mutex);
    if (interrupts.head == ctx) {
        interrupts.head = ctx->next;
    }
    if (ctx->next) {
        ctx->next->prev = ctx->prev;
    }
    if (ctx->prev) {
        ctx->prev->next = ctx->next;
    }
    pthread_mutex_unlock(&interrupts.mutex);
    return 0;
}


int net_run(void){
    struct net_device* dev;
    int err;

    //Open all registered devices
    for(dev=devices;dev!=NULL;dev=dev->next){
        if(net_device_open(dev) == -1){
            return -1;
        }
    }
    debugf("create background thread...");

    //Create the background thread to poll the receive queues of the protocols
    terminate = 0;
    err = pthread_create(&thread, NULL, net_thread, NULL);
    if(err){
        errorf("pthread_create() failure, err=%d", err);
        return -1;
    }
    debugf("running...");
    return 0;
}

void net_shutdown(void){
    struct net_device* dev;
    int err;

    debugf("terminate background thread...");
    terminate = 1;
    err = pthread_join(thread, NULL);
    if(err){
        errorf("pthread_join() failure, err=%d", err);
        return;
    }
    debugf("close all devices...");
    for(dev=devices;dev!=NULL;dev=dev->next){
        net_device_close(dev);
    }
    debugf("shutdown");
}

int net_init(void){
    if(ip_init()<0){
        errorf("ip_init() failure");
        return -1;
    }

    if(icmp_init()<0){
        errorf("icmp_init() failure");
        return -1;
    }

    if(arp_init()<0){
        errorf("arp_init() failure");
        return -1;
    }

    if(udp_init()<0){
        errorf("udp_init() failure");
        return -1;
    }

    if(tcp_init()<0){
        errorf("tcp_init() failure");
        return -1;
    }

    return 0;
}