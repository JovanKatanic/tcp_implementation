#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
//#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>

#include "hash_map.h"
#include "utarray.h"

#include "tcp.h"
#include "infrastructure.h"

#define TUN_DEVICE "/dev/net/tun"

int create_tun_interface(char *dev_name, int flags) {
    struct ifreq ifr;
    int fd, err;

    // Open the TUN device
    if ((fd = open(TUN_DEVICE, O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    // Set the interface flags (TUN or TAP, and persistent)
    ifr.ifr_flags = flags | IFF_NO_PI; // IFF_NO_PI disables packet information header
    if (*dev_name) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ); // Set the name if provided
    }

    // Create the interface
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }

    // Copy the actual interface name back
    strcpy(dev_name, ifr.ifr_name);

    return fd;
}

struct connection_manager* create_manager(){//todo validity checks
    struct connection_manager* manager=malloc(sizeof(struct connection_manager));
    if (!manager) {
        return NULL;  
    }

    manager->terminate = false;
    manager->connections=hashtable_create(16);
    manager->pending=hashtable_create(16);

    pthread_mutex_init(&manager->mutex, NULL);
    pthread_cond_init(&manager->recv_var, NULL);
    pthread_cond_init(&manager->pend_var, NULL);

    return manager;
}

struct interface* create_interface(struct connection_manager* manager, int tun_fd){
    struct interface* interface = malloc(sizeof(struct interface));
    interface->manager=manager;

    struct packet_loop_args* args = malloc(sizeof(struct packet_loop_args));
    args->tun_fd=tun_fd;
    args->manager=manager;

    pthread_t thread;
    if (pthread_create(&thread, NULL, packet_loop, args) != 0) {
        perror("Failed to create thread");
        return NULL;
    }
    
    return interface;
}

struct tcp_listener* bind_ports(struct interface* interface,uint16_t port){

    struct connection_manager* manager = interface->manager;
    hashtable_kv_t key = {};
    key.data = &port;
    key.bytes = sizeof(uint16_t);
    
    if(hashtable_get(manager->pending, key.data, key.bytes)==NULL){
        UT_array *queue;
        utarray_new(queue, &ut_int_icd);
        hashtable_kv_t val = {};
        val.data = queue;
        val.bytes = sizeof(UT_array);
        hashtable_put(manager->pending, &key, &val);
    }
    else{
        printf("port %u is already taken\n",port);
        exit(EXIT_FAILURE);
    }
    struct tcp_listener* listener = malloc(sizeof(struct tcp_listener));
    listener->manager=interface->manager;
    listener->port=port;
    return listener;
}

struct tcp_stream* accept_connections(struct tcp_listener* listener){
    hashtable_kv_t key = {};
    uint16_t port = listener->port;
    key.data = &port;
    key.bytes = sizeof(port);

    pthread_mutex_lock(&(listener->manager->mutex));

    hashtable_entry_t* entry=hashtable_get(listener->manager->pending, key.data, key.bytes);
    if(entry==NULL){
        printf("port not available\n");
        exit(EXIT_FAILURE);//todo remove this.  makes our system vunerable
    }
    UT_array* queue = (UT_array*) entry->val.data;
    if(queue==NULL){
        printf("q was NULL\n");
        exit(EXIT_FAILURE);
    }
    //printf("len is %u\n",utarray_len(queue));
    while(utarray_len(queue)==0){ 
        pthread_cond_wait(&(listener->manager->pend_var), &(listener->manager->mutex));
    }

    struct quad* quad = utarray_front(queue);
    struct tcp_stream* stream = malloc(sizeof(struct tcp_stream));
    stream->manager=listener->manager;
    stream->quad=quad;
    pthread_mutex_unlock(&(listener->manager->mutex));
    return stream;
}

int read_stream(struct tcp_stream* stream,char* buff){
    hashtable_kv_t key = {};
    key.data = stream->quad;
    key.bytes = sizeof(struct quad);
    pthread_mutex_lock(&(stream->manager->mutex));
    
    while(1){
        hashtable_entry_t* entry=hashtable_get(stream->manager->connections, key.data, key.bytes);
        if(entry==NULL){
            printf("connection has been terminated\n");
            exit(EXIT_FAILURE);//todo remove this.  makes our system vunerable
        }  
        struct connection* conn = (struct connection*) entry->val.data;
        if(conn==NULL){
            printf("connection was NULL\n");
            exit(EXIT_FAILURE);
        }
        //todo handle when connection is closed
        //if(conn.is_terminated && utarray_len(conn->incoming)==0)return 0;

        if(utarray_len(conn->incoming)!=0){
            char* incom = utarray_front(conn->incoming);
            int n=strlen(incom) + 1;
            memcpy(buff, incom, n);
            return n;
        }

        
        pthread_cond_wait(&(stream->manager->recv_var), &(stream->manager->mutex));
    }
    pthread_mutex_unlock(&(stream->manager->mutex));
    return -1;
}
