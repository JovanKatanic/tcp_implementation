#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnet.h>
#include <stdbool.h>

#define HASHTABLE_IMPLEMENTATION
#include "state_machine.h"

#define TUN_DEVICE "/dev/net/tun"
#define BUFFER_SIZE 1500

enum state {
    Closed=0,
    SynAckSent=1,
    Established=2,
    FinWait1=3,
    FinWait2=4,
    Closing=5,
    TimeWait=6,
    CloseWait=7,
};
struct quad {
    uint32_t source;
    uint32_t destination;
    uint16_t source_port;
    uint16_t destination_port;
};
struct send_sequence_space{
    uint32_t una;
    uint32_t nxt;
    uint16_t wnd;
    bool up;
    uint32_t wl1;
    uint32_t wl2;
    uint32_t iss;
};
struct recieve_sequence_space{
    uint32_t nxt;
    uint16_t wnd;
    bool up;
    uint32_t irs;
};
struct connection{
    enum state state;
    struct send_sequence_space sent;
    struct recieve_sequence_space recieved;
    struct iphdr ip_packet;
    struct tcphdr tcp_packet;
};


struct interface{
    pthread_mutex_t mutex;//pthread_mutex_lock(&(nameofstruct->mutex))
    pthread_t main_th;//join handle
};

int create_tun_interface(char *dev_name, int flags) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open(TUN_DEVICE, O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags | IFF_NO_PI; // IFF_NO_PI disables packet information header
    if (*dev_name) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
    }
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }
    strcpy(dev_name, ifr.ifr_name);
    
    return fd;
}

void *packet_loop(){

}

struct interface create_interface(char *tun_name){
    int tun_fd = create_tun_interface(tun_name, IFF_TUN);
    if (tun_fd < 0) {
        fprintf(stderr, "Error creating TUN interface\n");
        exit(EXIT_FAILURE);
    }

    struct interface iface;
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, packet_loop, NULL) != 0) {
        perror("Failed to create thread");
        exit(EXIT_FAILURE);
    }
    iface.main_th=thread_id;

    if (pthread_mutex_init(&(iface.mutex), NULL) != 0) {
        perror("Mutex initialization failed");
        exit(EXIT_FAILURE);
    }

    return iface;
}

void bind_interface(struct interface *iface,struct connection_manager *cm, uint16_t port){
    pthread_mutex_lock(&(iface->mutex));

    hashtable_kv_t key = {};
    key.data = &port;
    key.bytes = sizeof(uint16_t);
    if(hashtable_get(&cm->connections, key.data, key.bytes)==NULL){
        hashtable_kv_t val = {};
        val.data = (int *)malloc(sizeof(int));//todo should be a deque
        val.bytes = sizeof(int);
        int r = hashtable_put(&cm->connections, &key, &val);//todo missing check
    }
    else{
        printf("Port is already in use");
    }
    pthread_mutex_unlock(&(iface->mutex));
    //todo return a tcp listener
}



void drop(struct interface* i){

}



