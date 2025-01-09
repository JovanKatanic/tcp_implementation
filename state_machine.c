#include <pthread.h>
#include <stdint.h>
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
#include "hash_map.h"
#include "utarray.h"

#define TUN_DEVICE "/dev/net/tun"
#define BUFFER_SIZE 1500

void print_packet(const struct iphdr* ip_header){
    printf("\nReceived Packet:\n");
    printf("Version: %d\n", ip_header->version);
    printf("Header Length: %d\n", ip_header->ihl * 4);
    printf("Total Length: %d\n", ntohs(ip_header->tot_len));
    printf("Protocol: %d\n", ip_header->protocol);
    printf("Source IP: %u\n", ip_header->saddr);//todo should print in dotted format address
    printf("Destination IP: %u\n", ip_header->daddr);
}

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

    UT_array* incoming;
    UT_array* unacked;
};

struct connection_manager{
    bool terminate;
    hashtable_t *connections;
    hashtable_t *pending;
    pthread_mutex_t mutex;
    pthread_cond_t recv_var;
    pthread_cond_t pend_var;
};

struct interface{
    struct connection_manager* manager;
    //THREAD??
};

struct tcp_listener{
    struct connection_manager* manager;
    uint16_t port;
};

struct tcp_stream{
    struct connection_manager* manager;
    struct quad* quad;
};

struct packet_loop_args{
    int tun_fd;
    struct connection_manager* manager;
};

void* packet_loop(void* arg){
    struct packet_loop_args* args = (struct packet_loop_args*)arg;
    char buffer[BUFFER_SIZE];
    while(1){
        int nread = read(args->tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("Reading from TUN interface");
            break;
        }
        
        struct iphdr *ip_header = (struct iphdr *)buffer;
        if (ip_header->protocol == IPPROTO_TCP) {
            int ip_header_length = ip_header->ihl * 4;
            struct tcphdr *tcp_header = (struct tcphdr *)(buffer + ip_header_length);
            int tcp_header_length = tcp_header->th_off * 4;

            unsigned char *data=buffer + ip_header_length + tcp_header_length;
            //int data_len = ntohs(ip_header->tot_len) - ip_header_length - tcp_header_length;
            uint32_t segment_len= nread - sizeof(struct iphdr) - sizeof(struct tcphdr);

            //printf("data len is: %u",data_len);
            //print_packet(ip_header);
            //print_tcp_header(tcp_header);
            
            struct quad* quad=malloc(sizeof(struct quad));//connection should not be formed before its established. 
            quad->destination=ip_header->daddr;
            quad->source=ip_header->saddr;
            quad->source_port=tcp_header->source;
            quad->destination_port=tcp_header->dest;

            print_packet(ip_header);
        }
    }
}

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

void* write_read_data(void* arg) {
    struct tcp_stream* stream = (struct tcp_stream*)arg;
    char buff[BUFFER_SIZE];
    printf("write\n");
    printf("shutdown\n");
    while(read_stream(stream,buff)!=0){
        struct iphdr *ip_header = (struct iphdr *)buff;
        print_packet(ip_header);
    }
    return NULL;
}

int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd;

    tun_fd = create_tun_interface(tun_name, IFF_TUN);
    if (tun_fd < 0) {
        fprintf(stderr, "Error creating TUN interface\n");
        return 1;
    }

    struct connection_manager* manager = create_manager();
    struct interface* interface = create_interface(manager,tun_fd);
    struct tcp_listener* listener=bind_ports(interface,80);
    
    while(1){
        struct tcp_stream* stream = accept_connections(listener);
        if(stream==NULL){
            printf("this should not happen stream was null!\n");//todo remove this
            break;
        }

        pthread_t thread; //should join them
        if (pthread_create(&thread, NULL, write_read_data, (void*)stream) != 0) {
            perror("Failed to create thread");
            return 1;
        }
    }

    sleep(1);
    
    return 0;
}
