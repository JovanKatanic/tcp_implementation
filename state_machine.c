#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <pthread.h>

#include "infrastructure.h"

void* write_read_data(void* arg) {
    struct tcp_stream* stream = (struct tcp_stream*)arg;
    char buff[1500];
    printf("write\n");
    printf("shutdown\n");
    while(read_stream(stream,buff)!=0){
        struct iphdr *ip_header = (struct iphdr *)buff;
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
    
    return 0;
}
