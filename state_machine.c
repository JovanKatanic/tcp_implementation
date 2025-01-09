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

uint16_t calculate_checksum(void *data, size_t len) {
    uint32_t sum = 0;
    uint16_t *buf = (uint16_t *)data;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len > 0) {
        sum += *((uint8_t *)buf);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t calculate_ip_checksum(struct iphdr *ip) {
    ip->check=0;
    // Save the current checksum value and set it to 0
    uint16_t old_check = ip->check;
    ip->check = 0;
    
    // Calculate checksum
    uint16_t checksum = calculate_checksum((uint16_t*)ip, sizeof(struct iphdr));
    
    // Restore the old checksum
    ip->check = old_check;
    
    return checksum;
}

uint16_t calculate_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp) {
    tcp->th_sum=0;
    struct pseudo_header psh;
    uint16_t tcp_len = ntohs(ip->tot_len) - (ip->ihl * 4);
    
    // Fill in pseudo header
    psh.source_address = ip->saddr;
    psh.dest_address = ip->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcp_len);
    
    // Calculate total size for checksum
    int total_len = sizeof(struct pseudo_header) + tcp_len;
    char *packet = malloc(total_len);
    if (!packet) return 0;  // Handle malloc failure
    
    // Copy pseudo header and TCP segment
    memcpy(packet, &psh, sizeof(struct pseudo_header));
    memcpy(packet + sizeof(struct pseudo_header), tcp, tcp_len);
    
    // Save old checksum and set to 0 for calculation
    uint16_t old_check = tcp->th_sum;
    tcp->th_sum = 0;
    
    // Calculate checksum
    uint16_t checksum = calculate_checksum((uint16_t*)packet, total_len);
    
    // Restore old checksum and free memory
    tcp->th_sum = old_check;
    free(packet);
    
    return checksum;
}

bool wrapping_lt(uint32_t l, uint32_t r){
    return l-r>(1U << 31);
}

bool is_between(uint32_t start, uint32_t x, uint32_t end){
    // if(end < start){
    //     if(end < x && x <= start){
    //         return false;
    //     }
    // }
    // else if(end > start){
    //     if(!(start < x && x <= end)){
    //         return false;
    //     }
    // }
    // else{
    //     return false;
    // }
    // return true;
    return wrapping_lt(start,x) && wrapping_lt(x,end+1);//end +1 so it covers x<=end
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

bool write_packet(struct connection *conn, int tun_fd, char *data, uint8_t flags) {
    conn->ip_packet.tot_len=htons(sizeof(struct iphdr) + sizeof(struct tcphdr));//todo missing data
    conn->tcp_packet.th_seq=htonl(conn->sent.nxt);
    conn->tcp_packet.th_ack=htonl(conn->recieved.nxt);
    conn->tcp_packet.th_flags=flags;
    conn->ip_packet.check = calculate_ip_checksum(&conn->ip_packet);
    conn->tcp_packet.th_sum = calculate_tcp_checksum(&conn->ip_packet, &conn->tcp_packet);

    //conn->sent.una=conn->sent.nxt; //this makes sense

    char packet[4096];
    memset(packet, 0, 4096);
    memcpy(packet, &conn->ip_packet, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), &conn->tcp_packet, sizeof(struct tcphdr));
    if (write(tun_fd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr)) < 0) {
        perror("Write to TUN interface failed");
        return false;
    } 
    conn->sent.nxt += 0;//todo missing data
    conn->sent.nxt += ((conn->tcp_packet.th_flags & TH_FIN) != 0) + ((conn->tcp_packet.th_flags & TH_SYN)!=0);
    return true;
}

int valid_numbers_check(struct connection *conn,struct tcphdr *tcp_header, uint32_t segment_len,int tun_fd){
    enum state current_state = conn->state;
    struct send_sequence_space sent = conn->sent;
    struct recieve_sequence_space recieved = conn->recieved;

    uint32_t seq=ntohl(tcp_header->th_seq);
    uint32_t seq_win=recieved.nxt + sent.wnd - 1;
    segment_len+=((tcp_header->th_flags & TH_FIN) != 0) + ((tcp_header->th_flags & TH_SYN)!=0);

    if(segment_len == 0 && sent.wnd==0){
        if(seq != recieved.nxt) {
            printf("not a valid seq number 1  ");
            return -1;
        }
    }
    else if(segment_len == 0 && sent.wnd>0){
        if(!is_between(recieved.nxt - 1, seq, recieved.nxt + sent.wnd - 1)){
            printf("not a valid seq number 2  ");
            return -1;
        }    
    }
    else if(segment_len > 0 && sent.wnd==0){
        printf("not a valid seq number 3  ");
        return -1;
    }
    else if(segment_len > 0 && sent.wnd > 0){
        if(!is_between(recieved.nxt - 1, seq, recieved.nxt + sent.wnd - 1) 
        && !is_between(recieved.nxt - 1, seq + segment_len -1, seq_win)){
            printf("not a valid seq number 4  " );
            return -1;
        }  
    }  
    conn->recieved.nxt=ntohl(tcp_header->th_seq)+segment_len;//todo if not acceptable send ack
    if((conn->tcp_packet.th_flags & TH_ACK ) != 0){
        return 0;
    }

    // if(current_state==SynAckSent){
        uint32_t ack=ntohl(tcp_header->th_ack);
    //     if(is_between(sent.una-1, ack, sent.nxt+1)){
    //         //todo should check what state its in adn should set seq and ack numbers accordingly 
    //         // if(current_state==SynAckSent){ //todo not a valid reset format 4:27:25
    //         //     printf("rst sent\n");
    //         //     write_packet(conn,tun_fd,NULL,TH_RST);
    //         //     return 1;

    //         // }
    //         conn->state=Established;
    //     }
    //     else{
    //         //todo reset
    //     }
    //     conn->sent.una=ack;
    // }
    // else if(current_state==Established){
    //     if(!is_between(sent.una, ack, sent.nxt+1)){
    //         printf("not a valid ack\n");
    //     }
    //     conn->sent.una=ack;
    //     write_packet(conn,tun_fd,NULL,TH_FIN );//| TH_ACK
    //     conn->state=FinWait1;
    // }
        if(!is_between(sent.una, ack, sent.nxt+1)){
            printf("not a valid ack\n");
        }
        conn->sent.una=ack;
        

    return 0;
}

void* packet_loop(void* arg){
    struct packet_loop_args* args = (struct packet_loop_args*)arg;
    struct connection_manager* manager=args->manager;
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
            //lock
            hashtable_kv_t key = {};
            key.data = quad;
            key.bytes = sizeof(struct quad);
            hashtable_entry_t* connection_state = hashtable_get(manager->connections, key.data, key.bytes);

            if(connection_state==NULL){ 
                if((tcp_header->th_flags & 0x02) == 0){
                    printf("Not a syn packet\n");
                    continue;
                }

                struct send_sequence_space sent;
                sent.iss=2440000;//2440000 is for testing, should be random
                sent.una=sent.iss;
                sent.nxt=sent.una;
                sent.up=false;//not used
                sent.wnd=10;
                sent.wl1=0;//todo
                sent.wl2=0;

                struct recieve_sequence_space recieved;
                recieved.irs=ntohl(tcp_header->th_seq);
                recieved.nxt=ntohl(tcp_header->th_seq) + 1;
                recieved.wnd=ntohs(tcp_header->th_win);
                recieved.up=false;//not used

                struct iphdr ip_packet;
                ip_packet.ihl=5;
                ip_packet.version=4;
                ip_packet.tos=0;
                ip_packet.tot_len=htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                ip_packet.id=12344;//todo
                ip_packet.frag_off=0;
                ip_packet.ttl=64;
                ip_packet.protocol=6;
                ip_packet.check=0;
                ip_packet.saddr=quad->destination;
                ip_packet.daddr=quad->source;

                struct tcphdr tcp_packet;
                tcp_packet.th_dport=quad->source_port;
                tcp_packet.th_sport = quad->destination_port;
                tcp_packet.th_seq = htonl(sent.iss);    
                tcp_packet.th_ack = htonl(recieved.nxt);//htonl(ntohl(tcp_header->th_seq) + 1);       
                tcp_packet.th_off = 5;     
                tcp_packet.th_flags = TH_SYN | TH_ACK;          
                tcp_packet.th_win = htons(sent.wnd);//htons(64240);//todo   
                tcp_packet.th_sum = 0;                 
                tcp_packet.th_urp = 0;

                ip_packet.check = calculate_ip_checksum(&ip_packet);
                tcp_packet.th_sum = calculate_tcp_checksum(&ip_packet, &tcp_packet);

                hashtable_kv_t val = {};
                val.data = (struct connection *)malloc(sizeof(struct connection));
                val.bytes = sizeof(struct connection);
                struct connection* conn=((struct connection *)val.data);
                conn->sent = sent;
                conn->recieved = recieved;
                conn->state = SynAckSent;
                conn->ip_packet = ip_packet;
                conn->tcp_packet = tcp_packet;
                

                if(!write_packet(conn,args->tun_fd,NULL, TH_SYN | TH_ACK)){
                    close(args->tun_fd);
                    return NULL;
                }

                int r = hashtable_put(manager->connections, &key, &val);
            }
            else{
                struct connection* conn=((struct connection *)connection_state->val.data);
                // print_packet(ip_header);
                // print_tcp_header(tcp_header);
                
                if(valid_numbers_check(conn,tcp_header,segment_len,args->tun_fd)==-1){
                    continue;
                }
                

                switch (conn->state)
                {
                case Closed:
                    printf("\nClosed\n");
                    break;
                case SynAckSent:  
                    // printf("\nSynAck should be unreachable\n");
                    // return -1;
                    
                    if((tcp_header->th_flags & TH_ACK)!=0){
                        conn->state=Established;   
                    }
                    else{
                        //send rst probably
                    }
                              
                    break;
                case Established:  
                    printf("Established\n"); 

                    if((tcp_header->th_flags & TH_FIN)!=0){
                        write_packet(conn,args->tun_fd,NULL,TH_ACK);
                        conn->state=CloseWait;
                    }
                    else if(data[0]=='q'){
                        write_packet(conn,args->tun_fd,NULL,TH_FIN | TH_ACK);//
                        conn->state=FinWait1;
                    }
                    else{
                        for (size_t i = 0; i < segment_len; ++i) {
                            printf("%c", data[i]);
                        }
                        printf("\n");
                        write_packet(conn,args->tun_fd,NULL,TH_ACK);//todo checks if wtite is succ
                    }
                    break; 
                case FinWait1:
                    printf("FinWait1\n");
                    if((tcp_header->th_flags & (TH_ACK | TH_FIN))==0){//todo test if i can use tcp_header->th_flags == TH_FLAG instead of this
                        printf("expected ack or fin");
                    }
                    else if((tcp_header->th_flags & TH_ACK)!=0){
                        conn->state=FinWait2;
                    }
                    else if((tcp_header->th_flags & TH_FIN)!=0){
                        conn->state=Closing;
                    }
                    break;  
                case FinWait2:
                    printf("FinWait2\n");
                    if((tcp_header->th_flags & TH_FIN)==0){//todo test if i can use tcp_header->th_flags == TH_FLAG instead of this
                        printf("expected fin");
                    }
                    else{
                        write_packet(conn,args->tun_fd,NULL,TH_ACK);
                        conn->state=TimeWait;
                    }
                    break; 
                case Closing:
                    if((tcp_header->th_flags & TH_ACK)==0){//todo test if i can use tcp_header->th_flags == TH_FLAG instead of this
                        printf("expected ack");
                    }
                    else{
                        conn->state=TimeWait;
                    }
                    break;  
                case TimeWait:
                    printf("TimeWait\n");
                    break;               
                default:
                    break;
                }
                
            }
            
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
