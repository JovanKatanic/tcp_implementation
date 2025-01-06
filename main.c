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
#include <libnet.h>//can i remove it???

#define HASHTABLE_IMPLEMENTATION
#include "hash_map.h"

#define TUN_DEVICE "/dev/net/tun"
#define BUFFER_SIZE 1500

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
void print_packet(const struct iphdr* ip_header){
    printf("\nReceived Packet:\n");
    printf("Version: %d\n", ip_header->version);
    printf("Header Length: %d\n", ip_header->ihl * 4);
    printf("Total Length: %d\n", ntohs(ip_header->tot_len));
    printf("Protocol: %d\n", ip_header->protocol);
    printf("Source IP: %u\n", ip_header->saddr);//todo should print in dotted format address
    printf("Destination IP: %u\n", ip_header->daddr);
}
void print_tcp_header(const struct tcphdr *tcp_header) {
    printf("Source port: %u\n", ntohs(tcp_header->source));
    printf("Destination port: %u\n", ntohs(tcp_header->dest));
    uint8_t flags=tcp_header->th_flags;
    if (flags & 0x01) printf("FIN ");
    if (flags & 0x02) printf("SYN ");
    if (flags & 0x04) printf("RST ");
    if (flags & 0x08) printf("PSH ");
    if (flags & 0x10) printf("ACK ");
    if (flags & 0x20) printf("URG ");
    printf("\n");
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
};
bool write_packet(struct connection *conn, int *tun_fd, char *data, uint8_t flags) {
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
    if (write(*tun_fd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr)) < 0) {
        perror("Write to TUN interface failed");
        return false;
    } 
    conn->sent.nxt += 0;//todo missing data
    conn->sent.nxt += ((conn->tcp_packet.th_flags & TH_FIN) != 0) + ((conn->tcp_packet.th_flags & TH_SYN)!=0);
    return true;
}
int valid_numbers_check(struct connection *conn,struct tcphdr *tcp_header, uint32_t segment_len,int *tun_fd){
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
    //     write_packet(conn,&tun_fd,NULL,TH_FIN );//| TH_ACK
    //     conn->state=FinWait1;
    // }
        if(!is_between(sent.una, ack, sent.nxt+1)){
            printf("not a valid ack\n");
        }
        conn->sent.una=ack;
        

    return 0;
}
void print_send_sequence_space(struct send_sequence_space sent) {
    printf("Send Sequence Space:\n");
    printf("  ISS: %u\n", sent.iss);
    printf("  UNA: %u\n", sent.una);
    printf("  NXT: %u\n", sent.nxt);
    printf("  UP: %s\n", sent.up ? "true" : "false");
    printf("  WND: %u\n", sent.wnd);
    printf("  WL1: %u\n", sent.wl1);
    printf("  WL2: %u\n", sent.wl2);
}

// Function to print receive sequence space
void print_receive_sequence_space(struct recieve_sequence_space recieved) {
    printf("Receive Sequence Space:\n");
    printf("  IRS: %u\n", recieved.irs);
    printf("  NXT: %u\n", recieved.nxt);
    printf("  WND: %u\n", recieved.wnd);
    printf("  UP: %s\n", recieved.up ? "true" : "false");
}

int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd;

    // Create a TUN interface
    tun_fd = create_tun_interface(tun_name, IFF_TUN);
    if (tun_fd < 0) {
        fprintf(stderr, "Error creating TUN interface\n");
        return 1;
    }
    printf("Created TUN interface: %s\n", tun_name);

    char buffer[BUFFER_SIZE];
    hashtable_t* connections = hashtable_create(16);
    if (connections == NULL) {
        perror("hashtable_create() failed");
        return 1;
    }

    while (1) {
        // Read packets from the TUN interface
        int nread = read(tun_fd, buffer, sizeof(buffer));
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
            hashtable_kv_t key = {};
            key.data = quad;
            key.bytes = sizeof(struct quad);
            hashtable_entry_t* connection_state = hashtable_get(connections, key.data, key.bytes);

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
                

                if(!write_packet(conn,&tun_fd,NULL, TH_SYN | TH_ACK)){
                    close(tun_fd);
                    return -1;
                }

                int r = hashtable_put(connections, &key, &val);
            }
            else{
                struct connection* conn=((struct connection *)connection_state->val.data);
                // print_packet(ip_header);
                // print_tcp_header(tcp_header);
                
                if(valid_numbers_check(conn,tcp_header,segment_len,&tun_fd)==-1){
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
                        write_packet(conn,&tun_fd,NULL,TH_ACK);
                        conn->state=CloseWait;
                    }
                    else if(data[0]=='q'){
                        write_packet(conn,&tun_fd,NULL,TH_FIN | TH_ACK);//
                        conn->state=FinWait1;
                    }
                    else{
                        for (size_t i = 0; i < segment_len; ++i) {
                            printf("%c", data[i]);
                        }
                        printf("\n");
                        write_packet(conn,&tun_fd,NULL,TH_ACK);//todo checks if wtite is succ
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
                        write_packet(conn,&tun_fd,NULL,TH_ACK);
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
            
        } else {
            //printf("\nNon-TCP packet (Protocol: %d) received\n", ip_header->protocol);
        }
    }

    close(tun_fd);
    return 0;
}
