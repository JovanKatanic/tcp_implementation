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
void print_packet(const struct ip* ip_header){
    printf("\nReceived Packet:\n");
    printf("Version: %d\n", ip_header->ip_v);
    printf("Header Length: %d\n", ip_header->ip_hl * 4);
    printf("Total Length: %d\n", ntohs(ip_header->ip_len));
    printf("Protocol: %d\n", ip_header->ip_p);
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
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
bool is_between(uint32_t start, uint32_t x, uint32_t end){
    if(end < start){
        if(end < x && x <= start){
            return false;
        }
    }
    else if(end > start){
        if(!(start < x && x <= end)){
            return false;
        }
    }
    else{
        return false;
    }
    return true;
}

enum state {
    Closed=0,
    SynAckSent=1,
    Established=2,
};
struct quad {
    struct in_addr source;
    struct in_addr destination;
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
};

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

        struct ip *ip_header = (struct ip *)buffer;
        if (ip_header->ip_p == IPPROTO_TCP) {
            unsigned int ip_header_length = ip_header->ip_hl * 4;
            struct tcphdr *tcp_header = (struct tcphdr *)(buffer + ip_header_length);

            //print_packet(ip_header);
            //print_tcp_header(tcp_header);
            
            struct quad* quad=malloc(sizeof(struct quad));//connection should not be formed before its established. 
            quad->destination=ip_header->ip_dst;
            quad->source=ip_header->ip_src;
            quad->source_port=tcp_header->source;
            quad->destination_port=tcp_header->dest;
            hashtable_kv_t key = {};
            key.data = quad;
            key.bytes = sizeof(struct quad);
            hashtable_entry_t* connection_state = hashtable_get(connections, key.data, key.bytes);

            if(connection_state==NULL){ 
                if((tcp_header->th_flags & 0x02) == 0){
                    printf("Not a syn packet");
                    return -1;
                }

                struct send_sequence_space sent;
                sent.iss=htonl(2440000);//2440000 is for testing, should be random
                sent.una=sent.iss;
                sent.nxt=htonl(sent.una + 1);
                sent.up=false;//not used
                sent.wnd=htons(10);
                sent.wl1=0;//todo
                sent.wl2=0;

                struct recieve_sequence_space recieved;
                recieved.irs=tcp_header->th_seq;
                recieved.nxt=htonl(ntohl(tcp_header->th_seq) + 1);
                recieved.wnd=htons(tcp_header->th_win);
                recieved.up=false;//not used

                if(!is_between(sent.una, tcp_header->th_ack, sent.nxt)){
                    printf("not a valid ack number");
                    return -1;
                }
                if(!is_between(recieved.nxt - 1, tcp_header->th_seq, recieved.nxt + sent.wnd - 1)){
                    printf("not a valid seq number");
                    return -1;
                }
                //todo
                if(!is_between(recieved.nxt - 1, tcp_header->th_seq + ip_packet->ip_len - ip_packet->ip_hl*4 - 1, recieved.nxt + sent.wnd - 1)){
                    printf("not a valid seq number");
                    return -1;
                }

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
                ip_packet.saddr=(quad->destination).s_addr;
                ip_packet.daddr=(quad->source).s_addr;

                struct tcphdr tcp_packet;
                tcp_packet.th_dport=quad->source_port;
                tcp_packet.th_sport = quad->destination_port;
                tcp_packet.th_seq = sent.iss;    
                tcp_packet.th_ack = recieved.nxt;//htonl(ntohl(tcp_header->th_seq) + 1);       
                tcp_packet.th_off = 5;     
                tcp_packet.th_flags = TH_SYN | TH_ACK;          
                tcp_packet.th_win = sent.wnd;//htons(64240);//todo   
                tcp_packet.th_sum = 0;                 
                tcp_packet.th_urp = 0;

                ip_packet.check = calculate_ip_checksum(&ip_packet);
                tcp_packet.th_sum = calculate_tcp_checksum(&ip_packet, &tcp_packet);

                char packet[4096];
                memset(packet, 0, 4096);
                memcpy(packet, &ip_packet, sizeof(struct iphdr));
                memcpy(packet + sizeof(struct iphdr), &tcp_packet, sizeof(struct tcphdr));
                if (write(tun_fd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr)) < 0) {
                    perror("Write to TUN interface failed");
                    close(tun_fd);
                    return 1;
                } 

                hashtable_kv_t val = {};
                val.data = (struct connection *)malloc(sizeof(struct connection));
                ((struct connection *)val.data)->sent = sent;
                ((struct connection *)val.data)->recieved = recieved;
                ((struct connection *)val.data)->state = SynAckSent;
                val.bytes = sizeof(struct connection);
                int r = hashtable_put(connections, &key, &val);
            }
            else{
                enum state current_state = ((struct connection *)connection_state->val.data)->state;
                switch (current_state)
                {
                case Closed:
                    printf("\nClosed\n");
                    break;
                case SynAckSent:  
                    printf("\nSynAck\n");                
                    break;
                case Established:  
                    printf("\nEstablished\n");                
                    break;    
                default:
                    break;
                }
            }
            
        } else {
            //printf("\nNon-TCP packet (Protocol: %d) received\n", ip_header->ip_p);
        }
    }

    close(tun_fd);
    return 0;
}
