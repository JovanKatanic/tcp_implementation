#ifndef TCP_H
#define TCP_H

#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUFFER_SIZE 1500

struct connection_manager{
    bool terminate;
    hashtable_t *connections;
    hashtable_t *pending;
    pthread_mutex_t mutex;
    pthread_cond_t recv_var;
    pthread_cond_t pend_var;
};

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

struct packet_loop_args{
    int tun_fd;
    struct connection_manager* manager;
};

void print_tcp_header(const struct tcphdr *tcp_header);

void print_packet(const struct iphdr* ip_header);

void print_send_sequence_space(struct send_sequence_space* sent) ;

void print_receive_sequence_space(struct recieve_sequence_space* recieved) ;

bool write_packet(struct connection *conn, int tun_fd, char *data, uint8_t flags);

void* packet_loop(void* arg);

#endif