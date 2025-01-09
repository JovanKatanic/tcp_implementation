#ifndef INFRASTRUCTURE_H
#define INFRASTRUCTURE_H

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

int create_tun_interface(char *dev_name, int flags);

struct connection_manager* create_manager();

struct interface* create_interface(struct connection_manager* manager, int tun_fd);

struct tcp_listener* bind_ports(struct interface* interface, uint16_t port);

struct tcp_stream* accept_connections(struct tcp_listener* listener);

int read_stream(struct tcp_stream* stream,char* buff);

#endif