#ifndef STATE_MACHINE
#define STATE_MACHINE


// #include "hash_map.h"

// struct connection_manager{
//     pthread_mutex_t mutex;
//     hashtable_t connections; //key = quad && val = connection
//     hashtable_t pending; //key = port(u16) && val = list<quad>
// };

struct interface create_interface(char *tun_name);
//void bind_interface(struct interface *iface,struct connection_manager *cm, uint16_t port);

#endif