#ifndef NETLINK_H
#define NETLINK_H

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>

struct nl_sock* init_nl_socket();
int get_nl80211_id(struct nl_sock* sock);

#endif
