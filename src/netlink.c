#include "netlink.h"
#include <netlink/genl/ctrl.h>
#include <stdio.h>
#include <stdlib.h>

struct nl_sock* init_nl_socket() {
    struct nl_sock* sock = nl_socket_alloc();
    if (!sock) {
        fprintf(stderr, "Failed to allocate netlink socket\n");
        exit(EXIT_FAILURE);
    }

    if (genl_connect(sock) != 0) {
        fprintf(stderr, "Failed to connect to generic netlink\n");
        nl_socket_free(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}

int get_nl80211_id(struct nl_sock* sock) {
    int id = genl_ctrl_resolve(sock, "nl80211");
    if (id < 0) {
        fprintf(stderr, "nl80211 not found\n");
        exit(EXIT_FAILURE);
    }
    return id;
}
