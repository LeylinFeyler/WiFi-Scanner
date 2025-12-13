#include "netlink.h"
#include "scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <wifi interface>\n", argv[0]);
        return 1;
    }

    const char* iface = argv[1];
    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    struct nl_sock* sock = init_nl_socket();
    int nl80211_id = get_nl80211_id(sock);

    int mcid = genl_ctrl_resolve_grp(sock, "nl80211", "scan");
    if (mcid >= 0) {
        nl_socket_add_membership(sock, mcid);
    } else {
        fprintf(stderr, "Failed to join nl80211 scan multicast group\n");
    }

    trigger_scan(sock, nl80211_id, ifindex);
    wait_for_scan(sock);
    get_scan_results(sock, nl80211_id, ifindex);

    nl_socket_free(sock);
    return 0;
}
