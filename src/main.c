#include "netlink.h"
#include "scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>

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

    //trigger_scan(sock, nl80211_id, ifindex);
    get_scan_results(sock, nl80211_id, ifindex);

    nl_socket_free(sock);
    return 0;
}
