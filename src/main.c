#include "netlink.h"
#include "scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>

int main(int argc, char* argv[]) {
    // перевірка аргументів командного рядка
    if (argc < 2) {
        printf("Usage: %s <wifi interface>\n", argv[0]);
        return 1;
    }

    const char* iface = argv[1];

    // отримування ifindex за іменем інтерфейсу
    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    // ініціалізація netlink
    struct nl_sock* sock = init_nl_socket();
    int nl80211_id = get_nl80211_id(sock);

    // підписка на multicast сканування
    int mcid = genl_ctrl_resolve_grp(sock, "nl80211", "scan");
    if (mcid >= 0) {
        nl_socket_add_membership(sock, mcid);
    } else {
        fprintf(stderr, "failed to join nl80211 scan multicast group\n");
    }

    // запуск сканування
    trigger_scan(sock, nl80211_id, ifindex);

    // очікування завершення сканування
    wait_for_scan(sock);

    // отримання та вивід результатів
    get_scan_results(sock, nl80211_id, ifindex);

    // звільнення ресурсів
    nl_socket_free(sock);
    return 0;
}
