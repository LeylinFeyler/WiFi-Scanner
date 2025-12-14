#ifndef SCAN_H
#define SCAN_H

#include <netlink/netlink.h>

// ініціює активне wifi-сканування через nl80211
void trigger_scan(struct nl_sock* sock, int nl80211_id, int ifindex);

// запитує та обробляє результати останнього сканування
void get_scan_results(struct nl_sock* sock, int nl80211_id, int ifindex);

// очікує подію завершення або скасування сканування
void wait_for_scan(struct nl_sock* sock);

#endif
