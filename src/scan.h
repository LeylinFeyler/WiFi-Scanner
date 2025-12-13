#ifndef SCAN_H
#define SCAN_H

#include <netlink/netlink.h>

void trigger_scan(struct nl_sock* sock, int nl80211_id, int ifindex);
void get_scan_results(struct nl_sock* sock, int nl80211_id, int ifindex);

#endif
