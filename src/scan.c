#include "scan.h"
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <linux/nl80211.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <netlink/attr.h>
#include <time.h>

static int bss_handler(struct nl_msg* msg, void* arg) {
    struct nlattr* attrs[NL80211_ATTR_MAX + 1];
    struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(attrs, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!attrs[NL80211_ATTR_BSS])
        return NL_OK;

    struct nlattr* bss[NL80211_BSS_MAX + 1];
    nla_parse_nested(bss, NL80211_BSS_MAX, attrs[NL80211_ATTR_BSS], NULL);

    if (bss[NL80211_BSS_BSSID]) {
        unsigned char* mac = nla_data(bss[NL80211_BSS_BSSID]);
        printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
        uint8_t* ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        int len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        char ssid[33] = {0};
        int pos = 0;
        while (pos + 1 < len) {
            int id = ie[pos];
            int l = ie[pos + 1];
            if (id == 0 && l <= 32) { // SSID
                memcpy(ssid, ie + pos + 2, l);
                ssid[l] = '\0';
                break;
            }
            if (strlen(ssid) == 0)
                printf("SSID: <hidden>\n");
            else
                printf("SSID: %s\n", ssid);
            pos += 2 + l;
        }
        printf("SSID: %s\n", ssid);
    }

    if (bss[NL80211_BSS_SIGNAL_MBM]) {
        int signal = nla_get_s32(bss[NL80211_BSS_SIGNAL_MBM]) / 100;
        printf("Signal: %d dBm\n", signal);
    }

    if (bss[NL80211_BSS_FREQUENCY]) {
        int freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
        int channel = 0;

        if (freq >= 2412 && freq <= 2472)
            channel = (freq - 2407) / 5;
        else if (freq == 2484)
            channel = 14;
        else if (freq >= 5180 && freq <= 5825)
            channel = (freq - 5000) / 5;

        printf("Channel: %d\n", channel);
    }




    if (bss[NL80211_BSS_CHAN_WIDTH]) {
        printf("Channel info: %d\n", nla_get_u32(bss[NL80211_BSS_CHAN_WIDTH]));
    }

    printf("---------------------\n");
    return NL_OK;
}

void trigger_scan(struct nl_sock* sock, int nl80211_id, int ifindex) {
    struct nl_msg* msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message\n");
        exit(EXIT_FAILURE);
    }

    genlmsg_put(msg, 0, 0, nl80211_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

    if (nl_send_auto(sock, msg) < 0) {
        fprintf(stderr, "Failed to send scan trigger\n");
        nlmsg_free(msg);
        exit(EXIT_FAILURE);
    }

    nlmsg_free(msg);

    // int time_wait = 8;
    // printf("Scanning... (sleep %ds)\n", time_wait);
    // sleep(time_wait);
}

void get_scan_results(struct nl_sock* sock, int nl80211_id, int ifindex) {
    struct nl_msg* msg = nlmsg_alloc();
    if (!msg) exit(EXIT_FAILURE);

    genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, bss_handler, NULL);
    nl_socket_modify_cb(sock, NL_CB_FINISH, NL_CB_DEFAULT, NULL, NULL);
    nl_socket_modify_cb(sock, NL_CB_ACK, NL_CB_DEFAULT, NULL, NULL);    


    if (nl_send_auto(sock, msg) < 0) {
        fprintf(stderr, "Failed to request scan results\n");
        nlmsg_free(msg);
        exit(EXIT_FAILURE);
    }

    nl_socket_disable_seq_check(sock);
    nl_recvmsgs_default(sock);
    nlmsg_free(msg);
}

static int scan_event_handler(struct nl_msg* msg, void* arg) {
    struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));

    if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
        printf("Scan finished\n");
        int* done = arg;
        *done = 1;
    }

    if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
        printf("Scan aborted\n");
        int* done = arg;
        *done = -1;
    }

    return NL_OK;
}


void wait_for_scan(struct nl_sock* sock) {
    int done = 0;
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, scan_event_handler, &done);

    time_t start = time(NULL);
    while (done == 0) {
        nl_recvmsgs_default(sock);

        // таймаут 10 секунд
        if (time(NULL) - start > 10) {
            fprintf(stderr, "Timeout waiting for scan event\n");
            break;
        }
    }

    if (done < 0) exit(EXIT_FAILURE);
}

