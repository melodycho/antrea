#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdio.h>
#include <linux/pkt_cls.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

typedef unsigned int u64;
typedef unsigned int u32;

#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

struct protoport {
    __u16 proto;
    __u16 port;
};

struct bpf_map_def SEC(

"maps")
ip_blocklist = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__be32),
        .value_size = 1,
        .max_entries = 100000,
};


struct bpf_map_def SEC(

"maps")
block_ports = {
        .type           = BPF_MAP_TYPE_HASH,
        .key_size       = sizeof(struct protoport),
        .value_size     = 1,
        .max_entries    = 65535,
};


static __inline int extract_ports(u32 len, void *data_end, struct iphdr *h, struct protoport *dport) {
    struct tcphdr *thdr;
    struct udphdr *uhdr;

    dport->proto = h->protocol;

    switch (h->protocol) {
        case IPPROTO_TCP:
            // Re-check buffer space for TCP (has larger headers than UDP).
            if (len <
                sizeof(struct ethhdr) + sizeof(*h) + sizeof(struct tcphdr)) {
                return 1; // Or maybe drop the packet? It's broken anyways.
            }

            thdr = (void *) ((__u64) (h) + sizeof(*h));
            if ((void *) (thdr + 1) > data_end) {
                return 1;
            };
            dport->port = bpf_ntohs(thdr->dest);
            break;
        case IPPROTO_UDP:
            uhdr = (void *) ((__u64) (h) + sizeof(*h));
            if ((void *) (uhdr + 1) > data_end){
                return 1;
            };
            dport->port = bpf_ntohs(uhdr->dest);
            break;
        default:
            // Neither TCP nor UDP
            return 0;
    }

    return 1;
}


static __inline bool parser_package(void *data_begin, void *data_end) {
    struct ethhdr *eth = data_begin;

    if ((void *) (eth + 1) > data_end) //
        return false;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *) (eth + 1); // or (struct iphdr *)( ((void*)eth) + ETH_HLEN );
        if ((void *) (iph + 1) > data_end)
            return false;

        u32 ip_src = iph->saddr;
        u32 ip_dst = iph->daddr;

        int init_val = 1;

        u64 *value = bpf_map_lookup_elem(&ip_blocklist, &ip_src);
        if (value) {
            bpfprint("src ip addr1: %d.%d.%d\n", (ip_src) & 0xFF, (ip_src >> 8) & 0xFF, (ip_src >> 16) & 0xFF);
            bpfprint("src ip addr2:.%d, %d\n", (ip_src >> 24) & 0xFF, ip_src);

            bpfprint("dest ip addr1: %d.%d.%d\n", (ip_dst) & 0xFF, (ip_dst >> 8) & 0xFF, (ip_dst >> 16) & 0xFF);
            bpfprint("dest ip addr2: .%d\n", (ip_dst >> 24) & 0xFF);

            bpfprint("ip_src found in map and will drop");
            // bpf_map_update_elem(&ip_blocklist, &ip_src, &init_val, BPF_NOEXIST);
            return true;
        }


        struct protoport dport = {0, 0};
        if (extract_ports(data_end - data_begin, data_end, iph, &dport)) {
            u64 *value_port = bpf_map_lookup_elem(&block_ports, &dport);

            if (value_port) {
                //bpf_map_update_elem(&block_ports, &dport, &init_val, BPF_NOEXIST);
                bpfprint("proto/port found in map and will drop: %d, %d", dport.proto, dport.port);
                return true;
            }
        }


    }
    return false;
}


SEC("tc")

int tc_filter_package(struct __sk_buff *skb) {

    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;

    if (parser_package(data, data_end))
        return TC_ACT_SHOT;
    else
        return TC_ACT_OK;
}

char _license[]
SEC("license") = "GPL";
