// dns_logger.c - DNS egress blocker for this pod (tc BPF)
#define KBUILD_MODNAME "dns_egress_blocker"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>   // <- for TC_ACT_SHOT / TC_ACT_OK

char LICENSE[] SEC("license") = "GPL";

SEC("tc")
int dns_egress_blocker(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // L2: Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // L3: IPv4 header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    // L4: start of transport header
    void *l4 = (void *)iph + iph->ihl * 4;
    if (l4 + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;

    // Interpret first 4 bytes as src/dst ports (same layout for TCP/UDP)
    struct udphdr *ports = l4;

    // All DNS (TCP or UDP) uses dest port 53
    if (ports->dest == bpf_htons(53)) {
        // Drop ALL DNS egress from this pod
        return TC_ACT_SHOT;
    }

    // Everything else passes
    return TC_ACT_OK;
}

