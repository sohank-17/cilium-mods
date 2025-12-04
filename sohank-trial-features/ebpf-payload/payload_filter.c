// payload_filter.c
#define KBUILD_MODNAME "payload_filter"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>   // <-- add this
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>         // <-- add this (for IPPROTO_TCP)

char LICENSE[] SEC("license") = "GPL";

// 1 MB threshold
#define MAX_PAYLOAD 40

// Helper: compute TCP payload length from IP header
static __always_inline int get_tcp_payload_len(void *data, void *data_end,
                                               struct iphdr *iph,
                                               struct tcphdr *tcph)
{
    __u16 ip_tot_len = bpf_ntohs(iph->tot_len);
    __u8 ip_hdr_len = iph->ihl * 4;
    __u8 tcp_hdr_len = tcph->doff * 4;

    if (ip_tot_len < ip_hdr_len + tcp_hdr_len)
        return 0;

    return ip_tot_len - ip_hdr_len - tcp_hdr_len;
}

// Attach at TC egress
SEC("tc")
int payload_filter(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return BPF_OK;

    // Only IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return BPF_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return BPF_OK;

    // Only TCP
    if (iph->protocol != IPPROTO_TCP)
        return BPF_OK;

    struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
    if ((void *)(tcph + 1) > data_end)
        return BPF_OK;

    int payload_len = get_tcp_payload_len(data, data_end, iph, tcph);
    if (payload_len <= 0)
        return BPF_OK;

    // Drop if payload > 1 MB
    if (payload_len > MAX_PAYLOAD) {
        return BPF_DROP;
    }

    return BPF_OK;
}

