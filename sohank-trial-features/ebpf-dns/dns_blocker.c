// dns_blocker.c
#define KBUILD_MODNAME "dns_blocker"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

char LICENSE[] SEC("license") = "GPL";

struct dns_hdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

#define MAX_QNAME_LEN 64

// Parse QNAME into out[] as a lowercase dot-separated string (e.g., "www.facebook.com")
static __always_inline int parse_qname(void *ptr, void *data_end, char out[MAX_QNAME_LEN])
{
    __u8 *cur = ptr;
    int idx = 0;

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAX_QNAME_LEN; i++)
        out[i] = 0;

    while (cur + 1 < (__u8 *)data_end) {
        __u8 len = *cur;
        cur++;

        if (len == 0) {
            // end of name
            break;
        }

        if (len > 63)
            return -1;

        if (cur + len > (__u8 *)data_end)
            return -1;

        // add dot between labels (not at beginning)
        if (idx != 0) {
            if (idx >= MAX_QNAME_LEN - 1)
                return -1;
            out[idx++] = '.';
        }

        #pragma clang loop unroll(full)
        for (int i = 0; i < 63; i++) {
            if (i >= len)
                break;
            if (idx >= MAX_QNAME_LEN - 1)
                return -1;

            char c = cur[i];
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 'a';
            out[idx++] = c;
        }

        cur += len;
    }

    return 0;
}

// Get length of a null-terminated string (up to MAX_QNAME_LEN)
static __always_inline int strnlen64(const char *s)
{
    int n = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < MAX_QNAME_LEN; i++) {
        if (!s[i])
            break;
        n++;
    }
    return n;
}

// Check if name ends with suffix (e.g., ends_with("www.facebook.com", "facebook.com"))
static __always_inline int ends_with(const char *name, const char *suffix)
{
    int nlen = strnlen64(name);
    int slen = strnlen64(suffix);

    if (slen == 0 || slen > nlen)
        return 0;

    int start = nlen - slen;

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAX_QNAME_LEN; i++) {
        if (i >= slen)
            break;
        if (name[start + i] != suffix[i])
            return 0;
    }

    return 1;
}

SEC("tc")
int dns_blocker(struct __sk_buff *skb)
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

    if (iph->protocol != 17)
        return BPF_OK;

    struct udphdr *udph = (void *)iph + iph->ihl * 4;
    if ((void *)(udph + 1) > data_end)
        return BPF_OK;

    // DNS is UDP dst port 53
    if (udph->dest != bpf_htons(53))
        return BPF_OK;

    struct dns_hdr *dns = (void *)(udph + 1);
    if ((void *)(dns + 1) > data_end)
        return BPF_OK;

    // Expect at least one question
    if (bpf_ntohs(dns->qdcount) < 1)
        return BPF_OK;

    void *qname_ptr = (void *)(dns + 1);
    if (qname_ptr >= data_end)
        return BPF_OK;

    char qname[MAX_QNAME_LEN];
    if (parse_qname(qname_ptr, data_end, qname) < 0)
        return BPF_OK;

    // Block anything ending in facebook.com or dropbox.com
    if (ends_with(qname, "facebook.com") || ends_with(qname, "dropbox.com")) {
        return BPF_DROP;
    }

    return BPF_OK;
}

