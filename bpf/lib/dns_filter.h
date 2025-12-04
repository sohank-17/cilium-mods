/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_DNS_FILTER_H_
#define __LIB_DNS_FILTER_H_

#include "common.h"
#include "maps.h"
#include "eth.h"
#include "dbg.h"
#include "udp.h"

/* Maximum DNS domain name length */
#define DNS_MAX_NAME_LENGTH 255

/* DNS header structure */
struct dnshdr {
	__u16 transaction_id;
	__u16 flags;
	__u16 questions;
	__u16 answers;
	__u16 authorities;
	__u16 additionals;
} __packed;

/* Map key for DNS filter - uses identity and domain hash */
struct dns_filter_key {
	__u32 identity;     /* Security identity or namespace ID */
	__u32 domain_hash;  /* Hash of the blocked domain */
} __packed;

/* Map value for DNS filter */
struct dns_filter_value {
	__u8 action;  /* 0 = allow, 1 = block */
} __packed;

/* Map to store blocked domains per identity */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dns_filter_key);
	__type(value, struct dns_filter_value);
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} DNS_FILTER_MAP __section_maps_btf;

/* Structure for logging DNS filter events */
struct dns_filter_event {
	__u32 identity;
	__u32 domain_hash;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 action; /* 0 = allow, 1 = block */
} __packed;

/* Map for passing DNS events to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} DNS_EVENTS __section_maps_btf;

/* Simple hash function for DNS domain names */
static __always_inline __u32
dns_domain_hash(const char *domain, __u32 len)
{
	__u32 hash = 5381;
	__u32 i;

	/* DJB2 hash algorithm - simple and effective */
	#pragma unroll
	for (i = 0; i < DNS_MAX_NAME_LENGTH && i < len; i++) {
		if (domain[i] == 0)
			break;
		hash = ((hash << 5) + hash) + domain[i];
	}

	return hash;
}

/* Extract DNS query name from DNS packet
 * Returns length of domain name extracted, or negative error
 */
static __always_inline int
dns_extract_query_name(struct __ctx_buff *ctx, __u32 dns_off,
		       char *domain_out, __u32 max_len)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 offset = dns_off + sizeof(struct dnshdr);
	__u32 domain_len = 0;
	__u8 label_len;
	int i;

	/* Parse DNS labels */
	#pragma unroll
	for (i = 0; i < 32; i++) { /* Max 32 labels */
		if (offset >= (__u32)(data_end - data))
			return -1;

		/* Read label length */
		if (bpf_skb_load_bytes(ctx, offset, &label_len, 1) < 0)
			return -1;

		offset++;

		/* End of domain name */
		if (label_len == 0)
			break;

		/* Check for DNS compression (not fully supported) */
		if (label_len >= 192)
			return -1;

		/* Check bounds */
		if (domain_len + label_len + 1 > max_len)
			return -1;

		/* Read label */
		if (bpf_skb_load_bytes(ctx, offset, domain_out + domain_len, 
				       label_len & 0x3f) < 0)
			return -1;

		domain_len += label_len;
		offset += label_len;

		/* Add dot separator (except for last label) */
		if (domain_len < max_len - 1) {
			domain_out[domain_len] = '.';
			domain_len++;
		}
	}

	/* Remove trailing dot if present */
	if (domain_len > 0 && domain_out[domain_len - 1] == '.')
		domain_len--;

	return domain_len;
}

/* Check if DNS query should be blocked */
static __always_inline int
dns_filter_check(struct __ctx_buff *ctx, __u32 identity, __u32 l4_off)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct udphdr *udp;
	struct dnshdr dns_hdr;
	char domain[DNS_MAX_NAME_LENGTH];
	struct dns_filter_key key = {};
	struct dns_filter_value *value;
	struct dns_filter_event event = {};
	__u32 dns_off;
	int domain_len;
	__u32 domain_hash;

	/* Verify UDP header is accessible */
	if (l4_off + sizeof(struct udphdr) > ctx_full_len(ctx))
		return CTX_ACT_OK;

	udp = data + l4_off;
	if ((void *)(udp + 1) > data_end)
		return CTX_ACT_OK;

	/* Check if this is DNS traffic (port 53) */
	if (udp->dest != bpf_htons(53))
		return CTX_ACT_OK;

	dns_off = l4_off + sizeof(struct udphdr);

	/* Load DNS header */
	if (bpf_skb_load_bytes(ctx, dns_off, &dns_hdr, sizeof(dns_hdr)) < 0)
		return CTX_ACT_OK;

	/* Only process DNS queries (QR bit = 0) */
	if (dns_hdr.flags & bpf_htons(0x8000))
		return CTX_ACT_OK;

	/* Extract domain name from query */
	__builtin_memset(domain, 0, sizeof(domain));
	domain_len = dns_extract_query_name(ctx, dns_off, domain, 
					    sizeof(domain) - 1);
	
	if (domain_len <= 0)
		return CTX_ACT_OK;

	/* Calculate domain hash */
	domain_hash = dns_domain_hash(domain, domain_len);

	/* Look up in filter map */
	key.identity = identity;
	key.domain_hash = domain_hash;

	value = map_lookup_elem(&DNS_FILTER_MAP, &key);
	if (!value)
		return CTX_ACT_OK; /* No policy for this domain */

	/* Check if domain should be blocked */
	if (value->action == 1) {
		/* Prepare event for logging */
		event.identity = identity;
		event.domain_hash = domain_hash;
		event.action = 1; /* block */

		/* Extract IP addresses for logging */
		struct iphdr *ip4 = data + ETH_HLEN;
		if ((void *)(ip4 + 1) <= data_end) {
			event.src_ip = ip4->saddr;
			event.dst_ip = ip4->daddr;
			event.src_port = udp->source;
			event.dst_port = udp->dest;
		}

		/* Send event to userspace */
		ctx_event_output(ctx, &DNS_EVENTS, BPF_F_CURRENT_CPU,
				 &event, sizeof(event));

		cilium_dbg(ctx, DBG_POLICY_DENIED, domain_hash, identity);
		return DROP_POLICY_DNS_BLOCKED;
	}

	return CTX_ACT_OK;
}

/* Wildcard matching helper - checks if domain matches pattern
 * Supports patterns like "*.example.com"
 * Returns 1 if matches, 0 if not
 */
static __always_inline int
dns_wildcard_match(const char *domain, __u32 domain_len,
		   const char *pattern, __u32 pattern_len)
{
	/* Simple suffix matching for wildcard domains */
	if (pattern_len < 2 || pattern[0] != '*' || pattern[1] != '.')
		return 0;

	/* Check if domain ends with the pattern (minus "*") */
	__u32 suffix_len = pattern_len - 2; /* Skip "*." */
	
	if (domain_len < suffix_len)
		return 0;

	/* Compare suffix */
	__u32 offset = domain_len - suffix_len;
	
	#pragma unroll
	for (__u32 i = 0; i < 128 && i < suffix_len; i++) {
		if (domain[offset + i] != pattern[2 + i])
			return 0;
	}

	return 1;
}

#endif /* __LIB_DNS_FILTER_H_ */