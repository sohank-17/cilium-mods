/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_PAYLOAD_FILTER_H_
#define __LIB_PAYLOAD_FILTER_H_

#include "common.h"
#include "maps.h"
#include "eth.h"
#include "dbg.h"

/* Map to store payload size limits per identity */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);    /* Security identity or namespace ID */
	__type(value, __u32);  /* Max payload size in bytes */
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} PAYLOAD_FILTER_MAP __section_maps_btf;

/* Structure for logging payload filter events */
struct payload_filter_event {
	__u32 identity;
	__u32 payload_size;
	__u32 limit;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u8 action; /* 0 = allow, 1 = drop */
} __packed;

/* Map for passing events to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} PAYLOAD_EVENTS __section_maps_btf;

static __always_inline int
payload_filter_check(struct __ctx_buff *ctx, __u32 identity, 
                     __u32 l3_off, __u32 l4_off, __u8 protocol)
{
	__u32 *size_limit;
	__u32 payload_size;
	__u32 total_len;
	struct payload_filter_event event = {};

	/* Look up size limit for this identity */
	size_limit = map_lookup_elem(&PAYLOAD_FILTER_MAP, &identity);
	if (!size_limit)
		return CTX_ACT_OK; /* No policy configured, allow */

	/* Calculate payload size based on packet type */
	total_len = ctx_full_len(ctx);
	
	if (protocol == IPPROTO_TCP) {
		/* For TCP, account for TCP header (minimum 20 bytes) */
		if (total_len > l4_off + 20)
			payload_size = total_len - l4_off - 20;
		else
			payload_size = 0;
	} else if (protocol == IPPROTO_UDP) {
		/* For UDP, account for UDP header (8 bytes) */
		if (total_len > l4_off + 8)
			payload_size = total_len - l4_off - 8;
		else
			payload_size = 0;
	} else {
		/* For other protocols, use full L4 payload */
		if (total_len > l4_off)
			payload_size = total_len - l4_off;
		else
			payload_size = 0;
	}

	/* Check against limit */
	if (payload_size > *size_limit) {
		/* Prepare event for logging */
		event.identity = identity;
		event.payload_size = payload_size;
		event.limit = *size_limit;
		event.protocol = protocol;
		event.action = 1; /* drop */

		/* Extract IP addresses and ports for logging */
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;
		
		/* Basic bounds checking for event data */
		if (l3_off + sizeof(struct iphdr) <= ctx_full_len(ctx)) {
			struct iphdr *ip4 = data + l3_off;
			if ((void *)(ip4 + 1) <= data_end) {
				event.src_ip = ip4->saddr;
				event.dst_ip = ip4->daddr;
			}
		}

		/* Send event to userspace */
		ctx_event_output(ctx, &PAYLOAD_EVENTS, BPF_F_CURRENT_CPU,
				 &event, sizeof(event));

		cilium_dbg(ctx, DBG_POLICY_DENIED, payload_size, *size_limit);
		return DROP_POLICY_PAYLOAD_SIZE;
	}

	return CTX_ACT_OK;
}

#endif /* __LIB_PAYLOAD_FILTER_H_ */
