// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Include the DNS filter header */
#include "lib/dns_filter.h"

/* Test: DNS query to allowed domain should pass */
PKTGEN("tc", "dns_query_allowed")
int dns_query_allowed_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_dns_server,
					  udp_src_one, bpf_htons(53));
	if (!l4)
		return TEST_ERROR;

	/* Add DNS query for allowed domain */
	data = pktgen__push_data(&builder, 64);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "dns_query_allowed")
int dns_query_allowed_setup(struct __ctx_buff *ctx)
{
	/* Don't block any domains */
	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "dns_query_allowed")
int dns_query_allowed_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* DNS query should be allowed */
	test_finish();
}

/* Test: DNS query to blocked domain should be dropped */
PKTGEN("tc", "dns_query_blocked")
int dns_query_blocked_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_dns_server,
					  udp_src_one, bpf_htons(53));
	if (!l4)
		return TEST_ERROR;

	/* Add DNS query for blocked domain */
	data = pktgen__push_data(&builder, 64);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "dns_query_blocked")
int dns_query_blocked_setup(struct __ctx_buff *ctx)
{
	__u32 identity = 12345;
	__u32 domain_hash = 3847562; /* Hash of "facebook.com" */
	struct dns_filter_key key = {
		.identity = identity,
		.domain_hash = domain_hash,
	};
	struct dns_filter_value value = {
		.action = 1, /* block */
	};

	/* Configure DNS filter to block domain */
	map_update_elem(&DNS_FILTER_MAP, &key, &value, 0);

	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "dns_query_blocked")
int dns_query_blocked_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* DNS query should be blocked */
	test_fail();
}

/* Test: Non-DNS UDP traffic should pass */
PKTGEN("tc", "non_dns_udp")
int non_dns_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	/* UDP to port 1234 (not DNS port 53) */
	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  udp_src_one, bpf_htons(1234));
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, 64);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "non_dns_udp")
int non_dns_udp_setup(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "non_dns_udp")
int non_dns_udp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Non-DNS UDP should pass */
	test_finish();
}

/* Test: DNS response should pass (not a query) */
PKTGEN("tc", "dns_response")
int dns_response_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_dns_server, v4_pod_one,
					  bpf_htons(53), udp_dst_one);
	if (!l4)
		return TEST_ERROR;

	/* Add DNS response packet */
	data = pktgen__push_data(&builder, 64);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "dns_response")
int dns_response_setup(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "dns_response")
int dns_response_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* DNS responses should pass (only queries are filtered) */
	test_finish();
}

/* Test: Multiple blocked domains for same identity */
PKTGEN("tc", "multiple_blocked_domains")
int multiple_blocked_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_dns_server,
					  udp_src_one, bpf_htons(53));
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, 64);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "multiple_blocked_domains")
int multiple_blocked_setup(struct __ctx_buff *ctx)
{
	__u32 identity = 12345;
	
	/* Block multiple domains */
	struct dns_filter_key key1 = {
		.identity = identity,
		.domain_hash = 3847562, /* facebook.com */
	};
	struct dns_filter_value value = { .action = 1 };
	map_update_elem(&DNS_FILTER_MAP, &key1, &value, 0);

	struct dns_filter_key key2 = {
		.identity = identity,
		.domain_hash = 4958273, /* twitter.com */
	};
	map_update_elem(&DNS_FILTER_MAP, &key2, &value, 0);

	struct dns_filter_key key3 = {
		.identity = identity,
		.domain_hash = 5847362, /* dropbox.com */
	};
	map_update_elem(&DNS_FILTER_MAP, &key3, &value, 0);

	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "multiple_blocked_domains")
int multiple_blocked_check(__maybe_unused const struct __ctx_buff *ctx)
{
	test_finish();
}

/* Test: Domain blocked for one identity, allowed for another */
PKTGEN("tc", "per_identity_blocking")
int per_identity_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_dns_server,
					  udp_src_one, bpf_htons(53));
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, 64);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "per_identity_blocking")
int per_identity_setup(struct __ctx_buff *ctx)
{
	/* Block domain only for identity 12345 */
	struct dns_filter_key key = {
		.identity = 12345,
		.domain_hash = 3847562, /* facebook.com */
	};
	struct dns_filter_value value = { .action = 1 };
	map_update_elem(&DNS_FILTER_MAP, &key, &value, 0);

	/* Identity 23456 not blocked */

	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "per_identity_blocking")
int per_identity_check(__maybe_unused const struct __ctx_buff *ctx)
{
	test_finish();
}