// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Include the payload filter header */
#include "lib/payload_filter.h"

/* Test: Payload under limit should be allowed */
PKTGEN("tc", "payload_under_limit")
int payload_under_limit_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	/* Add 500 bytes of payload (under 1MB limit) */
	data = pktgen__push_data(&builder, 500);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "payload_under_limit")
int payload_under_limit_setup(struct __ctx_buff *ctx)
{
	__u32 identity = 12345;
	__u32 size_limit = 1048576; /* 1MB */

	/* Configure payload limit for this identity */
	map_update_elem(&PAYLOAD_FILTER_MAP, &identity, &size_limit, 0);

	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "payload_under_limit")
int payload_under_limit_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Packet should be allowed */
	test_finish();
}

/* Test: Payload over limit should be dropped */
PKTGEN("tc", "payload_over_limit")
int payload_over_limit_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	/* Add 2MB of payload (over 1MB limit) */
	data = pktgen__push_data(&builder, 2097152);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "payload_over_limit")
int payload_over_limit_setup(struct __ctx_buff *ctx)
{
	__u32 identity = 12345;
	__u32 size_limit = 1048576; /* 1MB */

	/* Configure payload limit for this identity */
	map_update_elem(&PAYLOAD_FILTER_MAP, &identity, &size_limit, 0);

	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "payload_over_limit")
int payload_over_limit_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Packet should be dropped */
	test_fail();
}

/* Test: No policy configured should allow packet */
PKTGEN("tc", "no_policy_configured")
int no_policy_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, 2097152);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "no_policy_configured")
int no_policy_setup(struct __ctx_buff *ctx)
{
	/* Don't configure any policy */
	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "no_policy_configured")
int no_policy_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Without policy, packet should be allowed */
	test_finish();
}

/* Test: UDP packet payload calculation */
PKTGEN("tc", "udp_payload_check")
int udp_payload_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  udp_src_one, udp_dst_one);
	if (!l4)
		return TEST_ERROR;

	/* Add 600KB payload (under 1MB limit) */
	data = pktgen__push_data(&builder, 614400);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "udp_payload_check")
int udp_payload_setup(struct __ctx_buff *ctx)
{
	__u32 identity = 12345;
	__u32 size_limit = 1048576; /* 1MB */

	map_update_elem(&PAYLOAD_FILTER_MAP, &identity, &size_limit, 0);

	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "udp_payload_check")
int udp_payload_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* UDP packet under limit should be allowed */
	test_finish();
}

/* Test: Exact limit boundary (should be allowed) */
PKTGEN("tc", "exact_limit_boundary")
int exact_limit_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	/* Exactly 1MB payload */
	data = pktgen__push_data(&builder, 1048576);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "exact_limit_boundary")
int exact_limit_setup(struct __ctx_buff *ctx)
{
	__u32 identity = 12345;
	__u32 size_limit = 1048576; /* 1MB */

	map_update_elem(&PAYLOAD_FILTER_MAP, &identity, &size_limit, 0);

	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "exact_limit_boundary")
int exact_limit_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Exact limit should be allowed */
	test_finish();
}

/* Test: One byte over limit (should be dropped) */
PKTGEN("tc", "one_byte_over_limit")
int one_byte_over_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	/* 1MB + 1 byte payload */
	data = pktgen__push_data(&builder, 1048577);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "one_byte_over_limit")
int one_byte_over_setup(struct __ctx_buff *ctx)
{
	__u32 identity = 12345;
	__u32 size_limit = 1048576; /* 1MB */

	map_update_elem(&PAYLOAD_FILTER_MAP, &identity, &size_limit, 0);

	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "one_byte_over_limit")
int one_byte_over_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* One byte over should be dropped */
	test_fail();
}