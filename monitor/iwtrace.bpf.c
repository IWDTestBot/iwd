/*
 * Embedded Linux library
 * Copyright (C) 2023  Cruise, LLC
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdint.h>
#include <string.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/netlink.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "iwtrace.h"

char LICENSE[] SEC("license") = "GPL";

struct sock;
struct netlink_ext_ack;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct sock {
	uint16_t sk_protocol;
};

struct sk_buff {
	unsigned int len, data_len;
	unsigned char *data;
	struct net_device *dev;
	union {
		struct sock		*sk;
		int			ip_defrag_offset;
	};
};

struct capture_256 {
	struct metadata meta;
	uint8_t packet[256 - sizeof(struct metadata)];
} __attribute__ ((packed));

struct capture_1k {
	struct metadata meta;
	uint8_t packet[1024 - sizeof(struct metadata)];
} __attribute__ ((packed));

struct capture_4k {
	struct metadata meta;
	uint8_t packet[4096 - sizeof(struct metadata)];
} __attribute__ ((packed));

struct capture_8k {
	struct metadata meta;
	uint8_t packet[8192 - sizeof(struct metadata)];
} __attribute__ ((packed));

struct capture_16k {
	struct metadata meta;
	uint8_t packet[16384];
} __attribute__ ((packed));

static void metadata_fill(struct metadata *meta, const struct sk_buff *skb)
{
	struct sock *sk = __builtin_preserve_access_index(skb->sk);

	meta->timestamp = bpf_ktime_get_boot_ns();
	meta->len = __builtin_preserve_access_index(skb->len);
	meta->protocol = __builtin_preserve_access_index(sk->sk_protocol);
}

static int capture_common(const struct sk_buff *skb)
{
	uint16_t len = __builtin_preserve_access_index(skb->len);
	const void *data = __builtin_preserve_access_index(skb->data);

	/*
	 * bpf_ringbuf_reserve is currently limited to a known constant
	 * value, and cannot handle values that are not constant (even if
	 * bounded).  bpf_ringbuf_output might be suitable, but no metadata
	 * could be prepended if that is used.  Another alternative is to use
	 * a perf buffer, but it is per-CPU and might result in packets being
	 * processed out of order.  We trick the validator by using several
	 * well known structure sizes (256/1k/4k/8k/16k) in order to save on
	 * memory space, but the resultant program is larger than it would be
	 * if dynamic sizing was supported.
	 */
	if (len <= 256 - sizeof(struct metadata)) {
		struct capture_256 *c256 = bpf_ringbuf_reserve(&rb,
					sizeof(struct capture_256), 0);

		if (!c256)
			return 0;

		metadata_fill(&c256->meta, skb);

		if (bpf_probe_read_kernel(c256->packet, len, data) < 0)
			bpf_ringbuf_discard(c256, BPF_RB_NO_WAKEUP);
		else
			bpf_ringbuf_submit(c256, 0);

		return 0;
	}

	if (len <= sizeof(struct capture_1k) - sizeof(struct metadata)) {
		struct capture_1k *c1k = bpf_ringbuf_reserve(&rb,
						sizeof(struct capture_1k), 0);

		if (!c1k)
			return 0;

		metadata_fill(&c1k->meta, skb);

		if (bpf_probe_read_kernel(c1k->packet, len, data) < 0)
			bpf_ringbuf_discard(c1k, BPF_RB_NO_WAKEUP);
		else
			bpf_ringbuf_submit(c1k, 0);

		return 0;
	}

	if (len <= sizeof(struct capture_4k) - sizeof(struct metadata)) {
		struct capture_4k *c4k = bpf_ringbuf_reserve(&rb,
						sizeof(struct capture_4k), 0);

		if (!c4k)
			return 0;

		metadata_fill(&c4k->meta, skb);

		if (bpf_probe_read_kernel(c4k->packet, len, data) < 0)
			bpf_ringbuf_discard(c4k, BPF_RB_NO_WAKEUP);
		else
			bpf_ringbuf_submit(c4k, 0);

		return 0;
	}

	if (len <= sizeof(struct capture_8k) - sizeof(struct metadata)) {
		struct capture_8k *c8k = bpf_ringbuf_reserve(&rb,
						sizeof(struct capture_8k), 0);

		if (!c8k)
			return 0;

		metadata_fill(&c8k->meta, skb);

		if (bpf_probe_read_kernel(c8k->packet, len, data) < 0)
			bpf_ringbuf_discard(c8k, BPF_RB_NO_WAKEUP);
		else
			bpf_ringbuf_submit(c8k, 0);

		return 0;
	}

	/* 16384 is the largest packet size for genl currently */
	if (len <= 16384) {
		struct capture_16k *c16k = bpf_ringbuf_reserve(&rb,
						sizeof(struct capture_16k), 0);

		if (!c16k)
			return 0;

		metadata_fill(&c16k->meta, skb);

		if (bpf_probe_read_kernel(c16k->packet, len, data) < 0)
			bpf_ringbuf_discard(c16k, BPF_RB_NO_WAKEUP);
		else
			bpf_ringbuf_submit(c16k, 0);

		return 0;
	}

	return 0;
}

SEC("fentry/__netlink_sendskb")
int BPF_PROG(trace___netlink_sendskb, struct sock *sk, struct sk_buff *skb)
{
	return capture_common(skb);
}

SEC("fentry/netlink_rcv_skb")
int BPF_PROG(trace_netlink_rcv_skb, struct sk_buff *skb,
					int (*cb)(struct sk_buff *,
                                                   struct nlmsghdr *,
                                                   struct netlink_ext_ack *))
{
	return capture_common(skb);
}
