/*
 * Copyright (C) 2023  Cruise, LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/rtnetlink.h>
#include "iwtrace.h"
#include "iwtrace.skel.h"
#include "monitor/nlmon.h"
#include "monitor/pcap.h"
#include "monitor/display.h"

#include <ell/ell.h>

static struct iwtrace_bpf *skel;
static struct ring_buffer *rb;
static struct l_io *io;
static struct l_genl *genl;
static struct nlmon_config config;
static const char *writer_path;
static struct nlmon *nlmon;

#ifndef ARPHRD_NETLINK
#define ARPHRD_NETLINK	824
#endif

static int libbpf_print_fn(enum libbpf_print_level level,
				const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int handle_packet(void *ctx, void *data, size_t size)
{
	struct metadata *meta = data;
	struct timeval tv;

	data += sizeof(struct metadata);

	tv.tv_sec = meta->timestamp / L_NSEC_PER_SEC;
	tv.tv_usec = (meta->timestamp % L_NSEC_PER_SEC) / L_NSEC_PER_USEC;

	switch (meta->protocol) {
	case NETLINK_ROUTE:
		nlmon_print_rtnl(nlmon, &tv, data, meta->len);
		break;
	case NETLINK_GENERIC:
		nlmon_print_genl(nlmon, &tv, data, meta->len);
		break;
	}

	return 0;
}

static bool ringbuf_receive(struct l_io *io, void *user_data)
{
	ring_buffer__poll(rb, 0);

	return true;
}

static void nl80211_appeared(const struct l_genl_family_info *info,
					void *user_data)
{
	int err;

	err = iwtrace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Unable to attach eBPF program\n");
		goto failed;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
					handle_packet, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ringbuffer\n");
		goto failed;
	}

	nlmon = nlmon_open(l_genl_family_info_get_id(info),
						writer_path, &config);
	if (!nlmon)
		goto failed;

	io = l_io_new(bpf_map__fd(skel->maps.rb));
	l_io_set_close_on_destroy(io, false);
	l_io_set_read_handler(io, ringbuf_receive, NULL, NULL);

	return;
failed:
	l_main_quit();
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_main_quit();
		break;
	}
}

static void usage(void)
{
	printf("iwtrace - Wireless monitor using eBPF\n"
		"Usage:\n");
	printf("\tiwtrace [options]\n");
	printf("Options:\n"
		"\t-w, --write <file>     Write netlink PCAP trace file\n"
		"\t-n, --nortnl           Don't show RTNL output\n"
		"\t-y, --nowiphy          Don't show 'New Wiphy' output\n"
		"\t-s, --noscan           Don't show scan result output\n"
		"\t-e, --noies            Don't show IEs except SSID\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "write",     required_argument, NULL, 'w' },
	{ "nortnl",    no_argument,       NULL, 'n' },
	{ "nowiphy",   no_argument,       NULL, 'y' },
	{ "noscan",    no_argument,       NULL, 's' },
	{ "noies",     no_argument,       NULL, 'e' },
	{ "version",   no_argument,       NULL, 'v' },
	{ "help",      no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	int exit_status = EXIT_FAILURE;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "w:nvhyse",
						main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'w':
			writer_path = optarg;
			break;
		case 'n':
			config.nortnl = true;
			break;
		case 'y':
			config.nowiphy = true;
			break;
		case 's':
			config.noscan = true;
			break;
		case 'e':
			config.noies = true;
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = iwtrace_bpf__open_and_load();
	if (!skel)
		return EXIT_FAILURE;

	fprintf(stdout, "Wireless monitor (eBPF) ver %s\n", VERSION);

	if (!l_main_init())
		goto init_failed;

	genl = l_genl_new();
	if (!genl) {
		fprintf(stderr, "Failed to open generic netlink socket\n");
		goto genl_failed;
	}

	l_genl_request_family(genl, "nl80211", nl80211_appeared, NULL, NULL);
	exit_status = l_main_run_with_signal(signal_handler, NULL);

	l_genl_unref(genl);
	nlmon_close(nlmon);
	l_io_destroy(io);
	ring_buffer__free(rb);

genl_failed:
	l_main_exit();
init_failed:
	iwtrace_bpf__destroy(skel);

	return exit_status;
}
