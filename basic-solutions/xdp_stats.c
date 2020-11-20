/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP stats program\n"
	" - Finding xdp_stats_map via --dev name info\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
/* This prog does not need to #include <bpf/libbpf.h> as it only uses
 * the simple bpf-syscall wrappers, defined in libbpf #include<bpf/bpf.h>
 */

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/xdp_stats_kern_user.h"

#include "bpf_util.h" /* bpf_num_possible_cpus */

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }}
};

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record {
	__u64 timestamp;
	struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record {
	struct record stats[MAX_RX_QUEUES];
};

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print_header()
{
	/* Print stats "header" */
	printf("%-12s\n", "[inet, rxq]");
}

static void stats_print(size_t len, struct stats_record *stats_rec,
			struct stats_record *stats_prev, struct bpf_map_info *infos)
{
	struct record *rec, *prev;
	__u64 packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */
	int i;

	stats_print_header(); /* Print stats "header" */

	/* Print for each XDP actions stats */
	for (size_t it = 0; it < len; ++it) {
		for (i = 0; i < MAX_RX_QUEUES; i++)
		{
			char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
						" %'11lld Kbytes (%'6.0f Mbits/s)"
						" period:%f\n";
			char action[10];
			snprintf(action, sizeof(action) - 1, "[%d, %d]", infos[it].ifindex, i);

			rec  = &stats_rec[it].stats[i];
			prev = &stats_prev[it].stats[i];
		
			if(rec->total.rx_packets == 0)
				continue;
		
			period = calc_period(rec, prev);
			if (period == 0)
		       return;

			packets = rec->total.rx_packets - prev->total.rx_packets;
			pps     = packets / period;

			bytes   = rec->total.rx_bytes   - prev->total.rx_bytes;
			bps     = (bytes * 8)/ period / 1000000;

			printf(fmt, action, rec->total.rx_packets, pps,
		    	   rec->total.rx_bytes / 1000 , bps,
			       period);
		}
	}
	printf("\n");
}


/* BPF_MAP_TYPE_ARRAY */
void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;

	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		map_get_value_percpu_array(fd, key, &value);
		break;
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
			map_type);
		return false;
		break;
	}

	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes   = value.rx_bytes;
	return true;
}

static void stats_collect(int map_fd, __u32 map_type,
			  struct stats_record *stats_rec)
{
	/* Collect all XDP actions stats  */
	__u32 key;

	for (key = 0; key < MAX_RX_QUEUES; key++) {
		map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
	}
}

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif


static int stats_poll(size_t devs_num, const char pin_dirs[devs_num][PATH_MAX], int *map_fds, struct bpf_map_info *infos, int interval)
{
	struct bpf_map_info info = {};
	struct stats_record prev[devs_num], record[devs_num];
	memset(record, 0, sizeof(record));

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Get initial reading quickly */
	for (size_t i = 0; i < devs_num; ++i) {
		stats_collect(map_fds[i], infos[i].type, &record[i]);
	}
	usleep(1000000/4);

	while (1) {
		for (size_t i = 0; i < devs_num; ++i) {
			prev[i] = record[i]; /* struct copy */
			map_fds[i] = open_bpf_map_file(pin_dirs[i], "xdp_stats_map", &info);
			if (map_fds[i] < 0) {
				return EXIT_FAIL_BPF;
			} else if (infos[i].id != info.id) {
				printf("BPF map xdp_stats_map changed its ID, restarting\n");
				return 0;
			}
			stats_collect(map_fds[i], infos[i].type, &record[i]);
		}
		stats_print(devs_num, record, prev, infos);
		sleep(interval);
	}

	return 0;
}

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	const struct bpf_map_info map_expect = {
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(struct datarec),
		.max_entries = MAX_RX_QUEUES,
	};
	int interval = 1;
	int len, err;

	struct config cfg = {
		.do_unload = false,
	};
	
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.devs == NULL) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Use the --dev name as subdir for finding pinned maps */
	const size_t dev_len = device_list_len(cfg.devs);
	struct bpf_map_info infos[dev_len];
	memset(infos, 0, sizeof(infos));
	char pin_dirs[dev_len][PATH_MAX];
	int stats_map_fds[dev_len];

	struct device_list *it = cfg.devs;
	for (size_t i = 0; i < dev_len; ++i) {
		if (it == NULL) {
			break;
		}
		len = snprintf(pin_dirs[i], PATH_MAX, "%s/%s", pin_basedir, it->config.ifname);
		if (len < 0) {
			fprintf(stderr, "ERR: creating pin dirname\n");
			free_device_list(&cfg.devs);
			return EXIT_FAIL_OPTION;
		}
		it = it->next;
	}

	for ( ;; ) {
		for (size_t i = 0; i < dev_len; ++i) {
			stats_map_fds[i] = open_bpf_map_file(pin_dirs[i], "xdp_stats_map", &infos[i]);
			if (stats_map_fds[i] < 0) {
				free_device_list(&cfg.devs);
				return EXIT_FAIL_BPF;
			}

			/* check map info, e.g. datarec is expected size */
			err = check_map_fd_info(&infos[i], &map_expect);
			if (err) {
				fprintf(stderr, "ERR: map via FD not compatible\n");
				free_device_list(&cfg.devs);
				return err;
			}
		}

		for (size_t i = 0; i < dev_len; ++i) {
			if (verbose) {
				printf("\nCollecting stats from BPF map\n");
				printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
				       " key_size:%d value_size:%d max_entries:%d\n",
				       infos[i].type, infos[i].id, infos[i].name,
			    	   infos[i].key_size, infos[i].value_size, infos[i].max_entries
				       );
			}
		}

		err = stats_poll(dev_len, pin_dirs, stats_map_fds, infos, interval);
		if (err < 0) {
			free_device_list(&cfg.devs);
			return err;
		}
	}

	free_device_list(&cfg.devs);
	return EXIT_OK;
}
