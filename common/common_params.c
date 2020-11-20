#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */
#include <linux/if_xdp.h>

#include "common_params.h"

int verbose = 1;

#define BUFSIZE 30

void free_device_list(struct device_list **list_head) {
	if (list_head == NULL) {
		return;
	}
	if (*list_head != NULL && (*list_head)->next != NULL) {
	 	free_device_list(&(*list_head)->next);
	}
	free(*list_head);
	*list_head = NULL;
}

void device_list_append(struct device_list **list_head, struct device_list *append) {
	struct device_list **it = list_head;
	while (*it != NULL) {
		it = &(*it)->next;
	}
	*it = append;
}

size_t device_list_len(struct device_list *list_head) {
	if (list_head == NULL) {
		return 0;
	}
	if (list_head->next != NULL) {
		return device_list_len(list_head->next) + 1;
	}
	return 1;
}

void _print_options(const struct option_wrapper *long_options, bool required)
{
	int i, pos;
	char buf[BUFSIZE];

	for (i = 0; long_options[i].option.name != 0; i++) {
		if (long_options[i].required != required)
			continue;

		if (long_options[i].option.val > 64) /* ord('A') = 65 */
			printf(" -%c,", long_options[i].option.val);
		else
			printf("    ");
		pos = snprintf(buf, BUFSIZE, " --%s", long_options[i].option.name);
		if (long_options[i].metavar)
			snprintf(&buf[pos], BUFSIZE-pos, " %s", long_options[i].metavar);
		printf("%-22s", buf);
		printf("  %s", long_options[i].help);
		printf("\n");
	}
}

void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full)
{
	printf("Usage: %s [options]\n", prog_name);

	if (!full) {
		printf("Use --help (or -h) to see full option list.\n");
		return;
	}

	printf("\nDOCUMENTATION:\n %s\n", doc);
	printf("Required options:\n");
	_print_options(long_options, true);
	printf("\n");
	printf("Other options:\n");
	_print_options(long_options, false);
	printf("\n");
}

int option_wrappers_to_options(const struct option_wrapper *wrapper,
				struct option **options)
{
	int i, num;
	struct option *new_options;
	for (i = 0; wrapper[i].option.name != 0; i++) {}
	num = i;

	new_options = malloc(sizeof(struct option) * num);
	if (!new_options)
		return -1;
	for (i = 0; i < num; i++) {
		memcpy(&new_options[i], &wrapper[i], sizeof(struct option));
	}

	*options = new_options;
	return 0;
}

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *options_wrapper,
                        struct config *cfg, const char *doc)
{
	struct option *long_options;
	bool full_help = false;
	int longindex = 0;
	char *dest;
	int opt;
	cfg->devs = NULL;

	if (option_wrappers_to_options(options_wrapper, &long_options)) {
		fprintf(stderr, "Unable to malloc()\n");
		exit(EXIT_FAIL_OPTION);
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hd:r:L:R:ASNFUMQ:czpq",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			struct device_list *new_device = (struct device_list *)malloc(sizeof(struct device_list));
			new_device->next = NULL;
			new_device->config.ifname = (char *)&new_device->config.ifname_buf;
			strncpy(new_device->config.ifname, optarg, IF_NAMESIZE);
			new_device->config.ifindex = if_nametoindex(new_device->config.ifname);
			if (new_device->config.ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				free(new_device);
				goto error;
			}
			device_list_append(&cfg->devs, new_device);
			break;
		case 'r':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --redirect-dev name too long\n");
				goto error;
			}
			cfg->redirect_ifname = (char *)&cfg->redirect_ifname_buf;
			strncpy(cfg->redirect_ifname, optarg, IF_NAMESIZE);
			cfg->redirect_ifindex = if_nametoindex(cfg->redirect_ifname);
			if (cfg->redirect_ifindex == 0) {
				fprintf(stderr,
						"ERR: --redirect-dev name unknown err(%d):%s\n",
						errno, strerror(errno));
				goto error;
			}
			break;
		case 'A':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			break;
		case 'S':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
			cfg->xsk_bind_flags &= XDP_ZEROCOPY;
			cfg->xsk_bind_flags |= XDP_COPY;
			break;
		case 'N':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
			break;
		case 3: /* --offload-mode */
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_HW_MODE;   /* Set   flag */
			break;
		case 'F':
			cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'M':
			cfg->reuse_maps = true;
			break;
		case 'U':
			cfg->do_unload = true;
			break;
		case 'p':
			cfg->xsk_poll_mode = true;
			break;
		case 'q':
			verbose = false;
			break;
		case 'Q':
			cfg->xsk_if_queue = atoi(optarg);
			break;
		case 1: /* --filename */
			dest  = (char *)&cfg->filename;
			strncpy(dest, optarg, sizeof(cfg->filename));
			break;
		case 2: /* --progsec */
			dest  = (char *)&cfg->progsec;
			strncpy(dest, optarg, sizeof(cfg->progsec));
			break;
		case 'L': /* --src-mac */
			dest  = (char *)&cfg->src_mac;
			strncpy(dest, optarg, sizeof(cfg->src_mac));
			break;
		case 'R': /* --dest-mac */
			dest  = (char *)&cfg->dest_mac;
			strncpy(dest, optarg, sizeof(cfg->dest_mac));
		case 'c':
			cfg->xsk_bind_flags &= XDP_ZEROCOPY;
			cfg->xsk_bind_flags |= XDP_COPY;
			break;
		case 'z':
			cfg->xsk_bind_flags &= XDP_COPY;
			cfg->xsk_bind_flags |= XDP_ZEROCOPY;
			break;
		case 'h':
			full_help = true;
			/* fall-through */
		error:
		default:
			usage(argv[0], doc, options_wrapper, full_help);
			free_device_list(&cfg->devs);
			free(long_options);
			exit(EXIT_FAIL_OPTION);
		}
	}
	free(long_options);
}
