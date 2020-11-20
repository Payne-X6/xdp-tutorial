/* This common_user.h is used by userspace programs */
#ifndef __COMMON_PARAMS_H
#define __COMMON_PARAMS_H

#include <getopt.h>
#include "common_defines.h"

struct option_wrapper {
  struct option option;
  char *help;
  char *metavar;
  bool required;
};

void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full);

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *long_options,
                        struct config *cfg, const char *doc);

void free_device_list(struct device_list **list_head);

void device_list_append(struct device_list **list_head, struct device_list *append);

size_t device_list_len(struct device_list *list_head);
#endif /* __COMMON_PARAMS_H */
