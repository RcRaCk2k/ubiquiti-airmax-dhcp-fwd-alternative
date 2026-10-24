/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 */
#ifndef DS82_CONFIG_H
#define DS82_CONFIG_H

#include <net/if.h>

#include "dhcp.h"

#define DEFAULT_CONFIG		"/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.conf"
#define DEFAULT_SYSTEM_CFG	"/tmp/system.cfg"
#define DEFAULT_PIDFILE		"/var/run/dhcp-fwd.pid"
#define DEFAULT_STATSFILE	"/var/run/dhcp-snooping-82.stats"
#define DEFAULT_EBTABLES	"/sbin/ebtables"
#define EBT_CHAIN		"DHCP_SNOOPING_82"

enum { POL_FORWARD = 0, POL_DROP };
enum { LOG_LVL_ERR = 0, LOG_LVL_WARN, LOG_LVL_INFO, LOG_LVL_DEBUG };

struct config {
	char		client_if[IFNAMSIZ];
	char		uplink_if[IFNAMSIZ];
	char		bridge_if[IFNAMSIZ];

	/* raw values as written; resolved into o82 by config_resolve() */
	char		circuit_id[256];
	char		remote_id[256];
	struct o82_cfg	o82;

	int		existing_o82;		/* POL_FORWARD | POL_DROP */
	int		reply_foreign;		/* POL_DROP default */
	int		reply_no_o82;		/* POL_FORWARD default */
	int		keep_rules_on_stop;
	unsigned	rate_pps;		/* per direction, 0 = off */
	unsigned	rate_burst;

	int		auto_rollback;
	unsigned	rollback_window;	/* seconds */
	unsigned	rollback_min_requests;
	char		rollback_cmd[256];

	int		log_level;
	unsigned	stats_interval;
	unsigned	rule_check_interval;
	char		stats_file[128];
	char		pidfile[128];
	char		ebtables[128];
	char		system_cfg[128];
	unsigned	worker_uid;		/* 0 = keep root */
	unsigned	worker_gid;
};

void config_defaults(struct config *c);
/* returns 0, or -1 with message in err */
int config_load(struct config *c, const char *path, char *err, size_t errlen);
/* derive circuit/remote id from hostname/MAC; 0 or -1 with err */
int config_resolve(struct config *c, char *err, size_t errlen);
int config_get_mac(const char *ifname, uint8_t mac[6]);
/* returns 1 if the file looks like our INI syntax (has a [section]) */
int config_is_ours(const char *path);

#endif
