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

#define MAX_BRIDGES		4
#define MAX_PORTS		16

enum { POL_FORWARD = 0, POL_DROP };
enum { LOG_LVL_ERR = 0, LOG_LVL_WARN, LOG_LVL_INFO, LOG_LVL_DEBUG };
enum { ROLE_NONE = 0, ROLE_CLIENT, ROLE_UPLINK };

struct bridge {
	char		name[IFNAMSIZ];
	uint8_t		mac[6];
};

struct port {
	char		name[IFNAMSIZ];
	char		lower[IFNAMSIZ];	/* physical device below VLANs */
	int		role;
	int		bridge;			/* index into config.br */
	struct o82_cfg	o82;			/* client ports: what we insert */
};

struct config {
	/* "auto" or comma separated interface names */
	char		bridges_spec[128];
	char		clients_spec[128];
	char		uplinks_spec[128];
	/* auto classification by the physical device below VLANs */
	char		client_prefix[64];
	char		uplink_prefix[64];

	/* templates: %h hostname, %b bridge, %p port, %m bridge MAC,
	 * %M port MAC (MACs as 12 lower case hex digits), %% percent */
	char		circuit_id[256];
	char		remote_id[256];
	size_t		mtu;
	unsigned	type_mask;

	/* filled in by config_resolve() */
	char		hostname[64];
	struct bridge	br[MAX_BRIDGES];
	int		nbr;
	struct port	port[MAX_PORTS];
	int		nport;

	int		existing_o82;		/* POL_FORWARD | POL_DROP */
	int		reply_foreign;		/* POL_DROP default */
	int		reply_no_o82;		/* POL_FORWARD default */
	int		keep_rules_on_stop;
	int		block_client_servers;	/* snooping: DHCP server on client */
	int		block_uplink_requests;	/* snooping: other customers */
	unsigned	rate_pps;		/* per port, 0 = off */
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
	char		root[128];		/* prefix for /sys and /proc (tests) */
	unsigned	worker_uid;		/* 0 = keep root */
	unsigned	worker_gid;
};

void config_defaults(struct config *c);
/* returns 0, or -1 with message in err */
int config_load(struct config *c, const char *path, char *err, size_t errlen);
/* detects bridges and ports, expands the ids; 0 or -1 with err */
int config_resolve(struct config *c, char *err, size_t errlen);
/* returns 1 if the file looks like our INI syntax (has a [section]) */
int config_is_ours(const char *path);
const char *role_str(int role);

#endif
