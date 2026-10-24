/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * Minimal INI parser:
 *   [section]
 *   key = value      # comment
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "config.h"

#define CFG_FILE_MAX	8192

static void copy(char *dst, size_t n, const char *src)
{
	size_t l = strlen(src);

	if (l >= n)
		l = n - 1;
	memcpy(dst, src, l);
	dst[l] = '\0';
}

static int read_file(const char *path, char *buf, size_t n)
{
	int fd = open(path, O_RDONLY);
	size_t got = 0;
	ssize_t r;

	if (fd < 0)
		return -1;
	while (got < n - 1 && (r = read(fd, buf + got, n - 1 - got)) > 0)
		got += (size_t)r;
	close(fd);
	buf[got] = '\0';
	return (int)got;
}

void config_defaults(struct config *c)
{
	memset(c, 0, sizeof(*c));
	copy(c->client_if, sizeof(c->client_if), "eth0");
	copy(c->uplink_if, sizeof(c->uplink_if), "ath0.1284");
	copy(c->bridge_if, sizeof(c->bridge_if), "br1");
	copy(c->circuit_id, sizeof(c->circuit_id), "hostname");
	copy(c->remote_id, sizeof(c->remote_id), "bridge-mac");
	c->o82.mtu = 1500;
	c->o82.type_mask = TYPE_BIT(0) | TYPE_BIT(DHCP_DISCOVER) |
			   TYPE_BIT(DHCP_REQUEST) | TYPE_BIT(DHCP_DECLINE) |
			   TYPE_BIT(DHCP_RELEASE) | TYPE_BIT(DHCP_INFORM);
	c->existing_o82 = POL_FORWARD;
	c->reply_foreign = POL_DROP;
	c->reply_no_o82 = POL_FORWARD;
	c->block_client_servers = 1;
	c->block_uplink_requests = 1;
	c->rate_pps = 20;
	c->rate_burst = 50;
	c->auto_rollback = 0;
	c->rollback_window = 600;
	c->rollback_min_requests = 5;
	copy(c->rollback_cmd, sizeof(c->rollback_cmd),
	     "/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh rollback");
	c->log_level = LOG_LVL_INFO;
	c->stats_interval = 10;
	c->rule_check_interval = 5;
	copy(c->stats_file, sizeof(c->stats_file), DEFAULT_STATSFILE);
	copy(c->pidfile, sizeof(c->pidfile), DEFAULT_PIDFILE);
	copy(c->ebtables, sizeof(c->ebtables), DEFAULT_EBTABLES);
	copy(c->system_cfg, sizeof(c->system_cfg), DEFAULT_SYSTEM_CFG);
	c->worker_uid = 99;	/* same unprivileged id the original used */
	c->worker_gid = 99;
}

static char *trim(char *s)
{
	char *e;

	while (isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
	return s;
}

static int parse_bool(const char *v, int *out)
{
	if (!strcmp(v, "true") || !strcmp(v, "yes") || !strcmp(v, "1") ||
	    !strcmp(v, "on"))
		*out = 1;
	else if (!strcmp(v, "false") || !strcmp(v, "no") || !strcmp(v, "0") ||
		 !strcmp(v, "off"))
		*out = 0;
	else
		return -1;
	return 0;
}

static int parse_uint(const char *v, unsigned *out, unsigned max)
{
	char *end;
	unsigned long l;

	errno = 0;
	l = strtoul(v, &end, 10);
	if (errno || end == v || *end || l > max)
		return -1;
	*out = (unsigned)l;
	return 0;
}

static int parse_policy(const char *v, int *out)
{
	if (!strcmp(v, "forward"))
		*out = POL_FORWARD;
	else if (!strcmp(v, "drop"))
		*out = POL_DROP;
	else
		return -1;
	return 0;
}

static int parse_types(const char *v, unsigned *mask)
{
	static const struct { const char *n; unsigned t; } map[] = {
		{ "bootp", 0 }, { "discover", DHCP_DISCOVER },
		{ "request", DHCP_REQUEST }, { "decline", DHCP_DECLINE },
		{ "release", DHCP_RELEASE }, { "inform", DHCP_INFORM },
	};
	char buf[256], *tok, *save = NULL;
	size_t i;

	copy(buf, sizeof(buf), v);
	*mask = 0;
	for (tok = strtok_r(buf, ", ", &save); tok;
	     tok = strtok_r(NULL, ", ", &save)) {
		for (i = 0; i < sizeof(map) / sizeof(map[0]); i++)
			if (!strcmp(tok, map[i].n))
				break;
		if (i == sizeof(map) / sizeof(map[0]))
			return -1;
		*mask |= TYPE_BIT(map[i].t);
	}
	return 0;
}

static int parse_level(const char *v, int *out)
{
	static const char *const n[] = { "error", "warn", "info", "debug" };
	int i;

	for (i = 0; i < 4; i++)
		if (!strcmp(v, n[i])) {
			*out = i;
			return 0;
		}
	return -1;
}

#define KEY(s, k)	(!strcmp(sec, s) && !strcmp(key, k))
#define STR(dst)	(copy(dst, sizeof(dst), val), 0)

static int set_key(struct config *c, const char *sec, const char *key,
		   const char *val)
{
	unsigned u;
	int r;

	if (KEY("interface", "client"))
		return STR(c->client_if);
	if (KEY("interface", "uplink"))
		return STR(c->uplink_if);
	if (KEY("interface", "bridge"))
		return STR(c->bridge_if);
	if (KEY("interface", "mtu")) {
		r = parse_uint(val, &u, 1500);
		if (r || u < 576)
			return -1;
		c->o82.mtu = u;
		return 0;
	}
	if (KEY("option82", "circuit_id"))
		return STR(c->circuit_id);
	if (KEY("option82", "remote_id"))
		return STR(c->remote_id);
	if (KEY("option82", "types"))
		return parse_types(val, &c->o82.type_mask);
	if (KEY("option82", "existing_option82"))
		return parse_policy(val, &c->existing_o82);
	if (KEY("reply", "foreign_option82"))
		return parse_policy(val, &c->reply_foreign);
	if (KEY("reply", "without_option82"))
		return parse_policy(val, &c->reply_no_o82);
	if (KEY("snooping", "block_client_servers"))
		return parse_bool(val, &c->block_client_servers);
	if (KEY("snooping", "block_uplink_requests"))
		return parse_bool(val, &c->block_uplink_requests);
	if (KEY("forwarding", "rate_limit"))
		return parse_uint(val, &c->rate_pps, 10000);
	if (KEY("forwarding", "rate_burst"))
		return parse_uint(val, &c->rate_burst, 10000);
	if (KEY("forwarding", "keep_rules_on_stop"))
		return parse_bool(val, &c->keep_rules_on_stop);
	if (KEY("forwarding", "rule_check_interval")) {
		r = parse_uint(val, &c->rule_check_interval, 3600);
		return r || !c->rule_check_interval ? -1 : 0;
	}
	if (KEY("forwarding", "ebtables"))
		return STR(c->ebtables);
	if (KEY("rollback", "enabled"))
		return parse_bool(val, &c->auto_rollback);
	if (KEY("rollback", "window"))
		return parse_uint(val, &c->rollback_window, 86400);
	if (KEY("rollback", "min_requests"))
		return parse_uint(val, &c->rollback_min_requests, 10000);
	if (KEY("rollback", "command"))
		return STR(c->rollback_cmd);
	if (KEY("logging", "level"))
		return parse_level(val, &c->log_level);
	if (KEY("logging", "stats_file"))
		return STR(c->stats_file);
	if (KEY("logging", "stats_interval")) {
		r = parse_uint(val, &c->stats_interval, 3600);
		return r || !c->stats_interval ? -1 : 0;
	}
	if (KEY("system", "pidfile"))
		return STR(c->pidfile);
	if (KEY("system", "system_cfg"))
		return STR(c->system_cfg);
	if (KEY("system", "worker_uid"))
		return parse_uint(val, &c->worker_uid, 65535);
	if (KEY("system", "worker_gid"))
		return parse_uint(val, &c->worker_gid, 65535);
	return -2;
}

int config_load(struct config *c, const char *path, char *err, size_t errlen)
{
	static char buf[CFG_FILE_MAX];
	char sec[32] = "", *line, *next;
	int lineno = 0, n;

	n = read_file(path, buf, sizeof(buf));
	if (n < 0) {
		snprintf(err, errlen, "%s: %s", path, strerror(errno));
		return -1;
	}
	if ((size_t)n >= sizeof(buf) - 1) {
		snprintf(err, errlen, "%s: file too large", path);
		return -1;
	}

	for (line = buf; line; line = next) {
		char *key, *val, *eq, *hash;
		int r;

		next = strchr(line, '\n');
		if (next)
			*next++ = '\0';
		lineno++;
		hash = strchr(line, '#');
		if (hash)
			*hash = '\0';
		line = trim(line);
		if (!*line || *line == ';')
			continue;
		if (*line == '[') {
			char *e = strchr(line, ']');

			if (!e || e[1]) {
				snprintf(err, errlen, "%s:%d: bad section",
					 path, lineno);
				return -1;
			}
			*e = '\0';
			copy(sec, sizeof(sec), trim(line + 1));
			continue;
		}
		eq = strchr(line, '=');
		if (!eq) {
			snprintf(err, errlen, "%s:%d: expected key = value",
				 path, lineno);
			return -1;
		}
		*eq = '\0';
		key = trim(line);
		val = trim(eq + 1);
		r = set_key(c, sec, key, val);
		if (r == -2) {
			snprintf(err, errlen, "%s:%d: unknown key [%s] %s",
				 path, lineno, sec, key);
			return -1;
		}
		if (r < 0) {
			snprintf(err, errlen, "%s:%d: invalid value for %s: %s",
				 path, lineno, key, val);
			return -1;
		}
	}
	return 0;
}

int config_is_ours(const char *path)
{
	char buf[512], *p;

	if (read_file(path, buf, sizeof(buf)) < 0)
		return 0;
	for (p = buf; *p; p++) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '[')
			return 1;
		p = strchr(p, '\n');
		if (!p)
			break;
	}
	return 0;
}

int config_get_mac(const char *ifname, uint8_t mac[6])
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	copy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}

/* airOS keeps the configured hostname in resolv.host.1.name */
static int system_hostname(const char *syscfg, char *out, size_t n)
{
	static char buf[32768];
	static const char key[] = "resolv.host.1.name=";
	char *p = buf;

	if (read_file(syscfg, buf, sizeof(buf)) > 0) {
		while (p && *p) {
			if (!strncmp(p, key, sizeof(key) - 1)) {
				char *v = p + sizeof(key) - 1;
				size_t l = strcspn(v, "\r\n");

				if (l && l < n) {
					memcpy(out, v, l);
					out[l] = '\0';
					return 0;
				}
			}
			p = strchr(p, '\n');
			if (p)
				p++;
		}
	}
	{
		struct utsname u;

		if (uname(&u) == 0 && u.nodename[0]) {
			copy(out, n, u.nodename);
			return 0;
		}
	}
	return -1;
}

/* "hostname" | "<ifname>-mac" | "bridge-mac" | "string:<literal>" | literal */
static int resolve_id(struct config *c, const char *spec, uint8_t *out,
		      uint8_t *outlen, char *err, size_t errlen)
{
	char tmp[256];
	size_t l;

	if (!strcmp(spec, "hostname")) {
		if (system_hostname(c->system_cfg, tmp, sizeof(tmp)) < 0) {
			snprintf(err, errlen, "cannot determine hostname");
			return -1;
		}
	} else if ((l = strlen(spec)) > 4 && !strcmp(spec + l - 4, "-mac")) {
		char ifn[IFNAMSIZ];
		uint8_t mac[6];

		if (!strcmp(spec, "bridge-mac"))
			copy(ifn, sizeof(ifn), c->bridge_if);
		else if (l - 4 < sizeof(ifn)) {
			memcpy(ifn, spec, l - 4);
			ifn[l - 4] = '\0';
		} else {
			snprintf(err, errlen, "bad interface in %s", spec);
			return -1;
		}
		if (config_get_mac(ifn, mac) < 0) {
			snprintf(err, errlen, "cannot read MAC of %s", ifn);
			return -1;
		}
		snprintf(tmp, sizeof(tmp), "%02x%02x%02x%02x%02x%02x",
			 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	} else if (!strncmp(spec, "string:", 7)) {
		copy(tmp, sizeof(tmp), spec + 7);
	} else {
		copy(tmp, sizeof(tmp), spec);
	}

	l = strlen(tmp);
	if (l > 250) {
		snprintf(err, errlen, "id too long: %s", tmp);
		return -1;
	}
	memcpy(out, tmp, l);
	*outlen = (uint8_t)l;
	return 0;
}

int config_resolve(struct config *c, char *err, size_t errlen)
{
	if (resolve_id(c, c->circuit_id, c->o82.cid, &c->o82.cid_len,
		       err, errlen) < 0)
		return -1;
	if (!c->o82.cid_len) {
		snprintf(err, errlen, "circuit_id must not be empty");
		return -1;
	}
	if (!strcmp(c->remote_id, "none") || !c->remote_id[0])
		c->o82.rid_len = 0;
	else if (resolve_id(c, c->remote_id, c->o82.rid, &c->o82.rid_len,
			    err, errlen) < 0)
		return -1;
	if (c->o82.cid_len + c->o82.rid_len + 4 > 255) {
		snprintf(err, errlen, "circuit_id + remote_id too long");
		return -1;
	}
	if (!strcmp(c->client_if, c->uplink_if)) {
		snprintf(err, errlen, "client and uplink must differ");
		return -1;
	}
	return 0;
}
