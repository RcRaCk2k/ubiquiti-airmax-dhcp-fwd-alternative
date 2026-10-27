/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * Minimal INI parser:
 *   [section]
 *   key = value      # comment
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
	copy(c->bridges_spec, sizeof(c->bridges_spec), "auto");
	copy(c->clients_spec, sizeof(c->clients_spec), "auto");
	copy(c->uplinks_spec, sizeof(c->uplinks_spec), "auto");
	copy(c->client_prefix, sizeof(c->client_prefix), "eth");
	copy(c->uplink_prefix, sizeof(c->uplink_prefix), "ath");
	copy(c->circuit_id, sizeof(c->circuit_id), "%h/%b:%p");
	copy(c->remote_id, sizeof(c->remote_id), "%m");
	c->mtu = 1500;
	c->type_mask = TYPE_BIT(0) | TYPE_BIT(DHCP_DISCOVER) |
		       TYPE_BIT(DHCP_REQUEST) | TYPE_BIT(DHCP_DECLINE) |
		       TYPE_BIT(DHCP_RELEASE) | TYPE_BIT(DHCP_INFORM);
	c->dhcp6_snooping = 1;
	c->ra_guard = 1;
	c->dhcp6_enterprise = 41112;	/* Ubiquiti's private enterprise number */
	c->dhcp6_relay_unicast = 1;
	c->sg_enable = 0;
	c->sg_ipv6 = 1;
	c->sg_block_ip_only = 1;
	c->sg_grace = 0;
	c->sg_max_bindings = 16;
	c->sg_slaac = 1;
	copy(c->sg_lease_file, sizeof(c->sg_lease_file), DEFAULT_LEASEFILE);
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
	if (!strcasecmp(v, "true") || !strcasecmp(v, "yes") ||
	    !strcmp(v, "1") || !strcasecmp(v, "on"))
		*out = 1;
	else if (!strcasecmp(v, "false") || !strcasecmp(v, "no") ||
		 !strcmp(v, "0") || !strcasecmp(v, "off"))
		*out = 0;
	else
		return -1;
	return 0;
}

static int parse_frame_types(const char *val)
{
	if (!strcasecmp(val, "any"))
		return FT_ANY;
	if (!strcasecmp(val, "untagged-only"))
		return FT_UNTAGGED;
	if (!strcasecmp(val, "vlan-only"))
		return FT_VLAN;
	return -1;
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

static void copy_n(char *dst, size_t n, const char *src, size_t l)
{
	if (l >= n)
		l = n - 1;
	memcpy(dst, src, l);
	dst[l] = '\0';
}

/* "br1:eth0, br1:eth1" -> explicit ports with the given role */
static int add_xports(struct config *c, const char *list, int role)
{
	const char *p = list;

	while (*p) {
		const char *colon;
		struct xport x;
		size_t n;
		int i;

		p += strspn(p, ", ");
		n = strcspn(p, ", ");
		if (!n)
			break;
		colon = memchr(p, ':', n);
		if (!colon || colon == p || colon == p + n - 1 ||
		    (size_t)(colon - p) >= IFNAMSIZ ||
		    (size_t)(p + n - colon - 1) >= IFNAMSIZ ||
		    memchr(colon + 1, ':', (size_t)(p + n - colon - 1)))
			return -1;
		memset(&x, 0, sizeof(x));
		copy_n(x.bridge, sizeof(x.bridge), p, (size_t)(colon - p));
		copy_n(x.name, sizeof(x.name), colon + 1,
		       (size_t)(p + n - colon - 1));
		x.role = role;
		for (i = 0; i < c->nxport; i++)
			if (!strcmp(c->xport[i].name, x.name))
				break;
		if (i < c->nxport) {
			/* the same port twice is fine, with two roles not */
			if (c->xport[i].role != role ||
			    strcmp(c->xport[i].bridge, x.bridge))
				return -1;
		} else {
			if (c->nxport == MAX_PORTS)
				return -1;
			c->xport[c->nxport++] = x;
		}
		p += n;
	}
	return 0;
}

#define KEY(s, k)	(!strcmp(sec, s) && !strcmp(key, k))
#define STR(dst)	(copy(dst, sizeof(dst), val), 0)

static int set_key(struct config *c, const char *sec, const char *key,
		   const char *val)
{
	unsigned u;
	int r;

	if (KEY("interface", "bridges"))
		return STR(c->bridges_spec);
	if (KEY("interface", "clients"))
		return STR(c->clients_spec);
	if (KEY("interface", "uplinks"))
		return STR(c->uplinks_spec);
	if (KEY("interface", "untrusted"))
		return add_xports(c, val, ROLE_CLIENT);
	if (KEY("interface", "trusted"))
		return add_xports(c, val, ROLE_UPLINK);
	if (KEY("interface", "client_prefix"))
		return STR(c->client_prefix);
	if (KEY("interface", "uplink_prefix"))
		return STR(c->uplink_prefix);
	if (KEY("interface", "frame_types"))
		return (c->frame_types = parse_frame_types(val)) < 0 ? -1 : 0;
	if (KEY("interface", "mtu")) {
		r = parse_uint(val, &u, 1500);
		if (r || u < 576)
			return -1;
		c->mtu = u;
		return 0;
	}
	if (KEY("option82", "circuit_id"))
		return STR(c->circuit_id);
	if (KEY("option82", "remote_id"))
		return STR(c->remote_id);
	if (KEY("option82", "types"))
		return parse_types(val, &c->type_mask);
	if (KEY("option82", "existing_option82"))
		return parse_policy(val, &c->existing_o82);
	if (!strcasecmp(sec, "dhcpv6")) {
		/* also as dhcpv6.RAguard=yes on the command line */
		if (!strcasecmp(key, "snooping"))
			return parse_bool(val, &c->dhcp6_snooping);
		if (!strcasecmp(key, "ra_guard") || !strcasecmp(key, "raguard"))
			return parse_bool(val, &c->ra_guard);
		if (!strcasecmp(key, "interface_id"))
			return STR(c->dhcp6_ifid);
		if (!strcasecmp(key, "remote_id"))
			return STR(c->dhcp6_rid);
		if (!strcasecmp(key, "enterprise"))
			return parse_uint(val, &c->dhcp6_enterprise, 0xffffffffu);
		if (!strcasecmp(key, "unicast")) {
			if (!strcmp(val, "relay"))
				c->dhcp6_relay_unicast = 1;
			else if (!strcmp(val, "forward"))
				c->dhcp6_relay_unicast = 0;
			else
				return -1;
			return 0;
		}
		return -2;
	}
	if (!strcasecmp(sec, "source_guard")) {
		if (!strcasecmp(key, "enable") || !strcasecmp(key, "enabled"))
			return parse_bool(val, &c->sg_enable);
		if (!strcasecmp(key, "ipv6"))
			return parse_bool(val, &c->sg_ipv6);
		if (!strcasecmp(key, "block_ip_only"))
			return parse_bool(val, &c->sg_block_ip_only);
		if (!strcasecmp(key, "grace"))
			return parse_uint(val, &c->sg_grace, 86400);
		if (!strcasecmp(key, "max_bindings")) {
			r = parse_uint(val, &c->sg_max_bindings, 64);
			return r || !c->sg_max_bindings ? -1 : 0;
		}
		if (!strcasecmp(key, "lease_file"))
			return STR(c->sg_lease_file);
		if (!strcasecmp(key, "slaac")) {
			int on;

			if (!strcasecmp(val, "eui64"))
				c->sg_slaac = 1;
			else if (!strcasecmp(val, "prefix"))
				c->sg_slaac = 2;
			else if (!parse_bool(val, &on) && !on)
				c->sg_slaac = 0;
			else
				return -1;
			return 0;
		}
		return -2;
	}
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
	if (KEY("system", "root"))
		return STR(c->root);
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

int config_set(struct config *c, const char *name, const char *val,
	       char *err, size_t errlen)
{
	const char *dot = strchr(name, '.');
	char sec[32], key[64];
	int r;

	if (!dot || dot == name || (size_t)(dot - name) >= sizeof(sec) ||
	    strlen(dot + 1) >= sizeof(key)) {
		snprintf(err, errlen, "bad option name %s (section.key)", name);
		return -1;
	}
	copy_n(sec, sizeof(sec), name, (size_t)(dot - name));
	copy(key, sizeof(key), dot + 1);
	r = set_key(c, sec, key, val);
	if (r == -2)
		snprintf(err, errlen, "unknown option %s", name);
	else if (r < 0)
		snprintf(err, errlen, "invalid value for %s: %s", name, val);
	return r < 0 ? -1 : 0;
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

const char *role_str(int role)
{
	return role == ROLE_CLIENT ? "client" :
	       role == ROLE_UPLINK ? "uplink" : "none";
}

static int sys_read(const struct config *c, const char *path, char *buf,
		    size_t n)
{
	char full[256];

	snprintf(full, sizeof(full), "%s%s", c->root, path);
	return read_file(full, buf, n);
}

static int read_mac(const struct config *c, const char *ifname, uint8_t mac[6])
{
	char path[96], buf[32];
	unsigned m[6];
	int i;

	snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
	if (sys_read(c, path, buf, sizeof(buf)) < 17 ||
	    sscanf(buf, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3],
		   &m[4], &m[5]) != 6)
		return -1;
	for (i = 0; i < 6; i++)
		mac[i] = (uint8_t)m[i];
	return 0;
}

static int read_int(const struct config *c, const char *ifname,
		    const char *attr)
{
	char path[96], buf[16];

	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", ifname, attr);
	if (sys_read(c, path, buf, sizeof(buf)) <= 0)
		return -1;
	return atoi(buf);
}

/* name of the interface with the given ifindex, via sysfs */
static int name_by_index(const struct config *c, int idx, char *out)
{
	char path[256];
	struct dirent *d;
	DIR *dir;
	int found = -1;

	snprintf(path, sizeof(path), "%s/sys/class/net", c->root);
	dir = opendir(path);
	if (!dir)
		return -1;
	while ((d = readdir(dir))) {
		if (d->d_name[0] == '.')
			continue;
		if (read_int(c, d->d_name, "ifindex") == idx) {
			copy(out, IFNAMSIZ, d->d_name);
			found = 0;
			break;
		}
	}
	closedir(dir);
	return found;
}

/* VLAN device -> underlying device: /proc/net/vlan/config, else iflink */
static int vlan_lower(const struct config *c, const char *ifname, char *out)
{
	static char buf[4096];
	char *line, *next;
	int idx, link;

	if (sys_read(c, "/proc/net/vlan/config", buf, sizeof(buf)) > 0) {
		for (line = buf; line; line = next) {
			char name[IFNAMSIZ + 1], lower[IFNAMSIZ + 1];
			unsigned vid;

			next = strchr(line, '\n');
			if (next)
				*next++ = '\0';
			if (sscanf(line, "%16s | %u | %16s", name, &vid, lower) == 3 &&
			    !strcmp(name, ifname)) {
				copy(out, IFNAMSIZ, lower);
				return 0;
			}
		}
		return -1;
	}
	/* no vlan proc file (e.g. inside a namespace): VLAN names contain
	 * a dot; iflink is the ifindex of the lower device */
	if (!strchr(ifname, '.'))
		return -1;
	idx = read_int(c, ifname, "ifindex");
	link = read_int(c, ifname, "iflink");
	if (idx < 0 || link <= 0 || link == idx)
		return -1;
	return name_by_index(c, link, out);
}

static void resolve_lower(const struct config *c, const char *ifname,
			  char *out)
{
	char cur[IFNAMSIZ], next[IFNAMSIZ];
	int depth;

	copy(cur, sizeof(cur), ifname);
	for (depth = 0; depth < 4 && vlan_lower(c, cur, next) == 0; depth++)
		copy(cur, sizeof(cur), next);
	copy(out, IFNAMSIZ, cur);
}

/* is word in the comma/space separated list? */
static int in_list(const char *list, const char *word)
{
	size_t l = strlen(word);
	const char *p = list;

	while (*p) {
		size_t n;

		p += strspn(p, ", ");
		n = strcspn(p, ", ");
		if (n == l && !strncmp(p, word, l))
			return 1;
		p += n;
	}
	return 0;
}

static int has_prefix(const char *list, const char *name)
{
	const char *p = list;

	while (*p) {
		size_t n;

		p += strspn(p, ", ");
		n = strcspn(p, ", ");
		if (n && !strncmp(p, name, n))
			return 1;
		p += n;
	}
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

/* value of key=... in system.cfg, "" if missing */
static const char *syscfg_get(const char *buf, const char *key, char *out,
			      size_t n)
{
	size_t kl = strlen(key);
	const char *p = buf;

	out[0] = '\0';
	while (p && *p) {
		if (!strncmp(p, key, kl) && p[kl] == '=') {
			size_t l = strcspn(p + kl + 1, "\r\n");

			if (l >= n)
				l = n - 1;
			memcpy(out, p + kl + 1, l);
			out[l] = '\0';
			break;
		}
		p = strchr(p, '\n');
		if (p)
			p++;
	}
	return out;
}

static int add_bridge(struct config *c, const char *name)
{
	int i;

	for (i = 0; i < c->nbr; i++)
		if (!strcmp(c->br[i].name, name))
			return 0;
	if (c->nbr == MAX_BRIDGES)
		return -1;
	memset(&c->br[c->nbr], 0, sizeof(c->br[0]));
	copy(c->br[c->nbr].name, IFNAMSIZ, name);
	c->nbr++;
	return 0;
}

static void del_bridge(struct config *c, const char *name)
{
	int i;

	for (i = 0; i < c->nbr; i++)
		if (!strcmp(c->br[i].name, name)) {
			memmove(&c->br[i], &c->br[i + 1],
				(size_t)(c->nbr - i - 1) * sizeof(c->br[0]));
			c->nbr--;
			return;
		}
}

/* value of a "key=value" word in an airOS comment field, e.g.
 * bridge.1.comment=Kunde X; dhcp-option-82=yes frame-types=untagged-only
 * Words are separated by blanks, commas or semicolons, keys ignore case,
 * other words are ignored. 1 if found. */
static int comment_word(const char *comment, const char *key, char *out,
			size_t n)
{
	size_t kl = strlen(key);
	const char *p = comment;

	while (*p) {
		size_t l;

		p += strspn(p, " \t,;");
		l = strcspn(p, " \t,;");
		if (l > kl && p[kl] == '=' && !strncasecmp(p, key, kl)) {
			size_t v = l - kl - 1;

			if (v >= n)
				v = n - 1;
			memcpy(out, p + kl + 1, v);
			out[v] = '\0';
			return 1;
		}
		p += l;
	}
	return 0;
}

/* comment of bridge.N with bridge.N.devname=name, "" if none */
static const char *bridge_comment(const char *buf, const char *name,
				  char *out, size_t n)
{
	char key[64], dev[IFNAMSIZ];
	int i;

	out[0] = '\0';
	for (i = 1; i <= 16; i++) {
		snprintf(key, sizeof(key), "bridge.%d.devname", i);
		if (strcmp(syscfg_get(buf, key, dev, sizeof(dev)), name))
			continue;
		snprintf(key, sizeof(key), "bridge.%d.comment", i);
		return syscfg_get(buf, key, out, n);
	}
	return out;
}

static char syscfg_buf[32768];

/* bridges with DHCP relay (option 82) enabled in airOS:
 *   dhcprelay.status=enabled
 *   dhcprelay.client.N.devname=br1 / dhcprelay.client.N.status=enabled
 * The web UI of airOS 6 has no relay switch for a bridge, so the bridge
 * comment can enable it ("dhcp-option-82=yes") or disable it ("=no"). */
static int detect_bridges(struct config *c, char *err, size_t errlen)
{
	char *buf = syscfg_buf;
	char key[64], val[64], com[256];
	int i, on, relay;

	if (read_file(c->system_cfg, buf, sizeof(syscfg_buf)) < 0) {
		snprintf(err, errlen, "%s: %s", c->system_cfg, strerror(errno));
		return -1;
	}
	relay = !strcmp(syscfg_get(buf, "dhcprelay.status", val, sizeof(val)),
			"enabled");
	for (i = 1; relay && i <= 16; i++) {
		char dev[IFNAMSIZ];

		snprintf(key, sizeof(key), "dhcprelay.client.%d.devname", i);
		syscfg_get(buf, key, dev, sizeof(dev));
		if (!dev[0])
			continue;
		snprintf(key, sizeof(key), "dhcprelay.client.%d.status", i);
		if (strcmp(syscfg_get(buf, key, val, sizeof(val)), "enabled"))
			continue;
		if (add_bridge(c, dev) < 0) {
			snprintf(err, errlen, "too many bridges");
			return -1;
		}
	}
	for (i = 1; i <= 16; i++) {
		char dev[IFNAMSIZ];

		snprintf(key, sizeof(key), "bridge.%d.devname", i);
		if (!syscfg_get(buf, key, dev, sizeof(dev))[0])
			continue;
		snprintf(key, sizeof(key), "bridge.%d.comment", i);
		if (!comment_word(syscfg_get(buf, key, com, sizeof(com)),
				  "dhcp-option-82", val, sizeof(val)) ||
		    parse_bool(val, &on) < 0)
			continue;
		if (!on) {
			del_bridge(c, dev);
			continue;
		}
		if (add_bridge(c, dev) < 0) {
			snprintf(err, errlen, "too many bridges");
			return -1;
		}
		c->br[c->nbr - 1].by_comment = 1;
	}
	if (!c->nbr) {
		snprintf(err, errlen, "no bridge with DHCP relay enabled or "
			 "dhcp-option-82=yes in its comment in %s",
			 c->system_cfg);
		return CONFIG_NO_BRIDGE;
	}
	return 0;
}

/* frame-types=... in a bridge comment overrides interface.frame_types */
static void bridge_frame_types(struct config *c)
{
	char com[256], val[32];
	int i, ft, have;

	have = read_file(c->system_cfg, syscfg_buf, sizeof(syscfg_buf)) >= 0;
	for (i = 0; i < c->nbr; i++) {
		c->br[i].frame_types = c->frame_types;
		if (have &&
		    comment_word(bridge_comment(syscfg_buf, c->br[i].name, com,
						sizeof(com)),
				 "frame-types", val, sizeof(val)) &&
		    (ft = parse_frame_types(val)) >= 0)
			c->br[i].frame_types = ft;
	}
}

static int bridges_from_list(struct config *c, char *err, size_t errlen)
{
	char buf[128], *tok, *save = NULL;

	copy(buf, sizeof(buf), c->bridges_spec);
	for (tok = strtok_r(buf, ", ", &save); tok;
	     tok = strtok_r(NULL, ", ", &save))
		if (add_bridge(c, tok) < 0) {
			snprintf(err, errlen, "too many bridges");
			return -1;
		}
	return 0;
}

static void hex_mac(const uint8_t *m, char *out)
{
	sprintf(out, "%02x%02x%02x%02x%02x%02x",
		m[0], m[1], m[2], m[3], m[4], m[5]);
}

static int expand(const struct config *c, const char *tpl,
		  const struct port *p, uint8_t *out, uint8_t *outlen)
{
	char buf[256], mac[13];
	size_t o = 0;
	const char *s;

	for (s = tpl; *s; s++) {
		const char *ins = NULL;
		uint8_t pm[6];

		if (*s != '%') {
			if (o + 1 >= sizeof(buf))
				return -1;
			buf[o++] = *s;
			continue;
		}
		switch (*++s) {
		case 'h': ins = c->hostname; break;
		case 'b': ins = c->br[p->bridge].name; break;
		case 'p': ins = p->name; break;
		case 'm': hex_mac(c->br[p->bridge].mac, mac); ins = mac; break;
		case 'M':
			if (read_mac(c, p->name, pm) < 0)
				return -1;
			hex_mac(pm, mac);
			ins = mac;
			break;
		case '%': ins = "%"; break;
		default: return -1;
		}
		if (o + strlen(ins) >= sizeof(buf))
			return -1;
		memcpy(buf + o, ins, strlen(ins));
		o += strlen(ins);
	}
	if (o > 250)
		return -1;
	memcpy(out, buf, o);
	*outlen = (uint8_t)o;
	return 0;
}

static int scan_bridge(struct config *c, int b, char *err, size_t errlen)
{
	char path[256];
	struct dirent *d;
	DIR *dir;
	int clients = 0, uplinks = 0, first = c->nport;

	if (read_mac(c, c->br[b].name, c->br[b].mac) < 0) {
		snprintf(err, errlen, "bridge %s not found", c->br[b].name);
		return -1;
	}
	snprintf(path, sizeof(path), "%s/sys/class/net/%s/brif", c->root,
		 c->br[b].name);
	dir = opendir(path);
	if (!dir) {
		snprintf(err, errlen, "%s is not a bridge", c->br[b].name);
		return -1;
	}
	while ((d = readdir(dir))) {
		struct port *p;
		int auto_c = !strcmp(c->clients_spec, "auto");
		int auto_u = !strcmp(c->uplinks_spec, "auto");

		if (d->d_name[0] == '.')
			continue;
		if (c->nport == MAX_PORTS) {
			closedir(dir);
			snprintf(err, errlen, "too many bridge ports");
			return -1;
		}
		p = &c->port[c->nport];
		memset(p, 0, sizeof(*p));
		copy(p->name, sizeof(p->name), d->d_name);
		resolve_lower(c, p->name, p->lower);
		p->bridge = b;
		if (!auto_c && in_list(c->clients_spec, p->name))
			p->role = ROLE_CLIENT;
		else if (!auto_u && in_list(c->uplinks_spec, p->name))
			p->role = ROLE_UPLINK;
		else if (auto_c && has_prefix(c->client_prefix, p->lower))
			p->role = ROLE_CLIENT;
		else if (auto_u && has_prefix(c->uplink_prefix, p->lower))
			p->role = ROLE_UPLINK;
		if (p->role == ROLE_NONE)
			continue;	/* e.g. gre tunnels: left alone */
		if (p->role == ROLE_CLIENT)
			clients++;
		else
			uplinks++;
		c->nport++;
	}
	closedir(dir);
	if (!clients || !uplinks) {
		/* nothing to relay between: ignore this bridge */
		c->nport = first;
		return 1;
	}
	return 0;
}

static int bridge_index(struct config *c, const char *name, char *err,
			size_t errlen)
{
	char path[256];
	int i;

	for (i = 0; i < c->nbr; i++)
		if (!strcmp(c->br[i].name, name))
			return i;
	if (add_bridge(c, name) < 0) {
		snprintf(err, errlen, "too many bridges");
		return -1;
	}
	if (read_mac(c, name, c->br[i].mac) < 0) {
		snprintf(err, errlen, "bridge %s not found", name);
		return -1;
	}
	snprintf(path, sizeof(path), "%s/sys/class/net/%s/brif", c->root, name);
	if (access(path, F_OK) < 0) {
		snprintf(err, errlen, "%s is not a bridge", name);
		return -1;
	}
	return i;
}

/* ports given on the command line or as [interface] untrusted/trusted:
 * exactly those, no system.cfg and no name based classification */
static int explicit_ports(struct config *c, char *err, size_t errlen)
{
	char path[256];
	int i, b;

	for (i = 0; i < c->nxport; i++) {
		const struct xport *x = &c->xport[i];
		struct port *p = &c->port[c->nport];

		b = bridge_index(c, x->bridge, err, errlen);
		if (b < 0)
			return -1;
		snprintf(path, sizeof(path), "%s/sys/class/net/%s/brif/%s",
			 c->root, x->bridge, x->name);
		if (access(path, F_OK) < 0) {
			snprintf(err, errlen, "%s is not a port of %s", x->name,
				 x->bridge);
			return -1;
		}
		memset(p, 0, sizeof(*p));
		copy(p->name, sizeof(p->name), x->name);
		resolve_lower(c, p->name, p->lower);
		p->bridge = b;
		p->role = x->role;
		c->nport++;
	}
	for (b = 0; b < c->nbr; b++) {
		int clients = 0, uplinks = 0;

		for (i = 0; i < c->nport; i++) {
			if (c->port[i].bridge != b)
				continue;
			if (c->port[i].role == ROLE_CLIENT)
				clients++;
			else
				uplinks++;
		}
		if (!clients || !uplinks) {
			snprintf(err, errlen, "bridge %s needs at least one "
				 "trusted and one untrusted port", c->br[b].name);
			return -1;
		}
	}
	return 0;
}

/* bridges from system.cfg (or the bridges list), ports by name */
static int auto_ports(struct config *c, char *err, size_t errlen)
{
	struct bridge br[MAX_BRIDGES];
	int i, nbr, r;

	r = !strcmp(c->bridges_spec, "auto") ? detect_bridges(c, err, errlen)
					     : bridges_from_list(c, err, errlen);
	if (r < 0)
		return r;

	/* keep only bridges that have client and uplink ports */
	memcpy(br, c->br, sizeof(br));
	nbr = c->nbr;
	c->nbr = 0;
	for (i = 0; i < nbr; i++) {
		int b = c->nbr;

		c->br[b] = br[i];
		c->nbr++;
		r = scan_bridge(c, b, err, errlen);
		if (r < 0)
			return -1;
		if (r > 0)
			c->nbr--;
	}
	if (!c->nbr) {
		snprintf(err, errlen, "no bridge with both a client (%s) and an "
			 "uplink (%s) port", c->client_prefix, c->uplink_prefix);
		return CONFIG_NO_BRIDGE;
	}
	return 0;
}

/* DHCPv6 Interface-ID / Remote-ID, by default the same as option 82 */
static int resolve_ldra(const struct config *c, struct port *p, char *err,
			size_t errlen)
{
	const char *ifid = c->dhcp6_ifid[0] ? c->dhcp6_ifid : c->circuit_id;
	const char *rid = c->dhcp6_rid[0] ? c->dhcp6_rid : c->remote_id;
	uint8_t buf[251], n;

	p->o6.mtu = c->mtu;
	p->o6.enterprise = c->dhcp6_enterprise;
	p->o6.relay_unicast = c->dhcp6_relay_unicast;
	if (expand(c, ifid, p, p->o6.ifid, &p->o6.ifid_len) < 0 ||
	    !p->o6.ifid_len) {
		snprintf(err, errlen, "bad dhcpv6 interface_id for %s", p->name);
		return -1;
	}
	if (!strcmp(rid, "none") || !rid[0]) {
		p->o6.rid_len = 0;
		return 0;
	}
	if (expand(c, rid, p, buf, &n) < 0 || n > sizeof(p->o6.rid)) {
		snprintf(err, errlen, "bad dhcpv6 remote_id for %s", p->name);
		return -1;
	}
	memcpy(p->o6.rid, buf, n);
	p->o6.rid_len = n;
	return 0;
}

int config_resolve(struct config *c, char *err, size_t errlen)
{
	int k, r;

	c->nbr = 0;
	c->nport = 0;
	if (system_hostname(c->system_cfg, c->hostname,
			    sizeof(c->hostname)) < 0) {
		snprintf(err, errlen, "cannot determine hostname");
		return -1;
	}
	r = c->nxport ? explicit_ports(c, err, errlen)
		      : auto_ports(c, err, errlen);
	if (r < 0)
		return r;
	bridge_frame_types(c);

	for (k = 0; k < c->nport; k++) {
		struct port *p = &c->port[k];

		if (p->role != ROLE_CLIENT)
			continue;
		p->o82.mtu = c->mtu;
		p->o82.type_mask = c->type_mask;
		if (expand(c, c->circuit_id, p, p->o82.cid,
			   &p->o82.cid_len) < 0 || !p->o82.cid_len) {
			snprintf(err, errlen, "bad circuit_id for %s", p->name);
			return -1;
		}
		if (!strcmp(c->remote_id, "none") || !c->remote_id[0])
			p->o82.rid_len = 0;
		else if (expand(c, c->remote_id, p, p->o82.rid,
				&p->o82.rid_len) < 0) {
			snprintf(err, errlen, "bad remote_id for %s", p->name);
			return -1;
		}
		if (p->o82.cid_len + p->o82.rid_len + 4 > 255) {
			snprintf(err, errlen, "circuit_id + remote_id too long");
			return -1;
		}
		if (resolve_ldra(c, p, err, errlen) < 0)
			return -1;
	}
	return 0;
}
