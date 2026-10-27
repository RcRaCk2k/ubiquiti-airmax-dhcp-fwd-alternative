/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * Source guard binding table: which (port, MAC, address) the DHCP server
 * handed out and until when. The worker turns ACKs, DHCPv6 Replies and
 * client releases into guard_msg records and sends them to the watcher,
 * which keeps this table and the ebtables rules made from it. A renew only
 * moves the expiry; rules change only when a binding appears or goes.
 * SLAAC: prefixes from router advertisements on the uplinks give every
 * client MAC with a DHCP binding its EUI-64 address in them (or the whole
 * /64); these bindings are derived by guard_sync(), never sent.
 * Pure functions, no system calls; host-testable.
 */
#ifndef DS82_GUARD_H
#define DS82_GUARD_H

#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "dhcp.h"
#include "dhcp6.h"

#define GUARD_MAX		256	/* bindings in all */
#define GUARD_INFINITE		0xffffffffu
#define GUARD_SLACK		10	/* seconds beyond the lifetime */
#define GUARD_MAX_RA		8	/* SLAAC prefixes in all */

struct binding {
	char		port[IFNAMSIZ];
	uint8_t		mac[6];
	uint8_t		v6;
	uint8_t		plen;		/* 32 for IPv4, 128 IA_NA, < 128 IA_PD */
	uint8_t		slaac;		/* derived from an RA prefix */
	uint8_t		addr[16];	/* IPv4: first 4 bytes, network order */
	time_t		expires;	/* monotonic seconds, 0 = never */
};

/* a /64 an uplink's router announced for SLAAC */
struct ra_prefix {
	char		port[IFNAMSIZ];	/* the uplink it was seen on */
	uint8_t		prefix[16];
	time_t		expires;	/* 0 = never */
};

struct guard_tab {
	struct binding	b[GUARD_MAX];
	int		n;
	struct ra_prefix ra[GUARD_MAX_RA];
	int		nra;
};

enum {
	GUARD_SLAAC_OFF = 0,
	GUARD_SLAAC_EUI64,	/* prefix + interface ID from the MAC */
	GUARD_SLAAC_PREFIX,	/* the whole /64 */
};

enum {
	GUARD_LEARN = 1,	/* lease granted or renewed (lifetime 0: gone) */
	GUARD_FORGET,		/* released or declined */
	GUARD_FORGET_MAC,	/* DHCPNAK: every IPv4 binding of the MAC */
	GUARD_RA,		/* SLAAC prefix on uplink port (lifetime 0: gone) */
};

/* worker -> watcher, one write() each (smaller than PIPE_BUF) */
struct guard_msg {
	uint8_t		op;
	uint8_t		v6;
	uint8_t		plen;
	uint8_t		pad;
	char		port[IFNAMSIZ];
	uint8_t		mac[6];
	uint8_t		addr[16];
	uint32_t	lifetime;	/* seconds, GUARD_INFINITE */
};

/* called for every binding that gets a rule or loses it */
struct guard_ops {
	void	(*add)(const struct binding *b, void *ctx);
	void	(*del)(const struct binding *b, void *ctx);
	void	*ctx;
	/* 1 if a client port and an uplink port share a bridge; NULL: all */
	int	(*same_bridge)(const char *client, const char *uplink,
			       void *ctx);
};

enum {
	GUARD_NOCHANGE = 0,
	GUARD_RENEWED,		/* expiry moved, rules unchanged */
	GUARD_CHANGED,		/* bindings added or removed */
	GUARD_FULL,		/* table full (GUARD_MAX), not added */
	GUARD_INVALID,		/* address not usable as a binding */
};

int guard_apply(struct guard_tab *t, const struct guard_msg *m, time_t now,
		unsigned max_per_port, const struct guard_ops *ops);
/* adds, renews (lifetime > 0) or removes a GUARD_RA prefix; returns
 * GUARD_NOCHANGE, GUARD_RENEWED, GUARD_CHANGED or GUARD_FULL. Bindings
 * follow with guard_sync(). */
int guard_ra(struct guard_tab *t, const struct guard_msg *m, time_t now);
/* makes the SLAAC bindings match the prefixes and the DHCP bindings
 * (mode GUARD_SLAAC_*); call after every other change */
int guard_sync(struct guard_tab *t, int mode, const struct guard_ops *ops);
/* removes expired bindings and prefixes; returns how many bindings */
int guard_expire(struct guard_tab *t, time_t now, const struct guard_ops *ops);
/* removes the bindings of ports keep() rejects; returns how many */
int guard_retain(struct guard_tab *t, int (*keep)(const char *port, void *),
		 void *arg, const struct guard_ops *ops);
int guard_count(const struct guard_tab *t, int v6);

/* message for the reply/request in a DHCPv4 frame; port is the client
 * port it belongs to. Returns 1 if *m is filled. */
int guard_msg4(const struct dhcp_info *in, const char *port, int from_client,
	       struct guard_msg *m);
/* messages for a plain DHCPv6 message: Reply (from_client 0, MAC = the
 * frame's destination) or Release/Decline (from_client 1, MAC = source).
 * Returns how many (at most max). */
int guard_msgs6(const uint8_t *frame, size_t len, const char *port,
		int from_client, struct guard_msg *m, int max);

/* lease file: text, one DHCP binding or SLAAC prefix per line (SLAAC
 * bindings are derived again after loading); entries of another boot
 * (other boot_id) are ignored since monotonic time restarts with the
 * kernel */
size_t guard_save(const struct guard_tab *t, const char *boot_id, time_t now,
		  char *buf, size_t len);
int guard_load(struct guard_tab *t, const char *text, const char *boot_id,
	       time_t now);

/* "eth0 aa:bb:cc:dd:ee:ff 192.0.2.10" or "... 2001:db8::/56", SLAAC
 * bindings with " slaac", buf >= 96 */
const char *binding_str(const struct binding *b, char *buf);
/* address part only: "192.0.2.10" or "2001:db8::/56", buf >= 48 */
const char *binding_addr(const struct binding *b, char *buf);

#endif
