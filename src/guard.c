/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guard.h"

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = (v >> 16) & 0xff;
	p[2] = (v >> 8) & 0xff;
	p[3] = v & 0xff;
}

static int same_addr(const struct binding *b, int v6, const uint8_t *addr,
		     uint8_t plen)
{
	return b->v6 == v6 && b->plen == plen &&
	       !memcmp(b->addr, addr, v6 ? 16 : 4);
}

static void remove_at(struct guard_tab *t, int i, const struct guard_ops *ops)
{
	struct binding gone = t->b[i];

	t->b[i] = t->b[--t->n];
	if (ops && ops->del)
		ops->del(&gone, ops->ctx);
}

/* clears the host bits of a prefix */
static void mask(uint8_t *a, unsigned plen, unsigned bits)
{
	unsigned i;

	for (i = plen; i < bits; i++)
		a[i / 8] &= (uint8_t)~(0x80 >> (i % 8));
}

static int usable(const struct guard_msg *m, uint8_t *addr)
{
	if ((m->mac[0] & 1) || !memcmp(m->mac, "\0\0\0\0\0\0", 6))
		return 0;
	if (!m->v6) {
		/* no 0/8, loopback, multicast, class E, broadcast */
		memcpy(addr, m->addr, 4);
		return m->plen == 32 && addr[0] && addr[0] != 127 &&
		       addr[0] < 224;
	}
	/* a trusted server never delegates anything that short; refuse it
	 * rather than open a whole range */
	if (m->plen < 16 || m->plen > 128)
		return 0;
	memcpy(addr, m->addr, 16);
	mask(addr, m->plen, 128);
	/* not ::, multicast or link-local (always allowed anyway) */
	return !(addr[0] == 0xff || (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80) ||
		 !memcmp(addr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16));
}

static int forget(struct guard_tab *t, const struct guard_msg *m,
		  const uint8_t *addr, const struct guard_ops *ops)
{
	int i, n = 0;

	for (i = t->n - 1; i >= 0; i--) {
		const struct binding *b = &t->b[i];

		if (strcmp(b->port, m->port) || memcmp(b->mac, m->mac, 6) ||
		    b->v6 != m->v6)
			continue;
		if (m->op == GUARD_FORGET_MAC || same_addr(b, m->v6, addr, m->plen)) {
			remove_at(t, i, ops);
			n++;
		}
	}
	return n ? GUARD_CHANGED : GUARD_NOCHANGE;
}

int guard_apply(struct guard_tab *t, const struct guard_msg *m, time_t now,
		unsigned max_per_port, const struct guard_ops *ops)
{
	uint8_t addr[16] = { 0 };
	struct binding *b;
	time_t expires;
	unsigned on_port = 0;
	int i;

	if (m->op == GUARD_FORGET_MAC)
		return m->v6 ? GUARD_INVALID : forget(t, m, addr, ops);
	if (!usable(m, addr))
		return GUARD_INVALID;
	if (m->op == GUARD_FORGET || (m->op == GUARD_LEARN && !m->lifetime))
		return forget(t, m, addr, ops);
	if (m->op != GUARD_LEARN)
		return GUARD_INVALID;

	expires = m->lifetime == GUARD_INFINITE ? 0 :
		  now + (time_t)m->lifetime + GUARD_SLACK;
	for (i = 0; i < t->n; i++) {
		b = &t->b[i];
		if (!strcmp(b->port, m->port) && !memcmp(b->mac, m->mac, 6) &&
		    same_addr(b, m->v6, addr, m->plen)) {
			if (b->expires == expires)
				return GUARD_NOCHANGE;
			b->expires = expires;
			return GUARD_RENEWED;
		}
	}
	for (i = t->n - 1; i >= 0; i--) {
		b = &t->b[i];
		/* the address moved to another client or port, or (IPv4) the
		 * client got a new address: the old binding is void */
		if (same_addr(b, m->v6, addr, m->plen) ||
		    (!m->v6 && !b->v6 && !strcmp(b->port, m->port) &&
		     !memcmp(b->mac, m->mac, 6))) {
			remove_at(t, i, ops);
		}
	}
	for (i = 0; i < t->n; i++)
		on_port += !strcmp(t->b[i].port, m->port);
	if (on_port >= max_per_port || t->n >= GUARD_MAX)
		return GUARD_FULL;
	b = &t->b[t->n++];
	memset(b, 0, sizeof(*b));
	memcpy(b->port, m->port, sizeof(b->port));
	b->port[sizeof(b->port) - 1] = '\0';
	memcpy(b->mac, m->mac, 6);
	b->v6 = m->v6;
	b->plen = m->plen;
	memcpy(b->addr, addr, 16);
	b->expires = expires;
	if (ops && ops->add)
		ops->add(b, ops->ctx);
	return GUARD_CHANGED;
}

int guard_expire(struct guard_tab *t, time_t now, const struct guard_ops *ops)
{
	int i, n = 0;

	for (i = t->n - 1; i >= 0; i--)
		if (t->b[i].expires && t->b[i].expires <= now) {
			remove_at(t, i, ops);
			n++;
		}
	return n;
}

int guard_retain(struct guard_tab *t, int (*keep)(const char *port, void *),
		 void *arg, const struct guard_ops *ops)
{
	int i, n = 0;

	for (i = t->n - 1; i >= 0; i--)
		if (!keep(t->b[i].port, arg)) {
			remove_at(t, i, ops);
			n++;
		}
	return n;
}

int guard_count(const struct guard_tab *t, int v6)
{
	int i, n = 0;

	for (i = 0; i < t->n; i++)
		n += t->b[i].v6 == v6;
	return n;
}

static void msg_init(struct guard_msg *m, int op, int v6, const char *port,
		     const uint8_t *mac)
{
	memset(m, 0, sizeof(*m));
	m->op = (uint8_t)op;
	m->v6 = (uint8_t)v6;
	m->plen = v6 ? 128 : 32;
	snprintf(m->port, sizeof(m->port), "%s", port);
	memcpy(m->mac, mac, 6);
}

int guard_msg4(const struct dhcp_info *in, const char *port, int from_client,
	       struct guard_msg *m)
{
	uint32_t a = 0;
	int op = 0;

	if (in->htype != 1 || in->hlen != 6)
		return 0;
	if (!from_client && in->msgtype == DHCP_ACK && in->yiaddr) {
		op = GUARD_LEARN;
		a = in->yiaddr;
	} else if (!from_client && in->msgtype == DHCP_NAK) {
		op = GUARD_FORGET_MAC;
	} else if (from_client && in->msgtype == DHCP_RELEASE && in->ciaddr) {
		op = GUARD_FORGET;
		a = in->ciaddr;
	} else if (from_client && in->msgtype == DHCP_DECLINE &&
		   in->requested_ip) {
		op = GUARD_FORGET;
		a = in->requested_ip;
	} else {
		return 0;
	}
	msg_init(m, op, 0, port, in->chaddr);
	put32(m->addr, a);
	/* RFC 2131: an ACK without lease time only comes from BOOTP-style
	 * servers, whose leases do not end */
	m->lifetime = in->has_lease_time ? in->lease_time : GUARD_INFINITE;
	return 1;
}

int guard_msgs6(const uint8_t *frame, size_t len, const char *port,
		int from_client, struct guard_msg *m, int max)
{
	struct dhcp6_lease l[DHCP6_MAX_LEASES];
	struct dhcp6_info info;
	const uint8_t *mac;
	int n, i, op;

	if (dhcp6_parse(frame, len, &info) != R6_PARSED)
		return 0;
	if (from_client && (info.msgtype == DHCP6_RELEASE ||
			    info.msgtype == DHCP6_DECLINE)) {
		op = GUARD_FORGET;
		mac = info.src_mac;
	} else if (!from_client && info.msgtype == DHCP6_REPLY) {
		op = GUARD_LEARN;
		mac = info.dst_mac;
	} else {
		return 0;
	}
	n = dhcp6_leases(frame, len, l, max < DHCP6_MAX_LEASES ? max :
			 DHCP6_MAX_LEASES);
	for (i = 0; i < n; i++) {
		msg_init(&m[i], op, 1, port, mac);
		memcpy(m[i].addr, l[i].addr, 16);
		m[i].plen = l[i].plen;
		m[i].lifetime = l[i].valid;
	}
	return n < 0 ? 0 : n;
}

const char *binding_addr(const struct binding *b, char *buf)
{
	if (!b->v6) {
		sprintf(buf, "%u.%u.%u.%u", b->addr[0], b->addr[1], b->addr[2],
			b->addr[3]);
		return buf;
	}
	ip6_str(b->addr, buf);
	if (b->plen != 128)
		sprintf(buf + strlen(buf), "/%u", b->plen);
	return buf;
}

const char *binding_str(const struct binding *b, char *buf)
{
	char a[48];

	sprintf(buf, "%s %02x:%02x:%02x:%02x:%02x:%02x %s", b->port,
		b->mac[0], b->mac[1], b->mac[2], b->mac[3], b->mac[4], b->mac[5],
		binding_addr(b, a));
	return buf;
}

size_t guard_save(const struct guard_tab *t, const char *boot_id, time_t now,
		  char *buf, size_t len)
{
	size_t o = 0;
	int i, r;

	r = snprintf(buf, len, "# dhcp-snooping-82 source guard: %d bindings\n"
		     "boot %s\n", t->n, boot_id && *boot_id ? boot_id : "-");
	if (r < 0 || (size_t)r >= len)
		return 0;
	o = (size_t)r;
	for (i = 0; i < t->n; i++) {
		const struct binding *b = &t->b[i];
		char s[96];

		r = b->expires ?
		    snprintf(buf + o, len - o, "%s %s %ld %lds\n",
			     b->v6 ? "v6" : "v4", binding_str(b, s),
			     (long)b->expires, (long)(b->expires - now)) :
		    snprintf(buf + o, len - o, "%s %s never\n",
			     b->v6 ? "v6" : "v4", binding_str(b, s));
		if (r < 0 || (size_t)r >= len - o)
			return 0;
		o += (size_t)r;
	}
	return o;
}

static int parse_mac(const char *s, uint8_t *mac)
{
	unsigned v[6];
	int i;

	if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &v[0], &v[1], &v[2], &v[3],
		   &v[4], &v[5]) != 6)
		return -1;
	for (i = 0; i < 6; i++)
		mac[i] = (uint8_t)v[i];
	return 0;
}

static int parse_line(const char *line, struct binding *b, time_t now)
{
	char fam[4], port[IFNAMSIZ], mac[24], addr[64], exp[24], *slash, *end;
	long e;

	if (sscanf(line, "%3s %15s %23s %63s %23s", fam, port, mac, addr,
		   exp) != 5)
		return -1;
	memset(b, 0, sizeof(*b));
	snprintf(b->port, sizeof(b->port), "%s", port);
	if (parse_mac(mac, b->mac) < 0)
		return -1;
	b->v6 = !strcmp(fam, "v6");
	if (!b->v6 && strcmp(fam, "v4"))
		return -1;
	b->plen = b->v6 ? 128 : 32;
	slash = strchr(addr, '/');
	if (slash) {
		unsigned long pl = strtoul(slash + 1, &end, 10);

		if (*end || !b->v6 || pl < 16 || pl > 128)
			return -1;
		b->plen = (uint8_t)pl;
		*slash = '\0';
	}
	if (inet_pton(b->v6 ? AF_INET6 : AF_INET, addr, b->addr) != 1)
		return -1;
	if (!strcmp(exp, "never"))
		return 0;
	e = strtol(exp, &end, 10);
	if (*end || e <= now)
		return -1;	/* broken or expired */
	b->expires = (time_t)e;
	return 0;
}

int guard_load(struct guard_tab *t, const char *text, const char *boot_id,
	       time_t now)
{
	const char *line, *next;

	t->n = 0;
	for (line = text; line && *line; line = next) {
		char l[256];
		size_t n;

		next = strchr(line, '\n');
		n = next ? (size_t)(next - line) : strlen(line);
		if (next)
			next++;
		if (n >= sizeof(l))
			continue;
		memcpy(l, line, n);
		l[n] = '\0';
		if (!strncmp(l, "boot ", 5)) {
			/* another boot: monotonic times mean nothing */
			if (boot_id && *boot_id && strcmp(l + 5, "-") &&
			    strcmp(l + 5, boot_id))
				return t->n = 0;
			continue;
		}
		if (l[0] == '#' || t->n >= GUARD_MAX ||
		    parse_line(l, &t->b[t->n], now) < 0)
			continue;
		t->n++;
	}
	return t->n;
}
