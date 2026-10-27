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

/* limits count IPv4 addresses, IPv6 addresses (IA_NA/IA_TA) and delegated
 * prefixes (IA_PD) separately, so one stack never crowds out the other;
 * SLAAC bindings are bounded by the DHCP ones they follow */
static int kind(int v6, unsigned plen, int slaac)
{
	return slaac ? 3 : !v6 ? 0 : plen == 128 ? 1 : 2;
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

		if (b->slaac || strcmp(b->port, m->port) ||
		    memcmp(b->mac, m->mac, 6) || b->v6 != m->v6)
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
	int i, oldest = -1;

	if (m->op == GUARD_RA)
		return GUARD_INVALID;	/* guard_ra() */
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
		if (!b->slaac && !strcmp(b->port, m->port) &&
		    !memcmp(b->mac, m->mac, 6) &&
		    same_addr(b, m->v6, addr, m->plen)) {
			if (b->expires == expires)
				return GUARD_NOCHANGE;
			b->expires = expires;
			return GUARD_RENEWED;
		}
	}
	for (i = t->n - 1; i >= 0; i--) {
		b = &t->b[i];
		if (b->slaac)
			continue;
		/* the address moved to another client or port, or (IPv4) the
		 * client got a new address: the old binding is void */
		if (same_addr(b, m->v6, addr, m->plen) ||
		    (!m->v6 && !b->v6 && !strcmp(b->port, m->port) &&
		     !memcmp(b->mac, m->mac, 6))) {
			remove_at(t, i, ops);
		}
	}
	for (i = 0; i < t->n; i++) {
		b = &t->b[i];
		if (strcmp(b->port, m->port) ||
		    kind(b->v6, b->plen, b->slaac) != kind(m->v6, m->plen, 0))
			continue;
		on_port++;
		/* the one renewed longest ago, "never" last */
		if (oldest < 0 || (b->expires && (!t->b[oldest].expires ||
						  b->expires < t->b[oldest].expires)))
			oldest = i;
	}
	/* the server just handed this out, so it wins over the binding that
	 * was renewed longest ago, e.g. that of a replaced router */
	if (on_port >= max_per_port)
		remove_at(t, oldest, ops);
	if (t->n >= GUARD_MAX)
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

int guard_ra(struct guard_tab *t, const struct guard_msg *m, time_t now)
{
	time_t expires;
	struct ra_prefix *r;
	int i;

	if (m->op != GUARD_RA || !m->v6 || m->plen != 64 ||
	    m->addr[0] == 0xff || (m->addr[0] == 0xfe && (m->addr[1] & 0xc0) == 0x80) ||
	    !memcmp(m->addr, "\0\0\0\0\0\0\0\0", 8))
		return GUARD_INVALID;
	expires = m->lifetime == GUARD_INFINITE ? 0 :
		  now + (time_t)m->lifetime + GUARD_SLACK;
	for (i = 0; i < t->nra; i++) {
		r = &t->ra[i];
		if (strcmp(r->port, m->port) || memcmp(r->prefix, m->addr, 8))
			continue;
		if (!m->lifetime) {
			t->ra[i] = t->ra[--t->nra];
			return GUARD_CHANGED;
		}
		if (r->expires == expires)
			return GUARD_NOCHANGE;
		r->expires = expires;
		return GUARD_RENEWED;
	}
	if (!m->lifetime)
		return GUARD_NOCHANGE;
	if (t->nra >= GUARD_MAX_RA)
		return GUARD_FULL;
	r = &t->ra[t->nra++];
	memset(r, 0, sizeof(*r));
	memcpy(r->port, m->port, sizeof(r->port));
	r->port[sizeof(r->port) - 1] = '\0';
	memcpy(r->prefix, m->addr, 8);
	r->expires = expires;
	return GUARD_CHANGED;
}

/* the SLAAC address (or /64) of mac in prefix r */
static void slaac_addr(const struct ra_prefix *r, const uint8_t *mac, int mode,
		       uint8_t *addr, uint8_t *plen)
{
	memcpy(addr, r->prefix, 8);
	memset(addr + 8, 0, 8);
	*plen = 64;
	if (mode != GUARD_SLAAC_EUI64)
		return;
	/* modified EUI-64, RFC 4291 appendix A */
	addr[8] = mac[0] ^ 0x02;
	addr[9] = mac[1];
	addr[10] = mac[2];
	addr[11] = 0xff;
	addr[12] = 0xfe;
	addr[13] = mac[3];
	addr[14] = mac[4];
	addr[15] = mac[5];
	*plen = 128;
}

static int has_dhcp_binding(const struct guard_tab *t, const char *port,
			    const uint8_t *mac)
{
	int i;

	for (i = 0; i < t->n; i++)
		if (!t->b[i].slaac && !strcmp(t->b[i].port, port) &&
		    !memcmp(t->b[i].mac, mac, 6))
			return 1;
	return 0;
}

static int ra_applies(const struct ra_prefix *r, const char *port,
		      const struct guard_ops *ops)
{
	return !ops || !ops->same_bridge ||
	       ops->same_bridge(port, r->port, ops->ctx);
}

int guard_sync(struct guard_tab *t, int mode, const struct guard_ops *ops)
{
	uint8_t addr[16], plen;
	int i, j, k, n0, ret = GUARD_NOCHANGE;

	/* drop what no prefix and no DHCP binding backs any more */
	for (i = t->n - 1; i >= 0; i--) {
		struct binding *b = &t->b[i];
		const struct ra_prefix *r = NULL;

		if (!b->slaac)
			continue;
		for (j = 0; mode && j < t->nra && !r; j++) {
			slaac_addr(&t->ra[j], b->mac, mode, addr, &plen);
			if (same_addr(b, 1, addr, plen) &&
			    ra_applies(&t->ra[j], b->port, ops))
				r = &t->ra[j];
		}
		if (!r || !has_dhcp_binding(t, b->port, b->mac)) {
			remove_at(t, i, ops);
			ret = GUARD_CHANGED;
		} else if (b->expires != r->expires) {
			b->expires = r->expires;
			if (ret == GUARD_NOCHANGE)
				ret = GUARD_RENEWED;
		}
	}
	if (!mode)
		return ret;
	/* every client MAC with a DHCP binding, once per port */
	n0 = t->n;
	for (i = 0; i < n0; i++) {
		const struct binding *d = &t->b[i];

		if (d->slaac)
			continue;
		for (k = 0; k < i; k++)
			if (!t->b[k].slaac && !strcmp(t->b[k].port, d->port) &&
			    !memcmp(t->b[k].mac, d->mac, 6))
				break;
		if (k < i)
			continue;
		for (j = 0; j < t->nra; j++) {
			struct binding *b;

			if (!ra_applies(&t->ra[j], d->port, ops))
				continue;
			slaac_addr(&t->ra[j], d->mac, mode, addr, &plen);
			for (k = 0; k < t->n; k++)
				if (!strcmp(t->b[k].port, d->port) &&
				    !memcmp(t->b[k].mac, d->mac, 6) &&
				    same_addr(&t->b[k], 1, addr, plen))
					break;
			if (k < t->n || t->n >= GUARD_MAX)
				continue;	/* there (from DHCP too) or full */
			b = &t->b[t->n++];
			memset(b, 0, sizeof(*b));
			memcpy(b->port, d->port, sizeof(b->port));
			memcpy(b->mac, d->mac, 6);
			b->v6 = 1;
			b->plen = plen;
			b->slaac = 1;
			memcpy(b->addr, addr, 16);
			b->expires = t->ra[j].expires;
			ret = GUARD_CHANGED;
			if (ops && ops->add)
				ops->add(b, ops->ctx);
		}
	}
	return ret;
}

int guard_expire(struct guard_tab *t, time_t now, const struct guard_ops *ops)
{
	int i, n = 0;

	for (i = t->nra - 1; i >= 0; i--)
		if (t->ra[i].expires && t->ra[i].expires <= now)
			t->ra[i] = t->ra[--t->nra];
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

	sprintf(buf, "%s %02x:%02x:%02x:%02x:%02x:%02x %s%s", b->port,
		b->mac[0], b->mac[1], b->mac[2], b->mac[3], b->mac[4], b->mac[5],
		binding_addr(b, a), b->slaac ? " slaac" : "");
	return buf;
}

size_t guard_save(const struct guard_tab *t, const char *boot_id, time_t now,
		  char *buf, size_t len)
{
	size_t o = 0;
	int i, r, n = 0;

	for (i = 0; i < t->n; i++)
		n += !t->b[i].slaac;
	r = snprintf(buf, len, "# dhcp-snooping-82 source guard: %d bindings, "
		     "%d SLAAC prefixes\nboot %s\n", n, t->nra,
		     boot_id && *boot_id ? boot_id : "-");
	if (r < 0 || (size_t)r >= len)
		return 0;
	o = (size_t)r;
	for (i = 0; i < t->nra; i++) {
		const struct ra_prefix *p = &t->ra[i];
		char a[48];

		ip6_str(p->prefix, a);
		r = p->expires ?
		    snprintf(buf + o, len - o, "ra %s %s/64 %ld %lds\n", p->port,
			     a, (long)p->expires, (long)(p->expires - now)) :
		    snprintf(buf + o, len - o, "ra %s %s/64 never\n", p->port, a);
		if (r < 0 || (size_t)r >= len - o)
			return 0;
		o += (size_t)r;
	}
	for (i = 0; i < t->n; i++) {
		const struct binding *b = &t->b[i];
		char s[96];

		if (b->slaac)
			continue;	/* derived again after loading */
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

static int parse_expiry(const char *exp, time_t now, time_t *e)
{
	char *end;
	long v;

	if (!strcmp(exp, "never")) {
		*e = 0;
		return 0;
	}
	v = strtol(exp, &end, 10);
	if (*end || v <= now)
		return -1;	/* broken or expired */
	*e = (time_t)v;
	return 0;
}

/* "ra ath0 2001:db8::/64 <expires>" */
static int parse_ra(const char *line, struct ra_prefix *r, time_t now)
{
	char port[IFNAMSIZ], addr[64], exp[24], *slash;

	if (sscanf(line, "ra %15s %63s %23s", port, addr, exp) != 3)
		return -1;
	memset(r, 0, sizeof(*r));
	snprintf(r->port, sizeof(r->port), "%s", port);
	slash = strchr(addr, '/');
	if (!slash || strcmp(slash, "/64"))
		return -1;
	*slash = '\0';
	if (inet_pton(AF_INET6, addr, r->prefix) != 1 ||
	    memcmp(r->prefix + 8, "\0\0\0\0\0\0\0\0", 8))
		return -1;
	return parse_expiry(exp, now, &r->expires);
}

static int parse_line(const char *line, struct binding *b, time_t now)
{
	char fam[4], port[IFNAMSIZ], mac[24], addr[64], exp[24], *slash, *end;

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
	return parse_expiry(exp, now, &b->expires);
}

int guard_load(struct guard_tab *t, const char *text, const char *boot_id,
	       time_t now)
{
	const char *line, *next;

	t->n = 0;
	t->nra = 0;
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
				return t->n = t->nra = 0;
			continue;
		}
		if (!strncmp(l, "ra ", 3)) {
			if (t->nra < GUARD_MAX_RA &&
			    !parse_ra(l, &t->ra[t->nra], now))
				t->nra++;
			continue;
		}
		if (l[0] == '#' || t->n >= GUARD_MAX ||
		    parse_line(l, &t->b[t->n], now) < 0)
			continue;
		t->n++;
	}
	return t->n;
}
