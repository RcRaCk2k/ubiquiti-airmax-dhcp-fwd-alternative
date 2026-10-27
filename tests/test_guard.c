/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * Unit tests for the source guard binding table: learning from ACKs and
 * DHCPv6 Replies, renew without rule changes, release, NAK, expiry, limits
 * and the lease file.
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guard.h"

static int failures, checks;

#define CHECK(c) do {							\
		checks++;						\
		if (!(c)) {						\
			failures++;					\
			fprintf(stderr, "%s:%d: CHECK(%s) failed\n",	\
				__FILE__, __LINE__, #c);		\
		}							\
	} while (0)

static void put16(uint8_t *p, unsigned v) { p[0] = v >> 8; p[1] = v & 0xff; }

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = (v >> 16) & 0xff;
	p[2] = (v >> 8) & 0xff;
	p[3] = v & 0xff;
}

/* rule changes the watcher would make */
static int adds, dels;
static char last[96];

static void on_add(const struct binding *b, void *ctx)
{
	adds++;
	binding_str(b, last);
}

static void on_del(const struct binding *b, void *ctx)
{
	dels++;
	binding_str(b, last);
}

static const struct guard_ops ops = { on_add, on_del, NULL };

static const uint8_t MAC_A[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t MAC_B[6] = { 0x02, 0x66, 0x77, 0x88, 0x99, 0xaa };

static struct guard_msg msg(int op, const char *port, const uint8_t *mac,
			    const char *addr, unsigned plen, uint32_t life)
{
	struct guard_msg m;
	char a[64];

	snprintf(a, sizeof(a), "%s", addr);
	a[strcspn(a, "/")] = '\0';
	memset(&m, 0, sizeof(m));
	m.op = (uint8_t)op;
	m.v6 = strchr(addr, ':') != NULL;
	m.plen = (uint8_t)(plen ? plen : m.v6 ? 128 : 32);
	snprintf(m.port, sizeof(m.port), "%s", port);
	memcpy(m.mac, mac, 6);
	inet_pton(m.v6 ? AF_INET6 : AF_INET, a, m.addr);
	m.lifetime = life;
	return m;
}

static int apply(struct guard_tab *t, struct guard_msg m, time_t now)
{
	return guard_apply(t, &m, now, 4, &ops);
}

static void test_learn_renew_release(void)
{
	static struct guard_tab t;

	adds = dels = 0;
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "192.0.2.10", 0, 600),
		    100) == GUARD_CHANGED);
	CHECK(adds == 1 && t.n == 1);
	CHECK(!strcmp(last, "eth0 02:11:22:33:44:55 192.0.2.10"));
	CHECK(t.b[0].expires == 100 + 600 + GUARD_SLACK);
	/* renew: only the expiry moves, no rule change */
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "192.0.2.10", 0, 600),
		    400) == GUARD_RENEWED);
	CHECK(adds == 1 && dels == 0 && t.b[0].expires == 400 + 600 + GUARD_SLACK);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "192.0.2.10", 0, 600),
		    400) == GUARD_NOCHANGE);
	/* new address for the same client: the old one goes */
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "192.0.2.11", 0, 600),
		    500) == GUARD_CHANGED);
	CHECK(adds == 2 && dels == 1 && t.n == 1);
	CHECK(!strcmp(last, "eth0 02:11:22:33:44:55 192.0.2.11"));
	/* release of a foreign address: nothing */
	CHECK(apply(&t, msg(GUARD_FORGET, "eth0", MAC_B, "192.0.2.11", 0, 0),
		    500) == GUARD_NOCHANGE);
	CHECK(apply(&t, msg(GUARD_FORGET, "eth0", MAC_A, "192.0.2.11", 0, 0),
		    500) == GUARD_CHANGED);
	CHECK(t.n == 0 && dels == 2);
}

static void test_moved_and_nak(void)
{
	static struct guard_tab t;

	adds = dels = 0;
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "192.0.2.10", 0, 600), 1);
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8:1::/56", 56, 600), 1);
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8::5", 0, 600), 1);
	CHECK(t.n == 3 && guard_count(&t, 1) == 2);
	/* address handed to another client on another port */
	CHECK(apply(&t, msg(GUARD_LEARN, "eth1", MAC_B, "192.0.2.10", 0, 600),
		    2) == GUARD_CHANGED);
	CHECK(t.n == 3 && dels == 1 && guard_count(&t, 0) == 1);
	CHECK(!strcmp(t.b[t.n - 1].port, "eth1"));
	/* NAK: every IPv4 binding of the MAC on that port, IPv6 stays */
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "192.0.2.20", 0, 600), 3);
	CHECK(apply(&t, msg(GUARD_FORGET_MAC, "eth0", MAC_A, "0.0.0.0", 0, 0),
		    4) == GUARD_CHANGED);
	CHECK(guard_count(&t, 0) == 1 && guard_count(&t, 1) == 2);
	/* lifetime 0 in a Reply removes the prefix */
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8:1::/56", 56, 0),
		    5) == GUARD_CHANGED);
	CHECK(guard_count(&t, 1) == 1);
	/* host bits of a prefix are cleared, so the renew matches */
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8:2::1", 48, 60),
		    6) == GUARD_CHANGED);
	CHECK(!strcmp(last, "eth0 02:11:22:33:44:55 2001:db8:2::/48"));
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8:2::", 48, 60),
		    7) == GUARD_RENEWED);
}

static void test_invalid_and_full(void)
{
	static struct guard_tab t;
	static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	static const uint8_t zero[6];

	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "0.0.0.0", 0, 60), 1) ==
	      GUARD_INVALID);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "224.0.0.1", 0, 60), 1) ==
	      GUARD_INVALID);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "127.0.0.1", 0, 60), 1) ==
	      GUARD_INVALID);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", bcast, "192.0.2.1", 0, 60), 1) ==
	      GUARD_INVALID);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", zero, "192.0.2.1", 0, 60), 1) ==
	      GUARD_INVALID);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "fe80::1", 0, 60), 1) ==
	      GUARD_INVALID);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "ff02::1", 0, 60), 1) ==
	      GUARD_INVALID);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2000::", 8, 60), 1) ==
	      GUARD_INVALID);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "::", 0, 60), 1) ==
	      GUARD_INVALID);
	CHECK(t.n == 0);
	/* limit per port and kind is 4 here; the newest lease replaces the
	 * one renewed longest ago */
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8::1", 0, 60), 1) ==
	      GUARD_CHANGED);
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8::2", 0, 50), 1);
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8::3", 0, 60), 1);
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8::4", 0, 60), 1);
	dels = 0;
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8::5", 0, 60), 1) ==
	      GUARD_CHANGED);
	CHECK(dels == 1 && !strncmp(last, "eth0 02:11:22:33:44:55 2001:db8::5", 34));
	CHECK(t.n == 4);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8::2", 0, 60), 1) ==
	      GUARD_CHANGED);	/* it was the one replaced */
	/* prefixes and IPv4 have limits of their own */
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8:1::/56", 56, 60),
		    1) == GUARD_CHANGED);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "192.0.2.10", 0, 60), 1) ==
	      GUARD_CHANGED);
	CHECK(t.n == 6);
	CHECK(apply(&t, msg(GUARD_LEARN, "eth1", MAC_A, "2001:db8::6", 0, 60), 1) ==
	      GUARD_CHANGED);
	/* renewing an existing one changes nothing else */
	dels = 0;
	CHECK(apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8::4", 0, 90), 1) ==
	      GUARD_RENEWED);
	CHECK(dels == 0);
}

/* max_bindings = 1: one IPv4 address, one IPv6 address and one prefix */
static void test_one_per_kind(void)
{
	struct guard_tab t = { .n = 0 };
	const struct guard_msg v4 = msg(GUARD_LEARN, "eth0", MAC_A, "192.0.2.10", 0, 600);
	const struct guard_msg na = msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8::10", 0, 600);
	const struct guard_msg pd = msg(GUARD_LEARN, "eth0", MAC_A, "2001:db8:1::/56", 56, 600);
	const struct guard_msg v4b = msg(GUARD_LEARN, "eth0", MAC_B, "192.0.2.11", 0, 600);

	CHECK(guard_apply(&t, &pd, 1, 1, &ops) == GUARD_CHANGED);
	CHECK(guard_apply(&t, &v4, 1, 1, &ops) == GUARD_CHANGED);
	CHECK(guard_apply(&t, &na, 1, 1, &ops) == GUARD_CHANGED);
	CHECK(t.n == 3);
	/* a second router on the port replaces the first one's IPv4 */
	dels = 0;
	CHECK(guard_apply(&t, &v4b, 5, 1, &ops) == GUARD_CHANGED);
	CHECK(dels == 1 && !strncmp(last, "eth0 02:66:77:88:99:aa 192.0.2.11", 33));
	CHECK(t.n == 3 && guard_count(&t, 0) == 1 && guard_count(&t, 1) == 2);
}

static int keep_eth0(const char *port, void *arg)
{
	return !strcmp(port, "eth0");
}

static void test_expire_retain(void)
{
	static struct guard_tab t;

	dels = 0;
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "192.0.2.1", 0, 100), 0);
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_B, "192.0.2.2", 0, 200), 0);
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_B, "2001:db8::2", 0,
		      GUARD_INFINITE), 0);
	apply(&t, msg(GUARD_LEARN, "eth1", MAC_A, "192.0.2.3", 0, 300), 0);
	CHECK(guard_expire(&t, 100 + GUARD_SLACK - 1, &ops) == 0);
	CHECK(guard_expire(&t, 100 + GUARD_SLACK, &ops) == 1 && t.n == 3);
	CHECK(guard_expire(&t, 1000000, &ops) == 2 && t.n == 1);
	CHECK(t.b[0].expires == 0);		/* infinite stays */
	apply(&t, msg(GUARD_LEARN, "eth1", MAC_A, "192.0.2.3", 0, 300), 0);
	CHECK(guard_retain(&t, keep_eth0, NULL, &ops) == 1 && t.n == 1);
	CHECK(dels == 4);
}

static void test_save_load(void)
{
	static struct guard_tab t, u;
	static char buf[8192];
	size_t n;

	apply(&t, msg(GUARD_LEARN, "eth0", MAC_A, "192.0.2.1", 0, 100), 50);
	apply(&t, msg(GUARD_LEARN, "eth0.10", MAC_A, "2001:db8:1::/56", 56,
		      GUARD_INFINITE), 50);
	apply(&t, msg(GUARD_LEARN, "eth0", MAC_B, "2001:db8::7", 0, 10), 50);
	n = guard_save(&t, "boot-1", 55, buf, sizeof(buf));
	CHECK(n > 0 && strstr(buf, "v4 eth0 02:11:22:33:44:55 192.0.2.1 160 105s\n"));
	CHECK(strstr(buf, "v6 eth0.10 02:11:22:33:44:55 2001:db8:1::/56 never\n"));
	CHECK(guard_load(&u, buf, "boot-1", 60) == 3);
	CHECK(!memcmp(&u.b[0], &t.b[0], sizeof(t.b[0])));
	CHECK(!memcmp(&u.b[1], &t.b[1], sizeof(t.b[1])));
	CHECK(!memcmp(&u.b[2], &t.b[2], sizeof(t.b[2])));
	/* expired entries are skipped */
	CHECK(guard_load(&u, buf, "boot-1", 70) == 2);
	/* another boot: monotonic times are meaningless */
	CHECK(guard_load(&u, buf, "boot-2", 60) == 0);
	CHECK(guard_load(&u, buf, NULL, 60) == 3);
	/* garbage */
	CHECK(guard_load(&u, "v4 eth0 nonsense\nv6 eth0 02:11:22:33:44:55 "
			 "2001:db8::/8 never\nv4 eth0 02:11:22:33:44:55 "
			 "192.0.2.1/24 never\n\n", NULL, 0) == 0);
	CHECK(guard_save(&t, "x", 0, buf, 20) == 0);	/* too small */
}

static void test_msg4(void)
{
	struct dhcp_info in;
	struct guard_msg m;

	memset(&in, 0, sizeof(in));
	in.htype = 1;
	in.hlen = 6;
	memcpy(in.chaddr, MAC_A, 6);
	in.msgtype = DHCP_ACK;
	in.yiaddr = 0xc000020a;
	in.lease_time = 3600;
	in.has_lease_time = 1;
	CHECK(guard_msg4(&in, "eth0", 0, &m) == 1);
	CHECK(m.op == GUARD_LEARN && !m.v6 && m.plen == 32 &&
	      m.lifetime == 3600 && !memcmp(m.mac, MAC_A, 6));
	CHECK(m.addr[0] == 192 && m.addr[3] == 10 && !strcmp(m.port, "eth0"));
	in.has_lease_time = 0;
	CHECK(guard_msg4(&in, "eth0", 0, &m) == 1 && m.lifetime == GUARD_INFINITE);
	/* an ACK from the customer side or for an INFORM binds nothing */
	CHECK(guard_msg4(&in, "eth0", 1, &m) == 0);
	in.yiaddr = 0;
	CHECK(guard_msg4(&in, "eth0", 0, &m) == 0);
	in.msgtype = DHCP_NAK;
	CHECK(guard_msg4(&in, "eth0", 0, &m) == 1 && m.op == GUARD_FORGET_MAC);
	in.msgtype = DHCP_RELEASE;
	in.ciaddr = 0xc000020a;
	CHECK(guard_msg4(&in, "eth0", 1, &m) == 1 && m.op == GUARD_FORGET &&
	      m.addr[3] == 10);
	CHECK(guard_msg4(&in, "eth0", 0, &m) == 0);
	in.msgtype = DHCP_DECLINE;
	in.requested_ip = 0xc000020b;
	CHECK(guard_msg4(&in, "eth0", 1, &m) == 1 && m.addr[3] == 11);
	in.msgtype = DHCP_OFFER;
	CHECK(guard_msg4(&in, "eth0", 0, &m) == 0);
	in.msgtype = DHCP_ACK;
	in.yiaddr = 1;
	in.hlen = 16;			/* not Ethernet */
	CHECK(guard_msg4(&in, "eth0", 0, &m) == 0);
}

/* DHCPv6 frame: type, IA_NA with one address, IA_PD with one prefix */
static size_t frame6(uint8_t *f, int type, const uint8_t *dmac,
		     const uint8_t *smac, uint32_t valid, int broken)
{
	uint8_t *d = f + 62, *o;
	size_t dlen, udp_len;

	memset(f, 0, 512);
	memcpy(f, dmac, 6);
	memcpy(f + 6, smac, 6);
	put16(f + 12, 0x86dd);
	f[14] = 0x60;
	f[20] = 17;
	f[21] = 1;
	f[22] = 0xfe;
	f[23] = 0x80;
	f[37] = 1;
	f[38] = 0xfe;
	f[39] = 0x80;
	f[53] = 2;
	put16(f + 54, 547);
	put16(f + 56, 546);
	d[0] = (uint8_t)type;
	d[3] = 7;
	o = d + 4;
	put16(o, 3);			/* IA_NA */
	put16(o + 2, 12 + 28);
	put16(o + 16, 5);		/* IAADDR */
	put16(o + 18, 24);
	o[20] = 0x20; o[21] = 0x01; o[22] = 0x0d; o[23] = 0xb8; o[35] = 0x99;
	put32(o + 36, valid / 2);
	put32(o + 40, valid);
	o += 4 + 12 + 28;
	put16(o, 25);			/* IA_PD */
	put16(o + 2, 12 + 29);
	put16(o + 16, 26);		/* IAPREFIX */
	put16(o + 18, 25);
	put32(o + 20, valid / 2);
	put32(o + 24, valid);
	o[28] = 56;
	o[29] = 0x20; o[30] = 0x01; o[31] = 0x0d; o[32] = 0xb8; o[33] = 0x45;
	o += 4 + 12 + 29;
	put16(o, 13);			/* status code inside nothing: ignored */
	put16(o + 2, 2);
	o += 6;
	dlen = (size_t)(o - d);
	if (broken)
		put16(d + 4 + 2, 200);	/* IA_NA longer than the message */
	udp_len = 8 + dlen;
	put16(f + 18, (unsigned)udp_len);
	put16(f + 58, (unsigned)udp_len);
	put16(f + 60, udp6_csum(f + 14, f + 54, udp_len));
	return 62 + dlen;
}

static void test_msgs6(void)
{
	static const uint8_t SRV[6] = { 0x02, 0, 0, 0, 0, 0x53 };
	uint8_t f[512];
	struct guard_msg m[8];
	size_t n;
	char s[96];
	struct binding b;

	n = frame6(f, DHCP6_REPLY, MAC_A, SRV, 7200, 0);
	CHECK(guard_msgs6(f, n, "eth0", 0, m, 8) == 2);
	CHECK(m[0].op == GUARD_LEARN && m[0].v6 && m[0].plen == 128 &&
	      m[0].lifetime == 7200 && !memcmp(m[0].mac, MAC_A, 6));
	CHECK(m[1].plen == 56 && m[1].addr[4] == 0x45);
	memset(&b, 0, sizeof(b));
	strcpy(b.port, "eth0");
	b.v6 = 1;
	b.plen = m[1].plen;
	memcpy(b.addr, m[1].addr, 16);
	memcpy(b.mac, m[1].mac, 6);
	CHECK(!strcmp(binding_str(&b, s), "eth0 02:11:22:33:44:55 2001:db8:4500::/56"));
	CHECK(guard_msgs6(f, n, "eth0", 0, m, 1) == 1);
	/* a Reply from the customer side or an Advertise binds nothing */
	CHECK(guard_msgs6(f, n, "eth0", 1, m, 8) == 0);
	n = frame6(f, DHCP6_ADVERTISE, MAC_A, SRV, 7200, 0);
	CHECK(guard_msgs6(f, n, "eth0", 0, m, 8) == 0);
	/* Release from the client: source MAC */
	n = frame6(f, DHCP6_RELEASE, SRV, MAC_B, 0, 0);
	CHECK(guard_msgs6(f, n, "eth0", 1, m, 8) == 2);
	CHECK(m[0].op == GUARD_FORGET && !memcmp(m[0].mac, MAC_B, 6));
	CHECK(guard_msgs6(f, n, "eth0", 0, m, 8) == 0);
	n = frame6(f, DHCP6_REPLY, MAC_A, SRV, 7200, 1);
	CHECK(guard_msgs6(f, n, "eth0", 0, m, 8) == 0);
	f[61] ^= 1;			/* checksum */
	CHECK(guard_msgs6(f, n, "eth0", 0, m, 8) == 0);
}

int main(void)
{
	test_learn_renew_release();
	test_moved_and_nak();
	test_invalid_and_full();
	test_one_per_kind();
	test_expire_retain();
	test_save_load();
	test_msg4();
	test_msgs6();
	printf("test_guard: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
