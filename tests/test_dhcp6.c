/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * Unit tests for the DHCPv6 lightweight relay agent (RFC 6221). The frames
 * the agent produces are written to test6_out.pcap so tshark can check
 * checksums and decode them independently (tests/check_pcap6.sh).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dhcp6.h"

static int failures, checks;
static FILE *pcap_out;

#define CHECK(c) do {							\
		checks++;						\
		if (!(c)) {						\
			failures++;					\
			fprintf(stderr, "%s:%d: CHECK(%s) failed\n",	\
				__FILE__, __LINE__, #c);		\
		}							\
	} while (0)

static void put16(uint8_t *p, unsigned v) { p[0] = v >> 8; p[1] = v & 0xff; }
static unsigned get16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }

static FILE *pcap_open(const char *name)
{
	FILE *f = fopen(name, "wb");
	uint32_t h[6] = { 0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1 };

	fwrite(h, 4, 1, f);
	fwrite((uint16_t[]){ 2, 4 }, 2, 2, f);
	fwrite(&h[2], 4, 4, f);
	return f;
}

static void pcap_write(const uint8_t *fr, size_t len)
{
	static uint32_t ts = 1;
	uint32_t r[4] = { ts++, 0, (uint32_t)len, (uint32_t)len };

	fwrite(r, 4, 4, pcap_out);
	fwrite(fr, 1, len, pcap_out);
}

/* ------------------------------------------------------------------ */
/* frame builder */

static const uint8_t CLIENT_MAC[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t ROUTER_MAC[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
static const uint8_t MCAST_MAC[6] = { 0x33, 0x33, 0x00, 0x01, 0x00, 0x02 };
static const uint8_t CLIENT_LL[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
				       0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55 };
static const uint8_t ROUTER_LL[16] = { 0xfe, 0x80, [15] = 1 };
static const uint8_t ALL_RELAYS[16] = { 0xff, 0x02, [13] = 1, [15] = 2 };
static const uint8_t SERVER_GUA[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 0x53 };

#define OFF_UDP	54
#define OFF_D	62

static void fix_csum(uint8_t *f, size_t udp_len)
{
	put16(f + OFF_UDP + 6, 0);
	put16(f + OFF_UDP + 6, udp6_csum(f + 14, f + OFF_UDP, udp_len));
}

/* IPv6/UDP frame around payload */
static size_t frame(uint8_t *f, const uint8_t *dmac, const uint8_t *smac,
		    const uint8_t *src, const uint8_t *dst, unsigned sport,
		    unsigned dport, const uint8_t *pl, size_t plen)
{
	size_t udp_len = 8 + plen;

	memset(f, 0, OFF_D + plen);
	memcpy(f, dmac, 6);
	memcpy(f + 6, smac, 6);
	put16(f + 12, 0x86dd);
	f[14] = 0x60;
	put16(f + 18, (unsigned)udp_len);
	f[20] = 17;
	f[21] = 1;			/* hop limit as clients send it */
	memcpy(f + 22, src, 16);
	memcpy(f + 38, dst, 16);
	put16(f + OFF_UDP, sport);
	put16(f + OFF_UDP + 2, dport);
	put16(f + OFF_UDP + 4, (unsigned)udp_len);
	memcpy(f + OFF_D, pl, plen);
	fix_csum(f, udp_len);
	return OFF_D + plen;
}

/* client message: type, xid 0x123456, Client-ID, IA_PD with a prefix hint */
static size_t client_msg(uint8_t *pl, int type)
{
	static const uint8_t opts[] = {
		0, 1, 0, 10, 0, 3, 0, 1, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
		0, 25, 0, 41, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,	/* IA_PD */
		0, 26, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0, 56,		/* IAPREFIX */
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 8, 0, 2, 0, 0,					/* elapsed */
	};

	pl[0] = (uint8_t)type;
	pl[1] = 0x12;
	pl[2] = 0x34;
	pl[3] = 0x56;
	memcpy(pl + 4, opts, sizeof(opts));
	return 4 + sizeof(opts);
}

static size_t client_frame(uint8_t *f, int type, int unicast)
{
	uint8_t pl[256];
	size_t n = client_msg(pl, type);

	return frame(f, unicast ? ROUTER_MAC : MCAST_MAC, CLIENT_MAC, CLIENT_LL,
		     unicast ? SERVER_GUA : ALL_RELAYS, 546, 547, pl, n);
}

static struct ldra_cfg cfg;

static void setup_cfg(void)
{
	memset(&cfg, 0, sizeof(cfg));
	memcpy(cfg.ifid, "cust-example/br1:eth0", 21);
	cfg.ifid_len = 21;
	memcpy(cfg.rid, "00005e005301", 12);
	cfg.rid_len = 12;
	cfg.enterprise = 41112;
	cfg.mtu = 1500;
	cfg.relay_unicast = 1;
}

/* option code in a relay message, data/len out; 0 if absent */
static int find_opt(const uint8_t *d, size_t dlen, unsigned code,
		    const uint8_t **data, size_t *len)
{
	size_t o = 34;

	while (o + 4 <= dlen) {
		unsigned c = get16(d + o), l = get16(d + o + 2);

		if (o + 4 + l > dlen)
			return 0;
		if (c == code) {
			*data = d + o + 4;
			*len = l;
			return 1;
		}
		o += 4 + l;
	}
	return 0;
}

/* ------------------------------------------------------------------ */

static void check_wrapped(const uint8_t *in, size_t in_len, const uint8_t *f,
			  size_t len)
{
	struct dhcp6_info info;
	const uint8_t *d = f + OFF_D, *v;
	size_t dlen = len - OFF_D, vl;

	CHECK(dhcp6_parse(f, len, &info) == R6_PARSED);	/* checksum valid */
	CHECK(info.msgtype == DHCP6_RELAY_FORW);
	CHECK(info.sport == 547 && info.dport == 547);
	CHECK(!memcmp(f, in, 12));			/* MACs unchanged */
	CHECK(!memcmp(f + 22, in + 22, 32));		/* IPs unchanged */
	CHECK(f[21] == in[21]);				/* hop limit */
	CHECK(d[1] == 0);				/* hop-count */
	CHECK(!memcmp(d + 2, (uint8_t[16]){ 0 }, 16));	/* link-address :: */
	CHECK(!memcmp(d + 18, in + 22, 16));		/* peer = client */
	CHECK(find_opt(d, dlen, 18, &v, &vl) && vl == cfg.ifid_len &&
	      !memcmp(v, cfg.ifid, vl));
	CHECK(find_opt(d, dlen, 37, &v, &vl) && vl == 4u + cfg.rid_len &&
	      get16(v) == 0 && get16(v + 2) == 41112 &&
	      !memcmp(v + 4, cfg.rid, cfg.rid_len));
	CHECK(find_opt(d, dlen, 9, &v, &vl) && vl == in_len - OFF_D &&
	      !memcmp(v, in + OFF_D, vl));		/* message unchanged */
	CHECK(get16(f + 18) == len - 54);		/* payload length */
}

static void test_wrap_client_types(void)
{
	static const int types[] = { 1, 3, 4, 5, 6, 8, 9, 11 };
	uint8_t in[2048], f[2048];
	size_t i;

	for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		struct dhcp6_info info;
		size_t n = client_frame(in, types[i], 0), len = n;

		memcpy(f, in, n);
		CHECK(dhcp6_handle_client(f, &len, sizeof(f), &cfg, &info) ==
		      VERDICT_FORWARD_MODIFIED);
		CHECK(info.reason == R6_WRAPPED);
		check_wrapped(in, n, f, len);
		pcap_write(f, len);
	}
}

static void test_remote_id_omitted(void)
{
	uint8_t in[2048], f[2048];
	struct dhcp6_info info;
	size_t n = client_frame(in, DHCP6_SOLICIT, 0), len = n;
	const uint8_t *v;
	size_t vl;

	cfg.rid_len = 0;
	memcpy(f, in, n);
	CHECK(dhcp6_handle_client(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD_MODIFIED);
	CHECK(!find_opt(f + OFF_D, len - OFF_D, 37, &v, &vl));
	CHECK(find_opt(f + OFF_D, len - OFF_D, 18, &v, &vl));
	CHECK(dhcp6_parse(f, len, &info) == R6_PARSED);
	setup_cfg();
}

static void test_unicast(void)
{
	uint8_t in[2048], f[2048];
	struct dhcp6_info info;
	size_t n = client_frame(in, DHCP6_RENEW, 1), len = n;

	memcpy(f, in, n);
	CHECK(dhcp6_handle_client(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD_MODIFIED);
	check_wrapped(in, n, f, len);
	CHECK(!memcmp(f, ROUTER_MAC, 6) && !memcmp(f + 38, SERVER_GUA, 16));

	cfg.relay_unicast = 0;
	len = n;
	memcpy(f, in, n);
	CHECK(dhcp6_handle_client(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD);
	CHECK(info.reason == R6_UNICAST && len == n && !memcmp(f, in, n));
	setup_cfg();
}

static void expect_client(uint8_t *f, size_t n, enum verdict v, enum reason6 r)
{
	uint8_t copy[2048];
	struct dhcp6_info info;
	size_t len = n;

	memcpy(copy, f, n);
	CHECK(dhcp6_handle_client(f, &len, 2048, &cfg, &info) == v);
	CHECK(info.reason == r);
	CHECK(len == n && !memcmp(copy, f, n));		/* never modified */
}

static void test_client_port_snooping(void)
{
	static const int server_types[] = { 2, 7, 10, 13 };
	uint8_t f[2048], pl[256];
	size_t i, n;

	n = client_frame(f, DHCP6_RELAY_FORW, 0);
	expect_client(f, n, VERDICT_DROP, R6_UNTRUSTED_RELAY);
	for (i = 0; i < 4; i++) {
		size_t m = client_msg(pl, server_types[i]);

		n = frame(f, MCAST_MAC, CLIENT_MAC, CLIENT_LL, ALL_RELAYS, 547,
			  547, pl, m < 34 ? 34 : m);
		expect_client(f, n, VERDICT_DROP, R6_SERVER_MSG);
	}
	n = client_frame(f, 42, 0);			/* unknown type */
	expect_client(f, n, VERDICT_FORWARD, R6_TYPE_SKIPPED);
}

static void test_client_malformed(void)
{
	uint8_t f[2048];
	size_t n = client_frame(f, DHCP6_SOLICIT, 0);

	f[OFF_UDP + 6] ^= 1;				/* checksum */
	expect_client(f, n, VERDICT_FORWARD, R6_BAD_CSUM);
	n = client_frame(f, DHCP6_SOLICIT, 0);
	put16(f + OFF_UDP + 6, 0);			/* zero: invalid in v6 */
	expect_client(f, n, VERDICT_FORWARD, R6_BAD_CSUM);
	n = client_frame(f, DHCP6_SOLICIT, 0);
	f[20] = 0;					/* hop-by-hop header */
	expect_client(f, n, VERDICT_FORWARD, R6_EXT_HEADER);
	n = client_frame(f, DHCP6_SOLICIT, 0);
	put16(f + 18, 2000);				/* payload length */
	expect_client(f, n, VERDICT_FORWARD, R6_MALFORMED);
	n = client_frame(f, DHCP6_SOLICIT, 0);
	expect_client(f, 60, VERDICT_FORWARD, R6_MALFORMED);	/* truncated */
	n = client_frame(f, DHCP6_SOLICIT, 0);
	put16(f + 12, 0x0800);
	expect_client(f, n, VERDICT_FORWARD, R6_MALFORMED);
}

static void test_too_big(void)
{
	uint8_t in[2048], f[2048], pl[1500];
	struct dhcp6_info info;
	size_t n, len;

	/* a message that fits the MTU alone but not wrapped */
	memset(pl, 0, sizeof(pl));
	client_msg(pl, DHCP6_SOLICIT);
	n = frame(in, MCAST_MAC, CLIENT_MAC, CLIENT_LL, ALL_RELAYS, 546, 547,
		  pl, 1500 - 48 - 10);
	len = n;
	memcpy(f, in, n);
	CHECK(dhcp6_handle_client(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_DROP);
	CHECK(info.reason == R6_TOO_BIG);
	/* and the buffer limit */
	n = client_frame(in, DHCP6_SOLICIT, 0);
	len = n;
	memcpy(f, in, n);
	CHECK(dhcp6_handle_client(f, &len, n + 20, &cfg, &info) == VERDICT_DROP);
	CHECK(info.reason == R6_TOO_BIG);
}

/* ------------------------------------------------------------------ */
/* uplink: Relay-Reply as the upstream relay sends it to the LDRA */

static size_t relay_reply(uint8_t *f, const uint8_t *ifid, size_t ifid_len,
			  int inner_type, const uint8_t *link,
			  const uint8_t *peer, const uint8_t *ipdst)
{
	uint8_t pl[512], *o;
	size_t n;

	pl[0] = DHCP6_RELAY_REPL;
	pl[1] = 0;
	memcpy(pl + 2, link, 16);
	memcpy(pl + 18, peer, 16);
	o = pl + 34;
	if (ifid) {
		put16(o, 18);
		put16(o + 2, (unsigned)ifid_len);
		memcpy(o + 4, ifid, ifid_len);
		o += 4 + ifid_len;
	}
	if (inner_type) {
		n = client_msg(o + 4, inner_type);
		put16(o, 9);
		put16(o + 2, (unsigned)n);
		o += 4 + n;
	}
	return frame(f, CLIENT_MAC, ROUTER_MAC, ROUTER_LL, ipdst, 547, 547, pl,
		     (size_t)(o - pl));
}

static void test_unwrap(void)
{
	static const int inner[] = { DHCP6_ADVERTISE, DHCP6_REPLY,
				     DHCP6_RECONFIGURE };
	uint8_t f[2048], want[256];
	size_t i;

	for (i = 0; i < 3; i++) {
		struct dhcp6_info info;
		size_t len = relay_reply(f, cfg.ifid, cfg.ifid_len, inner[i],
					 (uint8_t[16]){ 0 }, CLIENT_LL,
					 CLIENT_LL);
		size_t wl = client_msg(want, inner[i]);

		CHECK(dhcp6_parse(f, len, &info) == R6_PARSED);
		CHECK(dhcp6_ifid_matches(&info, &cfg));
		CHECK(dhcp6_handle_uplink(f, &len, &cfg, &info) ==
		      VERDICT_FORWARD_MODIFIED);
		CHECK(info.reason == R6_REPLY_OURS);
		CHECK(len == OFF_D + wl && !memcmp(f + OFF_D, want, wl));
		CHECK(dhcp6_parse(f, len, &info) == R6_PARSED);
		CHECK(info.sport == 547 && info.dport == 546);
		CHECK(!memcmp(f, CLIENT_MAC, 6) && !memcmp(f + 6, ROUTER_MAC, 6));
		CHECK(!memcmp(f + 22, ROUTER_LL, 16) && !memcmp(f + 38, CLIENT_LL, 16));
		CHECK(info.msgtype == inner[i] && info.xid == 0x123456);
		pcap_write(f, len);
	}
}

static void expect_uplink(uint8_t *f, size_t n, const struct ldra_cfg *c,
			  enum reason6 r)
{
	struct dhcp6_info info;
	size_t len = n;

	CHECK(dhcp6_handle_uplink(f, &len, c, &info) == VERDICT_DROP);
	CHECK(info.reason == r);
	CHECK(len == n);
}

static void test_uplink_drops(void)
{
	static const uint8_t other[] = "cust-other/br1:eth0";
	static const uint8_t zero[16], link[16] = { 0x20, 0x01, [15] = 1 };
	uint8_t f[2048];
	size_t n;

	n = relay_reply(f, other, sizeof(other) - 1, DHCP6_REPLY, zero,
			CLIENT_LL, CLIENT_LL);
	expect_uplink(f, n, NULL, R6_REPLY_FOREIGN);
	n = relay_reply(f, cfg.ifid, cfg.ifid_len, DHCP6_REPLY, zero,
			CLIENT_LL, CLIENT_LL);
	expect_uplink(f, n, NULL, R6_REPLY_FOREIGN);	/* no owner port */
	n = relay_reply(f, other, sizeof(other) - 1, DHCP6_REPLY, zero,
			CLIENT_LL, CLIENT_LL);
	expect_uplink(f, n, &cfg, R6_REPLY_FOREIGN);	/* wrong owner */
	n = relay_reply(f, cfg.ifid, cfg.ifid_len, DHCP6_REPLY, link,
			CLIENT_LL, CLIENT_LL);
	expect_uplink(f, n, &cfg, R6_REPLY_FOREIGN);	/* for a full relay */
	n = relay_reply(f, cfg.ifid, cfg.ifid_len, DHCP6_REPLY, zero,
			CLIENT_LL, ROUTER_LL);
	expect_uplink(f, n, &cfg, R6_REPLY_INVALID);	/* peer != dst */
	n = relay_reply(f, NULL, 0, DHCP6_REPLY, zero, CLIENT_LL, CLIENT_LL);
	expect_uplink(f, n, &cfg, R6_REPLY_INVALID);	/* no Interface-ID */
	n = relay_reply(f, cfg.ifid, cfg.ifid_len, 0, zero, CLIENT_LL,
			CLIENT_LL);
	expect_uplink(f, n, &cfg, R6_REPLY_INVALID);	/* no Relay-Message */
	n = relay_reply(f, cfg.ifid, cfg.ifid_len, DHCP6_SOLICIT, zero,
			CLIENT_LL, CLIENT_LL);
	expect_uplink(f, n, &cfg, R6_REPLY_INVALID);	/* client msg inside */
	n = relay_reply(f, cfg.ifid, cfg.ifid_len, DHCP6_REPLY, zero,
			CLIENT_LL, CLIENT_LL);
	f[OFF_UDP + 6] ^= 0x40;
	expect_uplink(f, n, &cfg, R6_BAD_CSUM);
	/* other customers' messages arriving from the uplink */
	n = client_frame(f, DHCP6_SOLICIT, 0);
	expect_uplink(f, n, &cfg, R6_CLIENT_MSG);
	n = client_frame(f, DHCP6_RELAY_FORW, 0);
	expect_uplink(f, n, &cfg, R6_CLIENT_MSG);
}

/* wrap, let a "server" answer like the upstream relay would, unwrap */
static void test_roundtrip(void)
{
	uint8_t f[2048], r[2048], want[256];
	struct dhcp6_info info;
	size_t len = client_frame(f, DHCP6_REQUEST, 0), rl, wl;

	CHECK(dhcp6_handle_client(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD_MODIFIED);
	CHECK(dhcp6_parse(f, len, &info) == R6_PARSED);
	/* the server echoes Interface-ID and answers to the peer-address */
	rl = relay_reply(r, info.ifid, info.ifid_len, DHCP6_REPLY,
			 info.link_addr, info.peer_addr, info.peer_addr);
	CHECK(dhcp6_handle_uplink(r, &rl, &cfg, &info) ==
	      VERDICT_FORWARD_MODIFIED);
	wl = client_msg(want, DHCP6_REPLY);
	CHECK(rl == OFF_D + wl && !memcmp(r + OFF_D, want, wl));
}

static uint32_t rnd_state = 12345;

static uint32_t rnd(void)
{
	rnd_state = rnd_state * 1103515245u + 12345u;
	return rnd_state >> 8;
}

static void test_fuzz(void)
{
	uint8_t base[2][2048], f[2048];
	size_t blen[2];
	int i;

	blen[0] = client_frame(base[0], DHCP6_SOLICIT, 0);
	blen[1] = relay_reply(base[1], cfg.ifid, cfg.ifid_len, DHCP6_REPLY,
			      (uint8_t[16]){ 0 }, CLIENT_LL, CLIENT_LL);
	for (i = 0; i < 200000; i++) {
		struct dhcp6_info info;
		int b = i & 1, k, nmut = 1 + (int)(rnd() % 6);
		size_t len = blen[b] - (rnd() % 4 == 0 ? rnd() % blen[b] : 0);

		memcpy(f, base[b], blen[b]);
		for (k = 0; k < nmut; k++)
			f[OFF_UDP + 8 + rnd() % (blen[b] - OFF_D)] = (uint8_t)rnd();
		if (rnd() % 2)	/* past the checksum, into the parser */
			fix_csum(f, get16(f + OFF_UDP + 4) <= len - OFF_UDP ?
				 get16(f + OFF_UDP + 4) : 8);
		if (b == 0) {
			size_t l = len;

			if (dhcp6_handle_client(f, &l, sizeof(f), &cfg, &info) ==
			    VERDICT_FORWARD_MODIFIED)
				CHECK(l <= sizeof(f) && dhcp6_parse(f, l, &info) ==
				      R6_PARSED);
		} else {
			size_t l = len;

			if (dhcp6_handle_uplink(f, &l, &cfg, &info) ==
			    VERDICT_FORWARD_MODIFIED)
				CHECK(l <= len && dhcp6_parse(f, l, &info) ==
				      R6_PARSED);
		}
	}
	for (i = 0; i < 100000; i++) {		/* pure garbage */
		struct dhcp6_info info;
		size_t len = rnd() % 300, k, l;

		for (k = 0; k < len; k++)
			f[k] = (uint8_t)rnd();
		if (len > 14) {
			put16(f + 12, 0x86dd);
			f[14] = 0x60;
		}
		l = len;
		dhcp6_handle_client(f, &l, sizeof(f), &cfg, &info);
		l = len;
		dhcp6_handle_uplink(f, &l, &cfg, &info);
		dhcp6_ra_guard(f, len, &info);
		if (len > 21) {		/* also as ICMPv6 behind ext headers */
			f[20] = (uint8_t)(rnd() % 2 ? 0 : 58);
			dhcp6_ra_guard(f, len, &info);
		}
	}
}

/* ICMPv6 frame, optionally behind an extension header (code ext) */
static size_t icmp6_frame(uint8_t *f, int type, int ext, size_t trunc)
{
	uint8_t pl[64];
	size_t n = 0;

	memset(pl, 0, sizeof(pl));
	if (ext >= 0) {
		pl[0] = 58;		/* next header */
		pl[1] = 0;		/* 8 bytes */
		if (ext == 0)		/* router alert, as MLD carries it */
			memcpy(pl + 2, "\x05\x02\x00\x00\x01\x00", 6);
		n = 8;
	}
	pl[n] = (uint8_t)type;
	n += 16;
	n = frame(f, MCAST_MAC, CLIENT_MAC, CLIENT_LL, ALL_RELAYS, 0, 0, pl, n);
	memmove(f + 54, f + OFF_D, n - OFF_D);	/* no UDP header */
	n -= 8;
	f[20] = ext >= 0 ? (uint8_t)ext : 58;
	f[21] = 255;
	put16(f + 18, (unsigned)(n - 54 - trunc));
	return n - trunc;
}

static void expect_ra(int type, int ext, size_t trunc, enum verdict v,
		      enum reason6 r)
{
	uint8_t f[256];
	struct dhcp6_info info;
	size_t n = icmp6_frame(f, type, ext, trunc);

	CHECK(dhcp6_ra_guard(f, n, &info) == v);
	CHECK(info.reason == r);
}

static void test_ra_guard(void)
{
	uint8_t f[256];
	struct dhcp6_info info;
	size_t n;

	expect_ra(134, -1, 0, VERDICT_DROP, R6_RA);	/* RA */
	expect_ra(134, 0, 0, VERDICT_DROP, R6_RA);	/* behind hop-by-hop */
	expect_ra(134, 60, 0, VERDICT_DROP, R6_RA);	/* behind dest options */
	expect_ra(134, 44, 0, VERDICT_DROP, R6_ICMP6_BAD); /* fragment */
	expect_ra(134, 43, 0, VERDICT_DROP, R6_ICMP6_BAD); /* routing header */
	expect_ra(135, -1, 0, VERDICT_FORWARD, R6_ICMP6);	/* NS */
	expect_ra(136, -1, 0, VERDICT_FORWARD, R6_ICMP6);	/* NA */
	expect_ra(133, -1, 0, VERDICT_FORWARD, R6_ICMP6);	/* RS */
	expect_ra(143, 0, 0, VERDICT_FORWARD, R6_ICMP6);	/* MLDv2 report */
	expect_ra(128, -1, 0, VERDICT_FORWARD, R6_ICMP6);	/* echo */
	expect_ra(134, -1, 14, VERDICT_DROP, R6_ICMP6_BAD); /* truncated */
	expect_ra(134, 0, 18, VERDICT_DROP, R6_ICMP6_BAD); /* in the ext hdr */
	n = icmp6_frame(f, 134, -1, 0);
	CHECK(dhcp6_ra_guard(f, n - 4, &info) == VERDICT_DROP);	/* short frame */
	CHECK(dhcp6_ra_guard(f, 30, &info) == VERDICT_DROP);
	put16(f + 12, 0x0800);
	CHECK(dhcp6_ra_guard(f, n, &info) == VERDICT_DROP);
}

static void test_ip6_str(void)
{
	char b[40];

	CHECK(!strcmp(ip6_str(CLIENT_LL, b), "fe80::11:22ff:fe33:4455"));
	CHECK(!strcmp(ip6_str(ALL_RELAYS, b), "ff02::1:2"));
	CHECK(!strcmp(ip6_str((uint8_t[16]){ 0 }, b), "::"));
	CHECK(!strcmp(ip6_str(SERVER_GUA, b), "2001:db8::53"));
}

int main(void)
{
	pcap_out = pcap_open("test6_out.pcap");
	setup_cfg();
	test_wrap_client_types();
	test_remote_id_omitted();
	test_unicast();
	test_client_port_snooping();
	test_client_malformed();
	test_too_big();
	test_unwrap();
	test_uplink_drops();
	test_roundtrip();
	test_ip6_str();
	test_ra_guard();
	test_fuzz();
	fclose(pcap_out);
	printf("dhcp6: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
