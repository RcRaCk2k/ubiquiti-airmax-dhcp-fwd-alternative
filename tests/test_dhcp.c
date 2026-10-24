/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * Unit tests for the frame logic. Every input/output frame is also written
 * to test_in.pcap / test_out.pcap so tshark can independently verify
 * checksums and decode option 82 (tests/check_pcap.sh).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dhcp.h"

static int failures, checks;
static FILE *pcap_in, *pcap_out;

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
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}
static unsigned get16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }

static FILE *pcap_open(const char *name)
{
	FILE *f = fopen(name, "wb");
	uint32_t h[6] = { 0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1 };

	/* native endian header; tshark detects it from the magic */
	fwrite(h, 4, 1, f);
	fwrite((uint16_t[]){ 2, 4 }, 2, 2, f);
	fwrite(&h[2], 4, 4, f);
	return f;
}

static void pcap_write(FILE *f, const uint8_t *fr, size_t len)
{
	static uint32_t ts = 1;
	uint32_t r[4] = { ts++, 0, (uint32_t)len, (uint32_t)len };

	fwrite(r, 4, 4, f);
	fwrite(fr, 1, len, f);
}

/* ------------------------------------------------------------------ */
/* frame builder */

struct spec {
	int	op;		/* 1 request, 2 reply */
	int	type;		/* DHCP message type, 0 = BOOTP */
	int	unicast;	/* unicast MAC/IP (renew) */
	uint32_t ciaddr, yiaddr, giaddr;
	int	hops;
	int	pad_to;		/* pad BOOTP payload with zeros to this size */
	const uint8_t *extra;	/* extra options (before END) */
	size_t	extra_len;
	const uint8_t *tail;	/* bytes after END */
	size_t	tail_len;
	int	no_udp_csum;
	int	overload;	/* option 52 value; file field gets option 82 */
};

static const uint8_t CLIENT_MAC[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t SERVER_MAC[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

static size_t build(uint8_t *f, const struct spec *s)
{
	uint8_t *ip = f + 14, *udp = ip + 20, *b = udp + 8, *o;
	size_t blen, i;

	memset(f, 0, FRAME_BUF_LEN);
	if (s->op == 1) {
		memcpy(f, s->unicast ? SERVER_MAC : (const uint8_t *)"\xff\xff\xff\xff\xff\xff", 6);
		memcpy(f + 6, CLIENT_MAC, 6);
	} else {
		memcpy(f, s->unicast ? CLIENT_MAC : (const uint8_t *)"\xff\xff\xff\xff\xff\xff", 6);
		memcpy(f + 6, SERVER_MAC, 6);
	}
	put16(f + 12, 0x0800);

	b[0] = (uint8_t)s->op;
	b[1] = 1;
	b[2] = 6;
	b[3] = (uint8_t)s->hops;
	put32(b + 4, 0x12345678);
	put16(b + 10, s->unicast ? 0 : 0x8000);
	put32(b + 12, s->ciaddr);
	put32(b + 16, s->yiaddr);
	put32(b + 24, s->giaddr);
	memcpy(b + 28, CLIENT_MAC, 6);
	put32(b + 236, 0x63825363);
	o = b + 240;
	if (s->type) {
		*o++ = 53; *o++ = 1; *o++ = (uint8_t)s->type;
	}
	if (s->overload) {
		*o++ = 52; *o++ = 1; *o++ = (uint8_t)s->overload;
		/* file field: option 82 + END */
		memcpy(b + 108, "\x52\x05\x01\x03" "abc" "\xff", 8);
	}
	if (s->extra) {
		memcpy(o, s->extra, s->extra_len);
		o += s->extra_len;
	}
	*o++ = 255;
	if (s->tail) {
		memcpy(o, s->tail, s->tail_len);
		o += s->tail_len;
	}
	blen = (size_t)(o - b);
	if (s->pad_to && (size_t)s->pad_to > blen)
		blen = (size_t)s->pad_to;

	ip[0] = 0x45;
	put16(ip + 2, (unsigned)(20 + 8 + blen));
	ip[8] = 64;
	ip[9] = 17;
	if (s->op == 1) {
		put32(ip + 12, s->unicast ? s->ciaddr : 0);
		put32(ip + 16, s->unicast ? 0x0a000001 : 0xffffffff);
		put16(udp, 68);
		put16(udp + 2, 67);
	} else {
		put32(ip + 12, 0x0a000001);
		put32(ip + 16, s->unicast ? s->yiaddr : 0xffffffff);
		put16(udp, 67);
		put16(udp + 2, 68);
	}
	put16(ip + 10, ip_header_csum(ip, 20));
	put16(udp + 4, (unsigned)(8 + blen));
	if (!s->no_udp_csum)
		put16(udp + 6, udp_csum(ip, udp, 8 + blen));
	(void)i;
	return 14 + 20 + 8 + blen;
}

#define TEST_CID "cust-example"
#define TEST_RID "00005e005301"
#define O82_SIZE (2u + 2 + sizeof(TEST_CID) - 1 + 2 + sizeof(TEST_RID) - 1)

static struct o82_cfg cfg;

static void setup_cfg(void)
{
	memset(&cfg, 0, sizeof(cfg));
	cfg.cid_len = (uint8_t)strlen(TEST_CID);
	memcpy(cfg.cid, TEST_CID, cfg.cid_len);
	cfg.rid_len = (uint8_t)strlen(TEST_RID);
	memcpy(cfg.rid, TEST_RID, cfg.rid_len);
	cfg.mtu = 1500;
	cfg.type_mask = TYPE_BIT(0) | TYPE_BIT(DHCP_DISCOVER) |
			TYPE_BIT(DHCP_REQUEST) | TYPE_BIT(DHCP_DECLINE) |
			TYPE_BIT(DHCP_RELEASE) | TYPE_BIT(DHCP_INFORM);
}

/* checks shared by every successful insertion */
static void check_inserted(const uint8_t *in, size_t in_len,
			   const uint8_t *out, size_t out_len)
{
	struct dhcp_info a, b;

	CHECK(dhcp_parse(in, in_len, &a) == R_PARSED);
	CHECK(dhcp_parse(out, out_len, &b) == R_PARSED);
	CHECK(b.has_o82);
	CHECK(b.o82_cid_len == cfg.cid_len &&
	      !memcmp(b.o82_cid, cfg.cid, cfg.cid_len));
	CHECK(b.o82_rid_len == cfg.rid_len &&
	      !memcmp(b.o82_rid, cfg.rid, cfg.rid_len));
	/* transparency: L2/L3 addressing and BOOTP header untouched */
	CHECK(!memcmp(in, out, 14));
	CHECK(!memcmp(in + 14 + 12, out + 14 + 12, 8));		/* IPs */
	CHECK(!memcmp(in + 34, out + 34, 4));			/* ports */
	CHECK(!memcmp(in + 42, out + 42, 236 + 4));		/* BOOTP */
	CHECK(a.xid == b.xid && a.flags == b.flags && b.giaddr == 0 &&
	      b.hops == 0 && a.msgtype == b.msgtype);
	CHECK(out_len - 14 <= cfg.mtu);
	pcap_write(pcap_out, out, out_len);
}

static void test_discover_padded(void)
{
	uint8_t f[FRAME_BUF_LEN], in[FRAME_BUF_LEN];
	struct spec s = { .op = 1, .type = DHCP_DISCOVER, .pad_to = 300 };
	struct dhcp_info info;
	size_t len = build(f, &s), in_len = len;
	enum verdict v;

	memcpy(in, f, len);
	pcap_write(pcap_in, in, in_len);
	v = dhcp_handle_request(f, &len, sizeof(f), &cfg, &info);
	CHECK(v == VERDICT_FORWARD_MODIFIED && info.reason == R_INSERTED);
	CHECK(len == in_len);		/* fits into PAD area */
	check_inserted(in, in_len, f, len);
}

static void test_discover_unpadded_grows(void)
{
	uint8_t f[FRAME_BUF_LEN], in[FRAME_BUF_LEN];
	struct spec s = { .op = 1, .type = DHCP_DISCOVER };
	struct dhcp_info info;
	size_t len = build(f, &s), in_len = len;

	memcpy(in, f, len);
	pcap_write(pcap_in, in, in_len);
	CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD_MODIFIED);
	CHECK(len == in_len + O82_SIZE);
	check_inserted(in, in_len, f, len);
}

static void test_request_states(void)
{
	static const struct { const char *name; struct spec s; } t[] = {
		{ "SELECTING", { .op = 1, .type = DHCP_REQUEST, .pad_to = 300,
		  .extra = (const uint8_t *)"\x36\x04\x0a\x00\x00\x01"
			   "\x32\x04\x0a\x00\x00\x64", .extra_len = 12 } },
		{ "INIT-REBOOT", { .op = 1, .type = DHCP_REQUEST, .pad_to = 300,
		  .extra = (const uint8_t *)"\x32\x04\x0a\x00\x00\x64",
		  .extra_len = 6 } },
		{ "RENEWING (unicast)", { .op = 1, .type = DHCP_REQUEST,
		  .unicast = 1, .ciaddr = 0x0a000064, .pad_to = 300 } },
		{ "REBINDING", { .op = 1, .type = DHCP_REQUEST,
		  .ciaddr = 0x0a000064, .pad_to = 300 } },
		{ "DECLINE", { .op = 1, .type = DHCP_DECLINE, .pad_to = 300 } },
		{ "RELEASE (unicast)", { .op = 1, .type = DHCP_RELEASE,
		  .unicast = 1, .ciaddr = 0x0a000064 } },
		{ "INFORM", { .op = 1, .type = DHCP_INFORM, .unicast = 1,
		  .ciaddr = 0x0a000064, .pad_to = 300 } },
		{ "BOOTP", { .op = 1, .type = 0, .pad_to = 300 } },
	};
	size_t i;

	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		uint8_t f[FRAME_BUF_LEN], in[FRAME_BUF_LEN];
		struct dhcp_info info;
		size_t len = build(f, &t[i].s), in_len = len;
		enum verdict v;

		memcpy(in, f, len);
		pcap_write(pcap_in, in, in_len);
		v = dhcp_handle_request(f, &len, sizeof(f), &cfg, &info);
		if (v != VERDICT_FORWARD_MODIFIED)
			fprintf(stderr, "  %s: %s\n", t[i].name,
				dhcp_reason_str(info.reason));
		CHECK(v == VERDICT_FORWARD_MODIFIED);
		check_inserted(in, in_len, f, len);
	}
}

static void expect_unchanged(const struct spec *s, enum reason want)
{
	uint8_t f[FRAME_BUF_LEN], in[FRAME_BUF_LEN];
	struct dhcp_info info;
	size_t len = build(f, s), in_len = len;
	enum verdict v;

	memcpy(in, f, len);
	pcap_write(pcap_in, in, in_len);
	v = dhcp_handle_request(f, &len, sizeof(f), &cfg, &info);
	if (info.reason != want)
		fprintf(stderr, "  expected %s, got %s\n",
			dhcp_reason_str(want), dhcp_reason_str(info.reason));
	CHECK(v == VERDICT_FORWARD);
	CHECK(info.reason == want);
	CHECK(len == in_len && !memcmp(in, f, len));
}

static void test_not_touched(void)
{
	struct spec s;

	/* existing option 82 from the customer: pass unchanged */
	s = (struct spec){ .op = 1, .type = DHCP_DISCOVER, .pad_to = 300,
		.extra = (const uint8_t *)"\x52\x06\x01\x04" "evil", .extra_len = 8 };
	expect_unchanged(&s, R_HAS_O82);

	/* option 82 hidden in the overloaded file field */
	s = (struct spec){ .op = 1, .type = DHCP_DISCOVER, .pad_to = 300,
		.overload = 1 };
	expect_unchanged(&s, R_HAS_O82);

	/* another relay already set giaddr / hops */
	s = (struct spec){ .op = 1, .type = DHCP_DISCOVER, .pad_to = 300,
		.giaddr = 0xc0a80001 };
	expect_unchanged(&s, R_RELAYED);
	s = (struct spec){ .op = 1, .type = DHCP_DISCOVER, .pad_to = 300,
		.hops = 1 };
	expect_unchanged(&s, R_RELAYED);

	/* BOOTREPLY arriving on the client port (rogue server) */
	s = (struct spec){ .op = 2, .type = DHCP_OFFER, .pad_to = 300 };
	expect_unchanged(&s, R_WRONG_OP);
}

static void test_type_mask(void)
{
	struct spec s = { .op = 1, .type = DHCP_INFORM, .pad_to = 300 };
	unsigned saved = cfg.type_mask;

	cfg.type_mask &= ~TYPE_BIT(DHCP_INFORM);
	expect_unchanged(&s, R_TYPE_SKIPPED);
	cfg.type_mask = saved;
}

static void test_malformed(void)
{
	uint8_t f[FRAME_BUF_LEN], in[FRAME_BUF_LEN];
	struct spec s = { .op = 1, .type = DHCP_DISCOVER, .pad_to = 300 };
	struct dhcp_info info;
	size_t len, in_len, cut;

	/* option length runs past the end, no END */
	len = build(f, &s);
	f[42 + 240 + 3] = 61;
	f[42 + 240 + 4] = 250;
	memset(f + 42 + 240 + 5, 1, len - (42 + 240 + 5));
	put16(f + 40, 0);	/* UDP csum off, so options are reached */
	in_len = len;
	memcpy(in, f, len);
	pcap_write(pcap_in, in, in_len);
	CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD);
	CHECK(info.reason == R_BAD_OPTIONS);
	CHECK(len == in_len && !memcmp(in, f, len));

	/* bad UDP checksum */
	len = build(f, &s);
	f[42 + 100] ^= 0x55;
	CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD && info.reason == R_BAD_CSUM);

	/* bad IP header checksum */
	len = build(f, &s);
	f[14 + 8] = 1;		/* TTL changed, checksum not */
	CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD && info.reason == R_BAD_CSUM);

	/* first fragment (MF set) */
	len = build(f, &s);
	put16(f + 14 + 6, 0x2000);
	put16(f + 14 + 10, 0);
	put16(f + 14 + 10, ip_header_csum(f + 14, 20));
	CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD && info.reason == R_FRAGMENT);

	/* wrong magic cookie */
	len = build(f, &s);
	f[42 + 236] = 0;
	put16(f + 40, 0);
	CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD && info.reason == R_BAD_OPTIONS);

	/* truncated at every length: must never crash or modify */
	len = build(f, &s);
	memcpy(in, f, len);
	for (cut = 0; cut < len; cut++) {
		size_t l = cut;

		memcpy(f, in, len);
		dhcp_handle_request(f, &l, sizeof(f), &cfg, &info);
		CHECK(l == cut);
	}
}

static void test_no_space(void)
{
	uint8_t f[FRAME_BUF_LEN];
	struct spec s = { .op = 1, .type = DHCP_DISCOVER };
	struct dhcp_info info;
	uint8_t big[1200];
	size_t len, i;

	/* option 43 blocks of 255 bytes to get close to 1500 */
	for (i = 0; i + 257 <= sizeof(big); i += 257) {
		big[i] = 43;
		big[i + 1] = 255;
		memset(big + i + 2, 'x', 255);
	}
	s.extra = big;
	s.extra_len = i;
	len = build(f, &s);
	/* leave only a few bytes below the MTU */
	cfg.mtu = len - 14 + 10;
	CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD && info.reason == R_NO_SPACE);
	cfg.mtu = 1500;

	/* large but fitting packet */
	len = build(f, &s);
	{
		uint8_t in[FRAME_BUF_LEN];
		size_t in_len = len;

		memcpy(in, f, len);
		pcap_write(pcap_in, in, in_len);
		CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
		      VERDICT_FORWARD_MODIFIED);
		check_inserted(in, in_len, f, len);
	}
}

static void test_udp_csum_zero(void)
{
	uint8_t f[FRAME_BUF_LEN], in[FRAME_BUF_LEN];
	struct spec s = { .op = 1, .type = DHCP_DISCOVER, .pad_to = 300,
			  .no_udp_csum = 1 };
	struct dhcp_info info;
	size_t len = build(f, &s), in_len = len;

	memcpy(in, f, len);
	pcap_write(pcap_in, in, in_len);
	CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD_MODIFIED);
	CHECK(get16(f + 40) == 0);	/* stays "no checksum" */
	check_inserted(in, in_len, f, len);
}

static void test_trailing_garbage(void)
{
	uint8_t f[FRAME_BUF_LEN], in[FRAME_BUF_LEN];
	struct spec s = { .op = 1, .type = DHCP_DISCOVER,
			  .tail = (const uint8_t *)"\x00\x00JUNK", .tail_len = 6 };
	struct dhcp_info info;
	size_t len = build(f, &s), in_len = len;

	memcpy(in, f, len);
	pcap_write(pcap_in, in, in_len);
	CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD_MODIFIED);
	CHECK(len == in_len + O82_SIZE);
	CHECK(!memcmp(f + len - 6, "\x00\x00JUNK", 6));
	check_inserted(in, in_len, f, len);
}

/* reply direction: build a reply that carries what we insert */
static size_t reply_with_o82(uint8_t *f, const uint8_t *cid, size_t cid_len,
			     int unicast)
{
	uint8_t opt[300];
	size_t n = 0;
	struct spec s = { .op = 2, .type = DHCP_OFFER, .unicast = unicast,
			  .yiaddr = 0x0a000064, .pad_to = 300 };

	opt[n++] = 54; opt[n++] = 4; memcpy(opt + n, "\x0a\x00\x00\x01", 4); n += 4;
	opt[n++] = 82;
	opt[n++] = (uint8_t)(2 + cid_len + 2 + cfg.rid_len);
	opt[n++] = 1; opt[n++] = (uint8_t)cid_len;
	memcpy(opt + n, cid, cid_len); n += cid_len;
	opt[n++] = 2; opt[n++] = cfg.rid_len;
	memcpy(opt + n, cfg.rid, cfg.rid_len); n += cfg.rid_len;
	opt[n++] = 51; opt[n++] = 4; memcpy(opt + n, "\x00\x00\x0e\x10", 4); n += 4;
	s.extra = opt;
	s.extra_len = n;
	return build(f, &s);
}

static void test_reply(void)
{
	uint8_t f[FRAME_BUF_LEN], in[FRAME_BUF_LEN];
	struct dhcp_info info, a;
	size_t len, in_len;
	int uc;

	for (uc = 0; uc <= 1; uc++) {
		len = reply_with_o82(f, cfg.cid, cfg.cid_len, uc);
		in_len = len;
		memcpy(in, f, len);
		pcap_write(pcap_in, in, in_len);
		CHECK(dhcp_handle_reply(f, &len, &cfg, &info) ==
		      VERDICT_FORWARD_MODIFIED && info.reason == R_REPLY_OURS);
		CHECK(len == in_len);
		CHECK(dhcp_parse(f, len, &a) == R_PARSED && !a.has_o82);
		CHECK(a.msgtype == DHCP_OFFER && a.xid == 0x12345678);
		CHECK(!memcmp(in, f, 14));		/* addressing kept */
		/* options after 82 moved up: lease time 51 must follow 54 */
		CHECK(f[42 + 240 + 3] == 54 && f[42 + 240 + 9] == 51);
		pcap_write(pcap_out, f, len);
	}

	/* foreign circuit id */
	len = reply_with_o82(f, (const uint8_t *)"foreign-cust-1", 14, 0);
	in_len = len;
	memcpy(in, f, len);
	pcap_write(pcap_in, in, in_len);
	CHECK(dhcp_handle_reply(f, &len, &cfg, &info) == VERDICT_DROP &&
	      info.reason == R_REPLY_FOREIGN);
	CHECK(!memcmp(in, f, len));

	/* prefix of our id must not match */
	len = reply_with_o82(f, cfg.cid, cfg.cid_len - 1, 0);
	CHECK(dhcp_handle_reply(f, &len, &cfg, &info) == VERDICT_DROP);

	/* without option 82 */
	{
		struct spec s = { .op = 2, .type = DHCP_ACK, .pad_to = 300 };

		len = build(f, &s);
		CHECK(dhcp_handle_reply(f, &len, &cfg, &info) ==
		      VERDICT_FORWARD && info.reason == R_REPLY_NO_O82);
	}
	/* NAK with our id */
	len = reply_with_o82(f, cfg.cid, cfg.cid_len, 0);
	f[42 + 240 + 2] = DHCP_NAK;
	put16(f + 40, 0);
	CHECK(dhcp_handle_reply(f, &len, &cfg, &info) ==
	      VERDICT_FORWARD_MODIFIED && info.msgtype == DHCP_NAK);
}

/* insert, turn into a reply, strip: options must be as before */
static void test_roundtrip(void)
{
	uint8_t f[FRAME_BUF_LEN], in[FRAME_BUF_LEN];
	struct spec s = { .op = 1, .type = DHCP_REQUEST, .pad_to = 300,
		.extra = (const uint8_t *)"\x32\x04\x0a\x00\x00\x64", .extra_len = 6 };
	struct dhcp_info info;
	size_t len = build(f, &s), in_len = len;

	memcpy(in, f, len);
	CHECK(dhcp_handle_request(f, &len, sizeof(f), &cfg, &info) ==
	      VERDICT_FORWARD_MODIFIED);
	f[42] = 2;		/* op = BOOTREPLY, then fix csum */
	put16(f + 40, 0);
	CHECK(dhcp_handle_reply(f, &len, &cfg, &info) == VERDICT_FORWARD_MODIFIED);
	CHECK(len == in_len);
	CHECK(!memcmp(in + 42 + 240, f + 42 + 240, len - 42 - 240));
}

/* random mutations: no crash, no out-of-bounds (ASan), sane output */
static void test_fuzz(void)
{
	uint8_t base[FRAME_BUF_LEN], f[FRAME_BUF_LEN];
	struct dhcp_info info, a;
	unsigned seed = 12345, iter;
	struct spec s = { .op = 1, .type = DHCP_DISCOVER, .pad_to = 300 };
	size_t blen = build(base, &s);

	for (iter = 0; iter < 200000; iter++) {
		size_t len = blen, k, nmut;
		enum verdict v;

		memcpy(f, base, sizeof(f));
		seed = seed * 1103515245u + 12345u;
		nmut = 1 + (seed >> 16) % 8;
		for (k = 0; k < nmut; k++) {
			seed = seed * 1103515245u + 12345u;
			f[14 + (seed >> 8) % (blen - 14)] = (uint8_t)(seed >> 24);
		}
		seed = seed * 1103515245u + 12345u;
		if ((seed >> 16) % 4 == 0)
			len = (seed >> 3) % blen;
		/* fuzz past checksums so the option parser is exercised */
		if (len >= 42)
			put16(f + 40, 0);
		if (len >= 34) {
			put16(f + 24, 0);
			put16(f + 24, ip_header_csum(f + 14, 20));
		}
		if (iter & 1)
			v = dhcp_handle_request(f, &len, sizeof(f), &cfg, &info);
		else
			v = dhcp_handle_reply(f, &len, &cfg, &info);
		if (v == VERDICT_FORWARD_MODIFIED) {
			CHECK(len <= sizeof(f) && len - 14 <= cfg.mtu);
			CHECK(dhcp_parse(f, len, &a) == R_PARSED);
		}
	}
}

int main(void)
{
	setup_cfg();
	pcap_in = pcap_open("test_in.pcap");
	pcap_out = pcap_open("test_out.pcap");

	test_discover_padded();
	test_discover_unpadded_grows();
	test_request_states();
	test_not_touched();
	test_type_mask();
	test_malformed();
	test_no_space();
	test_udp_csum_zero();
	test_trailing_garbage();
	test_reply();
	test_roundtrip();
	test_fuzz();

	fclose(pcap_in);
	fclose(pcap_out);
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
