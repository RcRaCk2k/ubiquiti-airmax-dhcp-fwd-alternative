/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 */
#include <string.h>

#include "dhcp.h"

#define BOOTP_FIXED_LEN	236		/* op .. file */
#define BOOTP_MIN_LEN	(BOOTP_FIXED_LEN + 4)	/* + magic cookie */
#define OFF_SNAME	44
#define OFF_FILE	108
#define OFF_OPTIONS	240

#define OPT_PAD		0
#define OPT_END		255
#define OPT_MSGTYPE	53
#define OPT_OVERLOAD	52
#define OPT_RELAY	82
#define SUB_CID		1
#define SUB_RID		2

struct parsed {
	uint8_t		*ip;
	size_t		ihl;
	uint8_t		*udp;
	size_t		udp_len;	/* incl. 8 byte header */
	uint8_t		*b;		/* BOOTP payload */
	size_t		blen;
	size_t		end_off;	/* END in main option field; 0 = none */
	size_t		o82_off;	/* option 82 in main field; 0 = none */
};

static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

static uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t n)
{
	while (n > 1) {
		sum += get16(p);
		p += 2;
		n -= 2;
	}
	if (n)
		sum += (uint32_t)p[0] << 8;
	return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

uint16_t ip_header_csum(const uint8_t *ip, size_t ihl)
{
	uint32_t sum = csum_add(0, ip, 10);

	sum = csum_add(sum, ip + 12, ihl - 12);
	return csum_fold(sum);
}

uint16_t udp_csum(const uint8_t *ip, const uint8_t *udp, size_t udp_len)
{
	uint32_t sum = csum_add(0, ip + 12, 8);	/* src + dst address */
	uint16_t c;

	sum += 17 + (uint32_t)udp_len;
	sum = csum_add(sum, udp, 6);
	sum = csum_add(sum, udp + 8, udp_len - 8);
	c = csum_fold(sum);
	return c ? c : 0xffff;
}

static void decode_o82(const uint8_t *v, size_t l, struct dhcp_info *info)
{
	size_t i = 0;

	info->has_o82 = 1;
	while (i + 2 <= l && i + 2 + v[i + 1] <= l) {
		uint8_t code = v[i], sl = v[i + 1];

		if (code == SUB_CID && !info->o82_cid_len) {
			memcpy(info->o82_cid, v + i + 2, sl);
			info->o82_cid_len = sl;
		} else if (code == SUB_RID && !info->o82_rid_len) {
			memcpy(info->o82_rid, v + i + 2, sl);
			info->o82_rid_len = sl;
		}
		i += 2 + sl;
	}
}

/* Walks one option field. Returns 0 on success, -1 if broken. For the main
 * field, *end_off receives the offset of END (0 if missing). */
static int scan_field(struct parsed *p, size_t start, size_t stop, int main,
		      int *overload, struct dhcp_info *info)
{
	const uint8_t *b = p->b;
	size_t i = start;

	while (i < stop) {
		uint8_t code = b[i], l;

		if (code == OPT_PAD) {
			i++;
			continue;
		}
		if (code == OPT_END) {
			if (main)
				p->end_off = i;
			return 0;
		}
		if (i + 2 > stop)
			return -1;
		l = b[i + 1];
		if (i + 2 + l > stop)
			return -1;
		if (code == OPT_MSGTYPE && l >= 1)
			info->msgtype = b[i + 2];
		else if (code == OPT_OVERLOAD && main && l >= 1)
			*overload = b[i + 2];
		else if (code == OPT_RELAY) {
			if (main && !p->o82_off)
				p->o82_off = i;
			decode_o82(b + i + 2, l, info);
		}
		i += 2 + l;
	}
	return main ? -1 : 0;	/* main field must be terminated */
}

static enum reason parse(uint8_t *f, size_t len, struct parsed *p,
			 struct dhcp_info *info)
{
	uint8_t *ip, *udp, *b;
	size_t ihl, ip_total, udp_len;
	uint16_t frag;
	int overload = 0;

	memset(info, 0, sizeof(*info));
	memset(p, 0, sizeof(*p));

	if (len < ETH_HDR_LEN + 20 + 8)
		return R_MALFORMED;
	memcpy(info->dst_mac, f, 6);
	memcpy(info->src_mac, f + 6, 6);
	if (get16(f + 12) != 0x0800)
		return R_MALFORMED;

	ip = f + ETH_HDR_LEN;
	if ((ip[0] >> 4) != 4)
		return R_MALFORMED;
	ihl = (size_t)(ip[0] & 0x0f) * 4;
	ip_total = get16(ip + 2);
	if (ihl < 20 || ip_total < ihl + 8 || ETH_HDR_LEN + ip_total > len)
		return R_MALFORMED;
	if (ip[9] != 17)
		return R_MALFORMED;
	info->ip_src = get32(ip + 12);
	info->ip_dst = get32(ip + 16);
	frag = get16(ip + 6);
	if (frag & 0x3fff)
		return R_FRAGMENT;
	if (csum_fold(csum_add(0, ip, ihl)) != 0)
		return R_BAD_CSUM;

	udp = ip + ihl;
	udp_len = get16(udp + 4);
	if (udp_len < 8 + BOOTP_MIN_LEN || udp_len > ip_total - ihl)
		return R_MALFORMED;
	if (get16(udp + 6) != 0 &&
	    udp_csum(ip, udp, udp_len) != get16(udp + 6))
		return R_BAD_CSUM;

	b = udp + 8;
	p->ip = ip;
	p->ihl = ihl;
	p->udp = udp;
	p->udp_len = udp_len;
	p->b = b;
	p->blen = udp_len - 8;

	info->op = b[0];
	info->hops = b[3];
	info->xid = get32(b + 4);
	info->flags = get16(b + 10);
	info->ciaddr = get32(b + 12);
	info->yiaddr = get32(b + 16);
	info->giaddr = get32(b + 24);
	memcpy(info->chaddr, b + 28, 6);

	if (get32(b + BOOTP_FIXED_LEN) != 0x63825363)
		return R_BAD_OPTIONS;
	if (scan_field(p, OFF_OPTIONS, p->blen, 1, &overload, info) < 0)
		return R_BAD_OPTIONS;
	if ((overload & 2) &&
	    scan_field(p, OFF_SNAME, OFF_SNAME + 64, 0, &overload, info) < 0)
		return R_BAD_OPTIONS;
	if ((overload & 1) &&
	    scan_field(p, OFF_FILE, OFF_FILE + 128, 0, &overload, info) < 0)
		return R_BAD_OPTIONS;
	return R_PARSED;
}

enum reason dhcp_parse(const uint8_t *frame, size_t len, struct dhcp_info *info)
{
	struct parsed p;

	/* parse() does not write to the frame */
	info->reason = parse((uint8_t *)frame, len, &p, info);
	return info->reason;
}

static void fix_lengths_and_csums(struct parsed *p, size_t new_blen, int had_csum)
{
	size_t udp_len = new_blen + 8;

	put16(p->ip + 2, (uint16_t)(p->ihl + udp_len));
	put16(p->ip + 10, 0);
	put16(p->ip + 10, ip_header_csum(p->ip, p->ihl));
	put16(p->udp + 4, (uint16_t)udp_len);
	put16(p->udp + 6, 0);
	if (had_csum)
		put16(p->udp + 6, udp_csum(p->ip, p->udp, udp_len));
	p->udp_len = udp_len;
	p->blen = new_blen;
}

static size_t o82_len(const struct o82_cfg *cfg)
{
	return (cfg->cid_len ? 2u + cfg->cid_len : 0) +
	       (cfg->rid_len ? 2u + cfg->rid_len : 0);
}

enum verdict dhcp_handle_request(uint8_t *f, size_t *len, size_t cap,
				 const struct o82_cfg *cfg,
				 struct dhcp_info *info)
{
	struct parsed p;
	size_t e, need, tail, new_blen, new_ip_total, i;
	int tail_zero = 1, had_csum;
	uint8_t *o;

	info->reason = parse(f, *len, &p, info);
	if (info->reason != R_PARSED)
		return VERDICT_FORWARD;
	if (info->op != 1) {
		info->reason = R_WRONG_OP;
		return VERDICT_FORWARD;
	}
	if (info->has_o82) {
		info->reason = R_HAS_O82;
		return VERDICT_FORWARD;
	}
	if (info->giaddr || info->hops) {
		info->reason = R_RELAYED;
		return VERDICT_FORWARD;
	}
	if (info->msgtype > 31 || !(cfg->type_mask & TYPE_BIT(info->msgtype))) {
		info->reason = R_TYPE_SKIPPED;
		return VERDICT_FORWARD;
	}

	/* layout after END: [82 len subopts][END][old tail] */
	e = p.end_off;
	need = 2 + o82_len(cfg);
	tail = p.blen - e - 1;
	for (i = e + 1; i < p.blen; i++)
		if (p.b[i]) {
			tail_zero = 0;
			break;
		}
	if (tail_zero)
		new_blen = p.blen > e + need + 1 ? p.blen : e + need + 1;
	else
		new_blen = p.blen + need;
	new_ip_total = p.ihl + 8 + new_blen;
	if (new_ip_total > cfg->mtu || ETH_HDR_LEN + new_ip_total > cap) {
		info->reason = R_NO_SPACE;
		return VERDICT_FORWARD;
	}

	if (!tail_zero)
		memmove(p.b + e + need + 1, p.b + e + 1, tail);
	else if (new_blen > p.blen)
		memset(p.b + p.blen, 0, new_blen - p.blen);

	o = p.b + e;
	*o++ = OPT_RELAY;
	*o++ = (uint8_t)(need - 2);
	if (cfg->cid_len) {
		*o++ = SUB_CID;
		*o++ = cfg->cid_len;
		memcpy(o, cfg->cid, cfg->cid_len);
		o += cfg->cid_len;
	}
	if (cfg->rid_len) {
		*o++ = SUB_RID;
		*o++ = cfg->rid_len;
		memcpy(o, cfg->rid, cfg->rid_len);
		o += cfg->rid_len;
	}
	*o = OPT_END;
	if (tail_zero)
		memset(o + 1, 0, new_blen - (size_t)(o + 1 - p.b));

	had_csum = get16(p.udp + 6) != 0;
	fix_lengths_and_csums(&p, new_blen, had_csum);
	*len = ETH_HDR_LEN + new_ip_total;
	info->reason = R_INSERTED;
	return VERDICT_FORWARD_MODIFIED;
}

static int is_ours(const struct dhcp_info *info, const struct o82_cfg *cfg)
{
	if (info->o82_cid_len != cfg->cid_len ||
	    memcmp(info->o82_cid, cfg->cid, cfg->cid_len))
		return 0;
	if (cfg->rid_len &&
	    (info->o82_rid_len != cfg->rid_len ||
	     memcmp(info->o82_rid, cfg->rid, cfg->rid_len)))
		return 0;
	return 1;
}

/* remove option 82 from the main field, keep the length (PAD) */
static void strip(struct parsed *p)
{
	size_t o = p->o82_off, l = 2u + p->b[o + 1];

	memmove(p->b + o, p->b + o + l, p->blen - o - l);
	memset(p->b + p->blen - l, 0, l);
	fix_lengths_and_csums(p, p->blen, get16(p->udp + 6) != 0);
}

enum verdict dhcp_handle_reply(uint8_t *f, size_t *len,
			       const struct o82_cfg *cfg,
			       struct dhcp_info *info)
{
	struct parsed p;
	/* length is kept, freed bytes become PAD */
	info->reason = parse(f, *len, &p, info);
	if (info->reason != R_PARSED)
		return VERDICT_FORWARD;
	if (info->op != 2) {
		info->reason = R_WRONG_OP;
		return VERDICT_FORWARD;
	}
	if (!info->has_o82) {
		info->reason = R_REPLY_NO_O82;
		return VERDICT_FORWARD;
	}
	/* only option 82 in the main field is ours to strip */
	if (!p.o82_off || !is_ours(info, cfg)) {
		info->reason = R_REPLY_FOREIGN;
		return VERDICT_DROP;
	}

	strip(&p);
	info->reason = R_REPLY_OURS;
	return VERDICT_FORWARD_MODIFIED;
}

int dhcp_strip_o82(uint8_t *f, size_t len)
{
	struct dhcp_info info;
	struct parsed p;

	if (parse(f, len, &p, &info) != R_PARSED || info.op != 2 || !p.o82_off)
		return -1;
	strip(&p);
	return 0;
}

const char *dhcp_reason_str(enum reason r)
{
	static const char *const s[R_MAX] = {
		[R_PARSED] = "parsed",
		[R_MALFORMED] = "malformed",
		[R_FRAGMENT] = "fragment",
		[R_BAD_CSUM] = "bad-checksum",
		[R_BAD_OPTIONS] = "bad-options",
		[R_WRONG_OP] = "wrong-op",
		[R_HAS_O82] = "has-option82",
		[R_RELAYED] = "already-relayed",
		[R_TYPE_SKIPPED] = "type-skipped",
		[R_NO_SPACE] = "no-space",
		[R_INSERTED] = "inserted",
		[R_REPLY_OURS] = "reply-ours",
		[R_REPLY_FOREIGN] = "reply-foreign",
		[R_REPLY_NO_O82] = "reply-no-option82",
	};

	return r < R_MAX && s[r] ? s[r] : "?";
}

const char *dhcp_type_str(uint8_t t)
{
	static const char *const s[] = {
		"BOOTP", "DISCOVER", "OFFER", "REQUEST", "DECLINE",
		"ACK", "NAK", "RELEASE", "INFORM",
	};

	return t < sizeof(s) / sizeof(s[0]) ? s[t] : "UNKNOWN";
}
