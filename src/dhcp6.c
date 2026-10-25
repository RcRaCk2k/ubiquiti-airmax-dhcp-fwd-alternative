/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 */
#include <stdio.h>
#include <string.h>

#include "dhcp6.h"

#define OFF_IP6		ETH_HDR_LEN
#define IP6_HDR_LEN	40
#define UDP_HDR_LEN	8
#define OFF_UDP		(OFF_IP6 + IP6_HDR_LEN)
#define OFF_DHCP	(OFF_UDP + UDP_HDR_LEN)
#define RELAY_HDR_LEN	34		/* type, hop-count, link, peer */

#define OPT_RELAY_MSG	9
#define OPT_INTERFACE_ID 18
#define OPT_REMOTE_ID	37

struct parsed6 {
	uint8_t		*ip;
	uint8_t		*udp;
	uint8_t		*d;		/* DHCPv6 message */
	size_t		dlen;
	size_t		relmsg_off;	/* Relay-Message data in d; 0 = none */
	size_t		relmsg_len;
};

static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = (v >> 16) & 0xff;
	p[2] = (v >> 8) & 0xff;
	p[3] = v & 0xff;
}

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

uint16_t udp6_csum(const uint8_t *ip6, const uint8_t *udp, size_t udp_len)
{
	uint32_t sum = csum_add(0, ip6 + 8, 32);	/* src + dst address */
	uint16_t c;

	sum += (uint32_t)(udp_len >> 16) + (uint32_t)(udp_len & 0xffff) + 17;
	sum = csum_add(sum, udp, 6);
	sum = csum_add(sum, udp + 8, udp_len - 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	c = (uint16_t)~sum;
	return c ? c : 0xffff;		/* zero is not allowed in IPv6 */
}

static int is_client_type(uint8_t t)
{
	switch (t) {
	case DHCP6_SOLICIT: case DHCP6_REQUEST: case DHCP6_CONFIRM:
	case DHCP6_RENEW: case DHCP6_REBIND: case DHCP6_RELEASE:
	case DHCP6_DECLINE: case DHCP6_INFO_REQUEST:
		return 1;
	}
	return 0;
}

static int is_server_type(uint8_t t)
{
	return t == DHCP6_ADVERTISE || t == DHCP6_REPLY ||
	       t == DHCP6_RECONFIGURE || t == DHCP6_RELAY_REPL;
}

static enum reason6 parse(uint8_t *frame, size_t len, struct parsed6 *p,
			  struct dhcp6_info *info)
{
	size_t pl, ulen, o;
	uint8_t nh;

	memset(info, 0, sizeof(*info));
	memset(p, 0, sizeof(*p));
	if (len < OFF_DHCP + 4 || get16(frame + 12) != ETH_P_IPV6_)
		return R6_MALFORMED;
	memcpy(info->dst_mac, frame, 6);
	memcpy(info->src_mac, frame + 6, 6);
	p->ip = frame + OFF_IP6;
	if (p->ip[0] >> 4 != 6)
		return R6_MALFORMED;
	memcpy(info->ip_src, p->ip + 8, 16);
	memcpy(info->ip_dst, p->ip + 24, 16);
	nh = p->ip[6];
	if (nh != 17)
		return nh == 0 || nh == 43 || nh == 44 || nh == 60 || nh == 51 ?
		       R6_EXT_HEADER : R6_MALFORMED;
	pl = get16(p->ip + 4);
	if (pl > len - OFF_UDP)
		return R6_MALFORMED;
	p->udp = frame + OFF_UDP;
	ulen = get16(p->udp + 4);
	if (ulen != pl || ulen < UDP_HDR_LEN + 4)
		return R6_MALFORMED;
	info->sport = get16(p->udp);
	info->dport = get16(p->udp + 2);
	if (!get16(p->udp + 6) || udp6_csum(p->ip, p->udp, ulen) != get16(p->udp + 6))
		return R6_BAD_CSUM;
	p->d = frame + OFF_DHCP;
	p->dlen = ulen - UDP_HDR_LEN;
	info->msgtype = p->d[0];
	if (info->msgtype != DHCP6_RELAY_FORW && info->msgtype != DHCP6_RELAY_REPL) {
		info->xid = (uint32_t)p->d[1] << 16 | (uint32_t)p->d[2] << 8 |
			    p->d[3];
		return R6_PARSED;
	}
	if (p->dlen < RELAY_HDR_LEN)
		return R6_MALFORMED;
	info->hop_count = p->d[1];
	memcpy(info->link_addr, p->d + 2, 16);
	memcpy(info->peer_addr, p->d + 18, 16);
	for (o = RELAY_HDR_LEN; o < p->dlen;) {
		uint16_t code, olen;

		if (o + 4 > p->dlen)
			return R6_MALFORMED;
		code = get16(p->d + o);
		olen = get16(p->d + o + 2);
		if (o + 4 + olen > p->dlen)
			return R6_MALFORMED;
		if (code == OPT_INTERFACE_ID && !info->has_ifid &&
		    olen <= sizeof(info->ifid)) {
			info->has_ifid = 1;
			memcpy(info->ifid, p->d + o + 4, olen);
			info->ifid_len = (uint8_t)olen;
		} else if (code == OPT_RELAY_MSG && !p->relmsg_off && olen) {
			p->relmsg_off = o + 4;
			p->relmsg_len = olen;
			info->inner_type = p->d[o + 4];
			if (olen >= 4)
				info->inner_xid = (uint32_t)p->d[o + 5] << 16 |
						  (uint32_t)p->d[o + 6] << 8 |
						  p->d[o + 7];
		}
		o += 4 + (size_t)olen;
	}
	return R6_PARSED;
}

enum reason6 dhcp6_parse(const uint8_t *frame, size_t len,
			 struct dhcp6_info *info)
{
	struct parsed6 p;

	/* parse() does not write to the frame */
	info->reason = parse((uint8_t *)frame, len, &p, info);
	return info->reason;
}

static void finish(struct parsed6 *p, size_t udp_len, uint16_t sport,
		   uint16_t dport)
{
	put16(p->ip + 4, (uint16_t)udp_len);
	put16(p->udp, sport);
	put16(p->udp + 2, dport);
	put16(p->udp + 4, (uint16_t)udp_len);
	put16(p->udp + 6, 0);
	put16(p->udp + 6, udp6_csum(p->ip, p->udp, udp_len));
}

enum verdict dhcp6_handle_client(uint8_t *frame, size_t *len, size_t cap,
				 const struct ldra_cfg *cfg,
				 struct dhcp6_info *info)
{
	struct parsed6 p;
	size_t opts, udp_len, ifid_at, rid_at, msg_at;
	enum reason6 r = parse(frame, *len, &p, info);

	info->reason = r;
	/* relay and server messages are dropped even if their options are
	 * broken: only the message type matters for snooping */
	if (p.d && info->dport == DHCP6_SERVER_PORT &&
	    (info->msgtype == DHCP6_RELAY_FORW || is_server_type(info->msgtype)))
		r = R6_PARSED;
	if (r != R6_PARSED || info->dport != DHCP6_SERVER_PORT) {
		if (r == R6_PARSED)
			info->reason = R6_MALFORMED;
		return VERDICT_FORWARD;		/* not ours to judge */
	}
	if (info->msgtype == DHCP6_RELAY_FORW) {
		/* RFC 6221 6.1.2: client ports are untrusted */
		info->reason = R6_UNTRUSTED_RELAY;
		return VERDICT_DROP;
	}
	if (is_server_type(info->msgtype)) {
		info->reason = R6_SERVER_MSG;
		return VERDICT_DROP;
	}
	if (!is_client_type(info->msgtype)) {
		info->reason = R6_TYPE_SKIPPED;
		return VERDICT_FORWARD;
	}
	if (info->ip_dst[0] != 0xff && !cfg->relay_unicast) {
		info->reason = R6_UNICAST;
		return VERDICT_FORWARD;
	}

	opts = 4 + cfg->ifid_len + (cfg->rid_len ? 8 + (size_t)cfg->rid_len : 0) +
	       4 + p.dlen;
	udp_len = UDP_HDR_LEN + RELAY_HDR_LEN + opts;
	if (IP6_HDR_LEN + udp_len > cfg->mtu || OFF_UDP + udp_len > cap ||
	    udp_len > 0xffff) {
		info->reason = R6_TOO_BIG;	/* RFC 6221 5.3.1: discard */
		return VERDICT_DROP;
	}
	ifid_at = RELAY_HDR_LEN;
	rid_at = ifid_at + 4 + cfg->ifid_len;
	msg_at = rid_at + (cfg->rid_len ? 8 + (size_t)cfg->rid_len : 0);
	memmove(p.d + msg_at + 4, p.d, p.dlen);

	p.d[0] = DHCP6_RELAY_FORW;
	p.d[1] = 0;				/* hop-count */
	memset(p.d + 2, 0, 16);			/* link-address :: */
	memcpy(p.d + 18, info->ip_src, 16);	/* peer-address */
	put16(p.d + ifid_at, OPT_INTERFACE_ID);
	put16(p.d + ifid_at + 2, cfg->ifid_len);
	memcpy(p.d + ifid_at + 4, cfg->ifid, cfg->ifid_len);
	if (cfg->rid_len) {
		put16(p.d + rid_at, OPT_REMOTE_ID);
		put16(p.d + rid_at + 2, (uint16_t)(4 + cfg->rid_len));
		put32(p.d + rid_at + 4, cfg->enterprise);
		memcpy(p.d + rid_at + 8, cfg->rid, cfg->rid_len);
	}
	put16(p.d + msg_at, OPT_RELAY_MSG);
	put16(p.d + msg_at + 2, (uint16_t)p.dlen);
	/* addresses stay the client's (RFC 6221 6.1), relay port 547 */
	finish(&p, udp_len, DHCP6_SERVER_PORT, DHCP6_SERVER_PORT);
	*len = OFF_UDP + udp_len;
	info->reason = R6_WRAPPED;
	return VERDICT_FORWARD_MODIFIED;
}

int dhcp6_ifid_matches(const struct dhcp6_info *info,
		       const struct ldra_cfg *cfg)
{
	return info->has_ifid && info->ifid_len == cfg->ifid_len &&
	       !memcmp(info->ifid, cfg->ifid, cfg->ifid_len);
}

static int is_zero(const uint8_t *a, size_t n)
{
	while (n--)
		if (*a++)
			return 0;
	return 1;
}

enum verdict dhcp6_handle_uplink(uint8_t *frame, size_t *len,
				 const struct ldra_cfg *cfg,
				 struct dhcp6_info *info)
{
	struct parsed6 p;
	enum reason6 r = parse(frame, *len, &p, info);
	uint8_t inner;

	info->reason = r;
	if (r != R6_PARSED)
		return VERDICT_DROP;
	if (info->dport != DHCP6_SERVER_PORT) {
		info->reason = R6_MALFORMED;
		return VERDICT_DROP;
	}
	if (is_client_type(info->msgtype) || info->msgtype == DHCP6_RELAY_FORW) {
		/* RFC 6221 6.2: only Relay-Reply is forwarded */
		info->reason = R6_CLIENT_MSG;
		return VERDICT_DROP;
	}
	if (info->msgtype != DHCP6_RELAY_REPL) {
		info->reason = R6_TYPE_SKIPPED;
		return VERDICT_DROP;
	}
	if (!is_zero(info->link_addr, 16)) {
		/* answer to a relay with an address, i.e. not an LDRA */
		info->reason = R6_REPLY_FOREIGN;
		return VERDICT_DROP;
	}
	inner = info->inner_type;
	if (!info->has_ifid || !p.relmsg_off ||
	    memcmp(info->peer_addr, info->ip_dst, 16) ||
	    (inner != DHCP6_ADVERTISE && inner != DHCP6_REPLY &&
	     inner != DHCP6_RECONFIGURE)) {
		info->reason = R6_REPLY_INVALID;
		return VERDICT_DROP;
	}
	if (!cfg || !dhcp6_ifid_matches(info, cfg)) {
		info->reason = R6_REPLY_FOREIGN;
		return VERDICT_DROP;
	}
	/* RFC 6221 6.2: link-layer and IP source stay, destination is the
	 * peer-address (already equal), the payload is the Relay-Message */
	memmove(p.d, p.d + p.relmsg_off, p.relmsg_len);
	finish(&p, UDP_HDR_LEN + p.relmsg_len, DHCP6_SERVER_PORT,
	       DHCP6_CLIENT_PORT);
	*len = OFF_DHCP + p.relmsg_len;
	info->reason = R6_REPLY_OURS;
	return VERDICT_FORWARD_MODIFIED;
}

const char *dhcp6_reason_str(enum reason6 r)
{
	static const char *const s[R6_MAX] = {
		"parsed", "malformed", "extension-header", "bad-checksum",
		"untrusted-relay", "server-message", "client-message",
		"type-skipped", "unicast", "too-big", "wrapped",
		"reply-ours", "reply-foreign", "reply-invalid",
	};

	return r < R6_MAX ? s[r] : "?";
}

const char *dhcp6_type_str(uint8_t t)
{
	static const char *const s[] = {
		"NONE", "SOLICIT", "ADVERTISE", "REQUEST", "CONFIRM", "RENEW",
		"REBIND", "REPLY", "RELEASE", "DECLINE", "RECONFIGURE",
		"INFORMATION-REQUEST", "RELAY-FORW", "RELAY-REPL",
	};

	return t < sizeof(s) / sizeof(s[0]) ? s[t] : "OTHER";
}

const char *ip6_str(const uint8_t *a, char *buf)
{
	int best = -1, blen = 0, i, o = 0;

	/* longest run of zero groups (at least two) becomes "::" */
	for (i = 0; i < 8; i++) {
		int j = i;

		while (j < 8 && !a[2 * j] && !a[2 * j + 1])
			j++;
		if (j - i > blen && j - i > 1) {
			best = i;
			blen = j - i;
		}
		if (j > i)
			i = j - 1;
	}
	for (i = 0; i < 8; i++) {
		if (i == best) {
			o += sprintf(buf + o, "::");
			i += blen - 1;
			continue;
		}
		o += sprintf(buf + o, "%s%x", o && buf[o - 1] != ':' ? ":" : "",
			     get16(a + 2 * i));
	}
	return buf;
}
