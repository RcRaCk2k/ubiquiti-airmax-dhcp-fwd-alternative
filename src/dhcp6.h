/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * DHCPv6 Lightweight Relay Agent (LDRA, RFC 6221): the IPv6 counterpart
 * of option 82. Client messages are wrapped into a Relay-Forward with
 * Interface-ID (option 18) and Remote-ID (option 37, RFC 4649); the
 * Relay-Reply coming back is unwrapped and delivered to the client port
 * its Interface-ID names. Prefix delegation (IA_PD) needs nothing extra,
 * the IA options travel unchanged inside the Relay-Message.
 * Pure functions on Ethernet frames, no system calls; host-testable.
 */
#ifndef DS82_DHCP6_H
#define DS82_DHCP6_H

#include <stddef.h>
#include <stdint.h>

#include "dhcp.h"

#define ETH_P_IPV6_		0x86dd
#define DHCP6_CLIENT_PORT	546
#define DHCP6_SERVER_PORT	547

#define DHCP6_SOLICIT		1
#define DHCP6_ADVERTISE		2
#define DHCP6_REQUEST		3
#define DHCP6_CONFIRM		4
#define DHCP6_RENEW		5
#define DHCP6_REBIND		6
#define DHCP6_REPLY		7
#define DHCP6_RELEASE		8
#define DHCP6_DECLINE		9
#define DHCP6_RECONFIGURE	10
#define DHCP6_INFO_REQUEST	11
#define DHCP6_RELAY_FORW	12
#define DHCP6_RELAY_REPL	13

enum reason6 {
	R6_PARSED = 0,
	R6_MALFORMED,		/* broken Ethernet/IPv6/UDP/DHCPv6 structure */
	R6_EXT_HEADER,		/* IPv6 extension header or fragment */
	R6_BAD_CSUM,		/* UDP checksum invalid (or zero) */
	R6_UNTRUSTED_RELAY,	/* Relay-Forward from a client port */
	R6_SERVER_MSG,		/* server message from a client port */
	R6_CLIENT_MSG,		/* client message from the uplink */
	R6_TYPE_SKIPPED,	/* unknown message type, passed unchanged */
	R6_UNICAST,		/* unicast client message, passed unchanged */
	R6_TOO_BIG,		/* Relay-Forward would exceed the MTU */
	R6_WRAPPED,		/* Relay-Forward built */
	R6_REPLY_OURS,		/* Relay-Reply with our Interface-ID, unwrapped */
	R6_REPLY_FOREIGN,	/* Relay-Reply for another relay agent */
	R6_REPLY_INVALID,	/* Relay-Reply failing the RFC 6221 checks */
	R6_RA,			/* router advertisement from a client port */
	R6_ICMP6,		/* other ICMPv6 (ND, MLD, ...), passed on */
	R6_ICMP6_BAD,		/* fragmented or truncated ICMPv6 */
	R6_MAX
};

struct ldra_cfg {
	uint8_t		ifid[251];	/* Interface-ID, never empty */
	uint8_t		ifid_len;
	uint8_t		rid[247];	/* Remote-ID; 0 = option omitted */
	uint8_t		rid_len;
	uint32_t	enterprise;	/* enterprise number of the Remote-ID */
	size_t		mtu;		/* max IPv6 packet length */
	int		relay_unicast;	/* wrap unicast client messages too */
};

struct dhcp6_info {
	uint8_t		dst_mac[6];
	uint8_t		src_mac[6];
	uint8_t		ip_src[16];
	uint8_t		ip_dst[16];
	uint16_t	sport;
	uint16_t	dport;
	uint8_t		msgtype;
	uint32_t	xid;		/* transaction-id, 24 bit */
	/* Relay-Reply / Relay-Forward */
	uint8_t		hop_count;
	uint8_t		link_addr[16];
	uint8_t		peer_addr[16];
	uint8_t		inner_type;	/* message inside the Relay-Message */
	uint32_t	inner_xid;
	int		has_ifid;
	uint8_t		ifid[255];
	uint8_t		ifid_len;
	enum reason6	reason;
};

/* Fill *info from a frame; returns R6_PARSED or the reason it is unusable */
enum reason6 dhcp6_parse(const uint8_t *frame, size_t len,
			 struct dhcp6_info *info);

/* Frame from a client port (UDP to port 547). Client messages are wrapped
 * into a Relay-Forward in place (cap = buffer size). Relay-Forward and
 * server messages are VERDICT_DROP; info->reason tells why. */
enum verdict dhcp6_handle_client(uint8_t *frame, size_t *len, size_t cap,
				 const struct ldra_cfg *cfg,
				 struct dhcp6_info *info);

/* Frame from the uplink (UDP to port 547). A valid Relay-Reply whose
 * Interface-ID is cfg's is unwrapped in place into the server message for
 * the client. Everything else is VERDICT_DROP with the reason. */
enum verdict dhcp6_handle_uplink(uint8_t *frame, size_t *len,
				 const struct ldra_cfg *cfg,
				 struct dhcp6_info *info);

/* RA guard. The 2.6.32 ebt_ip6 cannot match ICMPv6 types, so the broute
 * rule diverts all link-local ICMPv6 of a client port (every valid RA has a
 * link-local source, RFC 4861) and this decides: router advertisements and
 * fragmented or truncated ICMPv6 (RFC 6980: ND must not be fragmented) are
 * VERDICT_DROP, everything else is VERDICT_FORWARD unchanged. Hop-by-hop
 * and destination options headers are skipped, so they cannot hide an RA
 * (RFC 7113). */
enum verdict dhcp6_ra_guard(const uint8_t *frame, size_t len,
			    struct dhcp6_info *info);

/* 1 if the Interface-ID decoded into info is cfg's */
int dhcp6_ifid_matches(const struct dhcp6_info *info,
		       const struct ldra_cfg *cfg);

const char *dhcp6_reason_str(enum reason6 r);
const char *dhcp6_type_str(uint8_t t);
/* "fe80::1" style, buf >= 40 bytes */
const char *ip6_str(const uint8_t *a, char *buf);

uint16_t udp6_csum(const uint8_t *ip6, const uint8_t *udp, size_t udp_len);

#endif
