/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * DHCPv4 frame parsing and RFC 3046 option 82 insertion/removal.
 * Pure functions on Ethernet frames, no system calls; host-testable.
 */
#ifndef DS82_DHCP_H
#define DS82_DHCP_H

#include <stddef.h>
#include <stdint.h>

#define ETH_HDR_LEN	14
#define FRAME_BUF_LEN	2048

#define DHCP_DISCOVER	1
#define DHCP_OFFER	2
#define DHCP_REQUEST	3
#define DHCP_DECLINE	4
#define DHCP_ACK	5
#define DHCP_NAK	6
#define DHCP_RELEASE	7
#define DHCP_INFORM	8

/* bit 0 of type_mask stands for plain BOOTP (no option 53) */
#define TYPE_BIT(t)	(1u << (t))

enum verdict {
	VERDICT_FORWARD = 0,		/* forward unchanged */
	VERDICT_FORWARD_MODIFIED,	/* forward modified frame */
	VERDICT_DROP,
};

enum reason {
	R_PARSED = 0,
	R_MALFORMED,		/* broken Ethernet/IP/UDP/BOOTP structure */
	R_FRAGMENT,		/* first fragment of a fragmented datagram */
	R_BAD_CSUM,		/* IP or UDP checksum invalid */
	R_BAD_OPTIONS,		/* option list broken or without END */
	R_WRONG_OP,		/* BOOTREPLY on client port or vice versa */
	R_HAS_O82,		/* request already carries option 82 */
	R_RELAYED,		/* giaddr or hops set: another relay touched it */
	R_TYPE_SKIPPED,		/* message type not selected for insertion */
	R_NO_SPACE,		/* option 82 would exceed MTU/buffer */
	R_INSERTED,		/* option 82 inserted */
	R_REPLY_OURS,		/* reply carried our option 82, stripped */
	R_REPLY_FOREIGN,	/* reply carried someone else's option 82 */
	R_REPLY_NO_O82,		/* reply without option 82 */
	R_MAX
};

struct o82_cfg {
	uint8_t		cid[251];
	uint8_t		cid_len;
	uint8_t		rid[251];
	uint8_t		rid_len;
	size_t		mtu;		/* max IP datagram length */
	unsigned	type_mask;	/* TYPE_BIT(msgtype) => insert */
};

struct dhcp_info {
	uint8_t		dst_mac[6];
	uint8_t		src_mac[6];
	uint32_t	ip_src;		/* host byte order */
	uint32_t	ip_dst;
	uint8_t		op;
	uint8_t		htype;
	uint8_t		hlen;
	uint8_t		hops;
	uint8_t		msgtype;	/* 0 = none (BOOTP) */
	uint16_t	flags;
	uint32_t	xid;
	uint32_t	ciaddr;
	uint32_t	yiaddr;
	uint32_t	giaddr;
	uint8_t		chaddr[6];
	uint32_t	lease_time;	/* option 51, if has_lease_time */
	int		has_lease_time;
	uint32_t	requested_ip;	/* option 50, 0 = none */
	int		has_o82;
	uint8_t		o82_cid[255];
	uint8_t		o82_cid_len;
	uint8_t		o82_rid[255];
	uint8_t		o82_rid_len;
	enum reason	reason;
};

/* Fill *info from a frame; returns R_PARSED or the reason it is unusable.
 * Fields that could be parsed before the error are still filled in. */
enum reason dhcp_parse(const uint8_t *frame, size_t len, struct dhcp_info *info);

/* Client -> server direction. May modify frame in place (cap = buffer size)
 * and update *len. info->reason tells why. */
enum verdict dhcp_handle_request(uint8_t *frame, size_t *len, size_t cap,
				 const struct o82_cfg *cfg,
				 struct dhcp_info *info);

/* Server -> client direction. Strips our option 82 (keeping the frame
 * length, freed bytes become PAD). Returns VERDICT_DROP with R_REPLY_FOREIGN
 * for foreign option 82 and VERDICT_FORWARD with R_REPLY_NO_O82 when there
 * is none; the caller applies its policy to these. */
enum verdict dhcp_handle_reply(uint8_t *frame, size_t *len,
			       const struct o82_cfg *cfg,
			       struct dhcp_info *info);

/* Removes the option 82 from the main option field of a reply whatever
 * its content (frame length kept, PAD). Used for replies to requests we
 * marked whose option 82 an upstream relay replaced. Returns 0 if stripped. */
int dhcp_strip_o82(uint8_t *frame, size_t len);

/* 1 if the option 82 decoded into info is the one cfg inserts */
int dhcp_o82_matches(const struct dhcp_info *info, const struct o82_cfg *cfg);

const char *dhcp_reason_str(enum reason r);
const char *dhcp_type_str(uint8_t t);

/* Internet checksum helpers (exposed for tests) */
uint16_t ip_header_csum(const uint8_t *ip, size_t ihl);
uint16_t udp_csum(const uint8_t *ip, const uint8_t *udp, size_t udp_len);

#endif
