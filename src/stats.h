/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 */
#ifndef DS82_STATS_H
#define DS82_STATS_H

#include <stdint.h>

#define STATS_FIELDS(X)							\
	X(rx_client)		/* frames diverted from client port */	\
	X(rx_uplink)		/* frames diverted from uplink port */	\
	X(rx_truncated)							\
	X(rx_outgoing_ignored)						\
	X(req_inserted)		/* option 82 added */			\
	X(req_has_o82)		/* already had option 82 */		\
	X(req_relayed)		/* giaddr/hops set */			\
	X(req_type_skipped)						\
	X(req_no_space)							\
	X(req_malformed)	/* incl. fragments, bad csum/options */	\
	X(req_wrong_op)							\
	X(req_dropped_policy)						\
	X(req_ratelimited)						\
	X(req_answered)		/* marked request got a reply */	\
	X(req_unanswered)	/* marked request expired unanswered */	\
	X(rep_ours)		/* our option 82, stripped */		\
	X(rep_foreign_dropped)						\
	X(rep_foreign_ours_by_xid)	/* replaced upstream, stripped */	\
	X(rep_foreign_forwarded)					\
	X(rep_no_o82_forwarded)						\
	X(rep_no_o82_dropped)						\
	X(rep_malformed)						\
	X(rep_wrong_op)							\
	X(rep_ratelimited)						\
	X(rx6_client)		/* DHCPv6 frames diverted from client port */ \
	X(rx6_uplink)							\
	X(req6_wrapped)		/* Relay-Forward built (LDRA) */	\
	X(req6_untrusted_relay)	/* Relay-Forward from customer, dropped */ \
	X(req6_server_msg)	/* DHCPv6 server on customer port, dropped */ \
	X(req6_unicast_passed)						\
	X(req6_type_skipped)						\
	X(req6_too_big)							\
	X(req6_malformed)	/* passed unchanged */			\
	X(req6_ratelimited)						\
	X(rep6_ours)		/* Relay-Reply unwrapped to the client */ \
	X(rep6_foreign_dropped)						\
	X(rep6_invalid)							\
	X(rep6_client_msg_dropped)	/* other customers' messages */	\
	X(rep6_client_msg_forwarded)					\
	X(rep6_malformed)						\
	X(rep6_ratelimited)						\
	X(ra_dropped)		/* RA guard: RAs from client ports */	\
	X(icmp6_passed)		/* ND/MLD of client ports, passed on */	\
	X(icmp6_dropped)	/* fragmented/truncated, dropped */	\
	X(icmp6_ratelimited)						\
	X(guard_msgs)		/* source guard: bindings to the watcher */ \
	X(guard_msgs_lost)	/* pipe full */				\
	X(guard_ra)		/* RAs with SLAAC prefixes on uplinks */	\
	X(tx_uplink)							\
	X(tx_client)							\
	X(tx_error)

struct stats {
#define X(n) uint32_t n;
	STATS_FIELDS(X)
#undef X
};

#endif
