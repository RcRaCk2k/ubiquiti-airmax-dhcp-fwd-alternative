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
	X(rep_foreign_forwarded)					\
	X(rep_no_o82_forwarded)						\
	X(rep_no_o82_dropped)						\
	X(rep_malformed)						\
	X(rep_wrong_op)							\
	X(rep_ratelimited)						\
	X(tx_uplink)							\
	X(tx_client)							\
	X(tx_error)

struct stats {
#define X(n) uint32_t n;
	STATS_FIELDS(X)
#undef X
};

#endif
