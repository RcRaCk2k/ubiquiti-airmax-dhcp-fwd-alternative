/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * Management of the broute rules that divert DHCP frames away from the
 * bridge to us. A frame dropped in the broute table is not bridged but
 * handed to the normal receive path of the port, where our ETH_P_IP packet
 * sockets bound to that port pick it up.
 */
#ifndef DS82_EBT_H
#define DS82_EBT_H

#include "config.h"

int ebt_install(const struct config *c);
/* 1 = rules complete, 0 = missing/incomplete, -1 = ebtables not usable */
int ebt_check(const struct config *c);
void ebt_remove(const struct config *c);

#endif
