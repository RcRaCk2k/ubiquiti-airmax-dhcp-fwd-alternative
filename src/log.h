/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 */
#ifndef DS82_LOG_H
#define DS82_LOG_H

#include "config.h"

void log_init(int level, int to_stderr);
void log_set_level(int level);
int log_enabled(int level);
void log_msg(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
/* per-packet messages; rate limited to protect syslog and CPU */
void log_pkt(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#define LOGE(...)	log_msg(LOG_LVL_ERR, __VA_ARGS__)
#define LOGW(...)	log_msg(LOG_LVL_WARN, __VA_ARGS__)
#define LOGI(...)	log_msg(LOG_LVL_INFO, __VA_ARGS__)
#define LOGD(...)	log_msg(LOG_LVL_DEBUG, __VA_ARGS__)

#endif
