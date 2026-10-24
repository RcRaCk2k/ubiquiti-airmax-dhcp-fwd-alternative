/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * Logs go to syslog (busybox syslogd keeps them in RAM) and optionally to
 * stderr. Nothing is ever written to flash.
 *
 * musl's syslog() always stamps messages in UTC. We write to /dev/log
 * ourselves without a timestamp; busybox syslogd then adds its own in
 * local time, like for every other airOS daemon.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

#define PKT_LOG_PER_SEC	20

static int cur_level = LOG_LVL_INFO;
static int use_stderr;
static int log_fd = -1;
static time_t pkt_window;
static unsigned pkt_count, pkt_suppressed;

static int log_connect(void)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX, .sun_path = "/dev/log" };

	if (log_fd < 0)
		log_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (log_fd < 0)
		return -1;
	if (connect(log_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(log_fd);
		log_fd = -1;
		return -1;
	}
	return 0;
}

/* syslogd restarts on every airOS "Apply": reconnect once on failure */
static void log_send(int prio, const char *msg)
{
	char buf[600];
	int n, i;

	n = snprintf(buf, sizeof(buf), "<%d>dhcp-fwd[%d]: %s",
		     LOG_DAEMON | prio, (int)getpid(), msg);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(buf))
		n = sizeof(buf) - 1;
	for (i = 0; i < 2; i++) {
		if (log_fd < 0 && log_connect() < 0)
			continue;
		if (send(log_fd, buf, (size_t)n, MSG_NOSIGNAL) >= 0)
			return;
		close(log_fd);
		log_fd = -1;
	}
}

void log_init(int level, int to_stderr)
{
	cur_level = level;
	use_stderr = to_stderr;
	log_connect();
}

void log_set_level(int level)
{
	cur_level = level;
}

int log_enabled(int level)
{
	return level <= cur_level;
}

static void vlog(int level, const char *fmt, va_list ap)
{
	static const int prio[] = { LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG };
	static const char *const tag[] = { "E", "W", "I", "D" };
	char buf[512];

	vsnprintf(buf, sizeof(buf), fmt, ap);
	log_send(prio[level], buf);
	if (use_stderr)
		fprintf(stderr, "%s: %s\n", tag[level], buf);
}

void log_msg(int level, const char *fmt, ...)
{
	va_list ap;

	if (!log_enabled(level))
		return;
	va_start(ap, fmt);
	vlog(level, fmt, ap);
	va_end(ap);
}

void log_pkt(int level, const char *fmt, ...)
{
	struct timespec ts;
	va_list ap;

	if (!log_enabled(level))
		return;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ts.tv_sec != pkt_window) {
		if (pkt_suppressed)
			log_msg(LOG_LVL_WARN, "%u packet log lines suppressed",
				pkt_suppressed);
		pkt_window = ts.tv_sec;
		pkt_count = 0;
		pkt_suppressed = 0;
	}
	if (++pkt_count > PKT_LOG_PER_SEC) {
		pkt_suppressed++;
		return;
	}
	va_start(ap, fmt);
	vlog(level, fmt, ap);
	va_end(ap);
}
