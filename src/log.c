/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * Logs go to syslog (busybox syslogd keeps them in RAM) and optionally to
 * stderr. Nothing is ever written to flash.
 */
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

#define PKT_LOG_PER_SEC	20

static int cur_level = LOG_LVL_INFO;
static int use_stderr;
static time_t pkt_window;
static unsigned pkt_count, pkt_suppressed;

/* uClibc reads /etc/TZ, musl only $TZ: take the airOS zone from there so
 * syslog timestamps match the rest of the system */
static void init_tz(void)
{
	char buf[64];
	ssize_t n;
	int fd;

	if (getenv("TZ"))
		return;
	fd = open("/etc/TZ", O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';
	buf[strcspn(buf, "\r\n")] = '\0';
	if (buf[0]) {
		setenv("TZ", buf, 1);
		tzset();
	}
}

void log_init(int level, int to_stderr)
{
	init_tz();
	cur_level = level;
	use_stderr = to_stderr;
	openlog("dhcp-fwd", LOG_PID, LOG_DAEMON);
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
	syslog(prio[level], "%s", buf);
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
