/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ebt.h"
#include "log.h"

#define EBT_TIMEOUT_MS	10000
#define LIST_MAX	4096

static void msleep(unsigned ms)
{
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };

	while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
}

/* Runs ebtables with argv; stdout goes to out (if given). Returns the exit
 * status or -1. ebtables 2.0.10-4 takes a lock file and may block while
 * airOS scripts run, hence the timeout. */
static int run(const struct config *c, char *const argv[], char *out,
	       size_t outlen)
{
	int pfd[2] = { -1, -1 }, status, waited = 0;
	size_t got = 0;
	pid_t pid;

	if (out && pipe(pfd) < 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		if (out) {
			close(pfd[0]);
			close(pfd[1]);
		}
		return -1;
	}
	if (pid == 0) {
		int nul = open("/dev/null", O_RDWR);

		if (nul >= 0) {
			dup2(nul, 0);
			dup2(out ? pfd[1] : nul, 1);
			dup2(nul, 2);
		}
		execv(c->ebtables, argv);
		_exit(127);
	}
	if (out) {
		close(pfd[1]);
		fcntl(pfd[0], F_SETFL, O_NONBLOCK);
	}
	for (;;) {
		pid_t r = waitpid(pid, &status, WNOHANG);

		if (out) {
			ssize_t n;

			while (got < outlen - 1 &&
			       (n = read(pfd[0], out + got, outlen - 1 - got)) > 0)
				got += (size_t)n;
		}
		if (r == pid)
			break;
		if (r < 0 && errno != EINTR) {
			status = -1;
			break;
		}
		if (waited >= EBT_TIMEOUT_MS) {
			LOGW("ebtables timed out, killing it");
			kill(pid, SIGKILL);
			waitpid(pid, &status, 0);
			status = -1;
			break;
		}
		msleep(20);
		waited += 20;
	}
	if (out) {
		ssize_t n;

		while (got < outlen - 1 &&
		       (n = read(pfd[0], out + got, outlen - 1 - got)) > 0)
			got += (size_t)n;
		out[got] = '\0';
		close(pfd[0]);
	}
	if (status == -1 || !WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

#define EBT(...) do {							\
		char *const a_[] = { (char *)"ebtables", (char *)"-t",	\
				     (char *)"broute", __VA_ARGS__, NULL }; \
		rc = run(c, a_, NULL, 0);				\
	} while (0)

static void own_mac(const struct config *c, char *buf, size_t n)
{
	uint8_t m[6];

	if (config_get_mac(c->bridge_if, m) < 0)
		memset(m, 0, sizeof(m));
	snprintf(buf, n, "%02x:%02x:%02x:%02x:%02x:%02x",
		 m[0], m[1], m[2], m[3], m[4], m[5]);
}

static int jump_count(const struct config *c);

int ebt_install(const struct config *c)
{
	char mac[18];
	int rc;

	own_mac(c, mac, sizeof(mac));

	/* user chain with policy RETURN: a user chain defaults to ACCEPT,
	 * which in broute would end BROUTING early and skip airOS' own
	 * EAP/VLAN rules */
	EBT((char *)"-N", (char *)EBT_CHAIN, (char *)"-P", (char *)"RETURN");
	EBT((char *)"-P", (char *)EBT_CHAIN, (char *)"RETURN");
	if (rc != 0)
		goto fail;
	EBT((char *)"-F", (char *)EBT_CHAIN);
	if (rc != 0)
		goto fail;
	EBT((char *)"-A", (char *)EBT_CHAIN, (char *)"-p", (char *)"IPv4",
	    (char *)"-i", (char *)c->client_if,
	    (char *)"--ip-proto", (char *)"udp",
	    (char *)"--ip-dport", (char *)"67", (char *)"-j", (char *)"DROP");
	if (rc != 0)
		goto fail;
	EBT((char *)"-A", (char *)EBT_CHAIN, (char *)"-p", (char *)"IPv4",
	    (char *)"-i", (char *)c->uplink_if, (char *)"-d", (char *)"!", mac,
	    (char *)"--ip-proto", (char *)"udp",
	    (char *)"--ip-sport", (char *)"67",
	    (char *)"--ip-dport", (char *)"68", (char *)"-j", (char *)"DROP");
	if (rc != 0)
		goto fail;
	rc = jump_count(c);
	while (rc > 1) {	/* duplicate jumps, e.g. after a race */
		EBT((char *)"-D", (char *)"BROUTING", (char *)"-j",
		    (char *)EBT_CHAIN);
		if (rc != 0)
			goto fail;
		rc = jump_count(c);
	}
	if (rc < 0)
		goto fail;
	if (rc == 0) {
		EBT((char *)"-I", (char *)"BROUTING", (char *)"1",
		    (char *)"-j", (char *)EBT_CHAIN);
		if (rc != 0)
			goto fail;
	}
	if (ebt_check(c) != 1)
		goto fail;
	LOGI("broute rules installed (chain %s)", EBT_CHAIN);
	return 0;
fail:
	LOGE("installing broute rules failed (ebtables rc=%d)", rc);
	return -1;
}

static int count(const char *hay, const char *needle)
{
	int n = 0;

	while ((hay = strstr(hay, needle))) {
		n++;
		hay += strlen(needle);
	}
	return n;
}

static char list_buf[LIST_MAX];

/* number of jumps from BROUTING into our chain, -1 if listing fails */
static int jump_count(const struct config *c)
{
	char *const lb[] = { (char *)"ebtables", (char *)"-t", (char *)"broute",
			     (char *)"-L", (char *)"BROUTING", NULL };

	if (run(c, lb, list_buf, sizeof(list_buf)) != 0)
		return -1;
	return count(list_buf, "-j " EBT_CHAIN "\n") +
	       count(list_buf, "-j " EBT_CHAIN " ");
}

int ebt_check(const struct config *c)
{
	char *const lc[] = { (char *)"ebtables", (char *)"-t", (char *)"broute",
			     (char *)"-L", (char *)EBT_CHAIN, NULL };
	char *buf = list_buf;
	int rc;

	rc = jump_count(c);
	if (rc < 0)
		return -1;
	if (rc != 1)
		return 0;
	rc = run(c, lc, buf, sizeof(list_buf));
	if (rc != 0)
		return 0;
	if (!strstr(buf, "entries: 2, policy: RETURN"))
		return 0;
	if (count(buf, "-j DROP") != 2)
		return 0;
	return 1;
}

void ebt_remove(const struct config *c)
{
	int rc, i;

	for (i = 0; i < 8; i++) {
		EBT((char *)"-D", (char *)"BROUTING", (char *)"-j",
		    (char *)EBT_CHAIN);
		if (rc != 0)
			break;
	}
	EBT((char *)"-F", (char *)EBT_CHAIN);
	EBT((char *)"-X", (char *)EBT_CHAIN);
	(void)rc;
	LOGI("broute rules removed");
}
