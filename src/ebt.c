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

static int jump_count(const struct config *c);

struct rule {
	int		v6;
	const char	*notdst;	/* "-d ! MAC" */
	const char	*sport;
	const char	*dport;
	int		ll_icmp6;	/* link-local ICMPv6 instead of UDP */
};

static int add_rule(const struct config *c, const char *ifname,
		    const struct rule *r)
{
	char *a[24];
	int n = 0;

	a[n++] = (char *)"ebtables";
	a[n++] = (char *)"-t";
	a[n++] = (char *)"broute";
	a[n++] = (char *)"-A";
	a[n++] = (char *)EBT_CHAIN;
	a[n++] = (char *)"-p";
	a[n++] = (char *)(r->v6 ? "IPv6" : "IPv4");
	a[n++] = (char *)"-i";
	a[n++] = (char *)ifname;
	if (r->notdst) {
		a[n++] = (char *)"-d";
		a[n++] = (char *)"!";
		a[n++] = (char *)r->notdst;
	}
	if (r->ll_icmp6) {
		a[n++] = (char *)"--ip6-src";
		a[n++] = (char *)"fe80::/10";
		a[n++] = (char *)"--ip6-proto";
		a[n++] = (char *)"58";	/* /etc/protocols may lack the name */
	} else {
		a[n++] = (char *)(r->v6 ? "--ip6-proto" : "--ip-proto");
		a[n++] = (char *)"udp";
		if (r->sport) {
			a[n++] = (char *)(r->v6 ? "--ip6-sport" : "--ip-sport");
			a[n++] = (char *)r->sport;
		}
		a[n++] = (char *)(r->v6 ? "--ip6-dport" : "--ip-dport");
		a[n++] = (char *)r->dport;
	}
	a[n++] = (char *)"-j";
	a[n++] = (char *)"DROP";
	a[n] = NULL;
	return run(c, a, NULL, 0);
}

/* Rules of one port; with out == NULL only counted (for ebt_check).
 * Diverted frames nobody listens for are discarded by the IP stack of the
 * port, which has no address (IPv6 is disabled on airOS bridge ports):
 * that is the snooping drop. */
static int port_rules(const struct config *c, const struct port *p,
		      struct rule *out)
{
	static char mac[18];
	const uint8_t *m = c->br[p->bridge].mac;
	struct rule r[8];
	int n = 0, i;

	memset(r, 0, sizeof(r));
	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		 m[0], m[1], m[2], m[3], m[4], m[5]);
	if (p->role == ROLE_CLIENT) {
		/* client requests (also unicast renews) to the agent */
		r[n++] = (struct rule){ 0, NULL, NULL, "67", 0 };
		/* snooping: DHCP server behind the customer port */
		if (c->block_client_servers)
			r[n++] = (struct rule){ 0, NULL, "67", "68", 0 };
		if (c->dhcp6_snooping) {
			/* client messages to the LDRA */
			r[n++] = (struct rule){ 1, NULL, NULL, "547", 0 };
			if (c->block_client_servers)
				r[n++] = (struct rule){ 1, NULL, "547", "546", 0 };
		}
		/* RA guard: ebt_ip6 of 2.6.32 cannot match ICMPv6 types, so
		 * all link-local ICMPv6 (ND, MLD, RA) goes to the agent, which
		 * drops the RAs and passes the rest on. Not for the station
		 * itself, so its own neighbour discovery keeps working. */
		if (c->ra_guard)
			r[n++] = (struct rule){ 1, mac, NULL, NULL, 1 };
	} else {
		/* server replies, except those for the station itself */
		r[n++] = (struct rule){ 0, mac, "67", "68", 0 };
		/* snooping: requests of other customers */
		if (c->block_uplink_requests)
			r[n++] = (struct rule){ 0, NULL, NULL, "67", 0 };
		/* Relay-Replies, and other customers' messages (dropped by
		 * the agent, RFC 6221 6.2) */
		if (c->dhcp6_snooping)
			r[n++] = (struct rule){ 1, NULL, NULL, "547", 0 };
	}
	if (out)
		for (i = 0; i < n; i++)
			out[i] = r[i];
	return n;
}

static int add_port_rules(const struct config *c, const struct port *p)
{
	struct rule r[8];
	int n = port_rules(c, p, r), i, rc = 0;

	for (i = 0; i < n && !rc; i++)
		rc = add_rule(c, p->name, &r[i]);
	return rc;
}

static int expected_rules(const struct config *c)
{
	int i, n = 0;

	for (i = 0; i < c->nport; i++)
		n += port_rules(c, &c->port[i], NULL);
	return n;
}

int ebt_install(const struct config *c)
{
	int rc, i;

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
	for (i = 0; i < c->nport; i++) {
		rc = add_port_rules(c, &c->port[i]);
		if (rc != 0)
			goto fail;
	}
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
	LOGI("broute rules installed (chain %s, %d rules)", EBT_CHAIN,
	     expected_rules(c));
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
	char *buf = list_buf, want[48];
	int rc, n = expected_rules(c);

	rc = jump_count(c);
	if (rc < 0)
		return -1;
	if (rc != 1)
		return 0;
	rc = run(c, lc, buf, sizeof(list_buf));
	if (rc != 0)
		return 0;
	snprintf(want, sizeof(want), "entries: %d, policy: RETURN", n);
	if (!strstr(buf, want))
		return 0;
	if (count(buf, "-j DROP") != n)
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
