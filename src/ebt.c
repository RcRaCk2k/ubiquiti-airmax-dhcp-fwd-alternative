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
#include "guard.h"
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

/* number of jumps from a built-in chain into target, -1 if listing fails */
static int jumps(const struct config *c, const char *table, const char *chain,
		 const char *target)
{
	char *const lb[] = { (char *)"ebtables", (char *)"-t", (char *)table,
			     (char *)"-L", (char *)chain, NULL };
	char want[64];
	int n;

	if (run(c, lb, list_buf, sizeof(list_buf)) != 0)
		return -1;
	snprintf(want, sizeof(want), "-j %s\n", target);
	n = count(list_buf, want);
	snprintf(want, sizeof(want), "-j %s ", target);
	return n + count(list_buf, want);
}

/* number of jumps from BROUTING into our chain, -1 if listing fails */
static int jump_count(const struct config *c)
{
	return jumps(c, "broute", "BROUTING", EBT_CHAIN);
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

/* ------------------------------------------------------------------ */
/* source guard: filter table chain EBT_GUARD_CHAIN, jumped to from INPUT
 * (frames for the station) and FORWARD (bridged frames). DHCP and the
 * link-local ICMPv6 of the RA guard never get here: broute diverts them
 * before the filter table. */

#define ARGS_MAX	32

struct args {
	char	*a[ARGS_MAX];
	int	n;
	char	mac[18];
	char	addr[48];
};

static void arg(struct args *a, const char *s)
{
	if (a->n < ARGS_MAX - 1)
		a->a[a->n++] = (char *)s;
	a->a[a->n] = NULL;
}

static void args_start(struct args *a, const char *op, const char *chain)
{
	a->n = 0;
	arg(a, "ebtables");
	arg(a, "-t");
	arg(a, "filter");
	arg(a, op);
	arg(a, chain);
}

static int guard_v6(const struct config *c)
{
	return c->sg_ipv6 && c->dhcp6_snooping;
}

/* the 1 or 2 rules of a binding: spec k (0, 1) appended to a */
static int binding_rules(const struct config *c, const struct binding *b)
{
	return b->v6 ? guard_v6(c) : 2;
}

static void binding_spec(struct args *a, const struct binding *b, int k)
{
	const uint8_t *m = b->mac;

	snprintf(a->mac, sizeof(a->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		 m[0], m[1], m[2], m[3], m[4], m[5]);
	binding_addr(b, a->addr);
	if (b->v6 && b->plen == 128)
		strcat(a->addr, "/128");
	arg(a, "-p");
	arg(a, b->v6 ? "IPv6" : k ? "ARP" : "IPv4");
	arg(a, "-i");
	arg(a, b->port);
	arg(a, "-s");
	arg(a, a->mac);
	if (b->v6) {
		arg(a, "--ip6-src");
	} else if (k) {
		/* the ARP sender must be the client itself */
		arg(a, "--arp-mac-src");
		arg(a, a->mac);
		arg(a, "--arp-ip-src");
	} else {
		arg(a, "--ip-src");
	}
	arg(a, a->addr);
	arg(a, "-j");
	arg(a, "RETURN");
}

/* rules at the end of the chain, per client port; with a == NULL only
 * counted */
static int port_guard_rules(const struct config *c, const char *port,
			    struct args *a, int k)
{
	const char *const *r;
	int n = 0;
	static const char *const ll6[] = { "-p", "IPv6", "--ip6-src",
					   "fe80::/10", "-j", "RETURN", NULL };
	/* DAD and MLD before an address is configured */
	static const char *const dad6[] = { "-p", "IPv6", "--ip6-src", "::/128",
					    "--ip6-proto", "58", "-j", "RETURN",
					    NULL };
	/* ARP probes of the client checking its new address (RFC 5227) */
	static const char *const probe[] = { "-p", "ARP", "--arp-ip-src",
					     "0.0.0.0", "-j", "RETURN", NULL };
	static const char *const ip4[] = { "-p", "IPv4", "-j", "DROP", NULL };
	static const char *const arp[] = { "-p", "ARP", "-j", "DROP", NULL };
	static const char *const ip6[] = { "-p", "IPv6", "-j", "DROP", NULL };
	static const char *const pass6[] = { "-p", "IPv6", "-j", "RETURN", NULL };
	/* VLAN tagged IP would bypass the rules above */
	static const char *const vlan4[] = { "-p", "802_1Q", "--vlan-encap",
					     "IPv4", "-j", "DROP", NULL };
	static const char *const vlanarp[] = { "-p", "802_1Q", "--vlan-encap",
					       "ARP", "-j", "DROP", NULL };
	static const char *const vlan6[] = { "-p", "802_1Q", "--vlan-encap",
					     "IPv6", "-j", "DROP", NULL };
	static const char *const all[] = { "-j", "DROP", NULL };
	const char *const *list[12];

	if (guard_v6(c)) {
		list[n++] = ll6;
		list[n++] = dad6;
	}
	list[n++] = probe;
	list[n++] = ip4;
	list[n++] = arp;
	if (guard_v6(c))
		list[n++] = ip6;
	else if (!c->sg_block_ip_only)
		list[n++] = pass6;
	if (c->sg_block_ip_only) {
		list[n++] = vlan4;
		list[n++] = vlanarp;
		if (guard_v6(c))
			list[n++] = vlan6;
	} else {
		list[n++] = all;	/* PPPoE and everything else */
	}
	if (a) {
		arg(a, "-i");
		arg(a, port);
		for (r = list[k]; *r; r++)
			arg(a, *r);
	}
	return n;
}

static int guard_expected(const struct config *c, const struct guard_tab *t)
{
	int i, n = 0;

	for (i = 0; i < c->nport; i++)
		if (c->port[i].role == ROLE_CLIENT)
			n += port_guard_rules(c, c->port[i].name, NULL, 0);
	for (i = 0; i < t->n; i++)
		n += binding_rules(c, &t->b[i]);
	return n;
}

static int run_args(const struct config *c, struct args *a)
{
	return run(c, a->a, NULL, 0);
}

int ebt_guard_add(const struct config *c, const struct binding *b)
{
	struct args a;
	int k, rc = 0;

	for (k = 0; k < binding_rules(c, b) && !rc; k++) {
		/* in front of the drop rules */
		args_start(&a, "-I", EBT_GUARD_CHAIN);
		arg(&a, "1");
		binding_spec(&a, b, k);
		rc = run_args(c, &a);
	}
	return rc;
}

int ebt_guard_del(const struct config *c, const struct binding *b)
{
	struct args a;
	int k, rc = 0, r;

	for (k = 0; k < binding_rules(c, b); k++) {
		args_start(&a, "-D", EBT_GUARD_CHAIN);
		binding_spec(&a, b, k);
		r = run_args(c, &a);
		if (r)
			rc = r;
	}
	return rc;
}

static const char *const guard_hooks[] = { "INPUT", "FORWARD" };

int ebt_guard_install(const struct config *c, const struct guard_tab *t)
{
	struct args a;
	int rc, i, k, h, n;

	args_start(&a, "-N", EBT_GUARD_CHAIN);
	arg(&a, "-P");
	arg(&a, "RETURN");
	run_args(c, &a);
	args_start(&a, "-P", EBT_GUARD_CHAIN);
	arg(&a, "RETURN");
	if ((rc = run_args(c, &a)) != 0)
		goto fail;
	args_start(&a, "-F", EBT_GUARD_CHAIN);
	if ((rc = run_args(c, &a)) != 0)
		goto fail;
	for (i = 0; i < t->n; i++)
		for (k = 0; k < binding_rules(c, &t->b[i]); k++) {
			args_start(&a, "-A", EBT_GUARD_CHAIN);
			binding_spec(&a, &t->b[i], k);
			if ((rc = run_args(c, &a)) != 0)
				goto fail;
		}
	for (i = 0; i < c->nport; i++) {
		if (c->port[i].role != ROLE_CLIENT)
			continue;
		n = port_guard_rules(c, c->port[i].name, NULL, 0);
		for (k = 0; k < n; k++) {
			args_start(&a, "-A", EBT_GUARD_CHAIN);
			port_guard_rules(c, c->port[i].name, &a, k);
			if ((rc = run_args(c, &a)) != 0)
				goto fail;
		}
	}
	for (h = 0; h < 2; h++) {
		rc = jumps(c, "filter", guard_hooks[h], EBT_GUARD_CHAIN);
		while (rc > 1) {
			args_start(&a, "-D", guard_hooks[h]);
			arg(&a, "-j");
			arg(&a, EBT_GUARD_CHAIN);
			if ((rc = run_args(c, &a)) != 0)
				goto fail;
			rc = jumps(c, "filter", guard_hooks[h], EBT_GUARD_CHAIN);
		}
		if (rc < 0)
			goto fail;
		if (rc == 0) {
			args_start(&a, "-I", guard_hooks[h]);
			arg(&a, "1");
			arg(&a, "-j");
			arg(&a, EBT_GUARD_CHAIN);
			if ((rc = run_args(c, &a)) != 0)
				goto fail;
		}
	}
	if (ebt_guard_check(c, t) != 1)
		goto fail;
	LOGI("source guard rules installed (chain %s, %d bindings, %d rules)",
	     EBT_GUARD_CHAIN, t->n, guard_expected(c, t));
	return 0;
fail:
	LOGE("installing source guard rules failed (ebtables rc=%d)", rc);
	return -1;
}

int ebt_guard_check(const struct config *c, const struct guard_tab *t)
{
	struct args a;
	char want[48];
	int h, rc;

	for (h = 0; h < 2; h++) {
		rc = jumps(c, "filter", guard_hooks[h], EBT_GUARD_CHAIN);
		if (rc < 0)
			return -1;
		if (rc != 1)
			return 0;
	}
	args_start(&a, "-L", EBT_GUARD_CHAIN);
	if (run(c, a.a, list_buf, sizeof(list_buf)) != 0)
		return 0;
	snprintf(want, sizeof(want), "entries: %d, policy: RETURN",
		 guard_expected(c, t));
	return strstr(list_buf, want) != NULL;
}

void ebt_guard_remove(const struct config *c)
{
	struct args a;
	int h, i;

	for (h = 0; h < 2; h++)
		for (i = 0; i < 8; i++) {
			args_start(&a, "-D", guard_hooks[h]);
			arg(&a, "-j");
			arg(&a, EBT_GUARD_CHAIN);
			if (run_args(c, &a) != 0)
				break;
		}
	args_start(&a, "-F", EBT_GUARD_CHAIN);
	run_args(c, &a);
	args_start(&a, "-X", EBT_GUARD_CHAIN);
	run_args(c, &a);
	LOGI("source guard rules removed");
}

int ebt_guard_exists(const struct config *c)
{
	struct args a;

	args_start(&a, "-L", EBT_GUARD_CHAIN);
	return run(c, a.a, list_buf, sizeof(list_buf)) == 0;
}
