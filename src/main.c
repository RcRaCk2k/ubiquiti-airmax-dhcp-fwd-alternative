/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * dhcp-snooping-82: transparent L2 DHCPv4 option 82 agent for airOS bridges.
 *
 * Process model
 *   watcher (root): installs the broute rules, supervises the worker,
 *                   re-installs rules airOS flushed, triggers rollback.
 *   worker  (uid 99): packet path. Receives only frames the broute rules
 *                   diverted, modifies them and sends them out exactly once
 *                   on the other bridge port.
 *
 * Why ETH_P_IP sockets: in Linux 2.6.32 netif_receive_skb() delivers to
 * ETH_P_ALL taps before the bridge hook, but to protocol (ETH_P_IP) handlers
 * only if the bridge hook returned the frame, i.e. a broute DROP. A socket
 * bound to ETH_P_IP on a bridge port therefore never sees frames the bridge
 * forwarded itself, so a missing rule cannot cause duplicates.
 */
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <grp.h>
#include <limits.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "dhcp.h"
#include "ebt.h"
#include "log.h"
#include "stats.h"

#ifndef VERSION
#define VERSION "0.1.0-dev"
#endif

#define EXIT_RESTART	3	/* worker: interface changed, restart me */
#define EXIT_ROLLBACK	42	/* worker: end-to-end check failed */
#define XID_SLOTS	64
#define XID_TTL		30	/* seconds a request waits for a reply */
#define BURST_PER_POLL	32

#define ETH_P_IP_	0x0800
#define ETH_P_ALL_	0x0003

static volatile sig_atomic_t sig_stop, sig_hup, sig_usr1, sig_chld;

static struct config cfg;
static const char *own_cfg_path = DEFAULT_CONFIG;
static char abs_cfg_path[PATH_MAX];

/* ------------------------------------------------------------------ */

static time_t mono(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

static void on_signal(int s)
{
	switch (s) {
	case SIGTERM:
	case SIGINT:
		sig_stop = 1;
		break;
	case SIGHUP:
		sig_hup = 1;
		break;
	case SIGUSR1:
		sig_usr1 = 1;
		break;
	case SIGCHLD:
		sig_chld = 1;
		break;
	}
}

static void set_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGCHLD, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
}

static const char *mac_str(const uint8_t *m, char *buf)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		m[0], m[1], m[2], m[3], m[4], m[5]);
	return buf;
}

static const char *ip_str(uint32_t a, char *buf)
{
	sprintf(buf, "%u.%u.%u.%u", a >> 24, (a >> 16) & 0xff,
		(a >> 8) & 0xff, a & 0xff);
	return buf;
}

/* printable copy of an option 82 sub-option for logs */
static const char *id_str(const uint8_t *v, size_t l, char *buf, size_t n)
{
	size_t i, o = 0;

	for (i = 0; i < l && o + 5 < n; i++) {
		if (v[i] >= 0x20 && v[i] < 0x7f && v[i] != '"' && v[i] != '\\')
			buf[o++] = (char)v[i];
		else
			o += (size_t)sprintf(buf + o, "\\x%02x", v[i]);
	}
	buf[o] = '\0';
	return buf;
}

/* ------------------------------------------------------------------ */
/* packet sockets */

static struct sock_filter bpf_request[] = {
	{ 0x28, 0, 0, 12 },		/* ldh [12]            */
	{ 0x15, 0, 8, ETH_P_IP_ },	/* jne IPv4 -> drop    */
	{ 0x30, 0, 0, 23 },		/* ldb [23]            */
	{ 0x15, 0, 6, 17 },		/* jne UDP -> drop     */
	{ 0x28, 0, 0, 20 },		/* ldh [20]            */
	{ 0x45, 4, 0, 0x1fff },		/* frag offset -> drop */
	{ 0xb1, 0, 0, 14 },		/* ldxb 4*([14]&0xf)   */
	{ 0x48, 0, 0, 16 },		/* ldh [x+16] dport    */
	{ 0x15, 0, 1, 67 },
	{ 0x06, 0, 0, 0xffff },
	{ 0x06, 0, 0, 0 },
};

static struct sock_filter bpf_reply[] = {
	{ 0x28, 0, 0, 12 },
	{ 0x15, 0, 10, ETH_P_IP_ },
	{ 0x30, 0, 0, 23 },
	{ 0x15, 0, 8, 17 },
	{ 0x28, 0, 0, 20 },
	{ 0x45, 6, 0, 0x1fff },
	{ 0xb1, 0, 0, 14 },
	{ 0x48, 0, 0, 14 },		/* sport 67 */
	{ 0x15, 0, 3, 67 },
	{ 0x48, 0, 0, 16 },		/* dport 68 */
	{ 0x15, 0, 1, 68 },
	{ 0x06, 0, 0, 0xffff },
	{ 0x06, 0, 0, 0 },
};

static struct sock_filter bpf_any_dhcp[] = {
	{ 0x28, 0, 0, 12 },
	{ 0x15, 0, 12, ETH_P_IP_ },
	{ 0x30, 0, 0, 23 },
	{ 0x15, 0, 10, 17 },
	{ 0x28, 0, 0, 20 },
	{ 0x45, 8, 0, 0x1fff },
	{ 0xb1, 0, 0, 14 },
	{ 0x48, 0, 0, 14 },
	{ 0x15, 4, 0, 67 },
	{ 0x15, 3, 0, 68 },
	{ 0x48, 0, 0, 16 },
	{ 0x15, 1, 0, 67 },
	{ 0x15, 0, 1, 68 },
	{ 0x06, 0, 0, 0xffff },
	{ 0x06, 0, 0, 0 },
};

#define BPF(a) { sizeof(a) / sizeof(a[0]), a }

static int open_packet(const char *ifname, unsigned proto,
		       struct sock_fprog *prog, int *ifindex)
{
	struct sockaddr_ll sll;
	int fd, idx, rcvbuf = 65536;

	idx = (int)if_nametoindex(ifname);
	if (!idx) {
		LOGE("interface %s not found", ifname);
		return -1;
	}
	/* protocol 0: no frames are queued before the filter is attached */
	fd = socket(AF_PACKET, SOCK_RAW, 0);
	if (fd < 0) {
		LOGE("socket(AF_PACKET): %s", strerror(errno));
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, prog,
		       sizeof(*prog)) < 0) {
		LOGE("SO_ATTACH_FILTER: %s", strerror(errno));
		close(fd);
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons((uint16_t)proto);
	sll.sll_ifindex = idx;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		LOGE("bind(%s): %s", ifname, strerror(errno));
		close(fd);
		return -1;
	}
	fcntl(fd, F_SETFL, O_NONBLOCK);
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	*ifindex = idx;
	return fd;
}

/* ------------------------------------------------------------------ */
/* worker */

struct bucket {
	unsigned	tokens;
	time_t		last;
};

/* runtime state per bridge port, same index as cfg.port[] */
struct pstate {
	int		fd;
	int		ifindex;
	struct bucket	tb;
	uint32_t	rx;
	uint32_t	tx;
};

struct xid_ent {
	uint32_t	xid;
	uint8_t		mac[6];
	uint8_t		kind;		/* 0 free, 1 marked, 2 passthrough */
	uint8_t		answered;
	int		port;		/* client port the request came from */
	time_t		t;
};

static struct stats st;
static struct pstate ps[MAX_PORTS];
static struct xid_ent xids[XID_SLOTS];
static int stats_fd = -1;

static int bucket_take(struct bucket *b, time_t now)
{
	if (!cfg.rate_pps)
		return 1;
	if (now != b->last) {
		unsigned long t = b->tokens +
			(unsigned long)(now - b->last) * cfg.rate_pps;

		b->tokens = t > cfg.rate_burst ? cfg.rate_burst : (unsigned)t;
		b->last = now;
	}
	if (!b->tokens)
		return 0;
	b->tokens--;
	return 1;
}

static void xid_expire(time_t now)
{
	int i;

	for (i = 0; i < XID_SLOTS; i++)
		if (xids[i].kind && now - xids[i].t > XID_TTL) {
			if (xids[i].kind == 1 && !xids[i].answered)
				st.req_unanswered++;
			xids[i].kind = 0;
		}
}

static struct xid_ent *xid_find(uint32_t xid, const uint8_t *mac)
{
	int i;

	for (i = 0; i < XID_SLOTS; i++)
		if (xids[i].kind && xids[i].xid == xid &&
		    !memcmp(xids[i].mac, mac, 6))
			return &xids[i];
	return NULL;
}

static void xid_add(uint32_t xid, const uint8_t *mac, int kind, int port,
		    time_t now)
{
	struct xid_ent *e = xid_find(xid, mac), *old = &xids[0];
	int i;

	if (!e) {
		for (i = 0; i < XID_SLOTS; i++) {
			if (!xids[i].kind) {
				e = &xids[i];
				break;
			}
			if (xids[i].t < old->t)
				old = &xids[i];
		}
		if (!e)
			e = old;	/* table full: reuse oldest */
	}
	e->xid = xid;
	memcpy(e->mac, mac, 6);
	e->kind = (uint8_t)kind;
	e->answered = 0;
	e->port = port;
	e->t = now;
}

static void write_stats(time_t started, unsigned restarts)
{
	char buf[4096], cid[256], rid[256];
	size_t n = 0;
	int i;

#define ADD(...) do {							\
		if (n + 1 < sizeof(buf)) {				\
			int r_ = snprintf(buf + n, sizeof(buf) - n,	\
					  __VA_ARGS__);			\
			if (r_ > 0)					\
				n += (size_t)r_ < sizeof(buf) - n ?	\
				     (size_t)r_ : sizeof(buf) - n - 1;	\
		}							\
	} while (0)

	if (stats_fd < 0)
		return;
	ADD("version %s\npid %d\nuptime %ld\nworker_restarts %u\n",
	    VERSION, (int)getpid(), (long)(mono() - started), restarts);
	for (i = 0; i < cfg.nport; i++) {
		const struct port *p = &cfg.port[i];

		ADD("port %s bridge=%s role=%s lower=%s rx=%u tx=%u", p->name,
		    cfg.br[p->bridge].name, role_str(p->role), p->lower,
		    ps[i].rx, ps[i].tx);
		if (p->role == ROLE_CLIENT)
			ADD(" circuit_id=\"%s\" remote_id=\"%s\"",
			    id_str(p->o82.cid, p->o82.cid_len, cid, sizeof(cid)),
			    id_str(p->o82.rid, p->o82.rid_len, rid, sizeof(rid)));
		ADD("\n");
	}
#define X(f) ADD(#f " %u\n", st.f);
	STATS_FIELDS(X)
#undef X
#undef ADD
	if (ftruncate(stats_fd, 0) == 0)
		(void)!pwrite(stats_fd, buf, n, 0);
}

static void log_packet(const char *ifname, int ifindex, const char *action,
		       const char *to, const struct dhcp_info *in)
{
	char sm[18], dm[18], ch[18], si[16], di[16], gi[16], c[128], r[128];

	if (!log_enabled(LOG_LVL_INFO))
		return;
	log_pkt(LOG_LVL_INFO,
		"%s if=%s/%d to=%s type=%s xid=0x%08x chaddr=%s src=%s/%s "
		"dst=%s/%s giaddr=%s hops=%u reason=%s cid=\"%s\" rid=\"%s\"",
		action, ifname, ifindex, to, dhcp_type_str(in->msgtype),
		in->xid, mac_str(in->chaddr, ch), mac_str(in->src_mac, sm),
		ip_str(in->ip_src, si), mac_str(in->dst_mac, dm),
		ip_str(in->ip_dst, di), ip_str(in->giaddr, gi), in->hops,
		dhcp_reason_str(in->reason),
		id_str(in->o82_cid, in->o82_cid_len, c, sizeof(c)),
		id_str(in->o82_rid, in->o82_rid_len, r, sizeof(r)));
}

/* returns -1 if the worker must restart */
static int xmit(int port, const uint8_t *buf, size_t len, uint32_t *ok)
{
	if (send(ps[port].fd, buf, len, 0) == (ssize_t)len) {
		(*ok)++;
		ps[port].tx++;
		return 0;
	}
	st.tx_error++;
	LOGW("send on %s: %s", cfg.port[port].name, strerror(errno));
	return errno == ENXIO || errno == ENODEV ? -1 : 0;
}

/* sends to every port of the bridge with the given role (or one port),
 * like the bridge would flood it */
static int xmit_role(int bridge, int role, int only, const uint8_t *buf,
		     size_t len, uint32_t *ok, char *to, size_t tolen)
{
	size_t o = 0;
	int i;

	to[0] = '\0';
	for (i = 0; i < cfg.nport; i++) {
		if (cfg.port[i].bridge != bridge || cfg.port[i].role != role ||
		    (only >= 0 && i != only))
			continue;
		if (o + strlen(cfg.port[i].name) + 2 < tolen)
			o += (size_t)sprintf(to + o, "%s%s", o ? "," : "",
					     cfg.port[i].name);
		if (xmit(i, buf, len, ok) < 0)
			return -1;
	}
	return 0;
}

static void count_request(enum reason r)
{
	switch (r) {
	case R_INSERTED:	st.req_inserted++; break;
	case R_HAS_O82:		st.req_has_o82++; break;
	case R_RELAYED:		st.req_relayed++; break;
	case R_TYPE_SKIPPED:	st.req_type_skipped++; break;
	case R_NO_SPACE:	st.req_no_space++; break;
	case R_WRONG_OP:	st.req_wrong_op++; break;
	default:		st.req_malformed++; break;
	}
}

static ssize_t receive(int port, uint8_t *buf, size_t cap, time_t now,
		       uint32_t *ratelimited)
{
	struct sockaddr_ll sll;
	socklen_t sl = sizeof(sll);
	ssize_t n;

	for (;;) {
		n = recvfrom(ps[port].fd, buf, cap, MSG_TRUNC,
			     (struct sockaddr *)&sll, &sl);
		if (n < 0)
			return -1;
		ps[port].rx++;
		if (cfg.port[port].role == ROLE_CLIENT)
			st.rx_client++;
		else
			st.rx_uplink++;
		if (sll.sll_pkttype == PACKET_OUTGOING) {
			st.rx_outgoing_ignored++;
			continue;
		}
		if ((size_t)n > cap) {
			st.rx_truncated++;
			continue;
		}
		if (!bucket_take(&ps[port].tb, now)) {
			(*ratelimited)++;
			continue;
		}
		return n;
	}
}

static int handle_client(int port, time_t now)
{
	static uint8_t buf[FRAME_BUF_LEN];
	const struct port *p = &cfg.port[port];
	struct dhcp_info info;
	char to[128];
	int i;

	for (i = 0; i < BURST_PER_POLL; i++) {
		ssize_t n = receive(port, buf, sizeof(buf), now,
				    &st.req_ratelimited);
		size_t len;
		enum verdict v;

		if (n < 0)
			return 0;
		len = (size_t)n;
		v = dhcp_handle_request(buf, &len, sizeof(buf), &p->o82, &info);
		count_request(info.reason);
		if (info.reason == R_HAS_O82 || info.reason == R_RELAYED) {
			xid_add(info.xid, info.chaddr, 2, port, now);
			if (cfg.existing_o82 == POL_DROP) {
				v = VERDICT_DROP;
				st.req_dropped_policy++;
			}
		} else if (info.reason == R_WRONG_OP) {
			/* BOOTREPLY from the customer: rogue server or relay */
			v = VERDICT_DROP;
			st.req_dropped_policy++;
		} else if (info.reason == R_INSERTED) {
			xid_add(info.xid, info.chaddr, 1, port, now);
			/* log what we put in, not what came in */
			memcpy(info.o82_cid, p->o82.cid, p->o82.cid_len);
			info.o82_cid_len = p->o82.cid_len;
			memcpy(info.o82_rid, p->o82.rid, p->o82.rid_len);
			info.o82_rid_len = p->o82.rid_len;
		}
		to[0] = '\0';
		if (v != VERDICT_DROP &&
		    xmit_role(p->bridge, ROLE_UPLINK, -1, buf, len,
			      &st.tx_uplink, to, sizeof(to)) < 0)
			return -1;
		log_packet(p->name, ps[port].ifindex,
			   v == VERDICT_DROP ? "req-drop" :
			   v == VERDICT_FORWARD_MODIFIED ? "req-mark" : "req-pass",
			   v == VERDICT_DROP ? "-" : to, &info);
	}
	return 0;
}

/* client port of this bridge whose option 82 the reply carries, or -1 */
static int reply_owner(int bridge, const struct dhcp_info *info)
{
	int i;

	if (!info->has_o82)
		return -1;
	for (i = 0; i < cfg.nport; i++)
		if (cfg.port[i].bridge == bridge &&
		    cfg.port[i].role == ROLE_CLIENT &&
		    dhcp_o82_matches(info, &cfg.port[i].o82))
			return i;
	return -1;
}

static int first_client(int bridge)
{
	int i;

	for (i = 0; i < cfg.nport; i++)
		if (cfg.port[i].bridge == bridge &&
		    cfg.port[i].role == ROLE_CLIENT)
			return i;
	return -1;
}

static int handle_uplink(int port, time_t now)
{
	static uint8_t buf[FRAME_BUF_LEN];
	const struct port *p = &cfg.port[port];
	struct dhcp_info info;
	char to[128];
	int i;

	for (i = 0; i < BURST_PER_POLL; i++) {
		ssize_t n = receive(port, buf, sizeof(buf), now,
				    &st.rep_ratelimited);
		size_t len;
		enum verdict v;
		struct xid_ent *e;
		int owner, target;

		if (n < 0)
			return 0;
		len = (size_t)n;
		/* which of our client ports does the option 82 belong to? */
		dhcp_parse(buf, len, &info);
		owner = reply_owner(p->bridge, &info);
		v = dhcp_handle_reply(buf, &len, &cfg.port[owner >= 0 ? owner :
				      first_client(p->bridge)].o82, &info);
		e = info.reason == R_PARSED || info.reason >= R_REPLY_OURS ?
			xid_find(info.xid, info.chaddr) : NULL;
		if (e && cfg.port[e->port].bridge != p->bridge)
			e = NULL;
		/* default: the port the request came from, else flood */
		target = owner >= 0 ? owner : e ? e->port : -1;
		switch (info.reason) {
		case R_REPLY_OURS:
			st.rep_ours++;
			break;
		case R_REPLY_FOREIGN:
			/* answer to a request we marked, but an upstream relay
			 * replaced our option 82: still our customer, strip */
			if (e && e->kind == 1 && dhcp_strip_o82(buf, len) == 0) {
				v = VERDICT_FORWARD_MODIFIED;
				st.rep_foreign_ours_by_xid++;
			} else if ((e && e->kind == 2) ||
				   cfg.reply_foreign == POL_FORWARD) {
				v = VERDICT_FORWARD;
				st.rep_foreign_forwarded++;
			} else {
				st.rep_foreign_dropped++;
			}
			break;
		case R_REPLY_NO_O82:
			if (cfg.reply_no_o82 == POL_DROP) {
				v = VERDICT_DROP;
				st.rep_no_o82_dropped++;
			} else {
				st.rep_no_o82_forwarded++;
			}
			break;
		case R_WRONG_OP:
			v = VERDICT_DROP;
			st.rep_wrong_op++;
			break;
		default:
			st.rep_malformed++;
			break;
		}
		if (e && e->kind == 1 && !e->answered && v != VERDICT_DROP) {
			e->answered = 1;
			st.req_answered++;
		}
		to[0] = '\0';
		if (v != VERDICT_DROP &&
		    xmit_role(p->bridge, ROLE_CLIENT, target, buf, len,
			      &st.tx_client, to, sizeof(to)) < 0)
			return -1;
		/* foreign drops are routine on a shared segment: debug only */
		if (v != VERDICT_DROP || log_enabled(LOG_LVL_DEBUG))
			log_packet(p->name, ps[port].ifindex,
				   v == VERDICT_DROP ? "rep-drop" :
				   v == VERDICT_FORWARD_MODIFIED ? "rep-strip" :
				   "rep-pass", v == VERDICT_DROP ? "-" : to, &info);
	}
	return 0;
}

static void drop_privileges(void)
{
	if (!cfg.worker_uid || getuid() != 0)
		return;
	if (setgroups(0, NULL) < 0 || setgid((gid_t)cfg.worker_gid) < 0 ||
	    setuid((uid_t)cfg.worker_uid) < 0) {
		LOGE("dropping privileges: %s", strerror(errno));
		exit(1);
	}
}

static int worker(unsigned restarts)
{
	struct sock_fprog preq = BPF(bpf_request), prep = BPF(bpf_reply);
	struct pollfd pfd[MAX_PORTS];
	int i, rc = 0;
	time_t started = mono(), t_stats = 0, t_if = 0, t_win;
	uint32_t win_marked = 0, win_answered = 0;

	for (i = 0; i < cfg.nport; i++) {
		const struct port *p = &cfg.port[i];

		ps[i].fd = open_packet(p->name, ETH_P_IP_,
				       p->role == ROLE_CLIENT ? &preq : &prep,
				       &ps[i].ifindex);
		if (ps[i].fd < 0)
			return EXIT_RESTART;
		ps[i].tb.tokens = cfg.rate_burst;
		ps[i].tb.last = started;
		pfd[i].fd = ps[i].fd;
		pfd[i].events = POLLIN;
		LOGI("worker: %s %s/%d (on %s) circuit_id=\"%.*s\"",
		     role_str(p->role), p->name, ps[i].ifindex,
		     cfg.br[p->bridge].name,
		     p->role == ROLE_CLIENT ? p->o82.cid_len : 0,
		     (const char *)p->o82.cid);
	}
	stats_fd = open(cfg.stats_file, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
	drop_privileges();
	t_win = started;

	while (!sig_stop) {
		time_t now;
		int n = poll(pfd, (nfds_t)cfg.nport, 1000);

		if (n < 0 && errno != EINTR) {
			LOGE("poll: %s", strerror(errno));
			rc = EXIT_RESTART;
			break;
		}
		now = mono();
		for (i = 0; n > 0 && i < cfg.nport; i++) {
			int r = 0;

			if (pfd[i].revents & (POLLERR | POLLNVAL)) {
				LOGW("socket error on %s", cfg.port[i].name);
				r = -1;
			} else if (pfd[i].revents & POLLIN) {
				r = cfg.port[i].role == ROLE_CLIENT ?
					handle_client(i, now) :
					handle_uplink(i, now);
			}
			if (r < 0) {
				rc = EXIT_RESTART;
				break;
			}
		}
		if (rc)
			break;
		if (now - t_if >= 10) {
			t_if = now;
			xid_expire(now);
			for (i = 0; i < cfg.nport; i++)
				if ((int)if_nametoindex(cfg.port[i].name) !=
				    ps[i].ifindex)
					break;
			if (i < cfg.nport) {
				LOGW("interface %s changed, restarting worker",
				     cfg.port[i].name);
				rc = EXIT_RESTART;
				break;
			}
		}
		if (cfg.auto_rollback && now - t_win >= (time_t)cfg.rollback_window) {
			uint32_t marked = st.req_inserted - win_marked;
			uint32_t answered = st.req_answered - win_answered;

			if (marked >= cfg.rollback_min_requests && !answered) {
				LOGE("%u marked requests, none answered in %us: "
				     "requesting rollback", marked,
				     cfg.rollback_window);
				rc = EXIT_ROLLBACK;
				break;
			}
			win_marked = st.req_inserted;
			win_answered = st.req_answered;
			t_win = now;
		}
		if (sig_usr1 || now - t_stats >= (time_t)cfg.stats_interval) {
			sig_usr1 = 0;
			t_stats = now;
			write_stats(started, restarts);
		}
	}
	write_stats(started, restarts);
	return rc;
}

/* ------------------------------------------------------------------ */
/* watcher */

static void run_rollback(void)
{
	pid_t pid;

	LOGE("ROLLBACK: removing rules and running: %s", cfg.rollback_cmd);
	ebt_remove(&cfg);
	pid = fork();
	if (pid == 0) {
		setsid();
		execl("/bin/sh", "sh", "-c", cfg.rollback_cmd, (char *)NULL);
		_exit(127);
	}
	/* stay alive without rules or worker until the rollback script
	 * replaces us; exiting would only make init respawn us */
	while (!sig_stop)
		pause();
}

static int reload_config(void)
{
	struct config n;
	char err[256];

	config_defaults(&n);
	if (config_is_ours(own_cfg_path) &&
	    config_load(&n, own_cfg_path, err, sizeof(err)) < 0) {
		LOGE("reload: %s (keeping old config)", err);
		return -1;
	}
	if (config_resolve(&n, err, sizeof(err)) < 0) {
		LOGE("reload: %s (keeping old config)", err);
		return -1;
	}
	cfg = n;
	log_set_level(cfg.log_level);
	return 0;
}

static pid_t start_worker(unsigned restarts)
{
	pid_t pid = fork();

	if (pid == 0) {
		int rc = worker(restarts);

		_exit(rc);
	}
	if (pid < 0)
		LOGE("fork: %s", strerror(errno));
	return pid;
}

static int watcher(void)
{
	pid_t child = -1;
	unsigned restarts = 0, backoff = 1;
	time_t t_check = 0, t_start = 0, now;
	int rules_ok = 0;

	if (ebt_install(&cfg) == 0)
		rules_ok = 1;
	t_check = mono();

	while (!sig_stop) {
		now = mono();
		if (child < 0 && now >= t_start) {
			child = start_worker(restarts);
			t_start = now;
		}
		{
			/* interrupted early by SIGCHLD/SIGTERM/SIGHUP */
			struct timespec ts = { 1, 0 };

			nanosleep(&ts, NULL);
		}
		if (sig_stop)
			break;
		sig_chld = 0;
		if (child > 0) {
			int status;

			if (waitpid(child, &status, WNOHANG) == child) {
				int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

				child = -1;
				if (code == EXIT_ROLLBACK) {
					run_rollback();
					break;
				}
				restarts++;
				if (mono() - t_start > 60)
					backoff = 1;
				LOGW("worker exited (%s %d), restart in %us",
				     WIFSIGNALED(status) ? "signal" : "code",
				     WIFSIGNALED(status) ? WTERMSIG(status) : code,
				     backoff);
				t_start = mono() + backoff;
				backoff = backoff * 2 > 30 ? 30 : backoff * 2;
				/* rules stay in place: fail closed */
			}
		}
		if (sig_hup) {
			sig_hup = 0;
			LOGI("SIGHUP: reloading configuration");
			if (reload_config() == 0) {
				rules_ok = ebt_install(&cfg) == 0;
				if (child > 0)
					kill(child, SIGTERM);
			}
		}
		now = mono();
		if (now - t_check >= (time_t)cfg.rule_check_interval) {
			int r = ebt_check(&cfg);

			t_check = now;
			if (r != 1) {
				if (rules_ok)
					LOGW("broute rules missing (airOS reload?), "
					     "re-installing");
				rules_ok = ebt_install(&cfg) == 0;
			} else if (!rules_ok) {
				rules_ok = 1;
			}
		}
	}

	if (child > 0) {
		kill(child, SIGTERM);
		waitpid(child, NULL, 0);
	}
	if (!cfg.keep_rules_on_stop)
		ebt_remove(&cfg);
	LOGI("stopped");
	return 0;
}

/* ------------------------------------------------------------------ */
/* passive diagnosis: never sends, never touches ebtables */

struct diag_sock {
	const char	*ifname;
	unsigned	proto;
	const char	*label;
	int		fd;
	int		ifindex;
};

static const char *pkttype_str(int t)
{
	static const char *const s[] = { "HOST", "BROADCAST", "MULTICAST",
					 "OTHERHOST", "OUTGOING" };

	return t >= 0 && t <= 4 ? s[t] : "?";
}

static int diag(unsigned seconds)
{
	struct sock_fprog prog = BPF(bpf_any_dhcp);
	struct diag_sock ds[2 * MAX_PORTS + MAX_BRIDGES];
	struct pollfd pfd[2 * MAX_PORTS + MAX_BRIDGES];
	static uint8_t buf[FRAME_BUF_LEN];
	time_t end = seconds ? mono() + seconds : 0;
	int i, N = 0;

	/* per port: everything (ALL) and only what broute diverts (IP) */
	for (i = 0; i < cfg.nport; i++) {
		ds[N++] = (struct diag_sock){ cfg.port[i].name, ETH_P_ALL_,
					      "ALL", -1, 0 };
		ds[N++] = (struct diag_sock){ cfg.port[i].name, ETH_P_IP_,
					      "IP", -1, 0 };
	}
	for (i = 0; i < cfg.nbr; i++)
		ds[N++] = (struct diag_sock){ cfg.br[i].name, ETH_P_ALL_,
					      "ALL", -1, 0 };

	for (i = 0; i < N; i++) {
		ds[i].fd = open_packet(ds[i].ifname, ds[i].proto, &prog,
				       &ds[i].ifindex);
		if (ds[i].fd < 0)
			return 1;
		pfd[i].fd = ds[i].fd;
		pfd[i].events = POLLIN;
		printf("# socket %d: %s %s ifindex=%d\n", i, ds[i].label,
		       ds[i].ifname, ds[i].ifindex);
	}
	printf("# passive diagnosis, nothing is sent; IP sockets only see "
	       "frames diverted by broute\n");
	fflush(stdout);

	while (!sig_stop && (!end || mono() < end)) {
		if (poll(pfd, (nfds_t)N, 1000) <= 0)
			continue;
		for (i = 0; i < N; i++) {
			struct sockaddr_ll sll;
			socklen_t sl = sizeof(sll);
			struct dhcp_info in;
			struct timespec ts;
			ssize_t n;
			char sm[18], dm[18], ch[18], si[16], di[16], gi[16];
			char c[128], r[128];

			if (!(pfd[i].revents & POLLIN))
				continue;
			n = recvfrom(ds[i].fd, buf, sizeof(buf), MSG_TRUNC,
				     (struct sockaddr *)&sll, &sl);
			if (n < 0)
				continue;
			if ((size_t)n > sizeof(buf))
				n = sizeof(buf);
			dhcp_parse(buf, (size_t)n, &in);
			clock_gettime(CLOCK_REALTIME, &ts);
			printf("%ld.%03ld %s@%s(%d) pkt=%s len=%d %s>%s "
			       "%s>%s op=%u type=%s xid=0x%08x chaddr=%s "
			       "giaddr=%s hops=%u flags=0x%04x o82=%d "
			       "cid=\"%s\" rid=\"%s\" parse=%s\n",
			       (long)ts.tv_sec, ts.tv_nsec / 1000000L,
			       ds[i].label, ds[i].ifname, sll.sll_ifindex,
			       pkttype_str(sll.sll_pkttype), (int)n,
			       mac_str(in.src_mac, sm), mac_str(in.dst_mac, dm),
			       ip_str(in.ip_src, si), ip_str(in.ip_dst, di),
			       in.op, dhcp_type_str(in.msgtype), in.xid,
			       mac_str(in.chaddr, ch), ip_str(in.giaddr, gi),
			       in.hops, in.flags, in.has_o82,
			       id_str(in.o82_cid, in.o82_cid_len, c, sizeof(c)),
			       id_str(in.o82_rid, in.o82_rid_len, r, sizeof(r)),
			       dhcp_reason_str(in.reason));
			fflush(stdout);
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */

static void usage(void)
{
	printf("dhcp-snooping-82 %s - transparent DHCP option 82 agent\n"
	       "usage: dhcp-fwd [-n] [-d] [-c airos.conf] [-C own.conf]\n"
	       "       dhcp-fwd --check | --status | --diag [seconds] | -v\n"
	       "  -n          stay in foreground (as started by airOS init)\n"
	       "  -d          foreground, log to stderr, level debug\n"
	       "  -c FILE     airOS dhcp-fwd.conf; ignored unless it uses our\n"
	       "              INI syntax\n"
	       "  -C FILE     own configuration (default %s)\n"
	       "  --check     print resolved configuration and exit\n"
	       "  --status    print counters and rule state\n"
	       "  --diag [s]  passive packet path diagnosis\n",
	       VERSION, DEFAULT_CONFIG);
}

static void print_config(void)
{
	char c[256], r[256];
	int i;

	printf("version         %s\n", VERSION);
	printf("hostname        %s\n", cfg.hostname);
	printf("circuit_id      %s\n", cfg.circuit_id);
	printf("remote_id       %s\n", cfg.remote_id);
	for (i = 0; i < cfg.nbr; i++)
		printf("bridge          %s mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
		       cfg.br[i].name, cfg.br[i].mac[0], cfg.br[i].mac[1],
		       cfg.br[i].mac[2], cfg.br[i].mac[3], cfg.br[i].mac[4],
		       cfg.br[i].mac[5]);
	for (i = 0; i < cfg.nport; i++) {
		const struct port *p = &cfg.port[i];

		printf("port            %s/%s %s (lower %s)", cfg.br[p->bridge].name,
		       p->name, role_str(p->role), p->lower);
		if (p->role == ROLE_CLIENT)
			printf(" circuit_id=\"%s\" remote_id=\"%s\"",
			       id_str(p->o82.cid, p->o82.cid_len, c, sizeof(c)),
			       id_str(p->o82.rid, p->o82.rid_len, r, sizeof(r)));
		printf("\n");
	}
	printf("type_mask       0x%x\n", cfg.type_mask);
	printf("mtu             %u\n", (unsigned)cfg.mtu);
	printf("existing_o82    %s\n", cfg.existing_o82 ? "drop" : "forward");
	printf("reply_foreign   %s\n", cfg.reply_foreign ? "drop" : "forward");
	printf("reply_no_o82    %s\n", cfg.reply_no_o82 ? "drop" : "forward");
	printf("snooping        client_servers=%s uplink_requests=%s\n",
	       cfg.block_client_servers ? "blocked" : "allowed",
	       cfg.block_uplink_requests ? "blocked" : "allowed");
	printf("rate_limit      %u/s burst %u per port\n", cfg.rate_pps,
	       cfg.rate_burst);
	printf("auto_rollback   %d (window %us, min %u)\n", cfg.auto_rollback,
	       cfg.rollback_window, cfg.rollback_min_requests);
}

static int status(void)
{
	char buf[2048];
	int fd = open(cfg.stats_file, O_RDONLY), r;
	ssize_t n;

	if (fd >= 0) {
		while ((n = read(fd, buf, sizeof(buf))) > 0)
			fwrite(buf, 1, (size_t)n, stdout);
		close(fd);
	} else {
		printf("# no stats file %s\n", cfg.stats_file);
	}
	r = ebt_check(&cfg);
	printf("broute_rules %s\n", r == 1 ? "ok" : r == 0 ? "missing" : "error");
	printf("snooping client_servers=%s uplink_requests=%s "
	       "(counters: ebtables -t broute -L %s --Lc)\n",
	       cfg.block_client_servers ? "blocked" : "allowed",
	       cfg.block_uplink_requests ? "blocked" : "allowed", EBT_CHAIN);
	return r == 1 ? 0 : 1;
}

static void write_pidfile(void)
{
	char buf[16];
	int fd = open(cfg.pidfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0)
		return;
	snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
	(void)!write(fd, buf, strlen(buf));
	close(fd);
}

int main(int argc, char **argv)
{
	const char *airos_cfg = NULL;
	char err[256];
	int foreground = 0, debug = 0, mode = 0, i, rc;
	unsigned diag_secs = 0;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (!strcmp(a, "-n") || !strcmp(a, "-N")) {
			foreground = 1;
		} else if (!strcmp(a, "-d")) {
			foreground = debug = 1;
		} else if (!strcmp(a, "-c") && i + 1 < argc) {
			airos_cfg = argv[++i];
		} else if (!strcmp(a, "-C") && i + 1 < argc) {
			own_cfg_path = argv[++i];
		} else if (!strcmp(a, "--check")) {
			mode = 'c';
		} else if (!strcmp(a, "--status")) {
			mode = 's';
		} else if (!strcmp(a, "--diag")) {
			mode = 'd';
			if (i + 1 < argc && argv[i + 1][0] != '-')
				diag_secs = (unsigned)strtoul(argv[++i], NULL, 10);
		} else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
			printf("dhcp-snooping-82 %s\n", VERSION);
			return 0;
		} else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage();
			return 0;
		} else {
			fprintf(stderr, "unknown argument: %s\n", a);
			usage();
			return 2;
		}
	}
	/* airOS passes its generated config via -c; use it only if it is
	 * written in our syntax */
	if (airos_cfg && config_is_ours(airos_cfg))
		own_cfg_path = airos_cfg;
	/* the daemon changes to / and SIGHUP reloads by path */
	if (realpath(own_cfg_path, abs_cfg_path))
		own_cfg_path = abs_cfg_path;

	config_defaults(&cfg);
	if (access(own_cfg_path, R_OK) == 0 &&
	    config_load(&cfg, own_cfg_path, err, sizeof(err)) < 0) {
		fprintf(stderr, "%s\n", err);
		return 2;
	}
	if (debug)
		cfg.log_level = LOG_LVL_DEBUG;
	log_init(cfg.log_level, debug || mode);
	set_signals();
	if (config_resolve(&cfg, err, sizeof(err)) < 0) {
		LOGE("%s", err);
		if (mode)
			return 2;
		/* started by init: exiting would only make init respawn us
		 * in a tight loop, so wait for the configuration instead */
		while (!sig_stop) {
			struct timespec ts = { 10, 0 };

			nanosleep(&ts, NULL);
			if (config_resolve(&cfg, err, sizeof(err)) == 0)
				break;
		}
		if (sig_stop)
			return 0;
	}

	switch (mode) {
	case 'c':
		print_config();
		return 0;
	case 's':
		return status();
	case 'd':
		return diag(diag_secs);
	}

	if (!foreground) {
		pid_t p = fork();

		if (p < 0)
			return 1;
		if (p > 0)
			return 0;
		setsid();
		if (chdir("/") < 0)
			return 1;
		rc = open("/dev/null", O_RDWR);
		if (rc >= 0) {
			dup2(rc, 0);
			dup2(rc, 1);
			dup2(rc, 2);
		}
	}
	write_pidfile();
	LOGI("dhcp-snooping-82 %s starting (config %s)", VERSION,
	     access(own_cfg_path, R_OK) == 0 ? own_cfg_path : "defaults");
	rc = watcher();
	unlink(cfg.pidfile);
	return rc;
}
