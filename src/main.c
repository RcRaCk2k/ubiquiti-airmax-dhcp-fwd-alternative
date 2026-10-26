/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 The dhcp-snooping-82 authors
 *
 * dhcp-snooping-82: transparent L2 DHCPv4 option 82 agent and DHCPv6
 * lightweight relay agent (RFC 6221) for airOS bridges.
 *
 * Process model
 *   watcher (root): installs the broute rules, supervises the worker,
 *                   re-installs rules airOS flushed, triggers rollback.
 *   worker  (uid 99): packet path. Receives only frames the broute rules
 *                   diverted, modifies them and sends them out exactly once
 *                   on the other bridge port.
 *   Source guard: the worker reports leases (ACK, DHCPv6 Reply, release)
 *   over a pipe; the watcher keeps the binding table, the lease file and
 *   the filter rules, so bindings survive a worker restart.
 *
 * Why ETH_P_IP sockets: in Linux 2.6.32 netif_receive_skb() delivers to
 * ETH_P_ALL taps before the bridge hook, but to protocol (ETH_P_IP) handlers
 * only if the bridge hook returned the frame, i.e. a broute DROP. A socket
 * bound to ETH_P_IP on a bridge port therefore never sees frames the bridge
 * forwarded itself, so a missing rule cannot cause duplicates. The same
 * holds for the ETH_P_IPV6 sockets used for DHCPv6.
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
#include "dhcp6.h"
#include "ebt.h"
#include "guard.h"
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

/* options from the command line, applied on top of the config file (also
 * on every SIGHUP reload) */
#define MAX_CLI_OPTS	64
static struct { const char *name, *val; } cli_opt[MAX_CLI_OPTS];
static int n_cli_opt;
static char cli_names[MAX_CLI_OPTS][96];

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

/* DHCPv6 to the relay/server port, no extension headers */
static struct sock_filter bpf_dhcp6[] = {
	{ 0x28, 0, 0, 12 },		/* ldh [12]            */
	{ 0x15, 0, 5, ETH_P_IPV6_ },	/* jne IPv6 -> drop    */
	{ 0x30, 0, 0, 20 },		/* ldb [20] next hdr   */
	{ 0x15, 0, 3, 17 },		/* jne UDP -> drop     */
	{ 0x28, 0, 0, 56 },		/* ldh [56] dport      */
	{ 0x15, 0, 1, DHCP6_SERVER_PORT },
	{ 0x06, 0, 0, 0xffff },
	{ 0x06, 0, 0, 0 },
};

/* client ports: DHCPv6 to port 547, and ICMPv6 (directly or behind a
 * hop-by-hop header) for the RA guard */
static struct sock_filter bpf_client6[] = {
	{ 0x28, 0, 0, 12 },		/* ldh [12]            */
	{ 0x15, 0, 7, ETH_P_IPV6_ },	/* jne IPv6 -> drop    */
	{ 0x30, 0, 0, 20 },		/* ldb [20] next hdr   */
	{ 0x15, 4, 0, 58 },		/* ICMPv6 -> accept    */
	{ 0x15, 3, 0, 0 },		/* hop-by-hop -> accept */
	{ 0x15, 0, 3, 17 },		/* jne UDP -> drop     */
	{ 0x28, 0, 0, 56 },		/* ldh [56] dport      */
	{ 0x15, 0, 1, DHCP6_SERVER_PORT },
	{ 0x06, 0, 0, 0xffff },
	{ 0x06, 0, 0, 0 },
};

/* ND/MLD of a client port is not limited like DHCP */
#define ICMP6_RATE	200
#define ICMP6_BURST	400

/* diagnosis: DHCPv4 (67/68) or DHCPv6 (546/547), either port */
static struct sock_filter bpf_any_dhcp[] = {
	{ 0x28, 0, 0, 12 },		/*  0 ldh [12]          */
	{ 0x15, 0, 11, ETH_P_IP_ },	/*  1 IPv4? else 13     */
	{ 0x30, 0, 0, 23 },		/*  2                   */
	{ 0x15, 0, 19, 17 },		/*  3 UDP? else drop    */
	{ 0x28, 0, 0, 20 },		/*  4                   */
	{ 0x45, 17, 0, 0x1fff },	/*  5 fragment -> drop  */
	{ 0xb1, 0, 0, 14 },		/*  6                   */
	{ 0x48, 0, 0, 14 },		/*  7 sport             */
	{ 0x15, 13, 0, 67 },		/*  8                   */
	{ 0x15, 12, 0, 68 },		/*  9                   */
	{ 0x48, 0, 0, 16 },		/* 10 dport             */
	{ 0x15, 10, 0, 67 },		/* 11                   */
	{ 0x15, 9, 10, 68 },		/* 12                   */
	{ 0x15, 0, 9, ETH_P_IPV6_ },	/* 13 IPv6? else drop   */
	{ 0x30, 0, 0, 20 },		/* 14 next header       */
	{ 0x15, 0, 7, 17 },		/* 15                   */
	{ 0x28, 0, 0, 54 },		/* 16 sport             */
	{ 0x15, 4, 0, DHCP6_CLIENT_PORT },	/* 17           */
	{ 0x15, 3, 0, DHCP6_SERVER_PORT },	/* 18           */
	{ 0x28, 0, 0, 56 },		/* 19 dport             */
	{ 0x15, 1, 0, DHCP6_CLIENT_PORT },	/* 20           */
	{ 0x15, 0, 1, DHCP6_SERVER_PORT },	/* 21           */
	{ 0x06, 0, 0, 0xffff },		/* 22 accept            */
	{ 0x06, 0, 0, 0 },		/* 23 drop              */
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
	int		fd6;		/* DHCPv6, -1 if off */
	int		ifindex;
	struct bucket	tb;
	struct bucket	tb_icmp6;
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
static int guard_pipe[2] = { -1, -1 };
static int guard_fd = -1;		/* worker: write end, -1 = off */
static struct xid_ent xids[XID_SLOTS];
static int stats_fd = -1;

static int bucket_take(struct bucket *b, time_t now, unsigned rate,
		       unsigned burst)
{
	if (!rate)
		return 1;
	if (now != b->last) {
		unsigned long t = b->tokens +
			(unsigned long)(now - b->last) * rate;

		b->tokens = t > burst ? burst : (unsigned)t;
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

static void guard_send(const struct guard_msg *m)
{
	if (guard_fd < 0)
		return;
	if (write(guard_fd, m, sizeof(*m)) == (ssize_t)sizeof(*m))
		st.guard_msgs++;
	else
		st.guard_msgs_lost++;
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

static ssize_t receive(int port, int v6, uint8_t *buf, size_t cap,
		       time_t now, uint32_t *ratelimited)
{
	struct sockaddr_ll sll;
	socklen_t sl = sizeof(sll);
	ssize_t n;

	for (;;) {
		n = recvfrom(v6 ? ps[port].fd6 : ps[port].fd, buf, cap,
			     MSG_TRUNC, (struct sockaddr *)&sll, &sl);
		if (n < 0)
			return -1;
		ps[port].rx++;
		if (cfg.port[port].role == ROLE_CLIENT)
			(*(v6 ? &st.rx6_client : &st.rx_client))++;
		else
			(*(v6 ? &st.rx6_uplink : &st.rx_uplink))++;
		if (sll.sll_pkttype == PACKET_OUTGOING) {
			st.rx_outgoing_ignored++;
			continue;
		}
		if ((size_t)n > cap) {
			st.rx_truncated++;
			continue;
		}
		if (v6 && n > 20 && buf[20] != 17) {	/* ICMPv6, RA guard */
			if (!bucket_take(&ps[port].tb_icmp6, now, ICMP6_RATE,
					 ICMP6_BURST)) {
				st.icmp6_ratelimited++;
				continue;
			}
		} else if (!bucket_take(&ps[port].tb, now, cfg.rate_pps,
					cfg.rate_burst)) {
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
	struct guard_msg gm;
	char to[128];
	int i;

	for (i = 0; i < BURST_PER_POLL; i++) {
		ssize_t n = receive(port, 0, buf, sizeof(buf), now,
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
		if (v != VERDICT_DROP && guard_msg4(&info, p->name, 1, &gm))
			guard_send(&gm);
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
	struct guard_msg gm;
	char to[128];
	int i;

	for (i = 0; i < BURST_PER_POLL; i++) {
		ssize_t n = receive(port, 0, buf, sizeof(buf), now,
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
		/* source guard: only leases of our own customers, i.e. the
		 * reply carries our option 82 or answers a request that came
		 * in on that port; never the station's own address */
		if (v != VERDICT_DROP && target >= 0 &&
		    memcmp(info.chaddr, cfg.br[p->bridge].mac, 6) &&
		    guard_msg4(&info, cfg.port[target].name, 0, &gm))
			guard_send(&gm);
		/* foreign drops are routine on a shared segment: debug only */
		if (v != VERDICT_DROP || log_enabled(LOG_LVL_DEBUG))
			log_packet(p->name, ps[port].ifindex,
				   v == VERDICT_DROP ? "rep-drop" :
				   v == VERDICT_FORWARD_MODIFIED ? "rep-strip" :
				   "rep-pass", v == VERDICT_DROP ? "-" : to, &info);
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* DHCPv6 */

static void log_packet6(const char *ifname, int ifindex, const char *action,
			const char *to, const struct dhcp6_info *in,
			const uint8_t *ifid, size_t ifid_len)
{
	char sm[18], dm[18], si[40], di[40], pa[40], c[128];
	int relay = in->msgtype == DHCP6_RELAY_FORW ||
		    in->msgtype == DHCP6_RELAY_REPL;

	if (!log_enabled(LOG_LVL_INFO))
		return;
	log_pkt(LOG_LVL_INFO,
		"%s if=%s/%d to=%s type=%s%s%s xid=0x%06x src=%s/%s dst=%s/%s "
		"peer=%s reason=%s ifid=\"%s\"",
		action, ifname, ifindex, to, dhcp6_type_str(in->msgtype),
		relay ? "/" : "", relay ? dhcp6_type_str(in->inner_type) : "",
		relay ? in->inner_xid : in->xid, mac_str(in->src_mac, sm),
		ip6_str(in->ip_src, si), mac_str(in->dst_mac, dm),
		ip6_str(in->ip_dst, di),
		relay ? ip6_str(in->peer_addr, pa) : "-",
		dhcp6_reason_str(in->reason),
		id_str(ifid, ifid_len, c, sizeof(c)));
}

/* RA guard: link-local ICMPv6 of a client port, as the bridge would have
 * forwarded it: multicast to every other port of the bridge, unicast to
 * the uplinks (frames for the station itself are not diverted) */
static int ra_guard(int port, const uint8_t *buf, size_t len)
{
	const struct port *p = &cfg.port[port];
	struct dhcp6_info info;
	char sm[18], si[40], di[40];
	uint32_t ok = 0;
	int i;

	if (dhcp6_ra_guard(buf, len, &info) == VERDICT_DROP) {
		if (info.reason == R6_RA) {
			st.ra_dropped++;
			log_pkt(LOG_LVL_INFO, "ra-drop if=%s/%d src=%s/%s dst=%s",
				p->name, ps[port].ifindex,
				mac_str(info.src_mac, sm),
				ip6_str(info.ip_src, si), ip6_str(info.ip_dst, di));
		} else {
			st.icmp6_dropped++;
		}
		return 0;
	}
	st.icmp6_passed++;
	for (i = 0; i < cfg.nport; i++) {
		if (i == port || cfg.port[i].bridge != p->bridge)
			continue;
		if (cfg.port[i].role != ROLE_UPLINK && !(buf[0] & 1))
			continue;
		if (xmit(i, buf, len, &ok) < 0)
			return -1;
	}
	return 0;
}

static int handle_client6(int port, time_t now)
{
	static uint8_t buf[FRAME_BUF_LEN];
	const struct port *p = &cfg.port[port];
	struct dhcp6_info info;
	struct guard_msg gm[DHCP6_MAX_LEASES];
	char to[128];
	int i, k, ngm;

	for (i = 0; i < BURST_PER_POLL; i++) {
		ssize_t n = receive(port, 1, buf, sizeof(buf), now,
				    &st.req6_ratelimited);
		size_t len;
		enum verdict v;

		if (n < 0)
			return 0;
		len = (size_t)n;
		if (len > 20 && buf[20] != 17) {
			if (ra_guard(port, buf, len) < 0)
				return -1;
			continue;
		}
		/* Release/Decline: read before the frame is wrapped */
		ngm = guard_fd < 0 ? 0 :
		      guard_msgs6(buf, len, p->name, 1, gm, DHCP6_MAX_LEASES);
		v = dhcp6_handle_client(buf, &len, sizeof(buf), &p->o6, &info);
		switch (info.reason) {
		case R6_WRAPPED:	st.req6_wrapped++; break;
		case R6_UNTRUSTED_RELAY: st.req6_untrusted_relay++; break;
		case R6_SERVER_MSG:	st.req6_server_msg++; break;
		case R6_UNICAST:	st.req6_unicast_passed++; break;
		case R6_TYPE_SKIPPED:	st.req6_type_skipped++; break;
		case R6_TOO_BIG:
			st.req6_too_big++;
			LOGW("%s: Relay-Forward would exceed the MTU, dropped",
			     p->name);
			break;
		default:		st.req6_malformed++; break;
		}
		to[0] = '\0';
		if (v != VERDICT_DROP &&
		    xmit_role(p->bridge, ROLE_UPLINK, -1, buf, len,
			      &st.tx_uplink, to, sizeof(to)) < 0)
			return -1;
		for (k = 0; v != VERDICT_DROP && k < ngm; k++)
			guard_send(&gm[k]);
		log_packet6(p->name, ps[port].ifindex,
			    v == VERDICT_DROP ? "req6-drop" :
			    v == VERDICT_FORWARD_MODIFIED ? "req6-relay" :
			    "req6-pass", v == VERDICT_DROP ? "-" : to, &info,
			    p->o6.ifid, v == VERDICT_FORWARD_MODIFIED ?
			    p->o6.ifid_len : 0);
	}
	return 0;
}

/* client port of this bridge the Relay-Reply's Interface-ID names, or -1 */
static int reply6_owner(int bridge, const struct dhcp6_info *info)
{
	int i;

	for (i = 0; i < cfg.nport; i++)
		if (cfg.port[i].bridge == bridge &&
		    cfg.port[i].role == ROLE_CLIENT &&
		    dhcp6_ifid_matches(info, &cfg.port[i].o6))
			return i;
	return -1;
}

static int handle_uplink6(int port, time_t now)
{
	static uint8_t buf[FRAME_BUF_LEN];
	const struct port *p = &cfg.port[port];
	struct dhcp6_info info;
	struct guard_msg gm[DHCP6_MAX_LEASES];
	char to[128];
	int i, k, ngm;

	for (i = 0; i < BURST_PER_POLL; i++) {
		ssize_t n = receive(port, 1, buf, sizeof(buf), now,
				    &st.rep6_ratelimited);
		size_t len;
		enum verdict v;
		int owner;

		if (n < 0)
			return 0;
		len = (size_t)n;
		dhcp6_parse(buf, len, &info);
		owner = reply6_owner(p->bridge, &info);
		v = dhcp6_handle_uplink(buf, &len,
					owner >= 0 ? &cfg.port[owner].o6 : NULL,
					&info);
		switch (info.reason) {
		case R6_REPLY_OURS:	st.rep6_ours++; break;
		case R6_REPLY_FOREIGN:	st.rep6_foreign_dropped++; break;
		case R6_REPLY_INVALID:	st.rep6_invalid++; break;
		case R6_CLIENT_MSG:
			/* other customers' messages: unchanged to our
			 * customers only if snooping allows it */
			if (!cfg.block_uplink_requests) {
				v = VERDICT_FORWARD;
				st.rep6_client_msg_forwarded++;
			} else {
				st.rep6_client_msg_dropped++;
			}
			break;
		default:		st.rep6_malformed++; break;
		}
		to[0] = '\0';
		if (v != VERDICT_DROP &&
		    xmit_role(p->bridge, ROLE_CLIENT,
			      v == VERDICT_FORWARD_MODIFIED ? owner : -1, buf,
			      len, &st.tx_client, to, sizeof(to)) < 0)
			return -1;
		/* the unwrapped Reply: leases of the client behind owner */
		ngm = v == VERDICT_FORWARD_MODIFIED && guard_fd >= 0 ?
		      guard_msgs6(buf, len, cfg.port[owner].name, 0, gm,
				  DHCP6_MAX_LEASES) : 0;
		for (k = 0; k < ngm; k++)
			guard_send(&gm[k]);
		if (v != VERDICT_DROP || log_enabled(LOG_LVL_DEBUG))
			log_packet6(p->name, ps[port].ifindex,
				    v == VERDICT_DROP ? "rep6-drop" :
				    v == VERDICT_FORWARD_MODIFIED ? "rep6-unwrap" :
				    "rep6-pass", v == VERDICT_DROP ? "-" : to,
				    &info, info.ifid, info.ifid_len);
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
	struct sock_fprog p6 = BPF(bpf_dhcp6), pc6 = BPF(bpf_client6);
	struct pollfd pfd[2 * MAX_PORTS];
	int pport[2 * MAX_PORTS], pv6[2 * MAX_PORTS];
	int i, rc = 0, npfd = 0;
	time_t started = mono(), t_stats = 0, t_if = 0, t_win;
	uint32_t win_marked = 0, win_answered = 0;

	for (i = 0; i < cfg.nport; i++) {
		const struct port *p = &cfg.port[i];

		ps[i].fd = open_packet(p->name, ETH_P_IP_,
				       p->role == ROLE_CLIENT ? &preq : &prep,
				       &ps[i].ifindex);
		if (ps[i].fd < 0)
			return EXIT_RESTART;
		ps[i].fd6 = -1;
		if (cfg.dhcp6_snooping ||
		    (cfg.ra_guard && p->role == ROLE_CLIENT)) {
			ps[i].fd6 = open_packet(p->name, ETH_P_IPV6_,
						p->role == ROLE_CLIENT ? &pc6 : &p6,
						&ps[i].ifindex);
			if (ps[i].fd6 < 0)
				return EXIT_RESTART;
		}
		ps[i].tb.tokens = cfg.rate_burst;
		ps[i].tb.last = started;
		ps[i].tb_icmp6.tokens = ICMP6_BURST;
		ps[i].tb_icmp6.last = started;
		pfd[npfd] = (struct pollfd){ ps[i].fd, POLLIN, 0 };
		pport[npfd] = i;
		pv6[npfd++] = 0;
		if (ps[i].fd6 >= 0) {
			pfd[npfd] = (struct pollfd){ ps[i].fd6, POLLIN, 0 };
			pport[npfd] = i;
			pv6[npfd++] = 1;
		}
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
		int n = poll(pfd, (nfds_t)npfd, 1000);

		if (n < 0 && errno != EINTR) {
			LOGE("poll: %s", strerror(errno));
			rc = EXIT_RESTART;
			break;
		}
		now = mono();
		for (i = 0; n > 0 && i < npfd; i++) {
			int r = 0, pi = pport[i];
			int client = cfg.port[pi].role == ROLE_CLIENT;

			if (pfd[i].revents & (POLLERR | POLLNVAL)) {
				LOGW("socket error on %s", cfg.port[pi].name);
				r = -1;
			} else if (pfd[i].revents & POLLIN) {
				if (pv6[i])
					r = client ? handle_client6(pi, now) :
						     handle_uplink6(pi, now);
				else
					r = client ? handle_client(pi, now) :
						     handle_uplink(pi, now);
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
/* watcher: source guard */

static struct guard_tab gtab;
static int guard_active;	/* rules in place (grace is over) */
static int guard_dirty;		/* an incremental change failed: rebuild */
static time_t guard_from;	/* end of the grace period */
static time_t guard_retry;	/* after a failed install */
static const char *guard_why = "";

static void guard_add_cb(const struct binding *b, void *ctx)
{
	char s[96];

	LOGI("sg-bind %s", binding_str(b, s));
	if (guard_active && !guard_dirty && ebt_guard_add(&cfg, b) != 0)
		guard_dirty = 1;
}

static void guard_del_cb(const struct binding *b, void *ctx)
{
	char s[96];

	LOGI("sg-unbind %s (%s)", binding_str(b, s), guard_why);
	if (guard_active && !guard_dirty && ebt_guard_del(&cfg, b) != 0)
		guard_dirty = 1;
}

static const struct guard_ops guard_ops = { guard_add_cb, guard_del_cb, NULL };

static const char *boot_id(void)
{
	static char id[64];
	char path[192];
	int fd, n;

	snprintf(path, sizeof(path), "%s/proc/sys/kernel/random/boot_id",
		 cfg.root);
	id[0] = '\0';
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		n = (int)read(fd, id, sizeof(id) - 1);
		id[n > 0 ? n : 0] = '\0';
		id[strcspn(id, "\n")] = '\0';
		close(fd);
	}
	return id;
}

/* the lease file lives in RAM (/var/run): written on every change, renew
 * included, so a restarted agent continues where it stopped */
static void guard_save_file(void)
{
	static char buf[GUARD_MAX * 96 + 128];
	char tmp[160];
	size_t n = guard_save(&gtab, boot_id(), mono(), buf, sizeof(buf));
	int fd;

	snprintf(tmp, sizeof(tmp), "%s.tmp", cfg.sg_lease_file);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return;
	if (write(fd, buf, n) != (ssize_t)n || close(fd) < 0 ||
	    rename(tmp, cfg.sg_lease_file) < 0) {
		LOGW("writing %s: %s", cfg.sg_lease_file, strerror(errno));
		unlink(tmp);
	}
}

static int guard_load_file(struct guard_tab *t, const char *bid)
{
	static char buf[GUARD_MAX * 96 + 128];
	int fd = open(cfg.sg_lease_file, O_RDONLY), n;

	t->n = 0;
	if (fd < 0)
		return 0;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	buf[n > 0 ? n : 0] = '\0';
	return guard_load(t, buf, bid, mono());
}

static int is_client_port(const char *name, void *arg)
{
	int i;

	for (i = 0; i < cfg.nport; i++)
		if (cfg.port[i].role == ROLE_CLIENT &&
		    !strcmp(cfg.port[i].name, name))
			return 1;
	return 0;
}

static void guard_start(void)
{
	int n = guard_load_file(&gtab, boot_id());

	guard_why = "port no longer a client port";
	if (guard_retain(&gtab, is_client_port, NULL, NULL))
		guard_save_file();
	guard_from = mono() + (time_t)cfg.sg_grace;
	LOGI("source guard: %d bindings from %s, %s", n, cfg.sg_lease_file,
	     cfg.sg_grace ? "learning only during the grace period" :
	     "blocking now");
}

/* A guard that is only half installed could block a customer who has a
 * valid lease, so on failure the chain goes and the customer is unfiltered
 * until the next attempt (fail open, unlike the DHCP rules). */
static void guard_install(void)
{
	guard_active = 1;
	guard_dirty = 0;
	if (ebt_guard_install(&cfg, &gtab) == 0)
		return;
	ebt_guard_remove(&cfg);
	LOGE("source guard off until the next attempt in %us",
	     cfg.rule_check_interval);
	guard_dirty = 1;
	guard_retry = mono() + (time_t)cfg.rule_check_interval;
}

/* messages from the worker; called whenever the pipe is readable */
static void guard_read(time_t now)
{
	struct guard_msg m[16];
	ssize_t n;
	int i, save = 0;

	while ((n = read(guard_pipe[0], m, sizeof(m))) > 0) {
		for (i = 0; i < (int)(n / (ssize_t)sizeof(m[0])); i++) {
			int r;

			m[i].port[sizeof(m[i].port) - 1] = '\0';
			if (!cfg.sg_enable || !is_client_port(m[i].port, NULL) ||
			    (m[i].v6 && !(cfg.sg_ipv6 && cfg.dhcp6_snooping)))
				continue;
			guard_why = m[i].op == GUARD_LEARN ? "lifetime 0 or replaced" :
				    m[i].op == GUARD_FORGET ? "released" : "NAK";
			r = guard_apply(&gtab, &m[i], now, cfg.sg_max_bindings,
					&guard_ops);
			if (r == GUARD_FULL)
				LOGW("source guard: %s has %u bindings, not adding "
				     "another", m[i].port, cfg.sg_max_bindings);
			save |= r == GUARD_RENEWED || r == GUARD_CHANGED;
		}
	}
	if (save)
		guard_save_file();
}

/* once a second: grace period, expiry, failed changes */
static void guard_tick(time_t now)
{
	if (!cfg.sg_enable)
		return;
	if (!guard_active && now >= guard_from) {
		if (cfg.sg_grace)
			LOGI("source guard: grace period over, blocking");
		guard_install();
	}
	guard_why = "expired";
	if (guard_expire(&gtab, now, &guard_ops))
		guard_save_file();
	if (guard_active && guard_dirty && now >= guard_retry)
		guard_install();
}

/* ------------------------------------------------------------------ */
/* watcher */

static void run_rollback(void)
{
	pid_t pid;

	LOGE("ROLLBACK: removing rules and running: %s", cfg.rollback_cmd);
	ebt_remove(&cfg);
	/* the original dhcp-fwd keeps no bindings: no rules may stay */
	if (cfg.sg_enable || ebt_guard_exists(&cfg))
		ebt_guard_remove(&cfg);
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

/* defaults, then the config file (if there is one), then the command line */
static int load_config(struct config *c, char *err, size_t errlen)
{
	int i;

	config_defaults(c);
	if (access(own_cfg_path, R_OK) == 0 &&
	    config_load(c, own_cfg_path, err, errlen) < 0)
		return -1;
	for (i = 0; i < n_cli_opt; i++)
		if (config_set(c, cli_opt[i].name, cli_opt[i].val, err,
			       errlen) < 0)
			return -1;
	return 0;
}

static int reload_config(void)
{
	struct config n;
	char err[256];

	if (load_config(&n, err, sizeof(err)) < 0) {
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
		int rc;

		if (guard_pipe[0] >= 0)
			close(guard_pipe[0]);
		guard_fd = cfg.sg_enable ? guard_pipe[1] : -1;
		rc = worker(restarts);

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
	if (pipe(guard_pipe) == 0) {
		fcntl(guard_pipe[0], F_SETFL, O_NONBLOCK);
		fcntl(guard_pipe[1], F_SETFL, O_NONBLOCK);
		fcntl(guard_pipe[0], F_SETFD, FD_CLOEXEC);
		fcntl(guard_pipe[1], F_SETFD, FD_CLOEXEC);
	} else {
		LOGE("pipe: %s", strerror(errno));
	}
	if (cfg.sg_enable)
		guard_start();
	else if (ebt_guard_exists(&cfg))
		ebt_guard_remove(&cfg);	/* left over by a killed agent */

	while (!sig_stop) {
		struct pollfd gp = { guard_pipe[0], POLLIN, 0 };

		now = mono();
		if (child < 0 && now >= t_start) {
			child = start_worker(restarts);
			t_start = now;
		}
		/* interrupted early by SIGCHLD/SIGTERM/SIGHUP */
		if (poll(&gp, guard_pipe[0] >= 0, 1000) > 0)
			guard_read(mono());
		if (sig_stop)
			break;
		guard_tick(mono());
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
				guard_why = "port no longer a client port";
				if (!cfg.sg_enable && guard_active) {
					ebt_guard_remove(&cfg);
					guard_active = 0;
				} else if (cfg.sg_enable && !guard_active) {
					guard_start();
				} else if (cfg.sg_enable) {
					guard_retain(&gtab, is_client_port, NULL,
						     NULL);
					guard_save_file();
					guard_install();
				}
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
			if (guard_active && !guard_dirty &&
			    ebt_guard_check(&cfg, &gtab) != 1) {
				LOGW("source guard rules missing (airOS reload?), "
				     "re-installing");
				guard_install();
			}
		}
	}

	if (child > 0) {
		kill(child, SIGTERM);
		waitpid(child, NULL, 0);
	}
	if (!cfg.keep_rules_on_stop) {
		ebt_remove(&cfg);
		if (guard_active)
			ebt_guard_remove(&cfg);
	}
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
	struct diag_sock ds[3 * MAX_PORTS + MAX_BRIDGES];
	struct pollfd pfd[3 * MAX_PORTS + MAX_BRIDGES];
	static uint8_t buf[FRAME_BUF_LEN];
	time_t end = seconds ? mono() + seconds : 0;
	int i, N = 0;

	/* per port: everything (ALL) and only what broute diverts (IP) */
	for (i = 0; i < cfg.nport; i++) {
		ds[N++] = (struct diag_sock){ cfg.port[i].name, ETH_P_ALL_,
					      "ALL", -1, 0 };
		ds[N++] = (struct diag_sock){ cfg.port[i].name, ETH_P_IP_,
					      "IP", -1, 0 };
		ds[N++] = (struct diag_sock){ cfg.port[i].name, ETH_P_IPV6_,
					      "IP6", -1, 0 };
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
	printf("# passive diagnosis, nothing is sent; IP/IP6 sockets only see "
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
			clock_gettime(CLOCK_REALTIME, &ts);
			if (n >= 14 && (buf[12] << 8 | buf[13]) == ETH_P_IPV6_) {
				struct dhcp6_info i6;
				char a6[40], b6[40], p6[40];

				dhcp6_parse(buf, (size_t)n, &i6);
				printf("%ld.%03ld %s@%s(%d) pkt=%s len=%d %s>%s "
				       "%s>%s udp=%u>%u type=%s/%s xid=0x%06x "
				       "peer=%s ifid=\"%s\" parse=%s\n",
				       (long)ts.tv_sec, ts.tv_nsec / 1000000L,
				       ds[i].label, ds[i].ifname, sll.sll_ifindex,
				       pkttype_str(sll.sll_pkttype), (int)n,
				       mac_str(i6.src_mac, sm),
				       mac_str(i6.dst_mac, dm),
				       ip6_str(i6.ip_src, a6),
				       ip6_str(i6.ip_dst, b6), i6.sport, i6.dport,
				       dhcp6_type_str(i6.msgtype),
				       dhcp6_type_str(i6.inner_type),
				       i6.inner_type ? i6.inner_xid : i6.xid,
				       ip6_str(i6.peer_addr, p6),
				       id_str(i6.ifid, i6.ifid_len, c, sizeof(c)),
				       dhcp6_reason_str(i6.reason));
				fflush(stdout);
				continue;
			}
			dhcp_parse(buf, (size_t)n, &in);
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
	       "usage: dhcp-fwd [-n] [-d] [-c airos.conf] [-C own.conf] [options]\n"
	       "       dhcp-fwd [options] --check | --status | --diag [seconds]\n"
	       "       dhcp-fwd -v\n"
	       "  -n          stay in foreground (as started by airOS init)\n"
	       "  -d          foreground, log to stderr, level debug\n"
	       "  -c FILE     airOS dhcp-fwd.conf; ignored unless it uses our\n"
	       "              INI syntax\n"
	       "  -C FILE     own configuration (default %s)\n"
	       "  --check     print resolved configuration and exit\n"
	       "  --status    print counters and rule state\n"
	       "  --diag [s]  passive packet path diagnosis\n"
	       "options (override the configuration file):\n"
	       "  -u, --untrusted BRIDGE:PORT[,...]\n"
	       "              customer port: option 82 is added to requests,\n"
	       "              DHCP servers are blocked\n"
	       "  -t, --trusted BRIDGE:PORT[,...]\n"
	       "              uplink port towards the DHCP server\n"
	       "              Without -u/-t, bridges come from the airOS relay\n"
	       "              settings and ports are classified by name.\n"
	       "  -i, --circuit-id TEMPLATE   default %%h/%%b:%%p\n"
	       "  -r, --remote-id TEMPLATE    default %%m, \"none\" to omit\n"
	       "              %%h hostname, %%b bridge, %%p port, %%m bridge MAC,\n"
	       "              %%M port MAC, %%%% percent sign\n"
	       "  -o, --option SECTION.KEY=VALUE, or just SECTION.KEY=VALUE\n"
	       "              any key of the configuration file, e.g.\n"
	       "              dhcpv6.snooping=yes dhcpv6.RAguard=yes\n"
	       "              source_guard.enable=yes source_guard.grace=600\n",
	       VERSION, DEFAULT_CONFIG);
}

static void print_config(void)
{
	char c[256], r[256];
	int i;

	printf("version         %s\n", VERSION);
	printf("hostname        %s\n", cfg.hostname);
	printf("ports           %s\n", cfg.nxport ?
	       "explicit (untrusted/trusted)" : "auto (airOS relay, port names)");
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
		if (p->role == ROLE_CLIENT) {
			printf(" circuit_id=\"%s\" remote_id=\"%s\"",
			       id_str(p->o82.cid, p->o82.cid_len, c, sizeof(c)),
			       id_str(p->o82.rid, p->o82.rid_len, r, sizeof(r)));
			if (cfg.dhcp6_snooping)
				printf(" interface_id6=\"%s\" remote_id6=\"%s\"",
				       id_str(p->o6.ifid, p->o6.ifid_len, c,
					      sizeof(c)),
				       id_str(p->o6.rid, p->o6.rid_len, r,
					      sizeof(r)));
		}
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
	printf("dhcpv6          snooping=%s ra_guard=%s unicast=%s "
	       "enterprise=%u\n", cfg.dhcp6_snooping ? "yes" : "no",
	       cfg.ra_guard ? "yes" : "no",
	       cfg.dhcp6_relay_unicast ? "relay" : "forward",
	       cfg.dhcp6_enterprise);
	printf("source_guard    %s", cfg.sg_enable ? "yes" : "no");
	if (cfg.sg_enable)
		printf(" ipv6=%s block_ip_only=%s grace=%us max_bindings=%u "
		       "lease_file=%s", cfg.sg_ipv6 && cfg.dhcp6_snooping ? "yes" :
		       cfg.sg_ipv6 ? "no (needs dhcpv6.snooping)" : "no",
		       cfg.sg_block_ip_only ? "yes" : "no", cfg.sg_grace,
		       cfg.sg_max_bindings, cfg.sg_lease_file);
	printf("\n");
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
	if (cfg.sg_enable) {
		struct guard_tab t;
		char b[96];
		int g, i;

		guard_load_file(&t, boot_id());
		g = ebt_guard_check(&cfg, &t);
		printf("source_guard_rules %s (counters: ebtables -t filter -L %s "
		       "--Lc)\n", g == 1 ? "ok" : g == 0 ?
		       "missing or grace period" : "error", EBT_GUARD_CHAIN);
		for (i = 0; i < t.n; i++)
			if (t.b[i].expires)
				printf("binding %s expires in %lds\n",
				       binding_str(&t.b[i], b),
				       (long)(t.b[i].expires - mono()));
			else
				printf("binding %s never expires\n",
				       binding_str(&t.b[i], b));
	}
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

/* short and long options that are shortcuts for a config key */
static const char *cli_alias(const char *a)
{
	static const struct { const char *s, *l, *key; } map[] = {
		{ "-u", "--untrusted", "interface.untrusted" },
		{ "-t", "--trusted", "interface.trusted" },
		{ "-i", "--circuit-id", "option82.circuit_id" },
		{ "-r", "--remote-id", "option82.remote_id" },
	};
	size_t i;

	for (i = 0; i < sizeof(map) / sizeof(map[0]); i++)
		if (!strcmp(a, map[i].s) || !strcmp(a, map[i].l))
			return map[i].key;
	return NULL;
}

/* name NULL: arg is "section.key=value" */
static int add_cli_opt(const char *name, const char *arg)
{
	const char *val = arg;

	if (n_cli_opt == MAX_CLI_OPTS) {
		fprintf(stderr, "too many options\n");
		return -1;
	}
	if (!name) {
		const char *eq = strchr(arg, '=');
		size_t l = eq ? (size_t)(eq - arg) : 0;

		if (!l || l >= sizeof(cli_names[0])) {
			fprintf(stderr, "-o %s: expected SECTION.KEY=VALUE\n", arg);
			return -1;
		}
		memcpy(cli_names[n_cli_opt], arg, l);
		cli_names[n_cli_opt][l] = '\0';
		name = cli_names[n_cli_opt];
		val = eq + 1;
	}
	cli_opt[n_cli_opt].name = name;
	cli_opt[n_cli_opt].val = val;
	n_cli_opt++;
	return 0;
}

int main(int argc, char **argv)
{
	const char *airos_cfg = NULL, *opt;
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
		} else if ((opt = cli_alias(a)) && i + 1 < argc) {
			if (add_cli_opt(opt, argv[++i]) < 0)
				return 2;
		} else if ((!strcmp(a, "-o") || !strcmp(a, "--option")) &&
			   i + 1 < argc) {
			if (add_cli_opt(NULL, argv[++i]) < 0)
				return 2;
		} else if (a[0] != '-' && strchr(a, '=') &&
			   strchr(a, '.') < strchr(a, '=')) {
			/* bare SECTION.KEY=VALUE, e.g. dhcpv6.RAguard=yes */
			if (add_cli_opt(NULL, a) < 0)
				return 2;
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

	if (load_config(&cfg, err, sizeof(err)) < 0) {
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
	LOGI("dhcp-snooping-82 %s starting (config %s%s, ports %s)", VERSION,
	     access(own_cfg_path, R_OK) == 0 ? own_cfg_path : "defaults",
	     n_cli_opt ? " + command line" : "",
	     cfg.nxport ? "explicit" : "auto");
	rc = watcher();
	unlink(cfg.pidfile);
	return rc;
}
