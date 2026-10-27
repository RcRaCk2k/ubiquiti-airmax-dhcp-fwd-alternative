#!/bin/sh
# SPDX-License-Identifier: MIT
# Namespace integration test, no root needed (user + network namespaces).
#
#   client ns:  c0 ---veth--- eth0 \
#                                   [br1 + agent] ath0.1284 (VLAN on ath0) ---veth--- s0 / s0.1284 :server ns
#   client2 ns: c1 ---veth--- eth1 /
#
# Bridge and ports are detected automatically from system.cfg and sysfs.
#
# The airOS broute rules are emulated with nft "meta broute", which has the
# same effect on a modern kernel: the frame is not bridged but continues on
# the port's receive path, where the agent's ETH_P_IP/ETH_P_IPV6 sockets
# get it.
# Old-kernel (2.6.32) behaviour must still be verified on the device.
set -eu

if [ "${DS82_IN_NS:-}" != 1 ]; then
	exec unshare -rnm --kill-child env DS82_IN_NS=1 sh "$0" "$@"
fi

top=$(cd "$(dirname "$0")/.." && pwd)
BIN=$top/build/host/dhcp-fwd
SIM="python3 -I $top/tests/netsim.py"
W=$(mktemp -d)
BRMAC=00:00:5e:00:53:01
fail=0

cleanup() {
	[ -n "${AGENT:-}" ] && kill "$AGENT" 2>/dev/null
	kill "$CNS" "$CNS2" "$SNS" 2>/dev/null
	if [ "$fail" = 0 ]; then
		rm -rf "$W"
	else
		echo "--- agent.log (tail)"; tail -20 "$W/agent.log" 2>/dev/null
		echo "logs kept in $W"
	fi
}
trap cleanup EXIT

ok()   { echo "  ok   $*"; }
bad()  { echo "  FAIL $*"; fail=1; }
expect() { if [ "$1" = "$2" ]; then ok "$3 ($1)"; else bad "$3: got '$1' want '$2'"; fi; }

# --- topology -------------------------------------------------------
# own sysfs, so /sys/class/net shows this namespace (auto detection)
mount -t sysfs sysfs /sys
unshare -n sleep 3600 & CNS=$!
unshare -n sleep 3600 & CNS2=$!
unshare -n sleep 3600 & SNS=$!
sleep 0.3
inc()  { nsenter -t "$CNS" -n "$@"; }
inc2() { nsenter -t "$CNS2" -n "$@"; }
ins()  { nsenter -t "$SNS" -n "$@"; }

ip link set lo up
ip link add eth0 type veth peer name c0
ip link add eth1 type veth peer name c1
ip link add ath0 type veth peer name s0
ip link add link ath0 name ath0.1284 type vlan id 1284
ip link set c0 netns "$CNS"
ip link set c1 netns "$CNS2"
ip link set s0 netns "$SNS"
ip link add br1 type bridge
ip link set br1 address $BRMAC
for i in eth0 eth1 ath0.1284; do ip link set "$i" master br1; done
for i in eth0 eth1 ath0 ath0.1284 br1; do ip link set "$i" up; done
inc ip link set c0 address 02:11:22:33:44:55
inc ip link set c0 up
inc2 ip link set c1 address 02:11:22:33:44:66
inc2 ip link set c1 up
ins ip link set s0 address 02:aa:bb:cc:dd:ee
ins ip link set s0 up
ins ip link add link s0 name s0.1284 type vlan id 1284
ins ip link set s0.1284 up
sleep 1

broute_on() {
	nft -f - <<EOF
table bridge ds82 {
	chain brouting {
		type filter hook prerouting priority -300;
		iifname { "eth0", "eth1" } ip protocol udp udp dport 67 meta broute set 1
		iifname { "eth0", "eth1" } ip protocol udp udp sport 67 udp dport 68 meta broute set 1
		iifname "ath0.1284" ether daddr != $BRMAC ip protocol udp udp sport 67 udp dport 68 meta broute set 1
		iifname "ath0.1284" ip protocol udp udp dport 67 meta broute set 1
		iifname { "eth0", "eth1" } ip6 nexthdr udp udp dport 547 meta broute set 1
		iifname { "eth0", "eth1" } ip6 nexthdr udp udp sport 547 udp dport 546 meta broute set 1
		iifname { "eth0", "eth1" } ether daddr != $BRMAC ip6 saddr fe80::/10 meta l4proto icmpv6 meta broute set 1
		iifname "ath0.1284" ip6 nexthdr udp udp dport 547 meta broute set 1
	}
}
EOF
}
broute_off() { nft delete table bridge ds82 2>/dev/null || true; }

# fake ebtables: broute rules are managed by this script via nft, the
# filter table (source guard) is translated to nft by the fake itself
cp "$top/tests/fake_ebtables.py" "$W/ebtables"
chmod +x "$W/ebtables"
cat > "$W/system.cfg" <<'EOF'
resolv.host.1.name=cust-example
dhcprelay.status=enabled
dhcprelay.client.1.devname=br1
dhcprelay.client.1.status=enabled
EOF
cat > "$W/agent.conf" <<EOF
[forwarding]
ebtables = $W/ebtables
[logging]
level = debug
stats_file = $W/stats
stats_interval = 1
[system]
pidfile = $W/pid
system_cfg = $W/system.cfg
worker_uid = 0
EOF

start_agent() {
	"$BIN" -d -C "$W/agent.conf" "$@" > "$W/agent.log" 2>&1 &
	AGENT=$!
	sleep 1
}
# waits up to 10 s for a line in the agent log
wait_log() {
	i=0
	while ! grep -q -- "$1" "$W/agent.log" && [ $i -lt 100 ]; do
		sleep 0.1; i=$((i + 1))
	done
}
stop_agent() { kill "$AGENT"; wait "$AGENT" 2>/dev/null || true; AGENT=; }

count() { grep -c "$1" "$2" 2>/dev/null || true; }

# --- 1: full lease cycle through the agent --------------------------
echo "1) DISCOVER/REQUEST/RENEW/REBIND through agent"
# ports as a vendor UI would pass them; scenario 5 uses auto detection
broute_on
start_agent -u br1:eth0,br1:eth1 -t br1:ath0.1284
expect "$(count 'ports explicit' "$W/agent.log")" 1 "agent uses the ports from the command line"
ins $SIM server s0.1284 "$W/server1.log" 14 &
SRV=$!
sleep 0.5
inc $SIM client c0 full > "$W/client1.json"
wait $SRV
python3 -I - "$W/client1.json" "$W/server1.log" <<'EOF' || fail=1
import json, sys
cl = json.load(open(sys.argv[1]))
srv = [json.loads(l) for l in open(sys.argv[2])]
xid = cl["xid"]
mine = [p for p in srv if p["xid"] == xid]
ok = True
def check(cond, msg):
    global ok
    print(("  ok   " if cond else "  FAIL ") + msg)
    ok &= cond
check(len(mine) == 4, "server got exactly 4 requests (%d)" % len(mine))
for p in mine:
    check(p["o82"] == {"1": "cust-example/br1:eth0", "2": "00005e005301"},
          "type %d has our option 82: %s" % (p["type"], p["o82"]))
    check(p["giaddr"] == "0.0.0.0", "giaddr untouched")
    check(p["udp_csum_ok"], "udp checksum valid")
renew = [p for p in mine if p["ciaddr"] != "0.0.0.0" and p["dst"] != "ffffffffffff"]
check(len(renew) == 1 and renew[0]["dst"] == "02aabbccddee" and
      renew[0]["ip_dst"] == "10.0.0.1", "unicast renew keeps server MAC/IP")
for st in cl["steps"]:
    r = st["reply"]
    check(r is not None, "%s answered" % st["name"])
    if r:
        check(r["o82"] is None, "%s reply reaches client without option 82" % st["name"])
        check(r["udp_csum_ok"], "%s reply checksum valid" % st["name"])
sys.exit(0 if ok else 1)
EOF

# --- 2: uplink broadcast must not be marked again --------------------
echo "2) foreign DISCOVER from uplink: not re-marked, not passed to customer"
ins $SIM sniff s0.1284 "$W/server2.log" 3 &
SN1=$!
inc $SIM sniff c0 "$W/client2.log" 3 &
SN2=$!
sleep 0.5
ins $SIM send s0.1284 foreign-discover
wait $SN1 $SN2
expect "$(count f0f0f0f0 "$W/server2.log")" 0 "no copy sent back to the uplink"
expect "$(grep -c '"xid": 4042322160' "$W/server2.log" || true)" 0 "no duplicate on uplink"
expect "$(grep -c '"xid": 4042322160' "$W/client2.log" || true)" 0 "snooping: other customer's request blocked"

echo "2b) DHCP server on the customer side is blocked"
ins $SIM sniff s0.1284 "$W/server2b.log" 3 &
SN=$!
sleep 0.5
inc $SIM send c0 rogue-offer
wait $SN
expect "$(grep -c '"op": 2' "$W/server2b.log" || true)" 0 "rogue OFFER does not reach the uplink"

# --- 3: foreign reply is filtered -----------------------------------
echo "3) OFFER with foreign option 82 does not reach the client"
inc $SIM sniff c0 "$W/client3.log" 3 &
SN=$!
sleep 0.5
ins $SIM send s0.1284 foreign-offer
wait $SN
expect "$(grep -c '"xid": 2882400001' "$W/client3.log" || true)" 0 "foreign offer filtered"

# --- 3b: upstream replaced our option 82 in the reply ---------------
echo "3b) reply carries upstream option 82 instead of ours"
ins $SIM server s0.1284 "$W/server3b.log" 6 replace &
SRV=$!
sleep 0.5
inc $SIM client c0 discover > "$W/client3b.json"
wait $SRV
python3 -I - "$W/client3b.json" <<'PY' || fail=1
import json, sys
r = json.load(open(sys.argv[1]))["steps"][0]["reply"]
ok = r is not None and r["o82"] is None and r["udp_csum_ok"]
print(("  ok   " if ok else "  FAIL ") + "client gets the OFFER, upstream option 82 stripped")
sys.exit(0 if ok else 1)
PY
sleep 1.5
expect "$(sed -n 's/^rep_foreign_ours_by_xid //p' "$W/stats")" 1 "counted as rep_foreign_ours_by_xid"

# --- 3c: second customer port --------------------------------------
echo "3c) second client port eth1: own circuit id, reply only to eth1"
ins $SIM server s0.1284 "$W/server3c.log" 6 &
SRV=$!
inc $SIM sniff c0 "$W/client3c-other.log" 5 &
SN=$!
sleep 0.5
inc2 $SIM client c1 discover 02:11:22:33:44:66 > "$W/client3c.json"
wait $SRV $SN
python3 -I - "$W/client3c.json" "$W/server3c.log" "$W/client3c-other.log" <<'PY' || fail=1
import json, sys
cl = json.load(open(sys.argv[1]))
srv = [json.loads(l) for l in open(sys.argv[2])]
other = [json.loads(l) for l in open(sys.argv[3])]
mine = [p for p in srv if p["xid"] == cl["xid"]]
ok = True
def check(cond, msg):
    global ok
    print(("  ok   " if cond else "  FAIL ") + msg)
    ok &= cond
check(len(mine) == 1 and mine[0]["o82"] == {"1": "cust-example/br1:eth1", "2": "00005e005301"},
      "server got one DISCOVER with circuit id .../br1:eth1")
r = cl["steps"][0]["reply"]
check(r is not None and r["o82"] is None, "OFFER reaches eth1 without option 82")
check(not [p for p in other if p["xid"] == cl["xid"]], "OFFER not sent to eth0")
sys.exit(0 if ok else 1)
PY

# --- 6: DHCPv6 through the lightweight relay agent ------------------
echo "6) DHCPv6 SOLICIT/REQUEST/RENEW with prefix delegation via LDRA"
ins $SIM server6 s0.1284 "$W/server6.log" 12 &
SRV=$!
inc2 $SIM sniff6 c1 "$W/client6-other.log" 11 &
SN=$!
sleep 0.5
inc $SIM client6 c0 02:11:22:33:44:55 > "$W/client6.json"
wait $SRV $SN
python3 -I - "$W/client6.json" "$W/server6.log" "$W/client6-other.log" <<'PY' || fail=1
import json, sys
cl = json.load(open(sys.argv[1]))
srv = [json.loads(l) for l in open(sys.argv[2])]
other = [json.loads(l) for l in open(sys.argv[3])]
ok = True
def check(cond, msg):
    global ok
    print(("  ok   " if cond else "  FAIL ") + msg)
    ok &= cond
peer = "fe80000000000000001122fffe334455"
check(not [p for p in srv if p["type"] != 12], "server never sees an unrelayed client message")
for st in cl["steps"]:
    mine = [p for p in srv if p.get("xid") == st["xid"]]
    check(len(mine) == 1, "%s: exactly one Relay-Forward at the server" % st["name"])
    if mine:
        p = mine[0]
        check(p["ifid"] == "cust-example/br1:eth0", "%s: Interface-ID %s" % (st["name"], p["ifid"]))
        check(p["rid"] == [41112, "00005e005301"], "%s: Remote-ID %s" % (st["name"], p["rid"]))
        check(p["link"] == "0" * 32 and p["peer"] == peer, "%s: link-address ::, peer = client" % st["name"])
        check(p["csum_ok"] and p["sport"] == 547, "%s: checksum, port 547" % st["name"])
    r = st["reply"]
    check(r is not None, "%s answered" % st["name"])
    if r:
        check(r["sport"] == 547 and r["dport"] == 546 and r["csum_ok"],
              "%s: plain server message to port 546, checksum ok" % st["name"])
        check(r["prefix"] == "20010db8010000000000000000000000/56",
              "%s: delegated prefix %s" % (st["name"], r["prefix"]))
check(not [p for p in other if p.get("dport") == 546], "replies not sent to eth1")
sys.exit(0 if ok else 1)
PY

echo "6b) second client port eth1: own Interface-ID"
ins $SIM server6 s0.1284 "$W/server6b.log" 11 &
SRV=$!
sleep 0.5
inc2 $SIM client6 c1 02:11:22:33:44:66 > "$W/client6b.json"
wait $SRV
python3 -I - "$W/client6b.json" "$W/server6b.log" <<'PY' || fail=1
import json, sys
cl = json.load(open(sys.argv[1]))
srv = [json.loads(l) for l in open(sys.argv[2])]
ids = {p["ifid"] for p in srv if p["type"] == 12}
ok = ids == {"cust-example/br1:eth1"} and all(s["reply"] for s in cl["steps"])
print(("  ok   " if ok else "  FAIL ") + "Interface-ID %s, all answered" % sorted(ids))
sys.exit(0 if ok else 1)
PY

echo "7) RA guard and DHCPv6 snooping"
ins $SIM sniff6 s0.1284 "$W/server7.log" 4 &
SN1=$!
inc2 $SIM sniff6 c1 "$W/client7-other.log" 4 &
SN2=$!
sleep 0.5
inc $SIM send6 c0 ra
inc $SIM send6 c0 ra-hbh
inc $SIM send6 c0 ns
inc $SIM send6 c0 rogue-advertise
inc $SIM send6 c0 relay-forward
wait $SN1 $SN2
expect "$(count '"kind": "ra"' "$W/server7.log")" 0 "customer RA does not reach the uplink"
expect "$(count '"kind": "ra"' "$W/client7-other.log")" 0 "customer RA does not reach the other port"
expect "$(count '"kind": "ns"' "$W/server7.log")" 1 "neighbour solicitation passes to the uplink once"
expect "$(grep '"kind": "ns"' "$W/server7.log" | grep -c '"hop": 255' || true)" 1 "with hop limit 255 unchanged"
expect "$(count '"kind": "ns"' "$W/client7-other.log")" 1 "and, being multicast, to the other customer port"
expect "$(count '"type": 2' "$W/server7.log")" 0 "rogue ADVERTISE blocked"
expect "$(count 'spoofed' "$W/server7.log")" 0 "spoofed Relay-Forward from the customer blocked"
expect "$(count '"type": 12' "$W/server7.log")" 0 "and nothing relayed in its place"
inc $SIM sniff6 c0 "$W/client7.log" 3 &
SN=$!
sleep 0.5
ins $SIM send6 s0.1284 uplink-ra
ins $SIM send6 s0.1284 foreign-solicit
wait $SN
expect "$(count '"kind": "ra"' "$W/client7.log")" 1 "RA from the uplink reaches the customer"
expect "$(count '"xid": "f0f0f0"' "$W/client7.log")" 0 "other customers' SOLICIT blocked"
sleep 1.5
expect "$(sed -n 's/^ra_dropped //p' "$W/stats")" 2 "counted as ra_dropped (plain and behind hop-by-hop)"
expect "$(sed -n 's/^req6_untrusted_relay //p' "$W/stats")" 1 "counted as req6_untrusted_relay"
expect "$(sed -n 's/^req6_server_msg //p' "$W/stats")" 1 "counted as req6_server_msg"
expect "$(sed -n 's/^rep6_client_msg_dropped //p' "$W/stats")" 1 "counted as rep6_client_msg_dropped"

stop_agent
grep -E "^(port|req_inserted|rep_ours|rep_foreign_dropped|req6_wrapped|rep6_ours|tx_error) " "$W/stats" | sed 's/^/  stat /'

# --- 8: source guard -------------------------------------------------
# probe frames from c0, one "kind source [MAC]" per line on stdin; the
# tags of the frames that crossed the bridge land in the log
sg_probe() {
	ins $SIM sniffp s0.1284 "$1" 2 &
	SN=$!
	sleep 0.5
	while read -r k a m; do inc $SIM probe c0 "$k" "$a" $m < /dev/null; done
	wait $SN
}
crossed() { grep -c "^$1:$2:${4:-021122334455}\$" "$3" || true; }
sg_chain() {
	python3 -I -c 'import json,sys; print(int("DHCP_SNOOPING_82_SG" in json.load(open(sys.argv[1]))["chains"]))' "$W/ebt_state.json"
}
SG="-u br1:eth0,br1:eth1 -t br1:ath0.1284 source_guard.enable=yes source_guard.lease_file=$W/leases"

echo "8) source guard: only addresses the DHCP server handed out"
start_agent $SG
wait_log "source guard rules installed"
expect "$(count 'source guard rules installed (chain DHCP_SNOOPING_82_SG, 0 bindings, 18 rules)' "$W/agent.log")" 1 "rules for both client ports at start"
sg_probe "$W/p8a.log" <<EOP
udp4 10.0.0.100
arp 10.0.0.100
arp 0.0.0.0
udp6 2001:db8:100::1
udp6 fe80::1
pppoe -
EOP
expect "$(crossed udp4 10.0.0.100 "$W/p8a.log")" 0 "before DHCP: IPv4 blocked"
expect "$(crossed arp 10.0.0.100 "$W/p8a.log")" 0 "before DHCP: ARP blocked"
expect "$(crossed arp 0.0.0.0 "$W/p8a.log")" 1 "ARP probe from 0.0.0.0 passes"
expect "$(crossed udp6 2001:db8:100::1 "$W/p8a.log")" 0 "before DHCPv6: global IPv6 blocked"
expect "$(crossed udp6 fe80::1 "$W/p8a.log")" 1 "link-local IPv6 passes"
expect "$(crossed pppoe - "$W/p8a.log")" 1 "PPPoE passes (block_ip_only=yes)"

: > "$W/ebt.log"
ins $SIM server s0.1284 "$W/server8.log" 5 &
SRV=$!
sleep 0.5
inc $SIM client c0 full > "$W/client8.json"
wait $SRV
wait_log "sg-bind eth0 02:11:22:33:44:55 10.0.0.100"
sleep 0.5
expect "$(grep -c -- '-I DHCP_SNOOPING_82_SG 1' "$W/ebt.log")" 2 "ACK adds an IPv4 and an ARP rule, RENEW/REBIND add nothing"
expect "$(grep -c -- '-D DHCP_SNOOPING_82_SG' "$W/ebt.log")" 0 "and remove nothing"
expect "$(grep -c '^v4 eth0 02:11:22:33:44:55 10.0.0.100 ' "$W/leases")" 1 "binding in the lease file"
sg_probe "$W/p8b.log" <<EOP
udp4 10.0.0.100
udp4 10.0.0.101
udp4 10.0.0.100 02:de:ad:be:ef:01
arp 10.0.0.100
arp 10.0.0.101
vlan4 10.0.0.100
EOP
expect "$(crossed udp4 10.0.0.100 "$W/p8b.log")" 1 "leased address passes"
expect "$(crossed udp4 10.0.0.101 "$W/p8b.log")" 0 "other address blocked"
expect "$(crossed udp4 10.0.0.100 "$W/p8b.log" 02deadbeef01)" 0 "leased address from another MAC blocked"
expect "$(crossed arp 10.0.0.100 "$W/p8b.log")" 1 "ARP for the leased address passes"
expect "$(crossed arp 10.0.0.101 "$W/p8b.log")" 0 "spoofed ARP blocked"
expect "$(crossed vlan4 10.0.0.100 "$W/p8b.log")" 0 "VLAN tagged IPv4 blocked"

ins $SIM server6 s0.1284 "$W/server8v6.log" 5 &
SRV=$!
sleep 0.5
inc $SIM client6 c0 02:11:22:33:44:55 > /dev/null
wait $SRV
wait_log "sg-bind eth0 02:11:22:33:44:55 2001:db8:100::/56"
expect "$(grep -c '^v6 eth0 02:11:22:33:44:55 2001:db8:100::/56 ' "$W/leases")" 1 "delegated prefix in the lease file"
sg_probe "$W/p8c.log" <<EOP
udp6 2001:db8:100::1
udp6 2001:db8:100:ff::1
udp6 2001:db8:200::1
udp6 2001:db8:100::1 02:de:ad:be:ef:01
EOP
expect "$(crossed udp6 2001:db8:100::1 "$W/p8c.log")" 1 "address from the delegated prefix passes"
expect "$(crossed udp6 2001:db8:100:ff::1 "$W/p8c.log")" 1 "anywhere in the /56"
expect "$(crossed udp6 2001:db8:200::1 "$W/p8c.log")" 0 "outside the prefix blocked"
expect "$(crossed udp6 2001:db8:100::1 "$W/p8c.log" 02deadbeef01)" 0 "prefix from another MAC blocked"

# SLAAC: the uplink router's prefix gives the client its EUI-64 address
SLAAC=2001:db8:0:1270:11:22ff:fe33:4455
ins $SIM send6 s0.1284 uplink-ra-slaac
wait_log "sg-bind eth0 02:11:22:33:44:55 $SLAAC slaac"
sleep 0.5
expect "$(count 'SLAAC prefix 2001:db8:0:1270::/64 on ath0.1284 learned' "$W/agent.log")" 1 "SLAAC prefix learned from the uplink RA"
expect "$(grep -c '^ra ath0.1284 2001:db8:0:1270::/64 ' "$W/leases")" 1 "prefix in the lease file"
ins $SIM send6 s0.1284 uplink-ra-slaac
sleep 0.5
expect "$(count 'sg-bind eth0 02:11:22:33:44:55 2001:db8:0:1270' "$W/agent.log")" 1 "repeated RA adds no rule"
sg_probe "$W/p8s.log" <<EOP
udp6 $SLAAC
udp6 2001:db8:0:1270::99
udp6 $SLAAC 02:de:ad:be:ef:01
EOP
expect "$(crossed udp6 $SLAAC "$W/p8s.log")" 1 "EUI-64 SLAAC address passes"
expect "$(crossed udp6 2001:db8:0:1270::99 "$W/p8s.log")" 0 "other address in the SLAAC prefix blocked"
expect "$(crossed udp6 $SLAAC "$W/p8s.log" 02deadbeef01)" 0 "SLAAC address from another MAC blocked"

: > "$W/ebt.log"
inc $SIM send c0 release
wait_log "sg-unbind eth0 02:11:22:33:44:55 10.0.0.100 (released)"
sleep 0.5
expect "$(grep -c -- '-D DHCP_SNOOPING_82_SG' "$W/ebt.log")" 2 "RELEASE removes both rules"
expect "$(grep -c '^v4 ' "$W/leases")" 0 "and the binding"
sg_probe "$W/p8d.log" <<EOP
udp4 10.0.0.100
EOP
expect "$(crossed udp4 10.0.0.100 "$W/p8d.log")" 0 "released address blocked"
sleep 1.5
expect "$(sed -n 's/^guard_msgs_lost //p' "$W/stats")" 0 "no binding message lost"
stop_agent
expect "$(sg_chain)" 0 "agent stopped: source guard chain removed"

echo "8b) restart: bindings come back from the lease file"
start_agent $SG
wait_log "source guard rules installed"
expect "$(count 'source guard: 1 bindings from' "$W/agent.log")" 1 "one binding restored"
sg_probe "$W/p8e.log" <<EOP
udp6 2001:db8:100::1
udp6 $SLAAC
udp4 10.0.0.100
EOP
expect "$(crossed udp6 2001:db8:100::1 "$W/p8e.log")" 1 "restored prefix passes"
expect "$(crossed udp6 $SLAAC "$W/p8e.log")" 1 "SLAAC address restored with the prefix"
expect "$(crossed udp4 10.0.0.100 "$W/p8e.log")" 0 "released address still blocked"
stop_agent

echo "8c) block_ip_only=no: PPPoE and other frames blocked too"
start_agent $SG source_guard.block_ip_only=no
wait_log "source guard rules installed"
sg_probe "$W/p8f.log" <<EOP
pppoe -
udp6 2001:db8:100::1
EOP
expect "$(crossed pppoe - "$W/p8f.log")" 0 "PPPoE blocked"
expect "$(crossed udp6 2001:db8:100::1 "$W/p8f.log")" 1 "bound prefix still passes"
stop_agent

echo "8d) grace period: learning only, then blocking"
rm -f "$W/leases"
start_agent $SG source_guard.grace=4
sg_probe "$W/p8g.log" <<EOP
udp4 10.0.0.100
vlan4 10.0.0.100
EOP
expect "$(crossed udp4 10.0.0.100 "$W/p8g.log")" 1 "during the grace period IPv4 passes"
expect "$(crossed vlan4 10.0.0.100 "$W/p8g.log")" 1 "and VLAN tagged frames too"
wait_log "grace period over"
wait_log "source guard rules installed"
sg_probe "$W/p8h.log" <<EOP
udp4 10.0.0.100
EOP
expect "$(crossed udp4 10.0.0.100 "$W/p8h.log")" 0 "after the grace period blocked"
stop_agent
expect "$(sg_chain)" 0 "chain removed again"

echo "8e) ebtables rejects a rule: guard removed, customer unfiltered"
export DS82_EBT_REJECT=--vlan-encap
start_agent $SG
wait_log "source guard off until the next attempt"
sg_probe "$W/p8i.log" <<EOP
udp4 10.0.0.100
EOP
expect "$(sg_chain)" 0 "no half installed chain"
expect "$(crossed udp4 10.0.0.100 "$W/p8i.log")" 1 "traffic passes (fail open)"
stop_agent
unset DS82_EBT_REJECT

echo "8f) no ebt_arp (airOS 6): IPv4 bound, ARP not filtered"
rm -f "$W/leases"
export DS82_EBT_REJECT=--arp-ip-src
start_agent $SG
wait_log "source guard rules installed"
expect "$(count 'ARP is not filtered' "$W/agent.log")" 1 "missing ARP match reported"
expect "$(count '0 bindings, 14 rules' "$W/agent.log")" 1 "port rules without ARP"
ins $SIM server s0.1284 "$W/server8f.log" 5 &
SRV=$!
sleep 0.5
inc $SIM client c0 full > /dev/null
wait $SRV
wait_log "sg-bind eth0 02:11:22:33:44:55 10.0.0.100"
sleep 0.5
sg_probe "$W/p8j.log" <<EOP
udp4 10.0.0.100
udp4 10.0.0.101
arp 10.0.0.101
EOP
expect "$(crossed udp4 10.0.0.100 "$W/p8j.log")" 1 "leased address passes"
expect "$(crossed udp4 10.0.0.101 "$W/p8j.log")" 0 "other address blocked"
expect "$(crossed arp 10.0.0.101 "$W/p8j.log")" 1 "ARP passes unchecked"
stop_agent
start_agent $SG source_guard.block_ip_only=no
wait_log "source guard rules installed"
sg_probe "$W/p8k.log" <<EOP
arp 10.0.0.100
pppoe -
EOP
expect "$(crossed arp 10.0.0.100 "$W/p8k.log")" 1 "block_ip_only=no: ARP still passes"
expect "$(crossed pppoe - "$W/p8k.log")" 0 "and PPPoE is blocked"
stop_agent
unset DS82_EBT_REJECT

# --- 9: frame types --------------------------------------------------
ft_chain() {
	python3 -I -c 'import json,sys; print(int("DHCP_SNOOPING_82_FT" in json.load(open(sys.argv[1]))["chains"]))' "$W/ebt_state.json"
}
PORTS="-u br1:eth0,br1:eth1 -t br1:ath0.1284"
echo "9) frame_types: VLAN tagged or untagged frames not bridged"
start_agent $PORTS
wait_log "broute rules installed"
expect "$(ft_chain)" 0 "any (default): no frame type chain"
stop_agent
start_agent $PORTS interface.frame_types=untagged-only
wait_log "broute rules installed"
expect "$(count 'frame types untagged-only on ' "$W/agent.log")" 3 "untagged-only: one rule per port"
sg_probe "$W/p9a.log" <<EOP
udp4 10.0.0.100
vlan4 10.0.0.100
EOP
expect "$(crossed udp4 10.0.0.100 "$W/p9a.log")" 1 "untagged frame passes"
expect "$(crossed vlan4 10.0.0.100 "$W/p9a.log")" 0 "VLAN tagged frame dropped"
stop_agent
expect "$(ft_chain)" 0 "agent stopped: chain removed"
export DS82_BROUTE_RULES=0
start_agent $PORTS interface.frame_types=vlan-only
wait_log "broute rules installed"
expect "$(count 'broute rules installed (chain DHCP_SNOOPING_82, 0 rules)' "$W/agent.log")" 1 "vlan-only: no DHCP diverted"
sg_probe "$W/p9b.log" <<EOP
udp4 10.0.0.100
vlan4 10.0.0.100
EOP
expect "$(crossed udp4 10.0.0.100 "$W/p9b.log")" 0 "untagged frame dropped"
expect "$(crossed vlan4 10.0.0.100 "$W/p9b.log")" 1 "VLAN tagged frame passes"
stop_agent
unset DS82_BROUTE_RULES

# --- 4: rules present but agent dead: fail closed -------------------
echo "4) agent stopped, rules kept: DHCP blocked (fail closed)"
ins $SIM sniff s0.1284 "$W/server4.log" 3 &
SN=$!
sleep 0.5
inc $SIM client c0 discover > /dev/null
wait $SN
expect "$(grep -c '"op": 1' "$W/server4.log" || true)" 0 "nothing leaks without option 82"
ins $SIM sniff6 s0.1284 "$W/server4v6.log" 3 &
SN=$!
sleep 0.5
inc $SIM client6 c0 02:11:22:33:44:55 > /dev/null &
CL=$!
inc $SIM send6 c0 ra
wait $SN
kill $CL 2>/dev/null; wait $CL 2>/dev/null || true
expect "$(count '"kind": "dhcp6"' "$W/server4v6.log")" 0 "no DHCPv6 leaks unrelayed"
expect "$(count '"kind": "ra"' "$W/server4v6.log")" 0 "RA guard holds without the agent"

# --- 5: agent running, rules missing: no duplicates -----------------
echo "5) agent running, no broute rules: bridge forwards exactly once"
broute_off
start_agent
expect "$(count 'ports auto' "$W/agent.log")" 1 "agent detects the ports itself"
ins $SIM sniff s0.1284 "$W/server5.log" 3 &
SN=$!
sleep 0.5
inc $SIM client c0 discover > /dev/null
wait $SN
ins $SIM sniff6 s0.1284 "$W/server5v6.log" 3 &
SN=$!
sleep 0.5
inc $SIM send6 c0 foreign-solicit
wait $SN
stop_agent
expect "$(count '"kind": "dhcp6"' "$W/server5v6.log")" 1 "exactly one SOLICIT on uplink, unrelayed"
expect "$(grep -c '"op": 1' "$W/server5.log" || true)" 1 "exactly one DISCOVER on uplink"
expect "$(grep '"op": 1' "$W/server5.log" | grep -c '"o82": null' || true)" 1 "and it is the unmodified original"

echo "5b) airOS 6: bridge comment instead of the relay switch, Apply without restart"
syscfg() {	# new system.cfg as airOS writes it, comment of br1 as $1
	cat > "$W/system.cfg.new" <<EOF
resolv.host.1.name=cust-example
dhcprelay.status=disabled
bridge.1.devname=br1
bridge.1.comment=$1
EOF
	mv "$W/system.cfg.new" "$W/system.cfg"
}
cp "$W/system.cfg" "$W/system.cfg.orig"
syscfg "Kunde X; dhcp-option-82=yes frame-types=untagged-only"
start_agent
wait_log "broute rules installed"
expect "$(count 'frame types untagged-only on ' "$W/agent.log")" 3 "enabled by comment, frame-types from it"
expect "$(ft_chain)" 1 "frame type chain installed"
syscfg "Kunde X"
wait_log "no bridge enabled: rules removed"
expect "$(count 'no bridge enabled: rules removed' "$W/agent.log")" 1 "comment removed: agent notices the changed file"
expect "$(ft_chain)" 0 "and removes its rules"
expect "$(kill -0 "$AGENT" 2>/dev/null && echo 1 || echo 0)" 1 "but keeps running, init would respawn it"
syscfg "dhcp-option-82=yes Kunde X"
wait_log "bridge enabled again, resuming"
i=0
while [ "$(count 'worker: client eth0' "$W/agent.log")" -lt 2 ] && [ $i -lt 50 ]; do
	sleep 0.1; i=$((i + 1))
done
expect "$(count 'bridge enabled again, resuming' "$W/agent.log")" 1 "comment back: resumed"
expect "$(count 'worker: client eth0' "$W/agent.log")" 2 "with a new worker"
stop_agent
mv "$W/system.cfg.orig" "$W/system.cfg"

[ "$fail" = 0 ] && echo "integration: PASS" || echo "integration: FAIL"
exit $fail
