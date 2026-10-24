#!/bin/sh
# SPDX-License-Identifier: MIT
# Namespace integration test, no root needed (user + network namespaces).
#
#   client ns: c0 ---veth--- eth0 [br1 + agent] ath0.1284 ---veth--- s0 :server ns
#
# The airOS broute rules are emulated with nft "meta broute", which has the
# same effect on a modern kernel: the frame is not bridged but continues on
# the port's receive path, where the agent's ETH_P_IP sockets get it.
# Old-kernel (2.6.32) behaviour must still be verified on the device.
set -eu

if [ "${DS82_IN_NS:-}" != 1 ]; then
	exec unshare -rn --kill-child env DS82_IN_NS=1 sh "$0" "$@"
fi

top=$(cd "$(dirname "$0")/.." && pwd)
BIN=$top/build/host/dhcp-fwd
SIM="python3 -I $top/tests/netsim.py"
W=$(mktemp -d)
BRMAC=00:00:5e:00:53:01
fail=0

cleanup() {
	[ -n "${AGENT:-}" ] && kill "$AGENT" 2>/dev/null
	kill "$CNS" "$SNS" 2>/dev/null
	wait 2>/dev/null
	if [ "$fail" = 0 ]; then rm -rf "$W"; else echo "logs kept in $W"; fi
}
trap cleanup EXIT

ok()   { echo "  ok   $*"; }
bad()  { echo "  FAIL $*"; fail=1; }
expect() { if [ "$1" = "$2" ]; then ok "$3 ($1)"; else bad "$3: got '$1' want '$2'"; fi; }

# --- topology -------------------------------------------------------
unshare -n sleep 3600 & CNS=$!
unshare -n sleep 3600 & SNS=$!
sleep 0.3
inc() { nsenter -t "$CNS" -n "$@"; }
ins() { nsenter -t "$SNS" -n "$@"; }

ip link set lo up
ip link add eth0 type veth peer name c0
ip link add ath0.1284 type veth peer name s0
ip link set c0 netns "$CNS"
ip link set s0 netns "$SNS"
ip link add br1 type bridge
ip link set br1 address $BRMAC
ip link set eth0 master br1
ip link set ath0.1284 master br1
for i in eth0 ath0.1284 br1; do ip link set "$i" up; done
inc ip link set c0 address 02:11:22:33:44:55
inc ip link set c0 up
ins ip link set s0 address 02:aa:bb:cc:dd:ee
ins ip link set s0 up
sleep 1

broute_on() {
	nft -f - <<EOF
table bridge ds82 {
	chain brouting {
		type filter hook prerouting priority -300;
		iifname "eth0" ip protocol udp udp dport 67 meta broute set 1
		iifname "ath0.1284" ether daddr != $BRMAC ip protocol udp udp sport 67 udp dport 68 meta broute set 1
		iifname "eth0" ip protocol udp udp sport 67 udp dport 68 meta broute set 1
		iifname "ath0.1284" ip protocol udp udp dport 67 meta broute set 1
	}
}
EOF
}
broute_off() { nft delete table bridge ds82 2>/dev/null || true; }

# fake ebtables: rules are managed by this script via nft
cat > "$W/ebtables" <<'EOF'
#!/bin/sh
case "$*" in
*"-L BROUTING"*) echo "Bridge chain: BROUTING, entries: 1, policy: ACCEPT"; echo "-j DHCP_SNOOPING_82 " ;;
*"-L DHCP_SNOOPING_82"*) echo "Bridge chain: DHCP_SNOOPING_82, entries: 4, policy: RETURN"; for i in 1 2 3 4; do echo "-j DROP "; done ;;
esac
exit 0
EOF
chmod +x "$W/ebtables"
echo "resolv.host.1.name=cust-example" > "$W/system.cfg"
cat > "$W/agent.conf" <<EOF
[interface]
client = eth0
uplink = ath0.1284
bridge = br1
[option82]
circuit_id = hostname
remote_id = bridge-mac
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
	"$BIN" -d -C "$W/agent.conf" > "$W/agent.log" 2>&1 &
	AGENT=$!
	sleep 1
}
stop_agent() { kill "$AGENT"; wait "$AGENT" 2>/dev/null || true; AGENT=; }

count() { grep -c "$1" "$2" 2>/dev/null || true; }

# --- 1: full lease cycle through the agent --------------------------
echo "1) DISCOVER/REQUEST/RENEW/REBIND through agent"
broute_on
start_agent
ins $SIM server s0 "$W/server1.log" 14 &
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
    check(p["o82"] == {1: "cust-example", 2: "00005e005301"} or
          p["o82"] == {"1": "cust-example", "2": "00005e005301"},
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
ins $SIM sniff s0 "$W/server2.log" 3 &
SN1=$!
inc $SIM sniff c0 "$W/client2.log" 3 &
SN2=$!
sleep 0.5
ins $SIM send s0 foreign-discover
wait $SN1 $SN2
expect "$(count f0f0f0f0 "$W/server2.log")" 0 "no copy sent back to the uplink"
expect "$(grep -c '"xid": 4042322160' "$W/server2.log" || true)" 0 "no duplicate on uplink"
expect "$(grep -c '"xid": 4042322160' "$W/client2.log" || true)" 0 "snooping: other customer's request blocked"

echo "2b) DHCP server on the customer side is blocked"
ins $SIM sniff s0 "$W/server2b.log" 3 &
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
ins $SIM send s0 foreign-offer
wait $SN
expect "$(grep -c '"xid": 2882400001' "$W/client3.log" || true)" 0 "foreign offer filtered"

# --- 3b: upstream replaced our option 82 in the reply ---------------
echo "3b) reply carries upstream option 82 instead of ours"
ins $SIM server s0 "$W/server3b.log" 6 replace &
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

stop_agent
grep -E "^(req_inserted|rep_ours|rep_foreign_dropped|tx_error) " "$W/stats" | sed 's/^/  stat /'

# --- 4: rules present but agent dead: fail closed -------------------
echo "4) agent stopped, rules kept: DHCP blocked (fail closed)"
ins $SIM sniff s0 "$W/server4.log" 3 &
SN=$!
sleep 0.5
inc $SIM client c0 discover > /dev/null
wait $SN
expect "$(grep -c '"op": 1' "$W/server4.log" || true)" 0 "nothing leaks without option 82"

# --- 5: agent running, rules missing: no duplicates -----------------
echo "5) agent running, no broute rules: bridge forwards exactly once"
broute_off
start_agent
ins $SIM sniff s0 "$W/server5.log" 3 &
SN=$!
sleep 0.5
inc $SIM client c0 discover > /dev/null
wait $SN
stop_agent
expect "$(grep -c '"op": 1' "$W/server5.log" || true)" 1 "exactly one DISCOVER on uplink"
expect "$(grep '"op": 1' "$W/server5.log" | grep -c '"o82": null' || true)" 1 "and it is the unmodified original"

[ "$fail" = 0 ] && echo "integration: PASS" || echo "integration: FAIL"
exit $fail
