#!/bin/sh
# SPDX-License-Identifier: MIT
# Bridge/port auto detection against a fake /sys + /proc tree.
set -eu

top=$(cd "$(dirname "$0")/.." && pwd)
BIN=$top/build/host/dhcp-fwd
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fail=0

# iface ifindex iflink mac
mkif() {
	d=$W/root/sys/class/net/$1
	mkdir -p "$d"
	echo "$2" > "$d/ifindex"
	echo "$3" > "$d/iflink"
	echo "$4" > "$d/address"
}
member() { mkdir -p "$W/root/sys/class/net/$1/brif/$2"; }

mkif eth0       2  2  00:00:5e:00:53:02
mkif eth1       3  3  00:00:5e:00:53:03
mkif ath0       8  8  00:00:5e:00:53:08
mkif ath0.1284  10 8  00:00:5e:00:53:08
mkif ath0.200   11 8  00:00:5e:00:53:08
mkif eth0.100   12 2  00:00:5e:00:53:02
mkif gre0       13 0  00:00:00:00:00:00
mkif br0        20 20 00:00:5e:00:53:20
mkif br1        21 21 00:00:5e:00:53:21
mkif br2        22 22 00:00:5e:00:53:22
mkif br3        23 23 00:00:5e:00:53:23
mkif br4        24 24 00:00:5e:00:53:24
member br0 ath0
member br1 eth0;     member br1 ath0.1284
member br2 eth0.100; member br2 eth1; member br2 ath0.200; member br2 gre0
member br3 eth1                         # relay disabled below
member br4 eth1                         # relay on, but no uplink

mkdir -p "$W/root/proc/net/vlan"
cat > "$W/root/proc/net/vlan/config" <<'EOF'
VLAN Dev name	 | VLAN ID
Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD
ath0.1284      | 1284  | ath0
ath0.200       | 200  | ath0
eth0.100       | 100  | eth0
EOF

cat > "$W/system.cfg" <<'EOF'
resolv.host.1.name=cust-example
dhcprelay.status=enabled
dhcprelay.client.1.devname=br1
dhcprelay.client.1.status=enabled
dhcprelay.client.2.devname=br2
dhcprelay.client.2.status=enabled
dhcprelay.client.3.devname=br3
dhcprelay.client.3.status=disabled
dhcprelay.client.4.devname=br4
dhcprelay.client.4.status=enabled
EOF

conf() {
	cat > "$W/agent.conf" <<EOF
[system]
root = $W/root
system_cfg = $W/system.cfg
$1
EOF
}

check() {	# name, expected lines (grep -F each)
	name=$1
	shift
	# shellcheck disable=SC2086
	out=$("$BIN" -C "$W/agent.conf" ${ARGS:-} --check 2>&1) || true
	for want in "$@"; do
		if printf '%s\n' "$out" | grep -qF -- "$want"; then :; else
			echo "  FAIL $name: missing: $want"
			fail=1
		fi
	done
	[ "$fail" = 0 ] && echo "  ok   $name"
	printf '%s\n' "$out" > "$W/last.out"
}

refute() {	# name, line that must not appear
	if grep -qF -- "$2" "$W/last.out"; then
		echo "  FAIL $1: unexpected: $2"
		fail=1
	else
		echo "  ok   $1"
	fi
}

echo "detect: relay bridges from system.cfg, ports by lower device"
conf ""
check "br1 eth0 + ath0.1284 (VLAN on ath0)" \
	'port            br1/eth0 client (lower eth0) circuit_id="cust-example/br1:eth0" remote_id="00005e005321"' \
	'port            br1/ath0.1284 uplink (lower ath0)'
check "br2 with VLAN client, second eth port, VLAN uplink" \
	'port            br2/eth0.100 client (lower eth0) circuit_id="cust-example/br2:eth0.100"' \
	'port            br2/eth1 client (lower eth1) circuit_id="cust-example/br2:eth1" remote_id="00005e005322"' \
	'port            br2/ath0.200 uplink (lower ath0)'
refute "gre0 ignored" 'gre0'
refute "br3 (relay disabled) not used" 'bridge          br3'
refute "br4 (no uplink) not used" 'bridge          br4'
refute "br0 (no relay) not used" 'bridge          br0'

echo "detect: without /proc/net/vlan/config (iflink fallback)"
mv "$W/root/proc/net/vlan/config" "$W/vlan.config"
check "lower devices via iflink" \
	'port            br1/ath0.1284 uplink (lower ath0)' \
	'port            br2/eth0.100 client (lower eth0)'
mv "$W/vlan.config" "$W/root/proc/net/vlan/config"

echo "detect: explicit settings"
conf "[interface]
bridges = br1
[option82]
circuit_id = %h-%p
remote_id = %M"
check "bridges list + templates" \
	'port            br1/eth0 client (lower eth0) circuit_id="cust-example-eth0" remote_id="00005e005302"'
refute "only br1" 'bridge          br2'

echo "detect: relay disabled globally"
sed -i 's/^dhcprelay.status=enabled/dhcprelay.status=disabled/' "$W/system.cfg"
conf ""
check "refuses to run" 'DHCP relay not enabled'

echo "explicit: ports from the command line (relay still disabled)"
ARGS="-u br1:eth0 -t br1:ath0.1284"
check "-u/-t without system.cfg relay settings" \
	'ports           explicit' \
	'port            br1/eth0 client (lower eth0) circuit_id="cust-example/br1:eth0" remote_id="00005e005321"' \
	'port            br1/ath0.1284 uplink (lower ath0)'
refute "only the given bridge" 'bridge          br2'
ARGS="--untrusted br2:eth1,br2:eth0.100 --trusted br2:ath0.200 --circuit-id %p@%h --remote-id none"
check "lists, long options, templates" \
	'port            br2/eth1 client (lower eth1) circuit_id="eth1@cust-example" remote_id=""' \
	'port            br2/eth0.100 client (lower eth0) circuit_id="eth0.100@cust-example"' \
	'port            br2/ath0.200 uplink (lower ath0)'
refute "unlisted member gre0 left alone" 'gre0'
ARGS="-u br2:gre0 -t br2:ath0.200"
check "any member can be untrusted" 'port            br2/gre0 client (lower gre0)'
ARGS="-u br1:eth1 -t br1:ath0.1284"
check "port not in bridge" 'eth1 is not a port of br1'
ARGS="-u br1:eth0"
check "bridge without trusted port" 'bridge br1 needs at least one trusted and one untrusted port'
ARGS="-u br9:eth0 -t br9:ath0"
check "unknown bridge" 'bridge br9 not found'
ARGS="-u eth0 -t br1:ath0.1284"
check "missing bridge name" 'invalid value for interface.untrusted: eth0'
ARGS="-u br1:eth0 -t br1:eth0"
check "port with two roles" 'invalid value for interface.trusted: br1:eth0'
ARGS="-u br1:eth0 -t br1:ath0.1284 -o snooping.block_client_servers=false -o logging.level=debug"
check "-o sets any key" 'snooping        client_servers=allowed uplink_requests=blocked'
ARGS="-u br1:eth0 -t br1:ath0.1284"
check "dhcpv6 defaults" \
	'dhcpv6          snooping=yes ra_guard=yes unicast=relay enterprise=41112' \
	'interface_id6="cust-example/br1:eth0" remote_id6="00005e005321"'
ARGS="-u br1:eth0 -t br1:ath0.1284 dhcpv6.snooping=no dhcpv6.RAguard=no"
check "bare dhcpv6.snooping=no dhcpv6.RAguard=no" \
	'dhcpv6          snooping=no ra_guard=no'
refute "no DHCPv6 ids without snooping" 'interface_id6'
ARGS="-u br1:eth0 -t br1:ath0.1284 -o dhcpv6.ra_guard=off -o dhcpv6.interface_id=%p -o dhcpv6.remote_id=none -o dhcpv6.enterprise=4491 -o dhcpv6.unicast=forward"
check "dhcpv6 keys via -o" \
	'dhcpv6          snooping=yes ra_guard=no unicast=forward enterprise=4491' \
	'interface_id6="eth0" remote_id6=""'
ARGS="dhcpv6.snooping=maybe"
check "dhcpv6 bad value" 'invalid value for dhcpv6.snooping: maybe'
ARGS="-u br1:eth0 -t br1:ath0.1284"
check "source guard off by default" 'source_guard    no'
ARGS="-u br1:eth0 -t br1:ath0.1284 source_guard.enable=yes"
check "source guard defaults" \
	'source_guard    yes ipv6=yes block_ip_only=yes grace=0s max_bindings=16 lease_file=/var/run/dhcp-snooping-82.leases'
ARGS="-u br1:eth0 -t br1:ath0.1284 source_guard.enable=yes source_guard.grace=600 source_guard.block_ip_only=no source_guard.max_bindings=4"
check "source guard options" \
	'source_guard    yes ipv6=yes block_ip_only=no grace=600s max_bindings=4'
ARGS="-u br1:eth0 -t br1:ath0.1284 source_guard.enable=yes dhcpv6.snooping=no"
check "IPv6 source guard needs DHCPv6 snooping" 'ipv6=no (needs dhcpv6.snooping)'
ARGS="source_guard.max_bindings=0"
check "source guard bad value" 'invalid value for source_guard.max_bindings: 0'
ARGS="source_guard.bogus=1"
check "source guard unknown key" 'unknown option source_guard.bogus'
ARGS="-o nosuch.key=1"
check "-o unknown key" 'unknown option nosuch.key'
ARGS="-o foo"
check "-o without value" 'expected SECTION.KEY=VALUE'

echo "explicit: ports from the config file, command line wins"
ARGS=""
conf "[interface]
untrusted = br1:eth0
trusted = br1:ath0.1284
[option82]
circuit_id = from-file"
check "[interface] untrusted/trusted" \
	'port            br1/eth0 client (lower eth0) circuit_id="from-file"'
ARGS="-i from-cli"
check "-i overrides the file" \
	'port            br1/eth0 client (lower eth0) circuit_id="from-cli"'
ARGS=""

[ "$fail" = 0 ] && echo "detect: PASS" || echo "detect: FAIL"
exit $fail
