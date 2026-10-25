#!/bin/sh
# SPDX-License-Identifier: MIT
# Independent check of the DHCPv6 frames test_dhcp6 produced: tshark must
# accept every UDP checksum and decode our Relay-Forwards and the unwrapped
# server messages.
set -eu
pcap=$1
ifid=$(printf 'cust-example/br1:eth0' | od -An -tx1 | tr -d ' \n')
out=$(tshark -r "$pcap" -o udp.check_checksum:TRUE -T fields \
	-e udp.checksum.status -e dhcpv6.msgtype -e dhcpv6.interface_id \
	-e dhcpv6.remoteid.enterprise 2>/dev/null)
total=$(printf '%s\n' "$out" | grep -c .)
good=$(printf '%s\n' "$out" | awk -F'\t' '$1 == 1' | wc -l)
relay=$(printf '%s\n' "$out" | awk -F'\t' -v id="$ifid" \
	'$2 ~ /^12,/ && $3 == id && $4 == 41112' | wc -l)
plain=$(printf '%s\n' "$out" | awk -F'\t' '$2 == 2 || $2 == 7 || $2 == 10' | wc -l)
echo "tshark6: $total frames, $good checksums ok, $relay Relay-Forward with our ids, $plain unwrapped"
[ "$total" -gt 0 ] && [ "$good" = "$total" ] && [ "$relay" = 8 ] && [ "$plain" = 3 ]
