#!/bin/sh
# Independent verification of the unit test output with tshark:
# every frame must have valid IP/UDP checksums and carry option 82 with
# the expected circuit/remote id (or none for stripped replies).
set -eu
pcap=${1:-build/test_out.pcap}

bad=$(tshark -r "$pcap" -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE \
	-Y 'ip.checksum.status == "Bad" || udp.checksum.status == "Bad" || _ws.malformed || _ws.expert.severity >= "Error"' \
	-T fields -e frame.number 2>/dev/null | wc -l)
total=$(tshark -r "$pcap" 2>/dev/null | wc -l)
ours=$(tshark -r "$pcap" -Y 'dhcp.option.agent_information_option.agent_circuit_id contains "cust-example" && dhcp.option.agent_information_option.agent_remote_id contains "00005e005301"' 2>/dev/null | wc -l)
stripped=$(tshark -r "$pcap" -Y 'dhcp.option.dhcp == 2 && !(dhcp.option.type == 82)' 2>/dev/null | wc -l)

echo "tshark: $total frames, $bad bad, $ours with our option 82, $stripped stripped replies"
[ "$bad" -eq 0 ] && [ $((ours + stripped)) -eq "$total" ]
