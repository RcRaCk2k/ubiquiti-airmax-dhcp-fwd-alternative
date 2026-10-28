#!/bin/sh
# Cross-check of tools/build-ebt_arp.sh against a device: ebt_ip.ko and
# ebt_ip6.ko built the same way as ebt_arp.ko must match the device's own
# in vermagic, struct module (size, init/exit), every load/store offset
# (sk_buff, xt_match_param, the match info), external symbols, relocation
# types and the xt_match registration. ebt_arp reads no field these two do
# not read as well. The machine code itself differs in register allocation
# (the device was built with Linaro 4.8-2014.01, the toolchain is 2014.04).
#
#   tools/check-ebt_arp.sh DIR   DIR holds ebt_ip.ko and ebt_ip6.ko from
#                                /lib/modules/2.6.32.71 of the device
# Needs llvm-objdump and llvm-readelf.
set -eu

dev=${1:?usage: $0 DIR-with-device-modules}
ours=$(cd "$(dirname "$0")/.." && pwd)/build/ebt_arp/ext
rc=0

vermagic() { grep -a -o 'vermagic=[[:print:]]*' "$1"; }
modsize() { llvm-readelf -s "$1" | awk '$8 == "__this_module" { print $3 }'; }
modrel() { llvm-readelf -r "$1" | sed -n '/this_module/,/^$/p' |
	awk '/_module$/ { print $1, $5 }'; }
mem() { llvm-objdump -d --no-show-raw-insn "$1" |
	grep -oE '\s(lw|lh|lhu|lb|lbu|sw|sh|sb)\s+\$[0-9a-z]+, -?0x[0-9a-f]+\(\$[0-9a-z]+\)' |
	grep -v '(\$sp)' | awk '{ split($3, a, "("); print $1, a[1] }' | sort -u; }
syms() { llvm-readelf -r "$1" | awk '$3 ~ /R_MIPS/ && $5 !~ /^\./ { print $5 }' | sort -u; }
rtypes() { llvm-readelf -r "$1" | grep -oE 'R_MIPS_[A-Z0-9_]+' | sort -u; }
data() { llvm-objdump -s -j .data "$1" | tail -n +5; }

for m in ebt_ip ebt_ip6; do
	for check in vermagic modsize modrel mem syms rtypes data; do
		if [ "$($check "$dev/$m.ko")" = "$($check "$ours/$m.ko")" ]; then
			echo "ok   $m $check"
		else
			echo "FAIL $m $check"
			rc=1
		fi
	done
done
[ $rc = 0 ] && echo "ebt_arp.ko matches the device kernel's layout"
exit $rc
