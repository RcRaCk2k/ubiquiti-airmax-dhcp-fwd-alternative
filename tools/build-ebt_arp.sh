#!/bin/sh
# Builds ebt_arp.ko for airOS 6 (XW.v6.3.26: Linux 2.6.32.71, MIPS32r2 big
# endian, no SMP), whose kernel ships without it; the source guard needs it
# to bind ARP. Ubiquiti publishes no GPL archive for this firmware, so the
# module is built from vanilla 2.6.32.71 with the OpenWrt 14.07 ar71xx
# toolchain (gcc 4.8 Linaro, the compiler named in the device's
# /proc/version), and the kernel is adjusted where the device's structures
# differ from vanilla:
#
#   struct sk_buff      len at 0x70, data_len 0x74, data 0xc4 (Ubiquiti
#                       fields): padding before len, no NETWORK_SECMARK.
#                       ebt_arp reads only these (skb_header_pointer).
#   struct module       312 bytes, exit at 0x130: OpenWrt's MIPS module
#                       relocation fields in mod_arch_specific, no
#                       CONFIG_CONSTRUCTORS.
#   modules             one .text, short calls (-mno-long-calls), as the
#                       device's own modules.
#
# tools/check-ebt_arp.sh compares ebt_ip/ebt_ip6 built the same way with
# the device's: vermagic, struct module, every load/store offset, symbols.
#
# Output: build/ebt_arp/ebt_arp-2.6.32.71-airos6.ko
set -eu

KVER=2.6.32.71
K_TARBALL=linux-$KVER.tar.xz
K_URL=https://cdn.kernel.org/pub/linux/kernel/v2.6/longterm/v2.6.32/$K_TARBALL
K_SHA256=60a5ffe0206a0ea8997c29ccc595aa7dae55f6cb20c7d92aab88029ca4fef598
TC_NAME=OpenWrt-Toolchain-ar71xx-for-mips_34kc-gcc-4.8-linaro_uClibc-0.9.33.2
TC_TARBALL=$TC_NAME.tar.bz2
TC_URL=https://archive.openwrt.org/barrier_breaker/14.07/ar71xx/generic/$TC_TARBALL
TC_MD5=2d8ce47a0668d25aa8049b3fc392e89d	# OpenWrt publishes md5sums only
TC_SHA256=09a831388b31550a9eb52f7a8f06c9c4903c8827cf3fdffae0e95d759e838a75

top=$(cd "$(dirname "$0")/.." && pwd)
cache=$top/.toolchain
B=$top/build/ebt_arp
mkdir -p "$cache"

cd "$cache"
[ -f "$K_TARBALL" ] || curl -fsSLO "$K_URL"
echo "$K_SHA256  $K_TARBALL" | sha256sum -c -
[ -f "$TC_TARBALL" ] || curl -fsSLO "$TC_URL"
echo "$TC_MD5  $TC_TARBALL" | md5sum -c -
echo "$TC_SHA256  $TC_TARBALL" | sha256sum -c -
[ -d "$TC_NAME" ] || tar xjf "$TC_TARBALL"

TC=$cache/$TC_NAME/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2
export STAGING_DIR=$TC
export PATH=$TC/bin:$PATH

rm -rf "$B"
mkdir -p "$B/kbuild" "$B/ext"
tar xJf "$cache/$K_TARBALL" -C "$B"
K=$B/linux-$KVER
O=$B/kbuild
mk() { make -C "$K" O="$O" ARCH=mips CROSS_COMPILE=mips-openwrt-linux- "$@"; }

# struct module: OpenWrt's MIPS module relocation fields, no constructors
sed -i '/const struct exception_table_entry \*dbe_end;/a\
\
	void *phys_plt_tbl;\
	void *virt_plt_tbl;\
	unsigned int phys_plt_offset;\
	unsigned int virt_plt_offset;' "$K/arch/mips/include/asm/module.h"
sed -i '/^config CONSTRUCTORS$/,/^$/s/^\tdefault y$/\tdefault n/' "$K/init/Kconfig"
# struct sk_buff: len, data_len and data where the device has them
sed -i 's/^\tchar\t\t\tcb\[48\];$/&\n\tchar\t\t\t__airos6_pad[28];/' \
	"$K/include/linux/skbuff.h"

mk malta_defconfig >/dev/null
"$K/scripts/config" --file "$O/.config" \
	--enable CPU_BIG_ENDIAN --disable CPU_LITTLE_ENDIAN \
	--enable CPU_MIPS32_R2 --enable CC_OPTIMIZE_FOR_SIZE \
	--enable MIPS_MT_DISABLED --disable MIPS_MT_SMP --disable MIPS_MT_SMTC \
	--disable MIPS_MT --disable MIPS_MT_FPAFF --disable SMP --disable SMP_UP \
	--disable PREEMPT --enable PREEMPT_NONE \
	--enable MODULES --enable MODULE_UNLOAD --disable MODVERSIONS \
	--disable MODULE_FORCE_UNLOAD \
	--enable NET --enable INET --module IPV6 --enable NETFILTER \
	--enable BRIDGE --module NETFILTER_XTABLES --disable NETWORK_SECMARK \
	--module BRIDGE_NF_EBTABLES --module BRIDGE_EBT_IP \
	--module BRIDGE_EBT_IP6 --module BRIDGE_EBT_ARP
yes "" | mk oldconfig >/dev/null
mk modules_prepare >/dev/null

# the matches, unchanged, as an external module directory
for m in ebt_ip ebt_ip6 ebt_arp; do
	cp "$K/net/bridge/netfilter/$m.c" "$B/ext/"
done
printf '%s\n' 'obj-m := ebt_ip.o ebt_ip6.o ebt_arp.o' \
	'ccflags-y := -fno-function-sections -mno-long-calls' > "$B/ext/Kbuild"
mk M="$B/ext" modules >/dev/null

vm=$(grep -a -o 'vermagic=[[:print:]]*' "$B/ext/ebt_arp.ko")
[ "$vm" = "vermagic=$KVER mod_unload MIPS32_R2 32BIT " ] || {
	echo "unexpected $vm" >&2
	exit 1
}
cp "$B/ext/ebt_arp.ko" "$B/ebt_arp-$KVER-airos6.ko"
echo "built: $B/ebt_arp-$KVER-airos6.ko"
