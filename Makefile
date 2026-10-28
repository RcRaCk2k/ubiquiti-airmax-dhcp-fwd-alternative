# dhcp-snooping-82 - transparent DHCPv4 option 82 agent for airOS
#
#   make            static MIPS32r2 big-endian soft-float binary (airOS WA)
#   make host       native build (diagnosis on a Linux PC)
#   make test       unit tests on the host
#   make toolchain  fetch the pinned Zig toolchain
#   make ebt-arp    ebt_arp.ko for airOS 6 (downloads kernel + gcc 4.8)

VERSION    := 0.3.0
ZIG        ?= $(CURDIR)/.toolchain/zig-linux-x86_64-0.13.0/zig
TARGET     := mips-linux-musl
MCPU       := mips32r2+soft_float

SRCS       := src/main.c src/dhcp.c src/dhcp6.c src/guard.c src/config.c \
              src/ebt.c src/log.c
HDRS       := $(wildcard src/*.h)
WARN       := -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes \
              -Wno-unused-parameter
DEFS       := -DVERSION='"$(VERSION)"' -D_GNU_SOURCE
# reproducible: no timestamps or paths in the binary
REPRO      := -ffile-prefix-map=$(CURDIR)=. -fno-ident

BUILD      := build
MIPS_BIN   := $(BUILD)/mips/dhcp-fwd
HOST_BIN   := $(BUILD)/host/dhcp-fwd

.PHONY: all mips host test integration toolchain clean dist ebt-arp

all: mips

mips: $(MIPS_BIN)

$(MIPS_BIN): $(SRCS) $(HDRS) Makefile
	@test -x $(ZIG) || { echo "run 'make toolchain' first"; exit 1; }
	@mkdir -p $(dir $@)
	$(ZIG) cc -target $(TARGET) -mcpu=$(MCPU) -Os -static -s \
		-ffunction-sections -fdata-sections -Wl,--gc-sections \
		-Wl,--build-id=none $(WARN) $(DEFS) $(REPRO) -o $@ $(SRCS)
	@ls -l $@
	@sha256sum $@ | tee $@.sha256

host: $(HOST_BIN)

$(HOST_BIN): $(SRCS) $(HDRS) Makefile
	@mkdir -p $(dir $@)
	$(CC) -O2 -g $(WARN) $(DEFS) -o $@ $(SRCS)

$(BUILD)/test_dhcp: tests/test_dhcp.c src/dhcp.c src/dhcp.h
	@mkdir -p $(dir $@)
	$(CC) -O1 -g -fsanitize=address,undefined $(WARN) $(DEFS) -Isrc \
		-o $@ tests/test_dhcp.c src/dhcp.c

$(BUILD)/test_dhcp6: tests/test_dhcp6.c src/dhcp6.c src/dhcp6.h src/dhcp.h
	@mkdir -p $(dir $@)
	$(CC) -O1 -g -fsanitize=address,undefined $(WARN) $(DEFS) -Isrc \
		-o $@ tests/test_dhcp6.c src/dhcp6.c

$(BUILD)/test_guard: tests/test_guard.c src/guard.c src/guard.h src/dhcp6.c \
		src/dhcp6.h src/dhcp.h
	@mkdir -p $(dir $@)
	$(CC) -O1 -g -fsanitize=address,undefined $(WARN) $(DEFS) -Isrc \
		-o $@ tests/test_guard.c src/guard.c src/dhcp6.c

test: $(BUILD)/test_dhcp $(BUILD)/test_dhcp6 $(BUILD)/test_guard host
	cd $(BUILD) && ./test_dhcp
	cd $(BUILD) && ./test_dhcp6
	cd $(BUILD) && ./test_guard
	sh tests/test_detect.sh
	@if command -v tshark >/dev/null; then sh tests/check_pcap.sh $(BUILD)/test_out.pcap; \
		sh tests/check_pcap6.sh $(BUILD)/test6_out.pcap; fi

toolchain:
	sh tools/fetch-toolchain.sh

EBT_ARP := $(BUILD)/ebt_arp/ebt_arp-2.6.32.71-airos6.ko
ebt-arp:
	sh tools/build-ebt_arp.sh

# release assets: tarball (binary, script, config, docs, and ebt_arp.ko for
# airOS 6 if built) plus the bare binary, all listed in SHA256SUMS;
# reproducible like the binary itself
DIST_NAME := dhcp-snooping-82-$(VERSION)
dist: mips
	@rm -rf $(BUILD)/dist && mkdir -p $(BUILD)/dist/$(DIST_NAME)
	cp $(MIPS_BIN) scripts/dhcp-snooping-82.sh etc/dhcp-snooping-82.conf.example \
		README.md LICENSE $(wildcard $(EBT_ARP)) $(BUILD)/dist/$(DIST_NAME)/
	cd $(BUILD)/dist/$(DIST_NAME) && sha256sum dhcp-fwd dhcp-snooping-82.sh \
		dhcp-snooping-82.conf.example $(notdir $(wildcard $(EBT_ARP))) > SHA256SUMS
	cd $(BUILD)/dist && tar --owner=0 --group=0 --mtime=@0 --sort=name \
		-cf - $(DIST_NAME) | gzip -9n > $(DIST_NAME)-mips.tar.gz
	cp $(MIPS_BIN) $(BUILD)/dist/dhcp-fwd-$(VERSION)-mips
	cd $(BUILD)/dist && sha256sum $(DIST_NAME)-mips.tar.gz \
		dhcp-fwd-$(VERSION)-mips > SHA256SUMS
	@cat $(BUILD)/dist/SHA256SUMS

clean:
	rm -rf $(BUILD)

integration: host
	sh tests/integration.sh
