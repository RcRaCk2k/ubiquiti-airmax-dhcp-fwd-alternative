# dhcp-snooping-82 - transparent DHCPv4 option 82 agent for airOS
#
#   make            static MIPS32r2 big-endian soft-float binary (airOS WA)
#   make host       native build (diagnosis on a Linux PC)
#   make test       unit tests on the host
#   make toolchain  fetch the pinned Zig toolchain

VERSION    := 0.1.0
ZIG        ?= $(CURDIR)/.toolchain/zig-linux-x86_64-0.13.0/zig
TARGET     := mips-linux-musl
MCPU       := mips32r2+soft_float

SRCS       := src/main.c src/dhcp.c src/config.c src/ebt.c src/log.c
HDRS       := $(wildcard src/*.h)
WARN       := -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes \
              -Wno-unused-parameter
DEFS       := -DVERSION='"$(VERSION)"' -D_GNU_SOURCE
# reproducible: no timestamps or paths in the binary
REPRO      := -ffile-prefix-map=$(CURDIR)=. -fno-ident

BUILD      := build
MIPS_BIN   := $(BUILD)/mips/dhcp-fwd
HOST_BIN   := $(BUILD)/host/dhcp-fwd

.PHONY: all mips host test integration toolchain clean dist

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

test: $(BUILD)/test_dhcp host
	cd $(BUILD) && ./test_dhcp
	sh tests/test_detect.sh
	@if command -v tshark >/dev/null; then sh tests/check_pcap.sh $(BUILD)/test_out.pcap; fi

toolchain:
	sh tools/fetch-toolchain.sh

dist: mips
	@rm -rf $(BUILD)/dist && mkdir -p $(BUILD)/dist/dhcp-snooping-82
	cp $(MIPS_BIN) scripts/dhcp-snooping-82.sh etc/dhcp-snooping-82.conf $(BUILD)/dist/dhcp-snooping-82/
	cd $(BUILD)/dist && tar --owner=0 --group=0 --mtime=@0 --sort=name \
		-czf dhcp-snooping-82-$(VERSION).tar.gz dhcp-snooping-82
	@sha256sum $(BUILD)/dist/dhcp-snooping-82-$(VERSION).tar.gz

clean:
	rm -rf $(BUILD)

integration: host
	sh tests/integration.sh
