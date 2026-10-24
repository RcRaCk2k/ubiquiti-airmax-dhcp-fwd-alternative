#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The dhcp-snooping-82 authors
#
# dhcp-snooping-82 control script for airOS 8 (busybox sh).
#
# The agent replaces the airOS dhcp-fwd by bind-mounting our binary over
# /bin/dhcp-fwd (squashfs, read-only). airOS init keeps starting
# "/bin/dhcp-fwd" as before, so the DHCP relay switch in the web UI still
# enables/disables the agent.
#
# Boot: "install" adds an "ensure" line to /etc/persistent/rc.poststart.
# Only CS (custom script) firmware runs it; standard airOS 8.7 firmware runs
# no custom boot scripts, so there the original dhcp-fwd runs after a reboot
# until "ensure" is called, e.g. by the management system over SSH.
#
#   dhcp-snooping-82.sh install [--save]  copy files from this directory to
#                                   /etc/persistent/dhcp-snooping-82
#   dhcp-snooping-82.sh activate          switch from original to agent
#   dhcp-snooping-82.sh ensure            activate unless active or rolled back
#   dhcp-snooping-82.sh deactivate        back to the original dhcp-fwd
#   dhcp-snooping-82.sh rollback          deactivate + block "ensure" until reboot
#   dhcp-snooping-82.sh status            state, counters, rules
#   dhcp-snooping-82.sh uninstall [--save]
#   dhcp-snooping-82.sh diag [SECONDS]    passive packet path diagnosis
set -u

DIR=/etc/persistent/dhcp-snooping-82
BIN=$DIR/dhcp-fwd
TARGET=/bin/dhcp-fwd
MARKER=/var/run/dhcp-snooping-82.rolledback
LOG=/var/log/dhcp-snooping-82.log
HEALTH_WAIT=15
POSTSTART=/etc/persistent/rc.poststart
HOOK_TAG="# dhcp-snooping-82"

log() {
	echo "$*"
	logger -t dhcp-snooping-82 "$*" 2>/dev/null
	echo "$(date '+%F %T') $*" >> "$LOG"
}

die() { log "ERROR: $*"; exit 1; }

is_active() { grep -q " $TARGET " /proc/mounts; }

relay_enabled() { grep -q '^dhcprelay.status=enabled' /tmp/system.cfg; }

save_flash() {
	log "saving /etc/persistent to flash (cfgmtd)"
	cfgmtd -w -p /etc/ || die "cfgmtd failed"
}

install_hook() {
	grep -q "$HOOK_TAG\$" "$POSTSTART" 2>/dev/null && return 0
	[ -f "$POSTSTART" ] || echo '#!/bin/sh' > "$POSTSTART" || die "write $POSTSTART"
	# background: the health check must not delay the rest of the boot
	echo "$DIR/dhcp-snooping-82.sh ensure >/dev/null 2>&1 & $HOOK_TAG" >> "$POSTSTART" ||
		die "write $POSTSTART"
	chmod 755 "$POSTSTART"
}

remove_hook() {
	[ -f "$POSTSTART" ] || return 0
	sed -i "/$HOOK_TAG\$/d" "$POSTSTART"
	# drop the file if only the shebang is left
	[ "$(grep -cv '^#!' "$POSTSTART")" = 0 ] && rm -f "$POSTSTART"
	return 0
}

cmd_install() {
	src=$(cd "$(dirname "$0")" && pwd)
	[ -f "$src/dhcp-fwd" ] || die "no dhcp-fwd binary next to $0"
	mkdir -p "$DIR" || die "mkdir $DIR"
	if [ "$src" != "$DIR" ]; then
		cp "$src/dhcp-fwd" "$BIN.new" && mv "$BIN.new" "$BIN" || die "copy binary"
		cp "$src/dhcp-snooping-82.sh" "$DIR/dhcp-snooping-82.sh" || die "copy script"
		[ -f "$DIR/dhcp-snooping-82.conf" ] || cp "$src/dhcp-snooping-82.conf" "$DIR/" ||
			die "copy config"
	fi
	chmod 755 "$BIN" "$DIR/dhcp-snooping-82.sh"
	"$BIN" -v >/dev/null 2>&1 || die "binary does not run on this device"
	self_check || die "configuration check failed"
	install_hook
	log "installed to $DIR ($("$BIN" -v))"
	[ "${1:-}" = "--save" ] && save_flash
	return 0
}

# --check needs a bridge with the relay enabled; without one init does not
# start dhcp-fwd at all, so only the binary itself can be checked
self_check() {
	relay_enabled || { "$BIN" -v >/dev/null 2>&1; return; }
	"$BIN" --check >/dev/null 2>&1
}

health_check() {
	i=0
	while [ $i -lt $HEALTH_WAIT ]; do
		sleep 1
		i=$((i + 1))
		"$BIN" --status >/dev/null 2>&1 && return 0
	done
	return 1
}

cmd_activate() {
	[ -x "$BIN" ] || die "not installed"
	self_check || die "binary self check failed, staying on original"
	relay_enabled || log "WARNING: DHCP relay disabled in airOS, agent will not be started by init"
	# "install" replaces the binary with a new file: mount that one
	if is_active && ! [ "$BIN" -ef "$TARGET" ]; then
		umount -l "$TARGET" || die "umount of old binary failed"
	fi
	if ! is_active; then
		mount -o bind "$BIN" "$TARGET" || die "bind mount failed"
	fi
	rm -f "$MARKER"
	# init respawns /bin/dhcp-fwd, which now is our binary
	killall dhcp-fwd 2>/dev/null
	relay_enabled || { log "activated (idle until relay is enabled)"; return 0; }
	if health_check; then
		log "activated: $("$BIN" -v), rules ok"
		return 0
	fi
	log "health check failed after ${HEALTH_WAIT}s, rolling back"
	cmd_rollback
	return 1
}

cmd_deactivate() {
	if is_active; then
		umount -l "$TARGET" || die "umount failed"
	fi
	# our agent removes its broute rules on SIGTERM; init respawns the
	# original from the squashfs
	killall dhcp-fwd 2>/dev/null
	sleep 2
	log "deactivated, original dhcp-fwd restored"
}

cmd_rollback() {
	touch "$MARKER"
	cmd_deactivate
	log "ROLLBACK done; 'ensure' is blocked until reboot or 'activate'"
}

cmd_ensure() {
	[ -f "$MARKER" ] && { echo "rolled back, not activating"; return 0; }
	if is_active; then
		echo "active"
		return 0
	fi
	cmd_activate
}

cmd_status() {
	if is_active; then echo "mode: agent (bind mount active)"
	else echo "mode: original airOS dhcp-fwd"; fi
	[ -f "$MARKER" ] && echo "rollback marker: set"
	relay_enabled && echo "airOS relay: enabled" || echo "airOS relay: disabled"
	echo "processes: $(pidof dhcp-fwd)"
	[ -x "$BIN" ] && "$BIN" --status
}

cmd_uninstall() {
	cmd_deactivate
	remove_hook
	rm -rf "$DIR"
	log "uninstalled"
	[ "${1:-}" = "--save" ] && save_flash
	return 0
}

case "${1:-}" in
install)	shift; cmd_install "$@" ;;
activate)	cmd_activate ;;
ensure)		cmd_ensure ;;
deactivate)	cmd_deactivate ;;
rollback)	cmd_rollback ;;
status)		cmd_status ;;
uninstall)	shift; cmd_uninstall "$@" ;;
diag)		shift; exec "$BIN" --diag "${1:-60}" ;;
*)		sed -n '2,/^set -u/p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
