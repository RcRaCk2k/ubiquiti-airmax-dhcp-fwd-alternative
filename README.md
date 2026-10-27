# dhcp-snooping-82

Transparent DHCPv4 option 82 agent (RFC 3046) and DHCPv6 lightweight relay
agent (RFC 6221) for Ubiquiti airOS 8 (PowerBeam 5AC, WA.v8.7.11). It replaces
`/bin/dhcp-fwd` and adds option 82 exactly once to every DHCP client packet
that physically arrives on a customer port, including unicast renews. Apart
from that the bridge is left unchanged. It is not an L3 relay: `giaddr` stays
0, the upstream relay sets it.

* **Bridges:** all bridges with the DHCP relay enabled in `/tmp/system.cfg`
  (`dhcprelay.client.N.devname`), or the ports given with `-u`/`-t`.
* **Ports:** each bridge member is classified by the physical interface below
  any VLANs: `eth*` = untrusted customer port, `ath*` = trusted uplink. This
  covers `eth0`, `eth0.100`, `ath0`, `ath0.1284` and several Ethernet ports.
  Other members (e.g. `gre0`) are left alone.
* **Circuit ID** `<hostname>/<bridge>:<port>`, e.g. `cust-example/br1:eth0`;
  **remote ID** = bridge MAC as hex text. Both can be changed with templates.
* **DHCP snooping:** DHCP servers on a customer port and requests of other
  customers arriving from the uplink are dropped. The airOS FIREWALL rules for
  this are not needed.
* **DHCPv6 with prefix delegation:** client messages from a customer port are
  wrapped into a Relay-Forward with Interface-ID (same text as the circuit ID)
  and Remote-ID (enterprise number + remote ID); the Relay-Reply is unwrapped
  and sent only to the port it belongs to. IA_PD passes unchanged, so prefix
  delegation works through the upstream relay. The same snooping applies.
* **RA guard:** router advertisements from customer ports are dropped. The
  ebtables of kernel 2.6.32 cannot match ICMPv6 types, so all link-local
  ICMPv6 of a customer port (neighbour discovery, MLD, RA) goes through the
  agent, which drops the RAs and passes everything else on unchanged.
* **Source guard** (optional, off by default): on customer ports only the
  addresses the DHCP server handed out may be used, bound to the client's
  MAC. Everything else, including spoofed ARP, is dropped.

Analysis and architecture: [docs/ANALYSIS.md](docs/ANALYSIS.md) (German).
License: MIT ([LICENSE](LICENSE)).

## Build

```sh
make toolchain    # Zig 0.13.0 (clang + musl), SHA256 verified, into .toolchain/
make              # build/mips/dhcp-fwd: static, MIPS32r2 BE, soft-float
make test         # unit tests (ASan/UBSan, fuzzing), tshark check, port detection
make integration  # bridge simulation in network namespaces, no root needed
make dist         # build/dist/: release tarball, bare binary, SHA256SUMS
```

The build is reproducible: the same sources give a bit-identical binary, its
SHA256 is written to `build/mips/dhcp-fwd.sha256`.

## Command line

The binary is a drop-in replacement for the airOS `dhcp-fwd`: init starts it
as `/bin/dhcp-fwd -n -c /etc/dhcp-fwd.conf`, and the airOS config given with
`-c` is ignored unless it uses our INI syntax. Without further options the
agent detects bridges and ports itself as described above.

A UI that knows which ports are trusted can pass them explicitly instead:

```sh
dhcp-fwd -n -u br1:eth0 -t br1:ath0.1284
dhcp-fwd -n -u br1:eth0,br1:eth1 -t br1:ath0 -u br2:eth0.100 -t br2:ath0.200 \
         -i '%h/%b:%p' -r '%m'
```

| Option | Meaning |
|---|---|
| `-u`, `--untrusted BRIDGE:PORT[,...]` | customer port: option 82 is added to requests, DHCP servers are blocked |
| `-t`, `--trusted BRIDGE:PORT[,...]` | uplink port towards the DHCP server |
| `-i`, `--circuit-id TEMPLATE` | circuit ID (sub-option 1), default `%h/%b:%p` |
| `-r`, `--remote-id TEMPLATE` | remote ID (sub-option 2), default `%m`, `none` omits it |
| `-o`, `--option SECTION.KEY=VALUE` | any key of the configuration file, e.g. `-o snooping.block_client_servers=false` |
| `SECTION.KEY=VALUE` | the same without `-o`, e.g. `dhcpv6.snooping=yes dhcpv6.RAguard=yes` |
| `-C FILE` | own configuration file (default `/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.conf`) |
| `-n` / `-d` | foreground / foreground with debug log on stderr |
| `--check`, `--status`, `--diag [s]` | print the resolved configuration / counters and rule state / passive packet path diagnosis |

Templates: `%h` hostname (`resolv.host.1.name`), `%b` bridge, `%p` port,
`%m` bridge MAC, `%M` port MAC (MACs as 12 hex digits), `%%` percent sign.

IPv6 options (all default on):

| Option | Meaning |
|---|---|
| `dhcpv6.snooping=yes\|no` | DHCPv6 lightweight relay agent and DHCPv6 snooping |
| `dhcpv6.RAguard=yes\|no` | drop router advertisements arriving on untrusted ports |
| `dhcpv6.interface_id=TEMPLATE` | Interface-ID (option 18), default: the circuit ID |
| `dhcpv6.remote_id=TEMPLATE` | Remote-ID (option 37), default: the remote ID, `none` omits it |
| `dhcpv6.enterprise=N` | enterprise number of the Remote-ID, default 41112 |
| `dhcpv6.unicast=relay\|forward` | relay unicast client messages too, or pass them unchanged |

The upstream relay or DHCPv6 server has to accept Relay-Forward messages from
a lightweight relay agent (link-address `::`) and echo the Interface-ID in its
Relay-Reply, as RFC 6221 requires.

With `ra_guard` the station itself no longer receives multicast neighbour
discovery from the customer side, so it cannot be reached over IPv6 from
the customer's LAN; from the uplink side nothing changes.

### Source guard

`source_guard.enable=yes` turns a customer port into one where only addresses
the DHCP server handed out can be used (IP source guard plus ARP inspection):

| Option | Meaning |
|---|---|
| `source_guard.enable=yes\|no` | default `no` |
| `source_guard.ipv6=yes\|no` | also guard IPv6 (default `yes`, needs `dhcpv6.snooping=yes`) |
| `source_guard.block_ip_only=yes\|no` | `yes` (default): only IPv4, ARP and IPv6 are filtered; `no`: PPPoE and every other non-IP frame from the port is dropped too |
| `source_guard.grace=SECONDS` | learn only, do not block, for this long after the start (default `0`) |
| `source_guard.max_bindings=N` | per port and kind: IPv4 addresses, IPv6 addresses (IA_NA) and delegated prefixes (IA_PD) are counted separately (default 16). `1` allows one router: one IPv4 address, one IPv6 address and one prefix. A new lease beyond the limit replaces the binding renewed longest ago, e.g. that of a replaced router |
| `source_guard.lease_file=PATH` | default `/var/run/dhcp-snooping-82.leases` |
| `source_guard.slaac=eui64\|prefix\|no` | SLAAC addresses from the uplink router's prefixes, for clients with a DHCP binding: `eui64` (default) only the address formed from the client's MAC, `prefix` the whole /64, `no` none |

* **Learning:** a DHCPACK (from the uplink, to the customer port it is
  delivered to) binds `yiaddr` to `chaddr` for the lease time. A DHCPv6 Reply
  binds every IA_NA address and IA_PD prefix to the client's MAC for its
  valid lifetime.
* **Renew** only moves the expiry in the agent's table; the ebtables rules
  are not touched. They change only when a binding appears, expires, is
  released (DHCPRELEASE, DHCPDECLINE, DHCPv6 Release/Decline, valid
  lifetime 0) or NAKed, or when the client gets another address.
* **Rules:** a chain `DHCP_SNOOPING_82_SG` in the ebtables filter table,
  jumped to from `INPUT` and `FORWARD`. Per binding: IPv4 with source MAC +
  IP, ARP with sender MAC + IP, IPv6 with source MAC + address/prefix. Always
  allowed: DHCP itself (diverted before the filter table), ARP probes from
  `0.0.0.0`, IPv6 link-local sources and `::` for duplicate address detection.
  VLAN tagged IPv4/ARP/IPv6 from a customer port is dropped so it cannot
  bypass the rules.
* **Restart:** the binding table is written to the lease file on every change
  (RAM, no flash wear), so a restarted agent (e.g. after "Apply") restores
  it. After a reboot the file is gone; the customer's router normally asks
  again after the link flap. If it may not, because a switch keeps the link
  up, set a grace period, e.g. `source_guard.grace=600`.
* **SLAAC:** many routers form their own WAN address from the operator's
  router advertisement (a /64 with the A flag) and use DHCPv6 only for the
  delegated prefix. The agent reads the RAs arriving on the uplink (a copy,
  they are forwarded as before) and, for every client MAC that has a DHCP
  binding on the port, allows the modified EUI-64 address of that MAC in
  each prefix (`slaac=prefix`: the whole /64) for the prefix's valid
  lifetime. These bindings go with the client's last DHCP binding or the
  prefix. The prefixes are kept in the lease file; RAs repeat every few
  minutes anyway. Privacy (temporary) addresses in the operator's /64 need
  `slaac=prefix`.
* Not covered: static addresses. They never appear in a DHCP reply and are
  blocked.

Rules for explicit ports:

* If any `-u`/`-t` (or `[interface] untrusted`/`trusted` in the file) is
  given, exactly these ports are used. The relay settings in `system.cfg` and
  the name based classification are not consulted; any bridge member can be
  either role.
* Every bridge needs at least one trusted and one untrusted port. Ports that
  are not listed are left alone.
* A port must be a member of the bridge. If it is not (yet), the agent logs
  the error and retries every 10 s instead of exiting, so init does not
  respawn it in a tight loop.
* Precedence: defaults, then the configuration file, then the command line.
  The command line options also apply after a `SIGHUP` reload.
* `--check` and `--status` resolve the configuration the same way, so pass
  them the same options as the running agent.

## Installation (one test device, step by step)

```sh
# on the PC
scp build/mips/dhcp-fwd scripts/dhcp-snooping-82.sh etc/dhcp-snooping-82.conf.example root@DEVICE:/tmp/
# on the device
sh /tmp/dhcp-snooping-82.sh install                            # to /etc/persistent/dhcp-snooping-82, checks the binary
/etc/persistent/dhcp-snooping-82/dhcp-fwd --check              # detected bridges, ports, IDs
/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh diag 120  # passive, sends nothing
/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh activate  # health check, rollback on failure
/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh status
# only when everything works, save to flash:
sh /etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh install --save
```

Configuration: airOS init starts `/bin/dhcp-fwd` with its own fixed
arguments, so settings such as `source_guard.enable=yes` belong in
`/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.conf`. `install` creates it
from `dhcp-snooping-82.conf.example` (every key with its default) only if it
does not exist yet, and always refreshes the `.example` next to it. The file
may contain just the keys that differ:

```ini
[source_guard]
enable = yes
```

`killall -HUP dhcp-fwd` reloads it; check the result with `dhcp-fwd --check`.

`install` and `activate` also work while the relay is disabled in the UI. This
is the recommended order: install and activate first, then enable the relay
and press "Apply", so the original `dhcp-fwd` never runs in between.

Back to the original: `dhcp-snooping-82.sh deactivate` (or `rollback`, which also
blocks `ensure` until the next reboot). Remove: `dhcp-snooping-82.sh uninstall --save`.

The "DHCP Relay" switch in the airOS web UI still turns the agent on and off,
because init keeps starting `/bin/dhcp-fwd`.

Update: copy the new files to `/tmp`, run `sh /tmp/dhcp-snooping-82.sh install`,
then `dhcp-snooping-82.sh activate` (mounts the new binary and restarts the agent;
the configuration is kept), finally `install --save`.

### Persistence

`install` adds a call of `dhcp-snooping-82.sh ensure` to
`/etc/persistent/rc.poststart` (the line is tagged `# dhcp-snooping-82`; `uninstall`
removes it). Only **CS firmware** runs this boot hook; tested with
WA.v8.7.15-cs: after a firmware upgrade and reboot, `/etc/persistent` was
kept and `ensure` mounted the agent before init first started `dhcp-fwd`, so
the original never ran. DHCP requests the customer sends before the
wireless link is up stay unanswered, as they would without the agent. The
standard firmware
runs **no** custom scripts at boot (`rc.poststart` only if `/etc/poststart`
exists, which only CS firmware creates). There the original runs after a
reboot until `dhcp-snooping-82.sh ensure` is called, e.g. by a device discovery over
SSH:

```sh
ssh root@DEVICE '/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh ensure'
```

## Operation and diagnosis

```sh
dhcp-snooping-82.sh status                   # mode, processes, counters, rules
cat /var/run/dhcp-snooping-82.stats          # counters (updated every 10 s)
grep dhcp-fwd /var/log/messages              # log (RAM), one line per packet
kill -HUP $(cat /var/run/dhcp-fwd.pid)       # reload the configuration

# packet path
tcpdump -i eth0      -e -n -vvv -s0 'udp port 67 or udp port 68'
tcpdump -i ath0.1284 -e -n -vvv -s0 'udp port 67 or udp port 68'
tcpdump -i eth0      -e -n -vvv -s0 'udp port 546 or udp port 547 or icmp6'
dhcp-fwd --diag 60                           # per socket: ALL = everything, IP/IP6 = diverted only

# rules
ebtables -t broute -L --Lc                   # jump to DHCP_SNOOPING_82 at position 1
ebtables -t broute -L DHCP_SNOOPING_82 --Lc  # counters = diverted DHCP frames
ebtables -L --Lc                             # airOS filter; FIREWALL DHCP rules no longer needed
ebtables -L DHCP_SNOOPING_82_SG --Lc         # source guard: bindings and drops
cat /var/run/dhcp-snooping-82.leases         # source guard bindings

# processes
pidof dhcp-fwd; grep " /bin/dhcp-fwd" /proc/mounts
ls -l /proc/$(cat /var/run/dhcp-fwd.pid)/fd; cat /proc/net/packet
```

Example log line:

```
req-mark if=eth0/2 to=ath0.1284 type=REQUEST xid=0x30336d42 chaddr=1c:ed:6f:00:00:01 src=1c:ed:6f:00:00:01/198.51.100.175
  dst=dc:9f:db:00:00:01/198.51.100.0 giaddr=0.0.0.0 hops=0 reason=inserted cid="cust-example/br1:eth0" rid="00005e005301"
```

## Behaviour

| Case | Action |
|---|---|
| client packet from a customer port without option 82 | insert option 82 into the PAD area, otherwise grow the packet up to the MTU; send it once to the uplink of the same bridge |
| already has option 82 / `giaddr` / `hops` | forward unchanged (`existing_option82 = forward`) |
| malformed, fragment, bad checksum | forward unchanged, counter `req_malformed` |
| reply with our own option 82 | strip option 82 (length kept, PAD), send only to the customer port the circuit ID belongs to |
| reply with foreign option 82 to a request we marked (xid + chaddr) | upstream replaced our option 82: strip it, send to the request's port (`rep_foreign_ours_by_xid`) |
| reply with foreign option 82 to a request we passed through | forward unchanged to the request's port |
| any other reply with foreign option 82 | drop (another station) |
| reply without option 82 | to the port the request came from (xid), otherwise to all customer ports of the bridge |
| DHCP request from the uplink (customers of other stations) | dropped (snooping, `block_uplink_requests`) |
| DHCP server reply from a customer port (server at the customer) | dropped (snooping, `block_client_servers`) |
| BOOTREPLY to port 67 from a customer port / BOOTREQUEST to port 68 from the uplink | dropped |
| DHCPv6 client message from a customer port | wrapped into a Relay-Forward (link-address `::`, peer-address = client, Interface-ID, Remote-ID), MAC and IP addresses kept, sent once to the uplink |
| Relay-Reply with our Interface-ID | unwrapped, sent as a plain server message to port 546, only to the port the Interface-ID names |
| Relay-Reply for another relay (other Interface-ID, or a link-address) | dropped |
| Relay-Forward or DHCPv6 server message from a customer port | dropped (RFC 6221: customer ports are untrusted) |
| DHCPv6 client message from the uplink (other stations' customers) | dropped (`block_uplink_requests`) |
| Relay-Forward that would exceed the MTU | dropped and logged (RFC 6221) |
| router advertisement from a customer port | dropped (`ra_guard`), also when hidden behind hop-by-hop or destination options headers |
| other link-local ICMPv6 from a customer port (ND, MLD, echo) | passed on unchanged: multicast to all other ports of the bridge, unicast to the uplink; fragmented ND is dropped (RFC 6980) |
| worker crashed while `ra_guard` is on | link-local ICMPv6 of the customer is blocked until the worker is back (fail-closed), so IPv6 pauses for that time |
| worker crashed | rules stay (fail-closed), restart with backoff |
| source guard: frame from a customer port with a leased source (MAC + IP / prefix) | passed |
| source guard: any other IPv4, ARP or IPv6 from a customer port | dropped; PPPoE and other frames too with `block_ip_only=no` |
| source guard: renew | expiry updated internally, rules unchanged |
| source guard: lease expired, released, declined or NAKed | binding and its rules removed |
| source guard: worker crashed | bindings and rules stay (the watcher holds them); new leases are bound once the worker is back |
| source guard: agent stopped or rolled back | rules removed, the customer is unfiltered again |
| airOS removes the rules (Apply) | re-installed within 5 s; until then the airOS behaviour applies, without duplicates |
| SIGTERM (relay switched off in the UI, deactivate) | remove rules, exit |
