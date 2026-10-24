# Ist-Analyse PowerBeam 5AC / airOS WA.v8.7.11 (Stand 2026-10-24)

Grundlage: nur lesende Diagnose auf `cust-example` (192.0.2.49),
statische Analyse von `/bin/dhcp-fwd`, Upstream-Quellen ensc/dhcp-fwd,
passiver Mitschnitt auf `eth0`, `ath0.1284` und `br1`.

## Bestätigte Fakten

| Thema | Befund |
|---|---|
| ABI | ELF32 MSB (Big-Endian), MIPS32r2, o32, uClibc 0.9.33.2, `/lib/ld-uClibc.so.0`, dynamisch (`libc.so.0`, `libgcc_s.so.1`) |
| RAM / Flash | 62 MB RAM (≈22 MB frei); `cfg`-Partition (`/etc/persistent`) 256 KB, davon 24 KB belegt; rootfs Squashfs 100 % voll, nur lesbar |
| Interfaces | eth0=2, ath0=8, ath0.1284=10, br0=11, br1=12; `br1` = eth0 + ath0.1284 |
| Management | 192.0.2.49/27 und 192.168.1.49 auf **br1**, 192.168.0.49 auf br0 (nur lokal) |
| Modus | Station WDS, `netmode=bridge`, fastpath aus (`/proc/net/ubnt_ptp_fast_txrx = 0`) |
| br-netfilter | `bridge-nf-call-iptables=0`, kein NFQUEUE |
| ebtables | v2.0.10-4, Module `ebtable_broute`, `ebt_ip`, `ebt_pkttype`, `ebt_mark`, `ebt_limit`, `ebt_vlan` geladen |
| Original | `dhcp-forwarder 0.10` (ensc, GPLv3), von Ubiquiti um `_mac_` erweitert; startet über `/etc/inittab` mit `respawn`, läuft als uid 99 |
| Funktionsweise Original | Klassisches **L3-Relay**: Empfang über UDP-Socket :67 mit `SO_BINDTODEVICE br1`, setzt `giaddr` und `hops++`, verlangt IPv4 an jedem Interface. Der `ETH_P_ALL`-Socket dient nur zum Senden |
| airOS-Regeln (`/etc/sysinit/ebtables.conf`) | `FORWARD --logical-in br1 -p IPv4 --ip-proto udp --ip-dport 67 -j DROP`; FIREWALL-Kette an INPUT **und** FORWARD: `-i eth0 sport 67 dport 68 DROP`, `-i ath0.1284 sport 68 dport 67 DROP`; broute: EAP-Kette, `-i ath0 -p 802_1Q --vlan-id 1284 -j DROP` |
| Neustart durch airOS | Bei jedem *Apply* im Webinterface: `ebtables -t broute -F/-X`, Module entladen und neu laden, `killall dhcp-fwd`, `kill -HUP 1` |
| Boot-Hooks | `rc.presysinit`/`rc.postsysinit`/`rc.prestart`/`rc.poststart` werden nur ausgeführt, wenn `/etc/<name>` existiert. Die Standard-Firmware legt diese Dateien **nie** an → **keine Custom-Scripts beim Boot** |

## Befunde zu den Hypothesen

1. **Unicast-Renew bekommt heute keine Option 82** – bestätigt per Mitschnitt
   (19:33:36): der Renew der Kunden-FRITZ!Box (`1c:ed:6f:00:00:01`,
   198.51.100.175 → 198.51.100.0) läuft unverändert, ohne Option 82, durch die
   Bridge. Das Original sieht Unicast an fremde MACs prinzipbedingt nicht.
2. Die von airOS generierte FORWARD-Regel (ohne `--ip-dst`) verwirft auch
   Unicast-Renews. Die heute aktive Regel mit `--ip-dst 255.255.255.255`
   weicht davon ab, wurde also von Hand geändert; nach dem nächsten *Apply*
   oder Reboot gilt wieder die generierte Fassung.
3. **Upstream gibt es bereits einen Option-82-Inserter**: das ACK trägt
   Circuit-ID `sfp-sfpplus23.dach:1281` und Remote-ID `c4:ad:34:00:00:01`
   (MikroTik-OUI, Format der MikroTik-Bridge mit DHCP-Snooping). Diese Option
   82 kommt bis zum Kunden durch, sie wird nicht entfernt.
4. Am 24.10. liefen zeitweise **zwei `dhcp-fwd`-Instanzen** (init-Respawn
   plus manueller Start aus `dhcp-option82.sh`). Die manuell gestartete wurde
   mit Freigabe beendet.

5. **Passiver `--diag`-Lauf auf 2.6.32** (20:03, Renew `0x1628e223`): Den
   Renew und das ACK sahen nur die `ETH_P_ALL`-Sockets auf eth0 und
   ath0.1284, die `ETH_P_IP`-Sockets nichts. Damit ist auf dem Altkernel
   belegt: Ohne broute-Regel erreicht ein gebridgter Frame den Agent nicht.
   Die Gegenprobe (mit Regel) steht noch aus. Das statische Binary läuft
   (108 KB RSS, 0 % CPU).
6. **Der MikroTik fügt Option 82 auch auf dem trusted-Port ein**
   (`trusted=yes`), mitten im Padding und ohne `giaddr` (beim Renew direkt
   zum Server: `giaddr=0`). Der Server beantwortet so einen Renew trotz
   `giaddr=0` und gibt die Option 82 zurück; der MikroTik entfernt sie auf dem
   Rückweg nicht.

## Architektur dhcp-snooping-82 (Kurzfassung)

* Eigener Agent (MIT), kein Code aus dhcp-fwd.
* ebtables-**broute** leitet nur DHCP von `eth0` (dport 67) und Serverantworten
  von `ath0.1284` (sport 67 → dport 68, nicht an die eigene MAC) aus der
  Bridge aus. Eigene Kette `DHCP_SNOOPING_82` mit Policy `RETURN`, Sprung an
  Position 1 in `BROUTING`.
* Empfang über `AF_PACKET`-Sockets mit **`ETH_P_IP`**, gebunden an den
  Bridge-Port, plus BPF. In 2.6.32 erreichen Protokoll-Handler einen Frame nur,
  wenn der Bridge-Hook ihn zurückgibt (broute DROP). Ohne Regel bekommt der
  Agent also nichts, und die Bridge leitet das Original genau einmal weiter:
  **keine Duplikate möglich**.
* Senden direkt auf den jeweils anderen Port (nie auf `br1`).
* Option 82 kommt in den PAD-Bereich hinter END; nur wenn der nicht reicht,
  wächst das Paket bis zur MTU. Prüfsummen und Längen werden neu berechnet,
  UDP-Prüfsumme 0 bleibt 0, `giaddr`/`hops`/`flags`/MAC/IP bleiben unverändert.
* Bereits vorhandene Option 82, `giaddr` oder `hops` → unverändert
  weiterleiten (nie überschreiben).
* Antworten: eigene Option 82 entfernen. Fremde Option 82 bei passender
  `xid`/`chaddr` eines von uns markierten Requests ebenfalls entfernen und
  weiterleiten (falls der MikroTik unsere ersetzt). Bei durchgereichten
  Requests unverändert weiterleiten, sonst verwerfen. Ohne Option 82
  weiterleiten.
* `giaddr` setzt der Agent nie, das macht der MikroTik-Relay mit seiner
  öffentlichen IP.
* Watcher setzt Regeln wieder ein, die airOS gelöscht hat (alle 5 s), und
  startet den Worker neu. Fail-closed: stirbt der Worker, bleiben die Regeln
  stehen.

## Offene Punkte

* Verhalten des Upstream-MikroTik (Port `sfp-sfpplus23`) bei Requests, die
  schon Option 82 enthalten: trusted/untrusted, ersetzen oder behalten?
* Eigener DHCP-Server: Antwortet er bei `giaddr=0` und gibt er Option 82
  zurück? Welche Kennung wertet er aus?
* Persistenz ohne Boot-Hook (siehe README, „Persistenz“).
* Altes Kernelverhalten (broute + `ETH_P_IP`-Zustellung) auf dem Testgerät mit
  `--diag` nachweisen.
