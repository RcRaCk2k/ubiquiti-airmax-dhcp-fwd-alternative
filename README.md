# dhcp-snooping-82

Transparenter DHCPv4-Option-82-Agent (RFC 3046) für Ubiquiti airOS 8
(PowerBeam 5AC, WA.v8.7.11). Er ersetzt `/bin/dhcp-fwd` und versieht jedes
DHCP-Clientpaket, das physisch auf `eth0` ankommt, genau einmal mit
Circuit-ID (Hostname) und Remote-ID (MAC von `br1`). Das gilt auch für
Unicast-Renews. Die Bridge bleibt sonst unverändert. Kein L3-Relay: `giaddr`
bleibt 0.

Ist-Analyse und Architektur: [docs/ANALYSIS.md](docs/ANALYSIS.md).
Lizenz: MIT ([LICENSE](LICENSE)).

## Build

```sh
make toolchain      # Zig 0.13.0 (clang + musl), SHA256 geprüft, nach .toolchain/
make                # build/mips/dhcp-fwd: statisch, MIPS32r2 BE, soft-float
make test           # Unit-Tests (ASan/UBSan, Fuzzing) + tshark-Prüfung
make integration    # Bridge-Simulation in Netz-Namensräumen, ohne root
make dist           # build/dist/dhcp-snooping-82-<ver>.tar.gz
```

Der Build ist reproduzierbar: gleiche Quellen ergeben bitgleiche Binaries,
die SHA256 steht in `build/mips/dhcp-fwd.sha256`.

## Installation (ein Testgerät, Schritt für Schritt)

```sh
# vom PC
scp build/mips/dhcp-fwd scripts/dhcp-snooping-82.sh etc/dhcp-snooping-82.conf root@GERÄT:/tmp/
# auf dem Gerät
sh /tmp/dhcp-snooping-82.sh install            # nach /etc/persistent/dhcp-snooping-82, prüft Binary
/etc/persistent/dhcp-snooping-82/dhcp-fwd --check
/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh diag 120   # passiv, sendet nichts
/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh activate   # Health-Check, sonst Rollback
/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh status
# erst wenn alles passt, dauerhaft speichern:
sh /etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh install --save
```

Zurück zum Original: `dhcp-snooping-82.sh deactivate` (oder `rollback`, das sperrt
zusätzlich `ensure` bis zum Reboot). Entfernen: `dhcp-snooping-82.sh uninstall --save`.

Im airOS-Webinterface schaltet der Schalter „DHCP Relay“ den Agent weiterhin
ein und aus, denn init startet weiter `/bin/dhcp-fwd`.

### Persistenz

Die Standard-Firmware führt beim Boot **keine** Custom-Scripts aus
(`rc.poststart` nur bei vorhandenem `/etc/poststart`, das nur CS-Firmware
anlegt). Nach einem Reboot läuft daher zunächst das Original, bis
`dhcp-snooping-82.sh ensure` aufgerufen wird. Vorgesehen ist der Aufruf durch die
Device-Discovery per SSH:

```sh
ssh root@GERÄT '/etc/persistent/dhcp-snooping-82/dhcp-snooping-82.sh ensure'
```

## Betrieb und Diagnose

```sh
dhcp-snooping-82.sh status                     # Modus, Prozesse, Zähler, Regeln
cat /var/run/dhcp-snooping-82.stats            # Zähler (alle 10 s aktualisiert)
grep dhcp-fwd /var/log/messages          # Log (RAM), ein Eintrag pro Paket
kill -HUP $(cat /var/run/dhcp-fwd.pid)   # Konfiguration neu laden

# Paketpfad
tcpdump -i eth0      -e -n -vvv -s0 'udp port 67 or udp port 68'
tcpdump -i ath0.1284 -e -n -vvv -s0 'udp port 67 or udp port 68'
dhcp-fwd --diag 60                       # zeigt pro Socket: ALL = alles, IP = nur ausgeleitet

# Regeln
ebtables -t broute -L --Lc               # Sprung nach DHCP_SNOOPING_82 an Position 1
ebtables -t broute -L DHCP_SNOOPING_82 --Lc    # Zähler = ausgeleitete DHCP-Frames
ebtables -L --Lc                         # airOS-Filter; FIREWALL-DHCP-Regeln werden nicht mehr gebraucht

# Prozesse
pidof dhcp-fwd; grep " /bin/dhcp-fwd " /proc/mounts
ls -l /proc/$(cat /var/run/dhcp-fwd.pid)/fd; cat /proc/net/packet
```

Logzeile, Beispiel:

```
req-mark if=eth0/2 type=REQUEST xid=0x30336d42 chaddr=1c:ed:6f:00:00:01 src=1c:ed:6f:00:00:01/198.51.100.175
  dst=dc:9f:db:00:00:01/198.51.100.0 giaddr=0.0.0.0 hops=0 reason=inserted cid="cust-example" rid="00005e005301"
```

## Verhalten

| Fall | Aktion |
|---|---|
| Client-Paket von eth0, ohne Option 82 | Option 82 in den PAD-Bereich, sonst Paket bis MTU vergrößern; einmal auf ath0.1284 senden |
| bereits Option 82 / `giaddr` / `hops` | unverändert weiterleiten (`existing_option82 = forward`) |
| fehlerhaft, Fragment, falsche Prüfsumme | unverändert weiterleiten, Zähler `req_malformed` |
| Antwort mit eigener Option 82 | Option 82 entfernen (Länge bleibt, PAD), an eth0 |
| Antwort mit fremder Option 82 zu einem von uns markierten Request (xid + chaddr) | Upstream hat unsere Option 82 ersetzt: Option 82 entfernen, an eth0 (`rep_foreign_ours_by_xid`) |
| Antwort mit fremder Option 82, durchgereichter Request | unverändert an eth0 |
| sonstige Antwort mit fremder Option 82 | verwerfen (andere Station) |
| Antwort ohne Option 82 | weiterleiten |
| DHCP-Request vom Uplink (Kunden anderer Stationen) | verworfen (Snooping, `block_uplink_requests`) |
| DHCP-Server-Antwort von eth0 (Server beim Kunden) | verworfen (Snooping, `block_client_servers`) |
| BOOTREPLY an Port 67 von eth0 / BOOTREQUEST an Port 68 vom Uplink | verworfen |
| Worker abgestürzt | Regeln bleiben (fail-closed), Neustart mit Backoff |
| airOS löscht Regeln (Apply) | innerhalb von 5 s neu gesetzt; dazwischen gilt das airOS-Verhalten, ohne Duplikate |
| SIGTERM (Relay im Webinterface aus, deactivate) | Regeln entfernen, beenden |
