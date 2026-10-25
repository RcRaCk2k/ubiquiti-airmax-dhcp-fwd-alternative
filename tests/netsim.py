#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The dhcp-snooping-82 authors
#
# Raw-socket DHCP client/server for the namespace integration test.
#   netsim.py server IFACE LOG SECONDS    answer requests, echo option 82
#   netsim.py client IFACE SCENARIO       run a client scenario, print JSON
#   netsim.py send IFACE KIND             send one crafted frame
#   netsim.py server6 IFACE LOG SECONDS   upstream relay/server for LDRA
#   netsim.py client6 IFACE MAC           Solicit/Request/Renew with IA_PD
#   netsim.py send6 IFACE KIND            ra, rogue-advertise, ...
#   netsim.py sniff6 IFACE LOG SECONDS    log DHCPv6 and RA frames
import json
import random
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
BCAST = b"\xff" * 6
SERVER_MAC = bytes.fromhex("02aabbccddee")
CLIENT_MAC = bytes.fromhex("021122334455")
SERVER_IP = 0x0A000001
LEASE_IP = 0x0A000064
PACKET_OUTGOING = 4


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(dst_mac, src_mac, src_ip, dst_ip, sport, dport, bootp):
    udp_len = 8 + len(bootp)
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 20 + udp_len, 0, 0, 64, 17, 0,
                     src_ip, dst_ip)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    pseudo = struct.pack("!IIBBH", src_ip, dst_ip, 0, 17, udp_len)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0)
    c = csum(pseudo + udp + bootp) or 0xFFFF
    udp = struct.pack("!HHHH", sport, dport, udp_len, c)
    return dst_mac + src_mac + b"\x08\x00" + ip + udp + bootp


def bootp(op, xid, chaddr, msgtype, ciaddr=0, yiaddr=0, flags=0x8000,
          options=b"", pad_to=300):
    b = struct.pack("!BBBBIHHIIII", op, 1, 6, 0, xid, 0, flags, ciaddr,
                    yiaddr, 0, 0)
    b += chaddr + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63"
    b += bytes([53, 1, msgtype]) + options + b"\xff"
    return b + b"\0" * max(0, pad_to - len(b))


def parse(f):
    """returns dict for DHCP frames, else None"""
    if len(f) < 14 + 20 + 8 + 240 or f[12:14] != b"\x08\x00":
        return None
    ihl = (f[14] & 0xF) * 4
    if f[14 + 9] != 17:
        return None
    u = 14 + ihl
    sport, dport, ulen, ucs = struct.unpack("!HHHH", f[u:u + 8])
    if not ({sport, dport} & {67, 68}):
        return None
    b = f[u + 8:u + ulen]
    r = {
        "dst": f[0:6].hex(), "src": f[6:12].hex(),
        "ip_dst": socket.inet_ntoa(f[14 + 16:14 + 20]),
        "op": b[0], "xid": struct.unpack("!I", b[4:8])[0],
        "chaddr": b[28:34].hex(), "ciaddr": socket.inet_ntoa(b[12:16]),
        "giaddr": socket.inet_ntoa(b[24:28]), "o82": None, "type": 0,
        "udp_csum_ok": True, "len": len(f),
    }
    if ucs:
        pseudo = f[14 + 12:14 + 20] + struct.pack("!BBH", 0, 17, ulen)
        r["udp_csum_ok"] = csum(pseudo + f[u:u + ulen]) == 0
    i = 240
    while i < len(b) and b[i] != 255:
        if b[i] == 0:
            i += 1
            continue
        code, ln = b[i], b[i + 1]
        val = b[i + 2:i + 2 + ln]
        if code == 53:
            r["type"] = val[0]
        elif code == 82:
            subs, j = {}, 0
            while j + 2 <= len(val):
                subs[val[j]] = val[j + 2:j + 2 + val[j + 1]].decode(
                    "latin1")
                j += 2 + val[j + 1]
            r["o82"] = subs
            r["o82_raw"] = val.hex()
        i += 2 + ln
    return r


def open_sock(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                      socket.htons(ETH_P_ALL))
    s.bind((iface, 0))
    s.settimeout(0.2)
    return s


def recv_dhcp(s, until, want_op=None):
    while time.time() < until:
        try:
            f, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        if addr[2] == PACKET_OUTGOING:
            continue
        p = parse(f)
        if p and (want_op is None or p["op"] == want_op):
            return p, f
    return None, None


# what a MikroTik bridge would put in if it replaced our option 82
UPSTREAM_O82 = bytes([1, 23]) + b"sfp-sfpplus23.dach:1281" + \
    bytes([2, 17]) + b"c4:ad:34:00:00:01"


def server(iface, log, seconds, mode="echo"):
    s = open_sock(iface)
    end = time.time() + float(seconds)
    with open(log, "w") as out:
        while time.time() < end:
            p, f = recv_dhcp(s, min(end, time.time() + 0.5), want_op=1)
            if not p:
                continue
            out.write(json.dumps(p) + "\n")
            out.flush()
            o82 = b""
            if mode == "replace":
                o82 = bytes([82, len(UPSTREAM_O82)]) + UPSTREAM_O82
            elif p["o82"] is not None:
                raw = bytes.fromhex(p["o82_raw"])
                o82 = bytes([82, len(raw)]) + raw
            chaddr = bytes.fromhex(p["chaddr"])
            opts = struct.pack("!BBI", 54, 4, SERVER_IP) + \
                struct.pack("!BBI", 51, 4, 3600) + o82
            if p["type"] == 1:
                rtype = 2
            elif p["type"] == 3:
                rtype = 5
            else:
                continue
            renew = p["ciaddr"] != "0.0.0.0"
            dst_mac = chaddr if renew else BCAST
            dst_ip = LEASE_IP if renew else 0xFFFFFFFF
            rep = bootp(2, p["xid"], chaddr, rtype, yiaddr=LEASE_IP,
                        ciaddr=LEASE_IP if renew else 0, options=opts)
            s.send(frame(dst_mac, SERVER_MAC, SERVER_IP, dst_ip, 67, 68, rep))


def client(iface, scenario, mac=None):
    global CLIENT_MAC
    if mac:
        CLIENT_MAC = bytes.fromhex(mac.replace(":", ""))
    s = open_sock(iface)
    xid = random.getrandbits(32)
    res = {"xid": xid, "steps": []}

    def exchange(name, f, want_type):
        s.send(f)
        p, _ = recv_dhcp(s, time.time() + 3, want_op=2)
        while p and p["xid"] != xid:
            p, _ = recv_dhcp(s, time.time() + 3, want_op=2)
        res["steps"].append({"name": name, "reply": p})
        return p

    if scenario == "full":
        exchange("discover", frame(BCAST, CLIENT_MAC, 0, 0xFFFFFFFF, 68, 67,
                 bootp(1, xid, CLIENT_MAC, 1)), 2)
        exchange("request-selecting", frame(
            BCAST, CLIENT_MAC, 0, 0xFFFFFFFF, 68, 67,
            bootp(1, xid, CLIENT_MAC, 3, options=struct.pack(
                "!BBIBBI", 50, 4, LEASE_IP, 54, 4, SERVER_IP))), 5)
        exchange("request-renewing-unicast", frame(
            SERVER_MAC, CLIENT_MAC, LEASE_IP, SERVER_IP, 68, 67,
            bootp(1, xid, CLIENT_MAC, 3, ciaddr=LEASE_IP, flags=0)), 5)
        exchange("request-rebinding", frame(
            BCAST, CLIENT_MAC, LEASE_IP, 0xFFFFFFFF, 68, 67,
            bootp(1, xid, CLIENT_MAC, 3, ciaddr=LEASE_IP, flags=0)), 5)
    elif scenario == "discover":
        exchange("discover", frame(BCAST, CLIENT_MAC, 0, 0xFFFFFFFF, 68, 67,
                 bootp(1, xid, CLIENT_MAC, 1)), 2)
    print(json.dumps(res))


def send(iface, kind):
    s = open_sock(iface)
    other = bytes.fromhex("02deadbeef01")
    if kind == "foreign-discover":
        # another station's customer, as seen on the uplink
        f = frame(BCAST, other, 0, 0xFFFFFFFF, 68, 67,
                  bootp(1, 0xF0F0F0F0, other, 1, options=bytes.fromhex(
                      "52100107") + b"cust-ex" + bytes.fromhex("0205")
                      + b"other"))
    elif kind == "foreign-offer":
        raw = bytes([1, 14]) + b"foreign-cust-1" + bytes([2, 5]) + b"other"
        f = frame(BCAST, SERVER_MAC, SERVER_IP, 0xFFFFFFFF, 67, 68,
                  bootp(2, 0xABCDEF01, CLIENT_MAC, 2, yiaddr=LEASE_IP,
                        options=bytes([82, len(raw)]) + raw))
    elif kind == "rogue-offer":
        # a DHCP server behind the customer's port
        f = frame(BCAST, CLIENT_MAC, 0xC0A8B201, 0xFFFFFFFF, 67, 68,
                  bootp(2, 0x0BADF00D, other, 2, yiaddr=0xC0A8B264))
    else:
        raise SystemExit("unknown kind")
    s.send(f)


def sniff(iface, log, seconds):
    s = open_sock(iface)
    end = time.time() + float(seconds)
    with open(log, "w") as out:
        while time.time() < end:
            p, _ = recv_dhcp(s, end)
            if p:
                out.write(json.dumps(p) + "\n")
                out.flush()


# ------------------------------------------------------------------
# DHCPv6 / IPv6

ALL_RELAYS = bytes.fromhex("ff020000000000000000000000010002")
ALL_NODES = bytes.fromhex("ff020000000000000000000000000001")
MCAST_RELAYS_MAC = bytes.fromhex("333300010002")
MCAST_NODES_MAC = bytes.fromhex("333300000001")
PD_PREFIX = bytes.fromhex("20010db8010000000000000000000000")


def link_local(mac):
    eui = bytes([mac[0] ^ 2]) + mac[1:3] + b"\xff\xfe" + mac[3:6]
    return bytes.fromhex("fe80000000000000") + eui


def frame6(dst_mac, src_mac, src, dst, nh, payload, hop=255):
    hdr = struct.pack("!IHBB", 0x60000000, len(payload), nh, hop) + src + dst
    return dst_mac + src_mac + b"\x86\xdd" + hdr + payload


def l4csum6(src, dst, nh, data):
    pseudo = src + dst + struct.pack("!IxxxB", len(data), nh)
    return csum(pseudo + data)


def udp6(dst_mac, src_mac, src, dst, sport, dport, msg):
    u = struct.pack("!HHHH", sport, dport, 8 + len(msg), 0) + msg
    c = l4csum6(src, dst, 17, u) or 0xFFFF
    u = u[:6] + struct.pack("!H", c) + u[8:]
    return frame6(dst_mac, src_mac, src, dst, 17, u, hop=1)


def opt(code, data):
    return struct.pack("!HH", code, len(data)) + data


def opts6(data):
    r, i = {}, 0
    while i + 4 <= len(data):
        code, ln = struct.unpack("!HH", data[i:i + 4])
        r.setdefault(code, data[i + 4:i + 4 + ln])
        i += 4 + ln
    return r


def parse6(f):
    """dict for DHCPv6 and RA frames, else None"""
    if len(f) < 62 or f[12:14] != b"\x86\xdd":
        return None
    nh, src, dst = f[20], f[22:38], f[38:54]
    pl = f[54:54 + struct.unpack("!H", f[18:20])[0]]
    r = {"dst": f[0:6].hex(), "src": f[6:12].hex(), "ip_src": src.hex(),
         "ip_dst": dst.hex()}
    if nh == 58 and pl and pl[0] == 134:
        r["kind"] = "ra"
        return r
    if nh != 17:
        return None
    sport, dport, ulen, ucs = struct.unpack("!HHHH", pl[:8])
    if not ({sport, dport} & {546, 547}):
        return None
    m = pl[8:ulen]
    r.update({"kind": "dhcp6", "sport": sport, "dport": dport,
              "type": m[0], "csum_ok": l4csum6(src, dst, 17, pl[:ulen]) == 0})
    if m[0] in (12, 13):
        o = opts6(m[34:])
        r["link"] = m[2:18].hex()
        r["peer"] = m[18:34].hex()
        r["ifid"] = o.get(18, b"").decode("latin1")
        rid = o.get(37)
        r["rid"] = None if rid is None else [
            struct.unpack("!I", rid[:4])[0], rid[4:].decode("latin1")]
        inner = o.get(9, b"")
        r["inner_type"] = inner[0] if inner else None
        r["xid"] = inner[1:4].hex() if len(inner) >= 4 else None
        r["inner"] = inner.hex()
    else:
        r["xid"] = m[1:4].hex()
        o = opts6(m[4:])
        pd = o.get(25)
        r["ia_pd"] = pd is not None
        r["prefix"] = None
        if pd and 26 in opts6(pd[12:]):
            pfx = opts6(pd[12:])[26]
            r["prefix"] = "%s/%d" % (pfx[9:25].hex(), pfx[8])
    return r


def recv6(s, until, want=lambda p: True):
    while time.time() < until:
        try:
            f, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        if addr[2] == PACKET_OUTGOING:
            continue
        p = parse6(f)
        if p and want(p):
            return p, f
    return None, None


def client_msg6(mtype, xid, mac, ia_pd=True):
    duid = opt(1, struct.pack("!HH", 3, 1) + mac)
    m = bytes([mtype]) + xid + duid + opt(8, b"\0\0")
    if ia_pd:
        m += opt(25, struct.pack("!III", 1, 0, 0))
    return m


def server6(iface, log, seconds):
    """answers Relay-Forwards like an upstream relay + server would"""
    s = open_sock(iface)
    me = link_local(SERVER_MAC)
    end = time.time() + float(seconds)
    with open(log, "w") as out:
        while time.time() < end:
            p, f = recv6(s, min(end, time.time() + 0.5),
                         lambda p: p["kind"] == "dhcp6" and p["dport"] == 547)
            if not p:
                continue
            out.write(json.dumps(p) + "\n")
            out.flush()
            if p["type"] != 12:
                continue	# a plain client message: nothing relayed
            inner = bytes.fromhex(p["inner"])
            rtype = {1: 2, 3: 7, 5: 7, 6: 7, 11: 7}.get(inner[0])
            if not rtype:
                continue
            o = opts6(inner[4:])
            iapd = opt(25, struct.pack("!III", 1, 1800, 2880) + opt(
                26, struct.pack("!IIB", 3600, 7200, 56) + PD_PREFIX))
            reply = bytes([rtype]) + inner[1:4] + opt(1, o.get(1, b"")) + \
                opt(2, struct.pack("!HH", 3, 1) + SERVER_MAC) + iapd
            m = f[54 + 8:]
            rel = opts6(m[34:])
            rr = bytes([13, 0]) + m[2:34] + opt(18, rel[18]) + opt(9, reply)
            peer = m[18:34]
            s.send(udp6(f[6:12], SERVER_MAC, me, peer, 547, 547, rr))


def client6(iface, mac):
    macb = bytes.fromhex(mac.replace(":", ""))
    s = open_sock(iface)
    me = link_local(macb)
    res = {"steps": []}
    for name, mtype in (("solicit", 1), ("request", 3), ("renew", 5)):
        xid = random.getrandbits(24).to_bytes(3, "big")
        s.send(udp6(MCAST_RELAYS_MAC, macb, me, ALL_RELAYS, 546, 547,
                    client_msg6(mtype, xid, macb)))
        p, _ = recv6(s, time.time() + 3,
                     lambda p: p["kind"] == "dhcp6" and p["dport"] == 546 and
                     p["xid"] == xid.hex())
        res["steps"].append({"name": name, "xid": xid.hex(), "reply": p})
    print(json.dumps(res))


def send6(iface, kind):
    s = open_sock(iface)
    other = bytes.fromhex("02deadbeef01")
    if kind == "ra":
        # router advertisement from the customer's router
        src = link_local(CLIENT_MAC)
        ra = bytes([134, 0, 0, 0, 64, 0]) + struct.pack("!HII", 1800, 0, 0)
        c = l4csum6(src, ALL_NODES, 58, ra)
        ra = ra[:2] + struct.pack("!H", c) + ra[4:]
        f = frame6(MCAST_NODES_MAC, CLIENT_MAC, src, ALL_NODES, 58, ra)
    elif kind == "uplink-ra":
        src = link_local(SERVER_MAC)
        ra = bytes([134, 0, 0, 0, 64, 0]) + struct.pack("!HII", 1800, 0, 0)
        c = l4csum6(src, ALL_NODES, 58, ra)
        ra = ra[:2] + struct.pack("!H", c) + ra[4:]
        f = frame6(MCAST_NODES_MAC, SERVER_MAC, src, ALL_NODES, 58, ra)
    elif kind == "rogue-advertise":
        # DHCPv6 server behind the customer port
        f = udp6(MCAST_RELAYS_MAC, CLIENT_MAC, link_local(CLIENT_MAC),
                 ALL_RELAYS, 547, 547, client_msg6(2, b"\xba\xdf\x00", other))
    elif kind == "relay-forward":
        # spoofed Relay-Forward with a made-up Interface-ID
        inner = client_msg6(1, b"\x5f\x00\x0f", CLIENT_MAC)
        rf = bytes([12, 0]) + b"\0" * 16 + link_local(CLIENT_MAC) + \
            opt(18, b"spoofed") + opt(9, inner)
        f = udp6(MCAST_RELAYS_MAC, CLIENT_MAC, link_local(CLIENT_MAC),
                 ALL_RELAYS, 547, 547, rf)
    elif kind == "foreign-solicit":
        # another station's customer, as seen on the uplink
        f = udp6(MCAST_RELAYS_MAC, other, link_local(other), ALL_RELAYS,
                 546, 547, client_msg6(1, b"\xf0\xf0\xf0", other))
    else:
        raise SystemExit("unknown kind")
    s.send(f)


def sniff6(iface, log, seconds):
    s = open_sock(iface)
    end = time.time() + float(seconds)
    with open(log, "w") as out:
        while time.time() < end:
            p, _ = recv6(s, end)
            if p:
                out.write(json.dumps(p) + "\n")
                out.flush()


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "server":
        server(*sys.argv[2:6])
    elif cmd == "client":
        client(*sys.argv[2:5])
    elif cmd == "send":
        send(*sys.argv[2:4])
    elif cmd == "sniff":
        sniff(*sys.argv[2:5])
    elif cmd == "server6":
        server6(*sys.argv[2:5])
    elif cmd == "client6":
        client6(*sys.argv[2:4])
    elif cmd == "send6":
        send6(*sys.argv[2:4])
    elif cmd == "sniff6":
        sniff6(*sys.argv[2:5])
