#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The dhcp-snooping-82 authors
#
# ebtables stand-in for the namespace integration test.
#   broute: the rules are emulated by integration.sh with nft, listings
#           report what the agent expects (BROUTE_RULES).
#   filter: kept in a JSON state file next to this script and turned into
#           the nft table "bridge ds82sg" after every change, so the
#           source guard rules really filter the test traffic.
# Every call is appended to ebt.log next to this script. DS82_EBT_REJECT=OPT
# makes every filter rule with that option fail.
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(sys.argv[0]))
STATE = os.path.join(HERE, "ebt_state.json")
BUILTIN = ("INPUT", "FORWARD", "OUTPUT")
BROUTE_RULES = int(os.environ.get("DS82_BROUTE_RULES", "13"))


def load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"chains": {c: [] for c in BUILTIN}, "policy": {}}


def save(st):
    with open(STATE + ".tmp", "w") as f:
        json.dump(st, f)
    os.rename(STATE + ".tmp", STATE)


PROTO = {"IPv4": "ip", "ARP": "arp", "IPv6": "ip6", "802_1Q": "vlan"}


def nft_rule(spec):
    out, i = [], 0
    while i < len(spec):
        a = spec[i]
        v = spec[i + 1] if i + 1 < len(spec) else None
        if a == "-p":
            out.append("ether type " + PROTO[v])
        elif a == "--vlan-encap":
            out.append("vlan type " + PROTO[v])
        elif a == "-i":
            out.append('iifname "%s"' % v)
        elif a == "-s":
            out.append("ether saddr " + v)
        elif a == "--ip-src":
            out.append("ip saddr " + v)
        elif a == "--arp-ip-src":
            out.append("arp saddr ip " + v)
        elif a == "--arp-mac-src":
            out.append("arp saddr ether " + v)
        elif a == "--ip6-src":
            out.append("ip6 saddr " + v)
        elif a == "--ip6-proto":
            out.append("meta l4proto " + v)
        elif a == "-j":
            out.append({"RETURN": "return", "DROP": "drop", "ACCEPT": "accept"}
                       .get(v, "jump " + v))
        else:
            raise SystemExit("fake ebtables: unsupported %s" % a)
        i += 2
    return " ".join(out)


def apply_nft(st):
    lines = ["table bridge ds82sg {}", "delete table bridge ds82sg",
             "table bridge ds82sg {"]
    users = [c for c in st["chains"] if c not in BUILTIN]
    for c in users:
        lines.append("chain %s {" % c)
        lines += ["  " + nft_rule(r) for r in st["chains"][c]]
        lines.append("}")
    for c, hook in (("INPUT", "input"), ("FORWARD", "forward")):
        lines.append("chain %s { type filter hook %s priority 0;" % (c, hook))
        lines += ["  " + nft_rule(r) for r in st["chains"][c]]
        lines.append("}")
    lines.append("}")
    r = subprocess.run(["nft", "-f", "-"], input="\n".join(lines) + "\n",
                       text=True, capture_output=True)
    if r.returncode:
        sys.stderr.write(r.stderr)
        sys.exit(2)


def listing(st, chain):
    rules = st["chains"][chain]
    pol = st["policy"].get(chain, "ACCEPT")
    print("Bridge chain: %s, entries: %d, policy: %s" % (chain, len(rules), pol))
    for r in rules:
        print(" ".join(r) + " ")


def filter_table(args):
    # an option the old kernel module might not know
    reject = os.environ.get("DS82_EBT_REJECT")
    if reject and reject in args:
        return 255
    st = load()
    ch = st["chains"]
    op = args[0]
    chain = args[1] if len(args) > 1 else None
    if op == "-L":
        if chain not in ch:
            return 1
        listing(st, chain)
        return 0
    if op == "-N":
        if chain in ch:
            return 1
        ch[chain] = []
        if len(args) > 3 and args[2] == "-P":
            st["policy"][chain] = args[3]
    elif op == "-P":
        if chain not in ch:
            return 1
        st["policy"][chain] = args[2]
    elif op == "-F":
        if chain not in ch:
            return 1
        ch[chain] = []
    elif op == "-X":
        if chain not in ch or chain in BUILTIN or \
                any(r[-1] == chain for c in ch.values() for r in c):
            return 1
        del ch[chain]
    elif op == "-A":
        if chain not in ch:
            return 1
        ch[chain].append(args[2:])
    elif op == "-I":
        if chain not in ch:
            return 1
        ch[chain].insert(int(args[2]) - 1, args[3:])
    elif op == "-D":
        if chain not in ch or args[2:] not in ch[chain]:
            return 1
        ch[chain].remove(args[2:])
    else:
        return 1
    save(st)
    apply_nft(st)
    return 0


def broute(args):
    if args[:2] == ["-L", "BROUTING"]:
        print("Bridge chain: BROUTING, entries: 1, policy: ACCEPT")
        print("-j DHCP_SNOOPING_82 ")
    elif args[:2] == ["-L", "DHCP_SNOOPING_82"]:
        print("Bridge chain: DHCP_SNOOPING_82, entries: %d, policy: RETURN"
              % BROUTE_RULES)
        for _ in range(BROUTE_RULES):
            print("-j DROP ")
    return 0


def main():
    args = sys.argv[1:]
    with open(os.path.join(HERE, "ebt.log"), "a") as f:
        f.write(" ".join(args) + "\n")
    table = "filter"
    if args[:1] == ["-t"]:
        table, args = args[1], args[2:]
    return broute(args) if table == "broute" else filter_table(args)


if __name__ == "__main__":
    sys.exit(main())
