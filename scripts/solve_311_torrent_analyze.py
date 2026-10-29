#!/usr/bin/env python3
"""Solver for Challenge 311 Torrent Analyze (picoCTF 2022, Forensics).

The pcap carries BitTorrent DHT traffic. The most frequent info_hash
(e2467cbf021192c241367b892230dc1e05c0580e, 29 of 36 occurrences) identifies
the downloaded torrent; its indexed name is `ubuntu-19.10-desktop-amd64.iso`.
(The single announce_peer 'name' in the capture — a Zoo (2017) WEB-DL string —
belongs to a different info_hash and is a decoy.)

Usage: solve_311_torrent_analyze.py [torrent.pcap path]
Verified: academy{ubuntu-19.10-desktop-amd64.iso} (POST /api/submissions/ -> correct:true)
"""
import re
import sys
from collections import Counter

EXPECTED = "academy{ubuntu-19.10-desktop-amd64.iso}"
# info_hash -> torrent name (resolved via public torrent indexers)
HASH2NAME = {
    "e2467cbf021192c241367b892230dc1e05c0580e":
        "ubuntu-19.10-desktop-amd64.iso",
}


def solve(path: str = "torrent.pcap") -> str:
    d = open(path, "rb").read()
    vals = re.findall(rb"9:info_hash20:(.{20})", d, re.S)
    assert vals, "no info_hash values found"
    top, n = Counter(vals).most_common(1)[0]
    print("info_hash values:", len(vals), "| top:", top.hex(), "x%d" % n)
    name = HASH2NAME.get(top.hex())
    assert name, "unknown top info_hash: %s" % top.hex()
    flag = "academy{%s}" % name
    assert flag == EXPECTED, flag
    return flag


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "torrent.pcap"))
