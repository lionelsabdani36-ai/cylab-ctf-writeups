"""Solver for challenge 84 shark on wire 2 (picoCTF 2019, Forensics).

The pcap hides one byte per UDP packet: packets with udp.dstport == 22 form
the covert stream framed by payload markers 'start'/'end', and the data byte
is chr(udp.srcport - 5000). Pure-stdlib pcap parser (no scapy needed).

Usage: solve_84_shark_on_wire_2.py <capture.pcap>
"""
import struct
import sys


def parse_pcap(path: str):
    raw = open(path, 'rb').read()
    magic = raw[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        endian = '<'
    elif magic == b'\xa1\xb2\xc3\xd4':
        endian = '>'
    else:
        raise ValueError('not a pcap file')
    off = 24
    pkts = []
    while off + 16 <= len(raw):
        _ts1, _ts2, incl, _orig = struct.unpack(endian + 'IIII', raw[off:off + 16])
        off += 16
        pkts.append(raw[off:off + incl])
        off += incl
    return pkts


def udp_ports(pkt: bytes):
    if len(pkt) < 14:
        return None
    eth = struct.unpack('!H', pkt[12:14])[0]
    ip = pkt[18:] if eth == 0x8100 else pkt[14:]
    if len(ip) < 20 or ip[9] != 17:  # not UDP
        return None
    ihl = (ip[0] & 0x0F) * 4
    udp = ip[ihl:]
    if len(udp) < 8:
        return None
    sport, dport, ulen = struct.unpack('!HHH', udp[:6])
    return sport, dport, udp[8:8 + max(0, ulen - 8)]


def solve(path: str) -> str:
    chars = []
    started = False
    for pkt in parse_pcap(path):
        u = udp_ports(pkt)
        if not u or u[1] != 22:
            continue
        sport, _dport, payload = u
        if not started:
            if payload == b'start':
                started = True
            continue
        if payload == b'end':
            break
        chars.append(chr(sport - 5000))
    return ''.join(chars)


if __name__ == '__main__':
    print(solve(sys.argv[1]))
