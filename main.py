#!/usr/bin/env python3
import argparse
import random
import select
import socket
import struct
import sys
import time

DNS_Q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"


def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


def tcp_pkt(src, dst, sp, dp, flags, seq=0):
    hdr = struct.pack("!HHLLBBHHH", sp, dp, seq, 0, 80, flags, 5840, 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst), 0, 6, 20)
    cs = checksum(pseudo + hdr)
    return struct.pack("!HHLLBBHHH", sp, dp, seq, 0, 80, flags, 5840, cs, 0)


def scan_tcp(ip, ports, timeout):
    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp.connect((ip, 80))
    my_ip = tmp.getsockname()[0]
    tmp.close()

    sp = random.randint(40000, 60000)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setblocking(False)
    opened = {}

    for i in range(0, len(ports), 200):
        batch = ports[i : i + 200]
        pending = set(batch)
        times = {}
        for p in batch:
            try:
                s.sendto(tcp_pkt(my_ip, ip, sp, p, 0x02), (ip, 0))
                times[p] = time.time()
            except OSError:
                pending.discard(p)

        end = time.time() + timeout
        while pending and time.time() < end:
            r, _, _ = select.select([s], [], [], max(0, end - time.time()))
            if not r:
                break
            data, _ = s.recvfrom(65535)
            ihl = (data[0] & 0x0F) * 4
            src_p, dst_p, _, ack, _, flags = struct.unpack("!HHLLBB", data[ihl : ihl + 14])
            if dst_p != sp:
                continue
            if flags & 0x12 == 0x12:
                opened[src_p] = (time.time() - times[src_p]) * 1000
                pending.remove(src_p)
                s.sendto(tcp_pkt(my_ip, ip, sp, src_p, 0x04, ack), (ip, 0))
            elif flags & 0x04:
                pending.remove(src_p)

    s.close()
    return opened


def scan_udp(ip, ports, timeout):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp.setblocking(False)
    opened = []

    for i in range(0, len(ports), 200):
        batch = ports[i : i + 200]
        closed = set()
        for p in batch:
            try:
                udp.sendto(b"\x00", (ip, p))
            except OSError:
                closed.add(p)

        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([icmp], [], [], max(0, end - time.time()))
            if not r:
                break
            data, _ = icmp.recvfrom(65535)
            ihl = (data[0] & 0x0F) * 4
            if len(data) >= ihl + 28 and data[ihl : ihl + 2] == b"\x03\x03":
                inner = ihl + 8
                in_ihl = (data[inner] & 0x0F) * 4
                if len(data) >= inner + in_ihl + 4 and socket.inet_ntoa(data[inner + 16 : inner + 20]) == ip:
                    _, dp = struct.unpack("!HH", data[inner + in_ihl : inner + in_ihl + 4])
                    closed.add(dp)

        for p in batch:
            if p not in closed:
                opened.append(p)

    udp.close()
    icmp.close()
    return opened


def guess(is_tcp, ip, port, timeout):
    checks = []
    if is_tcp:
        checks.append(("HTTP", f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()))
    checks.append(("ECHO", b"hello\r\n"))
    checks.append(("DNS", (struct.pack("!H", len(DNS_Q)) + DNS_Q) if is_tcp else DNS_Q))

    kind = socket.SOCK_STREAM if is_tcp else socket.SOCK_DGRAM
    for name, payload in checks:
        try:
            with socket.socket(socket.AF_INET, kind) as s:
                s.settimeout(timeout)
                if is_tcp:
                    s.connect((ip, port))
                    s.sendall(payload)
                    resp = s.recv(1024)
                else:
                    s.sendto(payload, (ip, port))
                    resp, _ = s.recvfrom(1024)
                if name == "HTTP" and resp.startswith(b"HTTP/"):
                    return "HTTP"
                if name == "ECHO" and b"hello" in resp:
                    return "ECHO"
                if name == "DNS" and (resp[2:4] if is_tcp else resp[:2]) == b"\x12\x34":
                    return "DNS"
        except OSError:
            pass
    return "-"


parser = argparse.ArgumentParser()
parser.add_argument("--timeout", type=float, default=2.0)
parser.add_argument("-j", "--num-threads", type=int, default=1)
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("-g", "--guess", action="store_true")
parser.add_argument("ip")
parser.add_argument("targets", nargs="+")
args = parser.parse_args()

if args.timeout <= 0 or args.num_threads < 1:
    sys.exit(1)

try:
    ip = socket.gethostbyname(args.ip)
    tcp_ports, udp_ports = set(), set()
    for t in args.targets:
        proto, raw = t.split("/", 1) if "/" in t else (t, "1-65535")
        ports = []
        for part in raw.split(","):
            if "-" in part:
                a, b = part.split("-", 1)
                a, b = int(a), int(b)
                if a > b or a < 1 or b > 65535:
                    sys.exit(1)
                ports.extend(range(a, b + 1))
            else:
                p = int(part)
                if p < 1 or p > 65535:
                    sys.exit(1)
                ports.append(p)
        if proto == "tcp":
            tcp_ports.update(ports)
        elif proto == "udp":
            udp_ports.update(ports)
        else:
            sys.exit(1)
except Exception:
    sys.exit(1)

if tcp_ports:
    res = scan_tcp(ip, sorted(tcp_ports), args.timeout)
    for p in sorted(res):
        line = f"TCP {p}"
        if args.verbose:
            line += f" {res[p]:.3f}"
        if args.guess:
            line += f" {guess(True, ip, p, args.timeout)}"
        print(line)

if udp_ports:
    for p in sorted(scan_udp(ip, sorted(udp_ports), args.timeout)):
        line = f"UDP {p}"
        if args.guess:
            line += f" {guess(False, ip, p, args.timeout)}"
        print(line)