#!/usr/bin/env python3
import argparse
import random
import select
import socket
import struct
import sys
import time

DNS_Q = (
    struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + b"\x07example\x03com\x00"
    + struct.pack("!HH", 1, 1)
)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def make_tcp(src_ip, dst_ip, src_port, dst_port, flags, seq=0):
    hdr = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, 0, 5 << 4, flags, 5840, 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(hdr))
    cs = checksum(pseudo + hdr)
    return struct.pack("!HHLLBBHHH", src_port, dst_port, seq, 0, 5 << 4, flags, 5840, cs, 0)


def parse_targets(targets):
    tcp_ports = set()
    udp_ports = set()

    for t in targets:
        if "/" in t:
            proto, raw = t.split("/", 1)
            if not raw:
                sys.exit(1)
            ports = []
            for part in raw.split(","):
                try:
                    if "-" in part:
                        a, b = map(int, part.split("-", 1))
                        if a > b or not (1 <= a <= 65535 and 1 <= b <= 65535):
                            sys.exit(1)
                        ports.extend(range(a, b + 1))
                    else:
                        p = int(part)
                        if not (1 <= p <= 65535):
                            sys.exit(1)
                        ports.append(p)
                except ValueError:
                    sys.exit(1)
        else:
            proto = t
            ports = range(1, 65536)

        if proto.lower() == "tcp":
            tcp_ports.update(ports)
        elif proto.lower() == "udp":
            udp_ports.update(ports)
        else:
            sys.exit(1)

    return sorted(tcp_ports), sorted(udp_ports)


def scan_tcp(ip, ports, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tmp:
        try:
            tmp.connect((ip, 80))
            my_ip = tmp.getsockname()[0]
        except OSError:
            my_ip = "127.0.0.1"

    src_port = random.randint(40000, 60000)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setblocking(False)

    opened = {}
    for i in range(0, len(ports), 200):
        batch = ports[i : i + 200]
        pending = set(batch)
        times = {}

        for p in batch:
            pkt = make_tcp(my_ip, ip, src_port, p, 0x02)
            try:
                s.sendto(pkt, (ip, 0))
                times[p] = time.time()
            except OSError:
                pending.discard(p)

        end = time.time() + timeout
        while pending:
            wait = end - time.time()
            if wait <= 0:
                break
            r, _, _ = select.select([s], [], [], wait)
            if not r:
                break

            try:
                data, _ = s.recvfrom(65535)
            except OSError:
                continue

            if len(data) < 40:
                continue
            ihl = (data[0] & 0x0F) * 4
            if len(data) < ihl + 14 or socket.inet_ntoa(data[12:16]) != ip:
                continue

            sp, dp, seq, ack, _, flags = struct.unpack("!HHLLBB", data[ihl : ihl + 14])
            if dp != src_port or sp not in pending:
                continue

            if flags & 0x12 == 0x12:
                opened[sp] = (time.time() - times[sp]) * 1000
                pending.remove(sp)
                rst = make_tcp(my_ip, ip, src_port, sp, 0x04, ack)
                try:
                    s.sendto(rst, (ip, 0))
                except OSError:
                    pass
            elif flags & 0x04:
                pending.remove(sp)

    s.close()
    return opened


def scan_udp(ip, ports, timeout):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setblocking(False)
    udp.bind(("", 0))

    icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp.setblocking(False)

    opened = []
    for i in range(0, len(ports), 100):
        batch = ports[i : i + 100]
        closed = set()

        for p in batch:
            try:
                udp.sendto(b"\x00", (ip, p))
            except OSError:
                closed.add(p)

        end = time.time() + timeout
        while True:
            wait = end - time.time()
            if wait <= 0:
                break
            r, _, _ = select.select([icmp, udp], [], [], wait)
            if not r:
                break

            for sock in r:
                try:
                    data, _ = sock.recvfrom(65535)
                except OSError:
                    continue

                if sock == icmp and len(data) >= 28:
                    ihl = (data[0] & 0x0F) * 4
                    if len(data) >= ihl + 28 and data[ihl] == 3 and data[ihl + 1] == 3:
                        inner = ihl + 8
                        inner_ihl = (data[inner] & 0x0F) * 4
                        if len(data) >= inner + inner_ihl + 4 and socket.inet_ntoa(data[inner + 16 : inner + 20]) == ip:
                            _, dport = struct.unpack("!HH", data[inner + inner_ihl : inner + inner_ihl + 4])
                            closed.add(dport)

        for p in batch:
            if p not in closed:
                opened.append(p)

    udp.close()
    icmp.close()
    return opened


def guess_tcp(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            if s.recv(1024).startswith(b"HTTP/"):
                return "HTTP"
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(b"hello\r\n")
            if b"hello" in s.recv(1024):
                return "ECHO"
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(struct.pack("!H", len(DNS_Q)) + DNS_Q)
            resp = s.recv(1024)
            if len(resp) >= 4 and resp[2:4] == b"\x12\x34":
                return "DNS"
    except OSError:
        pass

    return "-"


def guess_udp(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"hello", (ip, port))
            resp, _ = s.recvfrom(1024)
            if b"hello" in resp:
                return "ECHO"
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(DNS_Q, (ip, port))
            resp, _ = s.recvfrom(1024)
            if len(resp) >= 2 and resp[:2] == b"\x12\x34":
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
except socket.gaierror:
    sys.exit(1)

tcp_ports, udp_ports = parse_targets(args.targets)

if tcp_ports:
    res = scan_tcp(ip, tcp_ports, args.timeout)
    for p in sorted(res):
        out = f"TCP {p}"
        if args.verbose:
            out += f" {res[p]:.1f}"
        if args.guess:
            out += f" {guess_tcp(ip, p, args.timeout)}"
        print(out)

if udp_ports:
    res = scan_udp(ip, udp_ports, args.timeout)
    for p in sorted(res):
        out = f"UDP {p}"
        if args.guess:
            out += f" {guess_udp(ip, p, args.timeout)}"
        print(out)