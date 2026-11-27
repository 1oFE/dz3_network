import argparse
import random
import select
import socket
import struct
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


def scan_tcp(ip, ports, timeout):
    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp.connect((ip, 80))
    my_ip = tmp.getsockname()[0]
    tmp.close()

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
            s.sendto(pkt, (ip, 0))
            times[p] = time.time()

        end = time.time() + timeout
        while pending:
            wait = end - time.time()
            if wait <= 0:
                break
            r, _, _ = select.select([s], [], [], wait)
            if not r:
                break

            data, _ = s.recvfrom(65535)
            ihl = (data[0] & 0x0F) * 4
            if socket.inet_ntoa(data[12:16]) != ip:
                continue

            sp, dp, seq, ack, _, flags = struct.unpack("!HHLLBB", data[ihl : ihl + 14])
            if dp != src_port or sp not in pending:
                continue

            if flags & 0x12 == 0x12:
                opened[sp] = (time.time() - times[sp]) * 1000
                pending.remove(sp)
                rst = make_tcp(my_ip, ip, src_port, sp, 0x04, ack)
                s.sendto(rst, (ip, 0))
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
            udp.sendto(b"\x00", (ip, p))

        end = time.time() + timeout
        while True:
            wait = end - time.time()
            if wait <= 0:
                break
            r, _, _ = select.select([icmp, udp], [], [], wait)
            if not r:
                break

            for sock in r:
                data, _ = sock.recvfrom(65535)
                if sock == icmp:
                    ihl = (data[0] & 0x0F) * 4
                    if data[ihl] == 3 and data[ihl + 1] == 3:
                        inner = ihl + 8
                        inner_ihl = (data[inner] & 0x0F) * 4
                        if socket.inet_ntoa(data[inner + 16 : inner + 20]) == ip:
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
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        resp = s.recv(1024)
        s.close()
        if resp.startswith(b"HTTP/"):
            return "HTTP"
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(b"hello\r\n")
        resp = s.recv(1024)
        s.close()
        if b"hello" in resp:
            return "ECHO"
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(struct.pack("!H", len(DNS_Q)) + DNS_Q)
        resp = s.recv(1024)
        s.close()
        if resp[2:4] == b"\x12\x34":
            return "DNS"
    except Exception:
        pass

    return "-"


def guess_udp(ip, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"hello", (ip, port))
        resp, _ = s.recvfrom(1024)
        s.close()
        if b"hello" in resp:
            return "ECHO"
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(DNS_Q, (ip, port))
        resp, _ = s.recvfrom(1024)
        s.close()
        if resp[:2] == b"\x12\x34":
            return "DNS"
    except Exception:
        pass

    return "-"


parser = argparse.ArgumentParser()
parser.add_argument("--timeout", type=float, default=2.0)
parser.add_argument("-j", "--num-threads", type=int, default=1)
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("-g", "--guess", action="store_true")
parser.add_argument("ip")
parser.add_argument("targets", nargs="*")
args = parser.parse_args()

tcp_ports = set()
udp_ports = set()
for t in args.targets:
    if "/" in t:
        proto, raw = t.split("/")
        ports = []
        for part in raw.split(","):
            if "-" in part:
                a, b = part.split("-")
                ports.extend(range(int(a), int(b) + 1))
            else:
                ports.append(int(part))
    else:
        proto = t
        ports = range(1, 65536)

    if proto.lower() == "tcp":
        tcp_ports.update(ports)
    elif proto.lower() == "udp":
        udp_ports.update(ports)

ip = socket.gethostbyname(args.ip)

if tcp_ports:
    res = scan_tcp(ip, sorted(tcp_ports), args.timeout)
    for p in sorted(res):
        out = f"TCP {p}"
        if args.verbose:
            out += f" {res[p]:.1f}"
        if args.guess:
            out += f" {guess_tcp(ip, p, args.timeout)}"
        print(out)

if udp_ports:
    res = scan_udp(ip, sorted(udp_ports), args.timeout)
    for p in sorted(res):
        out = f"UDP {p}"
        if args.guess:
            out += f" {guess_udp(ip, p, args.timeout)}"
        print(out)