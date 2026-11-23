import argparse
import random
import select
import socket
import struct
import sys
import time


def get_local_ip(target_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


def calc_checksum(data):
    if len(data) % 2 != 0:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def build_tcp_packet(src_ip, dst_ip, src_port, dst_port, flags, seq=0):
    ack_num = 0
    data_offset = 5
    offset_res = (data_offset << 4) + 0
    window = socket.htons(5840)
    urgent_ptr = 0

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack_num,
        offset_res,
        flags,
        window,
        0,
        urgent_ptr,
    )

    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    pseudo_header = struct.pack(
        "!4s4sBBH",
        src_addr,
        dst_addr,
        0,
        socket.IPPROTO_TCP,
        len(tcp_header),
    )

    checksum = calc_checksum(pseudo_header + tcp_header)

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack_num,
        offset_res,
        flags,
        window,
        checksum,
        urgent_ptr,
    )
    return tcp_header


def parse_ports(port_args):
    tcp_ports = []
    udp_ports = []

    for arg in port_args:
        if "/" in arg:
            proto, ports_str = arg.split("/", 1)
            ports_list = []
            for part in ports_str.split(","):
                if "-" in part:
                    start, end = part.split("-", 1)
                    for p in range(int(start), int(end) + 1):
                        if 1 <= p <= 65535:
                            ports_list.append(p)
                else:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports_list.append(p)
        else:
            proto = arg
            ports_list = list(range(1, 65536))

        proto = proto.lower()
        if proto == "tcp":
            tcp_ports.extend(ports_list)
        elif proto == "udp":
            udp_ports.extend(ports_list)
        else:
            sys.exit(1)

    return sorted(set(tcp_ports)), sorted(set(udp_ports))


def scan_tcp(target_ip, ports, timeout):
    if not ports:
        return {}

    local_ip = get_local_ip(target_ip)
    src_port = random.randint(40000, 60000)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setblocking(False)

    open_ports = {}
    batch_size = 200

    for i in range(0, len(ports), batch_size):
        batch = ports[i : i + batch_size]
        pending = set(batch)
        send_times = {}

        for port in batch:
            syn_pkt = build_tcp_packet(local_ip, target_ip, src_port, port, flags=0x02)
            try:
                sock.sendto(syn_pkt, (target_ip, 0))
                send_times[port] = time.time()
            except OSError:
                pending.discard(port)

        deadline = time.time() + timeout

        while pending and time.time() < deadline:
            wait_time = deadline - time.time()
            if wait_time <= 0:
                break

            ready, _, _ = select.select([sock], [], [], wait_time)
            if not ready:
                break

            try:
                data, _ = sock.recvfrom(65535)
            except OSError:
                continue

            if len(data) < 40:
                continue
            ihl = (data[0] & 0x0F) * 4
            pkt_src_ip = socket.inet_ntoa(data[12:16])
            if pkt_src_ip != target_ip:
                continue

            tcp_data = data[ihl : ihl + 20]
            if len(tcp_data) < 20:
                continue

            pkt_src_port, pkt_dst_port, pkt_seq, pkt_ack, _, pkt_flags, _, _, _ = struct.unpack(
                "!HHLLBBHHH", tcp_data
            )

            if pkt_dst_port != src_port or pkt_src_port not in pending:
                continue

            if (pkt_flags & 0x12) == 0x12:
                rtt_ms = (time.time() - send_times[pkt_src_port]) * 1000.0
                open_ports[pkt_src_port] = rtt_ms
                pending.discard(pkt_src_port)

                rst_pkt = build_tcp_packet(
                    local_ip, target_ip, src_port, pkt_src_port, flags=0x04, seq=pkt_ack
                )
                try:
                    sock.sendto(rst_pkt, (target_ip, 0))
                except OSError:
                    pass

            elif pkt_flags & 0x04:
                pending.discard(pkt_src_port)

    sock.close()
    return open_ports


def scan_udp(target_ip, ports, timeout):
    if not ports:
        return []

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setblocking(False)
    udp_sock.bind(("", 0))

    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.setblocking(False)

    open_ports = []
    batch_size = 100

    for i in range(0, len(ports), batch_size):
        batch = ports[i : i + batch_size]
        closed_ports = set()

        for port in batch:
            try:
                udp_sock.sendto(b"\x00", (target_ip, port))
            except OSError:
                pass

        deadline = time.time() + timeout

        while time.time() < deadline:
            wait_time = deadline - time.time()
            if wait_time <= 0:
                break

            ready, _, _ = select.select([icmp_sock, udp_sock], [], [], wait_time)
            if not ready:
                break

            for s in ready:
                try:
                    data, addr = s.recvfrom(65535)
                except OSError:
                    continue

                if s == icmp_sock:
                    if len(data) < 28:
                        continue
                    ihl = (data[0] & 0x0F) * 4
                    icmp_type = data[ihl]
                    icmp_code = data[ihl + 1]

                    if icmp_type == 3 and icmp_code == 3:
                        inner_start = ihl + 8
                        if len(data) < inner_start + 28:
                            continue
                        inner_ihl = (data[inner_start] & 0x0F) * 4
                        inner_dst_ip = socket.inet_ntoa(data[inner_start + 16 : inner_start + 20])
                        if inner_dst_ip != target_ip:
                            continue

                        udp_start = inner_start + inner_ihl
                        if len(data) >= udp_start + 4:
                            _, dst_port = struct.unpack("!HH", data[udp_start : udp_start + 4])
                            if dst_port in batch:
                                closed_ports.add(dst_port)

        for port in batch:
            if port not in closed_ports:
                open_ports.append(port)

    udp_sock.close()
    icmp_sock.close()
    return open_ports


def make_dns_query():
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    return header + question


def guess_tcp_protocol(target_ip, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, port))
        req = f"GET / HTTP/1.0\r\nHost: {target_ip}\r\n\r\n".encode()
        s.sendall(req)
        resp = s.recv(1024)
        s.close()
        if resp.startswith(b"HTTP/"):
            return "HTTP"
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, port))
        test_msg = b"ECHO_TEST_12345\r\n"
        s.sendall(test_msg)
        resp = s.recv(1024)
        s.close()
        if b"ECHO_TEST_12345" in resp:
            return "ECHO"
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, port))
        query = make_dns_query()
        s.sendall(struct.pack("!H", len(query)) + query)
        resp = s.recv(1024)
        s.close()
        if len(resp) >= 14 and resp[2:4] == b"\x12\x34":
            return "DNS"
    except Exception:
        pass

    return "-"


def guess_udp_protocol(target_ip, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(make_dns_query(), (target_ip, port))
        resp, _ = s.recvfrom(1024)
        s.close()
        if len(resp) >= 12 and resp[0:2] == b"\x12\x34":
            return "DNS"
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        test_msg = b"ECHO_TEST_12345"
        s.sendto(test_msg, (target_ip, port))
        resp, _ = s.recvfrom(1024)
        s.close()
        if b"ECHO_TEST_12345" in resp:
            return "ECHO"
    except Exception:
        pass

    return "-"


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("-j", "--num-threads", type=int, default=1)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-g", "--guess", action="store_true")
    parser.add_argument("ip")
    parser.add_argument("targets", nargs="+")

    args = parser.parse_args()

    target_ip = socket.gethostbyname(args.ip)
    tcp_ports, udp_ports = parse_ports(args.targets)

    tcp_open = scan_tcp(target_ip, tcp_ports, args.timeout)
    for port in sorted(tcp_open.keys()):
        parts = ["TCP", str(port)]
        if args.verbose:
            parts.append(f"{tcp_open[port]:.1f}")
        if args.guess:
            proto = guess_tcp_protocol(target_ip, port, args.timeout)
            parts.append(proto)
        print(" ".join(parts))

    udp_open = scan_udp(target_ip, udp_ports, args.timeout)
    for port in sorted(udp_open):
        parts = ["UDP", str(port)]
        if args.guess:
            proto = guess_udp_protocol(target_ip, port, args.timeout)
            parts.append(proto)
        print(" ".join(parts))


if __name__ == "__main__":
    main()