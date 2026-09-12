#!/usr/bin/env python3
"""Generate a small synthetic PCAP for drill 02. Standard library only.

The capture contains two HTTP requests on one TCP connection between a fictional
workstation and a fictional service, including a JSON POST that carries a
synthetic flag. Every value is invented for practice; nothing is captured from a
real network.

Usage:
    python make-synthetic-pcap.py OUT.pcap                 # pcap only
    python make-synthetic-pcap.py OUT.pcap --transcript    # also a text view
    python make-synthetic-pcap.py OUT.pcap --json          # machine summary

The output is deterministic: same input arguments, same file bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from typing import Dict, List, Tuple

CLIENT_IP = "10.0.0.42"
SERVER_IP = "10.0.0.10"
SERVER_PORT = 8080
CLIENT_PORT = 49152
CLIENT_MAC = bytes.fromhex("020000000042")
SERVER_MAC = bytes.fromhex("020000000010")
BASE_TS = 1_800_000_000  # fixed epoch: deterministic output

FLAG = "FLAG{synthetic_pcap_reconstruction_7f3a}"
POST_BODY = '{"title":"drill note","body":"' + FLAG + '","tags":["synthetic"]}'

REQUESTS: List[Tuple[bytes, bytes]] = [
    (
        b"GET /healthz HTTP/1.1\r\n"
        b"Host: 10.0.0.10:8080\r\n"
        b"User-Agent: drill-client/1.0\r\n"
        b"Accept: */*\r\n"
        b"\r\n",
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 15\r\n"
        b"\r\n"
        b'{"status":"ok"}',
    ),
    (
        (
            "POST /api/notes HTTP/1.1\r\n"
            "Host: 10.0.0.10:8080\r\n"
            "User-Agent: drill-client/1.0\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(POST_BODY)}\r\n"
            "\r\n" + POST_BODY
        ).encode("ascii"),
        b"HTTP/1.1 201 Created\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 17\r\n"
        b"\r\n"
        b'{"id":"note-7"}\r\n',
    ),
]

# direction, seq, ack, tcp flags, payload. "c" = client -> server, "s" = server.
Packet = Tuple[str, int, int, int, bytes]


def build_packets() -> List[Packet]:
    packets: List[Packet] = []
    cseq, sseq = 1000, 5000
    packets.append(("c", cseq, 0, 0x02, b""))  # SYN
    packets.append(("s", sseq, cseq + 1, 0x12, b""))  # SYN-ACK
    packets.append(("c", cseq + 1, sseq + 1, 0x10, b""))  # ACK
    for request, response in REQUESTS:
        packets.append(("c", cseq + 1, sseq + 1, 0x18, request))
        cseq += len(request)
        packets.append(("s", sseq + 1, cseq + 1, 0x18, response))
        sseq += len(response)
    packets.append(("c", cseq + 1, sseq + 1, 0x11, b""))  # FIN-ACK
    packets.append(("s", sseq + 1, cseq + 2, 0x11, b""))  # FIN-ACK
    packets.append(("c", cseq + 2, sseq + 2, 0x10, b""))  # ACK
    return packets


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip_bytes(address: str) -> bytes:
    return bytes(int(part) for part in address.split("."))


def _ipv4(src: str, dst: str, payload_len: int, ident: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + payload_len,
        ident,
        0x4000,
        64,
        6,
        0,
        _ip_bytes(src),
        _ip_bytes(dst),
    )
    return header[:10] + struct.pack("!H", _checksum(header)) + header[12:]


def _tcp(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload_len: int,
) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0
    )
    pseudo = (
        _ip_bytes(src_ip)
        + _ip_bytes(dst_ip)
        + struct.pack("!BBH", 0, 6, len(header) + payload_len)
    )
    return header[:16] + struct.pack("!H", _checksum(pseudo + header)) + header[18:]


def render(packet: Packet, ident: int) -> bytes:
    direction, seq, ack, flags, payload = packet
    if direction == "c":
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
        sport, dport = CLIENT_PORT, SERVER_PORT
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
    else:
        src_ip, dst_ip = SERVER_IP, CLIENT_IP
        sport, dport = SERVER_PORT, CLIENT_PORT
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
    tcp = _tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, len(payload))
    ip = _ipv4(src_ip, dst_ip, len(tcp) + len(payload), ident)
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + tcp + payload


def build_pcap() -> Tuple[bytes, Dict[str, object]]:
    packets = build_packets()
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, packet in enumerate(packets):
        frame = render(packet, 600 + index)
        ts = BASE_TS + index
        out += struct.pack("<IIII", ts, index * 10000, len(frame), len(frame))
        out += frame
    summary = {
        "client": f"{CLIENT_IP}:{CLIENT_PORT}",
        "server": f"{SERVER_IP}:{SERVER_PORT}",
        "packets": len(packets),
        "requests": [
            {"method": "GET", "path": "/healthz"},
            {"method": "POST", "path": "/api/notes"},
        ],
        "flag": FLAG,
        "note_id": "note-7",
        "user_agent": "drill-client/1.0",
    }
    return bytes(out), summary


def transcript() -> str:
    lines = [
        "synthetic transcript for the pcap drill (no real traffic)",
        f"{CLIENT_IP}:{CLIENT_PORT} -> {SERVER_IP}:{SERVER_PORT}",
        "",
    ]
    for request, response in REQUESTS:
        lines.append(">>> request")
        lines.append(request.decode("ascii", "replace").rstrip())
        lines.append("<<< response")
        lines.append(response.decode("ascii", "replace").rstrip())
        lines.append("")
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="path for the generated .pcap")
    parser.add_argument(
        "--transcript", action="store_true", help="also write OUT.pcap.transcript.txt"
    )
    parser.add_argument("--json", action="store_true", help="print a JSON summary")
    args = parser.parse_args(argv)

    data, summary = build_pcap()
    with open(args.output, "wb") as fh:
        fh.write(data)
    summary["pcap"] = os.path.abspath(args.output)
    summary["sha256"] = hashlib.sha256(data).hexdigest()
    summary["bytes"] = len(data)
    if args.transcript:
        path = args.output + ".transcript.txt"
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(transcript())
        summary["transcript"] = os.path.abspath(path)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            f"wrote {summary['pcap']} ({summary['bytes']} bytes, "
            f"{summary['packets']} packets, sha256 {summary['sha256'][:16]}...)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
