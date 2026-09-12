# Drill 02 — PCAP to request reconstruction

**Time:** 15-20 minutes. **Track:** PCAP/forensics.
**Data:** a synthetic capture you generate yourself; no real traffic is stored in
this repository.

## Goal

Take an unfamiliar capture, find the application conversation, reconstruct the
requests, and produce the exact answer a challenged teammate would need: which
request carried data, what path it hit, and what was in the body.

## Setup

Generate the capture (takes a second):

```bash
mkdir -p captures
python drills/assets/make-synthetic-pcap.py captures/drill02.pcap --json
```

The file lists the synthetic ground truth in JSON, so do not read that output
before working the capture. Record the packet count and move on.

Tooling: `tshark`/Wireshark if available. If neither is installed, ask the
generator for the text view with `--transcript` and work from that; say which
track you used when you report.

## Tasks

1. List the TCP conversations. Which two endpoints are talking, and on which
   server port?
2. Follow the client-to-server stream. How many HTTP requests are in it?
3. Reconstruct each request line: method, path, HTTP version.
4. Extract the `User-Agent`.
5. One request carries a JSON body. Recover it byte for byte, then extract the
   flag from the body and the `Content-Length` that declared its size.
6. State the exact filter or command you used for each answer, so a teammate
   could repeat it under time pressure.

## Expected evidence

* A conversation summary naming `10.0.0.42` and the server port.
* Two request lines: one `GET`, one `POST`.
* The POST body with the synthetic flag and the declared length.
* The `User-Agent` string.

## Success criteria

* You produce the flag unchanged, and the path, method and length match the
  capture exactly.
* You can explain how you would do the same against a live service with a
  bounded capture (`./ctfctl watch --iface <iface> --seconds 60`) instead of a
  file.

## Reset

```bash
rm captures/drill02.pcap*        # generated, git-ignored, safe to delete
```
