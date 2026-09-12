# Rebuild an observed exploit from the capture, then prove it on your own instance

**First useful action.** Follow the conversation and recover it in order — method, path, query, headers, body — then replay the smallest equivalent request against your own copy of the service.

```bash
tshark -r <PCAP> -Y 'tcp.stream==<STREAM_ID>' -T fields \
  -e http.request.method -e http.request.uri -e http.host -e http.user_agent -e http.content_length 2>/dev/null | head
tshark -r <PCAP> -q -z follow,http,ascii,<STREAM_ID> 2>/dev/null | head -n 40
```

Expected: the request line plus enough of the stream to reconstruct the payload. If both commands return nothing, the stream is not decoded as HTTP — follow raw TCP bytes and frame the request yourself.

## Symptoms

- A capture contains one HTTP transaction that differs from every normal request.
- You know an attacker reached a privileged result, but not how.
- A teammate is trying to guess the payload instead of reading the one that worked.

## Prerequisites and assumptions

- A capture with the suspicious conversation, and either a local copy of the service or an owned test instance.
- Stream index or a stable way to re-select the conversation from the CLI.
- Assumption: HTTP is visible and unencrypted at your capture point. If TLS terminates elsewhere, this card needs keys or logs instead.

## Diagnostic sequence

1. Follow the stream and reconstruct the request verbatim → branch A: complete request recovered, replay it; branch B: gaps (compression, chunking, a second stream), so look for related streams by host/URI.
2. Replay the request once against `http://127.0.0.1:<PORT>` on `<LOCAL_FIXTURE>` → branch A: the same effect appears, so the primitive is proven and this becomes your regression test; branch B: no effect, so note the required state (the attacker's request may depend on data they created earlier).
3. Minimise: strip headers, cookies, and fields one class at a time, keeping method, path, auth state, and body → the short request becomes your exploit and your patch test.
4. Classify: label the transaction as exploit, scanner noise, checker behaviour, or failed attempt — a suspicious string alone is not an exploit.

If the replay works, go to `card-ad-narrow-trust-boundary-patch` with the minimised request as the exploit half of the pair. If it needs prior state, recreate the minimum prerequisite state locally instead of mutating your graded instance.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -r <PCAP> -Y 'http.request' -T fields -e tcp.stream -e http.request.uri` | stream ids and URIs | finds the candidate conversation; `<STREAM_ID>` selects it for the follow command |
| `tshark -r <PCAP> -q -z follow,http,ascii,<STREAM_ID>` | reconstructed request/response | the request you will replay; version-sensitive syntax |
| `curl -sS -X <METHOD> '<URL>' -H '<HEADER>' --data '<BODY>'` | status and body | one replay against your own instance; compare with the capture's response |
| `<SERVICE_ACCESS_LOG>` grep by timestamp | matching line | the same request as the service saw it, including what the capture could not show |

## State-changing actions

- **Impact:** replaying an exploit mutates the state of the instance you send it to; doing so against a peer is an attack, doing so against your graded instance can destroy flag data you need.
- **Preconditions:** an owned local copy or isolated fixture, a baseline you can restore, and permission to replay internally.
- **Health check before:** legitimate smoke test passing on the fixture.
- **Apply:** replay once, with the smallest client possible (a `curl` line or a short script), and capture the response and the service's own log line.
- **Health check after:** the legitimate smoke test still passes after the replay; regression probe: store-then-retrieve on the fixture.
- **Rollback:** restore the fixture from its snapshot. Replay is unsafe to automate against any host whose state you cannot reset.

## Exploit → patch pair

- **Flaw:** the recovered request reaches an object or operation the caller should not be able to address; the request is the evidence that the boundary is missing.
- **Reproduce on the isolated fixture:** `curl ... '<RECONSTRUCTED_REQUEST>'` against `http://127.0.0.1:<PORT>` → expect the privileged or foreign result.
- **Narrow patch:** fix the server-side condition the replayed request bypasses; do not blacklist the literal strings recovered from the capture.
- **Legitimate functionality that must keep working:** the original route's legitimate use with the same method and headers, including checker traffic that shares the URI.
- **Verify:** replay fails, legitimate request passes, and the minimised request still fails after a restart.

## Failure modes and things teams stopped doing

- Teams stopped chasing payload strings without effects. Retrospective guidance emphasises binding a suspect request to an actual effect on the service instead of treating an odd-looking string as a finding. [src-dttw-defcon2018-retro-83e7e6ea]
- Teams stopped replaying captured traffic at scale before understanding it. Reflecting suspicious traffic automatically is the fastest way to damage a service whose semantics you have not yet established. [src-maplebacon-ad-primer-23bd534f]
- Teams stopped assuming the capture shows everything. Payload recovery from logs worked in an event that exposed them; the technique is useful exactly where the sensor sits on the right layer. [src-vicevirus-ihack2024-12725f0d]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No capture was analysed and no request was replayed; `tshark` was unavailable in this session.
- **Our adaptation vs the source:** the minimise-and-freeze step is ours. The follow-stream mechanics come from the tool maintainer's documentation and are version-sensitive; the defensive framing comes from the cited team material.

## Sources

- `src-wireshark-follow-stream-00828e3e` — reconstructing a single application conversation from a capture.
- `src-tshark-man-page-d914bcdd` — CLI fields and follow statistics; pin the local version.
- `src-dttw-defcon2018-retro-83e7e6ea` — relating traffic to effects during a live event.
- `src-maplebacon-ad-primer-23bd534f` — A/D primer covering traffic analysis and reflection practices.
- `src-vicevirus-ihack2024-12725f0d` — log-based payload recovery.
