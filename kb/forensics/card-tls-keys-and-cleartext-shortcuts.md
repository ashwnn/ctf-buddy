# Check for a key log before spending a single minute on TLS

**First useful action.** Answer one question first: does a key log exist for these sessions? If not, stop treating the capture as a content source and switch to metadata plus endpoint artifacts.

```bash
tshark -r <CAPTURE.pcap> -o tls.keylog_file:<KEYLOG_FILE> -Y "http.request" -T fields -e frame.number -e ip.src -e http.host -e http.request.uri
```

Expected: decrypted HTTP rows. If the command returns nothing, either the key log does not cover these sessions, the handshake is missing from the capture, or your release spells the preference differently (`ssl.keylog_file` in older builds) — check `tshark -G defaultprefs | grep -i keylog` locally.

## Symptoms

- The interesting payload sits behind TLS and the challenge did not obviously hand you keys.
- A teammate is about to try "cracking" or brute-forcing TLS, or is searching for a decryptor tool.
- You have other protocols in the capture and are ignoring them because TLS looks like the hard path.

## Prerequisites and assumptions

- Capture contains at least the handshake for the sessions of interest, plus application records.
- A key log file exists **only** if a client was configured to write one (`SSLKEYLOGFILE` for NSS/OpenSSL-style clients, browser key-log settings) or the challenge provided it.
- Stack/version: Wireshark 3.6+/4.x; preference renamed over time; TLS 1.3 uses traffic secrets rather than a master secret.

## Diagnostic sequence

1. Inventory protocols first (`tshark -q -z io,phs`). Branch: cleartext protocols present (HTTP, FTP, SMTP, IMAP, POP, Telnet, SMB) → mine those fields directly; encrypted-only → continue.
2. Hunt for a key log inside the capture itself: check exported objects and stream text for lines beginning with `CLIENT_RANDOM` or containing `_TRAFFIC_SECRET`. Branch: found → decrypt; not found → step 3.
3. Check whether the file you were given covers these sessions: a key log must contain the client random from *this* handshake. Branch: the capture starts mid-session or the handshake is missing → decryption fails even with correct secrets.
4. If no keys exist and cannot exist, extract everything TLS still exposes: SNI (`tls.handshake.extensions_server_name`), certificates (`tls.handshake.certificate`), record sizes and timing. Branch: that metadata is enough for a volume/beaconing question → card-exfil-detection; you need *content* → go to endpoint artifacts (card-image-triage-memory-and-disk) and application logs.

If the cleartext shortcuts in step 1 give you a request you cannot interpret, go to card-unknown-protocol-triage.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -r <C> -q -z io,phs` | protocol tree | Which flows are cleartext and need no crypto work |
| `tshark -r <C> -o tls.keylog_file:<KEYLOG> -Y "tls"` | decrypted/tracked TLS frames | Preference name accepted for this release |
| `tshark -r <C> -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name` | SNI list | Destinations even without decryption |
| `tshark -r <C> -Y "ftp.request.command==\"USER\" \|\| ftp.request.command==\"PASS\"" -T fields -e ftp.request.command -e ftp.request.arg` | credentials | Cleartext protocol shortcut that needs no keys at all |
| `tshark -r <C> -Y "http.authorization" -T fields -e http.host -e http.authorization` | auth header values | HTTP Basic-style credentials in a cleartext capture |
| `tshark -r <C> -Y "smtp.req.command==\"AUTH\"" -T fields -e smtp.req.parameter` | SMTP auth parameters | Mail protocol shortcut (PLAIN/LOGIN variants are visible in clear) |

## State-changing actions (only if the card changes a host or service)

Not applicable to a capture file. One host-level action is worth knowing before the event: capturing your *own* client session with `SSLKEYLOGFILE` set in that client's environment produces a matching key log. That is a preparation technique for building a practice fixture, not a way to decrypt an opponent's traffic.

## Exploit → patch pair (web/service cards where applicable)

Not applicable in this lane. The transferable security judgment is defensive: if a service you own logs or transports data in a protocol with no encryption, the capture *is* the leak. The patch (enabling TLS, removing plaintext credentials from logs) belongs to the service-owner workflow.

## Failure modes and things teams stopped doing

- **Trying to break TLS.** Without keys, ECDHE and TLS 1.3 sessions are not recoverable from a capture; teams that spend a tick on this usually finish with nothing. The captured traffic is still a legitimate evidence source at the metadata level (S005 treats traffic analysis as defender evidence).
- **Assuming a private key decrypts everything.** A server private key only helps for RSA key exchange; modern handshakes negotiate ephemeral keys, so the key is useless for that session. Rule now: look for a *session* secret, not a key.
- **Assuming the key log is retroactive.** A key log created after the traffic was captured cannot decrypt sessions whose secrets were never logged. Rule now: match the key log to the session by client random before trusting a failed decryption.
- **Ignoring cleartext protocols.** Challenge authors pick protocols for convenience; the protocol hierarchy decides where the five free minutes go. Rule now: hierarchy first, TLS last.

## Evidence status

- **Status:** documentation-derived and version-sensitive; untested locally (no Wireshark/TShark, no key log or capture available).
- **What we actually ran:** nothing — preference names and key-log format are stated from tool documentation knowledge and must be confirmed with `tshark -G defaultprefs` on the event laptop.
- **Our adaptation vs the source:** the brief's bullet combined "TLS/key-log and cleartext-protocol shortcuts"; this card deliberately leads with the cleartext/missing-key branch because that is the branch a first-time team will actually hit.

## Sources

- `src-tshark-man-page-d914bcdd` — `-o` preference setting and TLS field names.
- `src-wireshark-follow-stream-00828e3e` — following streams, including when stream content is encrypted.
- `src-maplebacon-ad-primer-23bd534f` — treating captured traffic as defensive evidence, including when content is unavailable.
