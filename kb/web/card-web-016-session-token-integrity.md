# Decide whether a session token is forgeable by looking at its structure

**First useful action.** Decode the session cookie or token, then ask whether the server can verify
integrity or only read the value.

```bash
printf '%s' '<COOKIE_VALUE>' | base64 -d 2>/dev/null | xxd | head
# then compare two sessions created minutes apart for the same account
curl -sS -i -c <JAR_1> -d 'username=<USER>&password=<PASS>' 'http://127.0.0.1:<PORT>/login' | grep -i set-cookie
curl -sS -i -c <JAR_2> -d 'username=<USER>&password=<PASS>' 'http://127.0.0.1:<PORT>/login' | grep -i set-cookie
```

Expected: a readable structure (payload, separator, signature-like suffix) or a plain identifier. If the
same account receives the same token twice, the value is server-side state, not a self-contained token —
which shifts the question to how that identifier is generated. If the value is structured and unsigned,
the question becomes whether the server recomputes the signature at all.

## Symptoms

- The session value looks like `base64(json).base64(mac)`, a long hex string, or a bare sequential
  identifier.
- The value contains a username, user id, role, or expiry in clear text.
- Sessions survive a password change, or a token stays valid after logout.

## Prerequisites and assumptions

- Two sessions you control (or two accounts), and the ability to send a modified cookie.
- Local service you may test against.
- Stack/version: signed-cookie mechanisms (for example framework session signing) differ entirely from
  JWT-style tokens and from opaque server-side session ids; identify which one you are looking at before
  drawing conclusions.

## Diagnostic sequence

1. Decode the token structure. → Readable fields, separators, or apparent signature.
2. Compare two tokens for the same account and two for different accounts. → Detects sequential or
   predictable generation, and identifies which fields vary.
3. Modify one decoded field and re-encode (identity/role/expiry) and send it back. → If the server accepts
   it, integrity is not verified. If it rejects with a signature error, integrity check exists.
4. If the token is opaque, look for the generator in source. → Non-cryptographic randomness or a
   timestamp-derived value makes the identifier predictable (`src-enowars-buggy-readme-f85b8d0e`,
   `src-thomasweigold-saarctf2025-eaa12cba`).
5. Check whether the token survives logout, password change, and restart. → Determines the blast radius of
   a stolen token and the correctness of the fix.

If the token is verifiably signed and unpredictable, stop — spend the time on
`card-web-023-route-method-role-matrix` instead of hunting a forgery that is not there.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `... \| base64 -d \| xxd` | JSON-ish bytes with a trailing binary blob | Self-contained token with a signature segment. |
| `... \| base64 -d` | `{"user":"<USER>","role":"user"}` with no MAC | Unsigned payload — tamper candidate. |
| two logins, identical cookie | same value | Server-side session keyed by a stable identifier. |
| two logins, value increments or contains a timestamp | sequential value | Predictable generation; acceptance depends on the lookup. |
| modified field accepted | `200` instead of `401` | The server trusts the client's claim. |

## Exploit → patch pair

- **Flaw:** a security-relevant value supplied by the client is accepted without server-side
  verification of integrity or freshness.
- **Reproduce on the isolated fixture:** against a local fixture with a two-account seed, decode your own
  cookie, change only the identity field, and observe whether the response follows the modified value
  (not yet run here).
- **Narrow patch:** stop deriving the principal from the cookie payload. Resolve it from a server-side
  session store, or verify the signature/MAC with the framework's own session mechanism and reject
  tampered values. Predictable identifiers must be replaced with a cryptographically secure generator —
  *not* with a different constant seed (`src-thomasweigold-saarctf2025-eaa12cba` documents the seed-change patch as
  an event example, explicitly not as recommended cryptography).
- **Legitimate functionality that must keep working:** login, logout, "remember me" if the product has
  it, and any checker flow that logs in, stores an object, and retrieves it in a later cycle.
- **Verify:** the tampered cookie is rejected **and** a fresh legitimate login still yields a working
  session that can create and retrieve data.

## Failure modes and things teams stopped doing

- "Fixing" predictability by changing a seed constant. Recorded in the SaarCTF 2025 Routerploit writeup
  as an event patch; the durable fix is a CSPRNG (`src-thomasweigold-saarctf2025-eaa12cba`).
- Adding a signature check only on the login route while other routes still read the cookie payload.
  Sweep every place the token is parsed.
- Invalidating all sessions to "be safe". That logs out the checker and legitimate users; it is a
  functional regression in an availability-scored event (`src-enowars-checker-tenets-bf4b0ac7`).
- Trusting "it is a framework, so it is signed". The framework signs only if the configured session
  mechanism is used; hand-rolled cookies next to a framework are common — the FAUST CTF 2020 Django
  writeup is indexed as an example of service-specific trust-boundary reasoning that transferred better
  than the framework details (`src-fluix-faust2020-marsu-8b6084b7`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No cookie was decoded and no session was created in this session.
- **Our adaptation vs the source:** the predictable-token patterns come from `src-enowars-buggy-readme-f85b8d0e` and
  `src-thomasweigold-saarctf2025-eaa12cba`; the "keep trust-boundary reasoning, drop framework specifics" caution is
  from `src-fluix-faust2020-marsu-8b6084b7`. The decode-then-tamper-one-field procedure is our synthesis and is written
  as a decision tree so the team can stop early when the token is genuinely protected.

## Sources

- `src-enowars-buggy-readme-f85b8d0e` — indexed A/D service with predictable token and authorization-logic defects.
- `src-thomasweigold-saarctf2025-eaa12cba` — predictable token construction and a seed-change patch kept as an
  anti-example.
- `src-fluix-faust2020-marsu-8b6084b7` — Django-era A/D web service; trust-boundary reasoning over framework trivia.
- `src-enowars-checker-tenets-bf4b0ac7` — service functionality must survive a defensive change.
