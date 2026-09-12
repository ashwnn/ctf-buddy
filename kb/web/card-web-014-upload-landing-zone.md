# Trace where an uploaded file lands, and what serves it

**First useful action.** Upload one uniquely named benign file, then find the exact path on disk and
determine whether anything executes or serves it.

```bash
echo '<UPLOAD_MARKER_CONTENT>' > <LOCAL_TMP>/<UNIQUE_NAME>.txt
curl -sS -i -F 'file=@<LOCAL_TMP>/<UNIQUE_NAME>.txt' 'http://127.0.0.1:<PORT>/<UPLOAD_ROUTE>'
find / -xdev -name '<UNIQUE_NAME>*' -printf '%p %s %m\n' 2>/dev/null | head
```

Expected: the response indicates success and `find` locates the stored file (often renamed or hashed).
If `find` prints nothing, the file is stored outside the searched filesystem, in a database blob, or the
upload never persisted — each of those changes the attack surface completely.

## Symptoms

- A route accepts `multipart/form-data`, a file field, an avatar/attachment/import upload.
- The response returns a URL or filename for the uploaded object.
- A static location in the proxy config points at an "uploads" directory.

## Prerequisites and assumptions

- A benign marker file; never upload anything executable to a scored service.
- Local read access for the `find` step, or a response that discloses the stored path/URL.
- Stack/version: framework upload handling differs; the Flask upload pattern documents the
  trusted-directory plus filename-handling approach that the safe implementation is built on
  (`src-flask-send-from-directory-24ec5c2a`).

## Diagnostic sequence

1. Upload a uniquely named benign file and record the response. → Stored name, URL, or an ID.
2. Locate the file on disk. → The physical landing zone and its permissions.
3. Determine what serves it back: the application (through an auth-checked route) or the proxy/static
   handler directly. → Direct static serving bypasses every application-level fix.
4. Ask whether the stored name is derived from the *client-supplied* filename or from server-side
   generation. → Client-derived names enable path escape and extension tricks; server-derived names
   usually do not.
5. Ask whether the landing zone is inside any directory the runtime executes from, or that a template
   or script engine reads from. → That is when upload becomes code execution.

If the stored file is served statically from the same tree that the application deploys code into, go
straight to `card-web-015-upload-validation-patch` and treat it as high priority.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `curl -F 'file=@...' .../upload` | `200 {"url":"/files/<UNIQUE_NAME>.txt"}` | Stored and addressable; the returned name shows the naming scheme. |
| `find / -xdev -name '<UNIQUE_NAME>*'` | `/srv/<APP>/uploads/<UNIQUE_NAME>.txt 34 644` | Landing zone, size, and mode; world-readable uploads are worth noting. |
| `curl -sS -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:<PORT>/uploads/<NAME>.txt'` | `200` | Served without the application's authorization logic. |
| `curl -sS -i -F 'file=@<LOCAL_TMP>/<NAME>.txt;filename=../../../<UNIQUE_NAME>.txt'` (own fixture only) | file appears outside the upload root | Client-controlled name is used unsafely. |
| `ss -ltnp` + proxy `location` map | static root overlapping the app tree | Upload and execution share a directory — the dangerous configuration. |

## State-changing actions

- **Impact:** uploads add files to the scored host and can consume disk; an unrestricted upload is a
  persistent foothold and a disk-exhaustion risk.
- **Preconditions:** the landing zone is known, the legitimate upload workflow is recorded, and the
  checker uses the same endpoint (if it does not, the endpoint may be removable within the rules).
- **Health check before:** `<CHECKER_COMMAND> ... baseline` and one recorded legitimate upload →
  expect success.
- **Apply:** enforce server-side generation of the stored name, confirm the final resolved path stays
  inside the intended directory, and restrict the accepted types to the feature's real need.
- **Health check after:** the checker is green and one legitimate upload/download round-trip still works;
  regression probe: download a previously uploaded legitimate file by its returned URL.
- **Rollback:** restore the one handler file from its committed revision; never delete the upload
  directory (it may contain legitimate and checker-created data).

## Exploit → patch pair

- **Flaw:** the client influences where a file lands (name/path) or what it is (type/extension) more than
  the product requires.
- **Reproduce on the isolated fixture:** against a local fixture with an upload route, submit a file
  whose client filename contains `..` and observe whether it lands outside the upload root (not yet run
  here).
- **Narrow patch:** generate the stored name server-side (random identifier plus a fixed extension),
  confine the resolved path to the upload root, and validate type by server-side inspection rather than
  by the client's filename or `Content-Type`.
- **Legitimate functionality that must keep working:** ordinary upload, the returned URL, the download
  path, and any size/type limits the checker relies on.
- **Verify:** the path-escape attempt fails and the ordinary upload/download round-trip still returns the
  same content bytes.

## Failure modes and things teams stopped doing

- Trusting the client's `Content-Type` and filename extension. Both are attacker input.
- Assuming "we renamed it, so it is safe" without checking the resolved path. Renaming without
  confinement still allows `..` if the rename target is built from the client name.
- Fixing the application while a static location serves the same directory. The proxy keeps serving the
  uploaded file regardless of what the handler does (`src-nginx-switches-o19-a2887699` for reading the effective
  config).
- Ignoring disk usage. Upload features are a cheap way for another team to fill the filesystem and
  degrade the service; measure free space as part of your baseline.
- Testing upload execution on a shared host. Multi-language service corpora in the indexed A/D repos
  include services whose file handling is intentionally dangerous; practice on a local fixture
  (`src-c4tbuts4d-stayhomectf2022-61868263`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No file was uploaded and no filesystem search was performed in this
  session.
- **Our adaptation vs the source:** the trusted-directory and filename-handling guidance comes from the
  Flask upload pattern and API documentation (`src-flask-send-from-directory-24ec5c2a`). The specific landing-zone
  investigation (upload → find on disk → determine the serving component) is our adaptation for
  attack/defend, where knowing *what serves the file* decides whether an application patch is sufficient.

## Sources

- `src-flask-send-from-directory-24ec5c2a` — framework guidance for saving uploads to a fixed location safely.
- `src-c4tbuts4d-stayhomectf2022-61868263` — cross-language A/D service corpus with file-handling code paths.
- `src-nginx-switches-o19-a2887699` — reading which paths the proxy serves directly.
