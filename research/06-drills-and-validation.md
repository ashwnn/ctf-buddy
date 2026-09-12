# 06 - Drills and Validation

Research date: 2026-09-11

## Scope and design goal

This sequence is for a first-time team preparing for the priorities in the supplied Raymond James CTF 2026 brief: web exploitation, PCAP/forensics, rapid attack-defend discovery, narrow patching without destroying availability, and quick handoff. It does not assume any unpublished Raymond James rule, scoring model, checker behavior, network layout, flag lifetime, or permission to add services/ports.

The sequence deliberately uses a very small number of local fixtures:

1. `switchboard`, an original line-oriented TCP service for discovery and protocol probing.
2. `notehub`, an original Python stdlib + SQLite web service reused for request diagnosis, patching, regression, and the final rehearsal.
3. `support-transfer.pcapng`, an original synthetic capture with plain HTTP traffic and an exported artifact.
4. `rjprep-host`, a disposable Linux VM image for systemd/nftables failure and recovery.
5. `toy-checker`, an original local functional checker that persists state across checks.

All original fixtures should be released under MIT-0 or MIT. No third-party CTF source needs to be copied into the training repository. Real challenge releases are used as design evidence and optional extra practice.

### Why this shape

Real attack-defend releases show that the defender has to preserve service semantics, not merely suppress an exploit. The FAUST CTF 2024 Todo service publishes its service, checker, exploits, and patches under ISC. Its checker exercises ordinary functionality and later retrieves data it placed previously; its published JSON patch narrows unsafe deserialization rather than deleting the import feature. ENOWARS releases similarly bundle deliberately vulnerable services with checkers that place/retrieve flags and test functionality. That is the model used here: every defensive change has an explicit legitimate flow that must continue working.

The sequence should be runnable without Internet access after images/tools have been pre-cached. A paid platform, cloud account, LLM, or live target is not required.

## Source and license basis

| Source | Why it is useful here | License/use decision |
|---|---|---|
| FAUST CTF 2024 Todo List Service | Original attack-defend service with checker, exploit, patch, and persistence-oriented checker behavior | ISC. Reference implementation pattern; do not need to copy it. https://github.com/fausecteam/faustctf-2024-todo-list-service |
| FAUST `exploit_json.py` and `deserialize.patch` | Concrete exploit-to-narrow-patch pair while retaining the import workflow | ISC through repository. https://github.com/fausecteam/faustctf-2024-todo-list-service/tree/master/exploits and https://github.com/fausecteam/faustctf-2024-todo-list-service/tree/master/patches |
| ENOWARS 3 CyberAlchemist | Original attack-defend release with service, checker, listed vulnerabilities, and checker functionality tests | MIT. Reference only. https://github.com/enowars/enowars3-service-cyber-alchemist |
| ENOWARS 4 Buggy | Original attack-defend web service with vulnerable code paths and patch notes | MIT. Reference only. https://github.com/enowars/enowars4-service-buggy |
| ENOWARS specification | Checker/service design context for attack-defend systems | MIT. Reference only. https://github.com/enowars/specification |
| Google CTF 2024 Postviewer v3 | Official, source-linked challenge analysis showing how source review maps browser behavior to an exploit path | Reference only; verify per-file license before redistributing code. https://github.com/google/google-ctf/tree/main/2024/quals/web-postviewer3 |
| USTC Hackergame 2024 writeups | Organizer repository containing official and player writeups, useful as a source-linked writeup corpus | Writeups and unmarked source are CC BY-NC-SA 4.0. Reference only; do not fold content into permissively licensed fixtures. https://github.com/USTC-Hackergame/hackergame2024-writeups |
| Nmap reference guide | Service discovery and `-sV` behavior | Official documentation. https://nmap.org/book/man.html |
| `ss(8)` | Local listener/socket inspection | Linux man page. https://man7.org/linux/man-pages/man8/ss.8.html |
| Wireshark/TShark manual | Stream following, protocol filters, object export | Official documentation. https://www.wireshark.org/docs/man-pages/tshark |
| Python `sqlite3` | Correct parameter binding and persistence behavior | Official documentation. https://docs.python.org/3/library/sqlite3.html |
| Docker Compose networking/down | Isolated local topology and deterministic teardown, including volume removal | Official documentation. https://docs.docker.com/compose/how-tos/networking/ and https://docs.docker.com/reference/cli/docker/compose/down/ |
| nftables manual | Rule handles, ruleset listing, check mode, narrow deletion/recovery | Official netfilter documentation. https://netfilter.org/projects/nftables/manpage.html |
| systemd `journalctl`/`systemctl` | Host-level diagnosis in the recovery drill | Official/system manual documentation. https://www.freedesktop.org/software/systemd/man/latest/journalctl.html and https://www.freedesktop.org/software/systemd/man/latest/systemctl.html |
| GDB manual | Optional binary inspection extension | Official GNU documentation. https://sourceware.org/gdb/current/onlinedocs/gdb.html/ |

### Source-selection rule

Third-party challenge releases are evidence and optional extras, not hidden dependencies. The six primary drills use original synthetic fixtures so that:

- licensing is clear;
- reset state is deterministic;
- difficulty can be tuned for a first-time team;
- answer keys are stable;
- no online service is required;
- exercises teach a transferable workflow rather than one challenge author's framework.

## Required local tool pack

Pre-cache before the rehearsal:

- Docker Engine + Compose v2 for container drills.
- Python 3.11+.
- `curl`, `jq`, `nc`/`socat`.
- `nmap`.
- Wireshark and/or `tshark`.
- `file`, `strings`, `xxd`, `unzip`, `sha256sum`.
- `git` and `diff`.
- For the host drill only: a disposable Linux VM with systemd and nftables, plus `ss`, `journalctl`, `systemctl`, `nft`.
- Optional: Burp Suite Community, GDB, Ghidra, CyberChef offline.

Record versions once in `evidence/environment.txt`:

```sh
python3 --version
docker version --format '{{.Server.Version}}'
docker compose version
nmap --version | head -n 1
tshark --version | head -n 1
```

Do not make a drill fail only because Burp, Ghidra, or a GUI is unavailable. Every primary task has a CLI path.

## Fixture repository contract

The research deliverable does not pretend these files already exist. The build agent should implement this exact small layout:

```text
prep/
  LICENSE                 # MIT-0 or MIT for original fixtures
  README.md
  evidence/
    .gitkeep
  checker/
    toy_checker.py
  fixtures/
    d1-switchboard/
      compose.yaml
      service/
      workbench/
      reset.sh
    d2-notehub-diagnose/
      compose.yaml
      service/
      seed.py
      reset.sh
    d3-notehub-patch/
      compose.yaml
      service/            # same codebase at vulnerable starting revision
      tests/
      reset.sh
    d4-pcap/
      support-transfer.master.pcapng
      expected-sha256.txt # facilitator-only or sealed answer directory
      generation/
      reset.sh
    d5-host-recovery/
      provision/
      snapshots.md
      bad-hardening.nft
      notehub.service
    d6-rehearsal/
      compose.yaml
      injections/
      score.py
      reset.sh
  answers/                # keep out of participant distribution
    d1.md ... d6.md
  extras/
    reversing/
    encodings/
```

Container resets should always remove named data volumes because ordinary `docker compose down` does not remove them. Standard reset contract:

```sh
docker compose down -v --remove-orphans
git restore --source=HEAD --staged --worktree .
docker compose up -d --build
```

Never put captured credentials, organizer tokens, real flags, event VPN material, or participant secrets into the fixture repository.

---

# Part A - Participant drill sheets

Participant sheets intentionally omit ground truth and exact answer diffs. Facilitators keep Part B separate.

## Drill 1 - Unknown service to mapped attack surface

**Target time:** 40 minutes. Optional extension: 20 minutes.

**Training objective:** Turn an unfamiliar IP into a concise service map, identify a non-obvious application protocol, reproduce one authorization failure, and propose the narrow control point that should be changed.

### Prerequisites

- Docker Compose.
- `nmap`, `nc`, `curl`.
- Basic TCP/HTTP knowledge.
- No source code initially.

### Isolated topology

```text
participant shell
     |
     v
  workbench  ---- isolated Docker bridge ----  target
                                             |-- unknown TCP listener A
                                             |-- unknown TCP listener B
```

Only `workbench` can reach `target`. `target` has no Internet route. Do not publish target service ports to the LAN.

### Setup

From `fixtures/d1-switchboard`:

```sh
./reset.sh
docker compose ps
docker compose exec workbench bash
```

Participant receives only:

```text
Target hostname: target
Goal: identify services, document normal operations, and determine whether one user's stored object can be read by another user.
```

### Reset expectation

`./reset.sh` must:

1. `docker compose down -v --remove-orphans`;
2. restore pristine fixture files;
3. recreate the database with two users and at least three records;
4. start services;
5. run a 3-second health probe;
6. print only `target is ready` if successful.

No ports, credentials, record IDs, or vulnerability hints are printed by reset.

### Participant tasks

1. Find all listening TCP services reachable on `target` within five minutes.
2. Identify the application protocol or useful banner for each listener.
3. For each service, write one ordinary request and its observed response.
4. Determine which listener stores user records.
5. Create a record as the supplied trainee user.
6. Test whether a record owned by another seeded user can be retrieved without possessing that user's credential.
7. Capture the minimum request required to demonstrate the failure.
8. Write a one-sentence patch hypothesis naming the authorization boundary, not a generic recommendation such as "add authentication."

Suggested first commands if needed:

```sh
nmap -Pn -p- --min-rate 1000 target
nmap -Pn -sV -p <ports> target
nc -nv target <port>
curl -i http://target:<port>/
```

### Expected evidence

Save under `evidence/d1/`:

- `ports.txt`: port, protocol guess, version/banner confidence.
- `normal.txt`: one legitimate request/response per service.
- `exploit.txt`: single unauthorized request and response, with any session/token redacted if generated randomly.
- `map.md`: listener -> protocol -> function -> suspected source/control point.
- `patch-hypothesis.txt`: one or two sentences.

### Failure hints

Use in order, only if blocked:

1. `-sV` is a second pass after finding ports; do not start by throwing every Nmap feature at the target.
2. If a line-oriented service answers but the protocol is unclear, test newline-terminated verbs such as `HELP` and observe error grammar.
3. Compare the fields required for a legitimate "read my record" operation with the fields required by export/retrieval alternatives.

### Cleanup

```sh
exit
docker compose down -v --remove-orphans
```

### Optional deeper extension

Map target listeners from inside the target container with `ss -lntp`, then correlate PID -> executable -> source directory. Compare what an external attacker can infer with what a defender can prove locally.

---

## Drill 2 - Web request and source-code diagnosis

**Target time:** 45 minutes. Optional extension: 15 minutes.

**Training objective:** Reproduce an access-control defect from HTTP, trace it to a specific source query, and distinguish the authentication step from the per-object authorization step.

### Prerequisites

- Docker Compose.
- `curl`; Burp Community optional.
- Ability to read small Python handlers and SQLite calls.

### Isolated topology

```text
workbench/browser ---- isolated bridge ---- notehub:8080 ---- SQLite volume
```

The service is a tiny original stdlib application, not a framework puzzle. Endpoints:

```text
POST /register
POST /login
POST /api/notes
GET  /api/notes?id=<integer>
GET  /api/notes/mine
```

The participant is given an `alice` training account. Another user's note is pre-seeded.

### Setup

```sh
cd fixtures/d2-notehub-diagnose
./reset.sh
docker compose exec workbench bash
```

Source is mounted read-only at `/src` inside `workbench` after the first ten minutes. Before then, diagnose from requests.

### Reset expectation

`reset.sh` recreates the SQLite volume, seeds two accounts and known test data, starts NoteHub, then runs a legitimate register/login/create/read smoke test. It must fail reset if that smoke test fails.

### Participant tasks

**Black-box phase, 10 minutes**

1. Log in as Alice and create a note.
2. Identify how the service addresses a single note.
3. Change only one request element at a time.
4. Determine whether Alice can retrieve an object that is not hers.

**Source phase, 25 minutes**

5. Locate the handler for the vulnerable request.
6. Trace request parameter -> session identity -> SQL statement -> returned object.
7. Mark the exact missing condition or validation step.
8. Write a minimal proposed query/control-flow change.
9. List the legitimate flows that must be regression-tested after patching.

### Expected evidence

`evidence/d2/`:

- `baseline.http` with login, create, own-read.
- `unauthorized.http` with the smallest altered request.
- `source-path.txt` containing file, function, and relevant statement numbers.
- `root-cause.md` with no more than 150 words.
- `regression-list.txt` with at least: login, create, own read, list mine, restart/persistence.

### Failure hints

1. A successful login proves identity only. Ask where ownership is enforced on object retrieval.
2. Find the SQL that fetches one note. Compare columns in the `WHERE` clause to the authenticated session data already available to the handler.
3. Do not "fix" this by hiding numeric IDs or making them random. Treat the object identifier as attacker-controlled.

### Cleanup

```sh
docker compose down -v --remove-orphans
```

### Optional deeper extension

Capture one normal and one unauthorized request in Burp or `curl -v`, then produce a request-level diff with only semantically relevant changes.

---

## Drill 3 - Narrow patch plus legitimate workflow regression

**Target time:** 50 minutes. Optional extension: 20 minutes.

**Training objective:** Patch the diagnosed authorization bug with the smallest defensible change, prove the exploit is blocked, and prove ordinary stateful use still works after service restart.

### Prerequisites

- Completion of Drill 2 or the provided diagnosis sheet.
- Git/diff.
- Python/SQLite source reading.
- `toy-checker` available locally.

### Isolated topology

Same NoteHub topology as Drill 2, plus a separate checker container:

```text
workbench ---> notehub:8080 ---> SQLite service volume
                  ^
                  |
             toy-checker ---> checker-state volume
```

Checker state and service state are deliberately separate.

### Setup

```sh
cd fixtures/d3-notehub-patch
./reset.sh
docker compose exec workbench bash
python3 /checker/toy_checker.py --base-url http://notehub:8080 baseline
```

### Reset expectation

Reset restores vulnerable source, deletes service and checker volumes, seeds data, and requires one all-green baseline checker cycle before handing the lab to participants.

### Participant tasks

1. Reproduce the Drill 2 unauthorized read once.
2. Save a baseline checker result.
3. Make the smallest source change that binds single-note reads to the authenticated owner.
4. Rebuild/restart only the affected service.
5. Confirm the original unauthorized request now fails with an intentional authorization/not-found response.
6. Run the full checker.
7. Restart NoteHub without deleting its data volume.
8. Run the checker again and prove that a canary created before restart is still retrievable.
9. Save the diff and explain why the patch does not remove legitimate functionality.

### Expected evidence

`evidence/d3/`:

- `before-exploit.http`.
- `patch.diff`.
- `after-exploit.http`.
- `checker-before.json`.
- `checker-after.json`.
- `checker-after-restart.json`.
- `decision.md`: exact invariant now enforced and one known limitation.

### Failure hints

1. Prefer adding ownership to the data retrieval condition over adding a broad deny rule or disabling the route.
2. Python's SQLite API supports bound parameters. User-controlled IDs should not be concatenated into SQL.
3. If the exploit is gone but the checker fails, treat checker failure as a regression until disproved.

### Cleanup

```sh
docker compose down -v --remove-orphans
```

### Optional deeper extension

Add one regression test covering a note ID that does not exist and one covering a valid note owned by another user. Make status-code behavior deterministic so teammates can reason from logs quickly.

---

## Drill 4 - PCAP reconstruction and artifact extraction

**Target time:** 45 minutes. Optional extension: 20 minutes.

**Training objective:** Move from packet overview -> candidate stream -> reconstructed HTTP transaction -> exported file -> content verification, while rejecting a deliberate distractor.

### Prerequisites

- Wireshark or `tshark`.
- `file`, `unzip`, `sha256sum`, `strings`.
- No Internet.

### Isolated topology

No live target is required for the primary drill. Participants receive an immutable original capture:

```text
support-transfer.master.pcapng

Captured synthetic topology:
client 10.77.0.20 -> support-api 10.77.0.10:8088
noise  10.77.0.30 -> static-api  10.77.0.11:8000
```

The main traffic is HTTP over TCP by design so the reconstruction workflow is visible. All names, credentials, tokens, addresses, and artifacts are synthetic.

### Setup

```sh
cd fixtures/d4-pcap
./reset.sh
mkdir -p ../../../evidence/d4/objects
cp support-transfer.pcapng ../../../evidence/d4/working.pcapng
```

`reset.sh` copies the immutable master capture to a working filename and verifies its SHA-256 against a public fixture hash. It does not reveal the answer artifact hash.

### Participant tasks

1. Produce a one-page traffic inventory: endpoints, protocols, unusual ports, and HTTP hosts/URIs.
2. Identify the stream associated with a support export.
3. Reconstruct the relevant HTTP conversation.
4. Export the transferred object without manually copying bytes from the GUI if possible.
5. Identify the object type and unpack it safely into a new directory.
6. Record file hashes before reading contents.
7. Identify which request allowed a second client to repeat an export it did not initiate.
8. Find the deliberate distractor and write one reason it should not drive the conclusion.
9. Propose the smallest server-side change that prevents replay while retaining a valid one-time export workflow.

Useful TShark patterns:

```sh
tshark -r working.pcapng -q -z conv,tcp
tshark -r working.pcapng -Y http.request -T fields \
  -e frame.number -e ip.src -e http.host -e http.request.method -e http.request.uri

tshark -r working.pcapng -q -z 'follow,tcp,ascii,<stream-index>'
tshark -r working.pcapng -d tcp.port==8088,http --export-objects http,objects
```

### Expected evidence

`evidence/d4/`:

- `inventory.txt`.
- `http-requests.tsv`.
- `stream.txt` or a Wireshark stream export.
- `objects/` with exported object(s).
- `hashes.txt` generated before opening/unpacking artifacts.
- `artifact-notes.md` identifying content and provenance.
- `replay.md` identifying the repeated request and proposed replay-prevention invariant.
- `distractor.md` explaining why the decoy/noise is not primary evidence.

### Failure hints

1. Start with conversations and HTTP requests, not packet-by-packet scrolling.
2. If HTTP is on a nonstandard port and not decoded, use Decode As in Wireshark or TShark's `-d tcp.port==PORT,http`.
3. TShark can follow a stream and can export supported protocol objects directly.
4. A flag-looking string is evidence only when its stream, endpoint, and transaction context fit the question.

### Optional decoy observation

The noise stream contains a harmless HTTP path and response body designed to look CTF-ish. Treat it as an observation test, not a deception system. The exercise is simply to avoid confusing conspicuous strings with relevant evidence. It opens no extra port on a real target, performs no callback, and has no relationship to real credentials.

### Cleanup

```sh
rm -rf ../../../evidence/d4/objects
rm -f ../../../evidence/d4/working.pcapng
```

Keep the evidence files you intentionally submitted elsewhere.

### Optional deeper extension

Rebuild the capture from `generation/` on an isolated lab network and compare the generated packet/object hashes. This is maintainer work, not required for ordinary participants.

---

## Drill 5 - Failed hardening and safe recovery

**Target time:** 50 minutes. Optional extension: 20 minutes.

**Training objective:** Diagnose a defender-caused outage, recover narrowly, then fix the application vulnerability without using network denial as a substitute for patching.

### Prerequisites

- Disposable Linux VM, not a personal workstation/server.
- Snapshot support.
- systemd + nftables.
- `ss`, `curl`, `journalctl`, `systemctl`, `nft`, `diff`.

### Isolated topology

```text
operator workstation ---- host-only network ---- rjprep-host VM
                                              |-- notehub.service :8080
                                              |-- SQLite data
                                              |-- nftables
```

No bridged corporate/home LAN attachment. Use a host-only or dedicated NAT lab network.

### Setup

Facilitator reverts VM to snapshot `d5-broken` and provides:

```text
VM IP: assigned by the host-only lab DHCP
Symptom: the team's service checker has changed from green to unreachable after a defensive change.
Goal: recover availability without erasing service data, identify the failed hardening, and apply a narrower application fix.
```

Participant begins with:

```sh
ssh trainee@<vm>
```

`trainee` has passwordless sudo only in this disposable image.

### Reset expectation

Revert the entire VM snapshot. Do not attempt to simulate this reset by deleting files on a reused host. Snapshot must contain:

- seeded NoteHub data;
- `notehub.service` enabled/running;
- the intentionally bad nftables rule already applied;
- a pre-change nftables backup at `/root/rjprep/prechange.nft`;
- service source at a known Git commit;
- local checker on the operator workstation.

### Participant tasks

1. Determine whether failure is process, listener, application, or network path.
2. Capture evidence before changing anything:
   - service state;
   - recent service logs;
   - listeners/process ownership;
   - current firewall rules with rule handles.
3. Identify the minimum bad defensive change.
4. Remove or replace only that change. Do not flush the ruleset.
5. Verify ordinary checker traffic is restored.
6. Reproduce the known application authorization defect from Drill 2/3.
7. Apply the narrow application fix.
8. Verify both checker availability and exploit failure.
9. Produce a rollback command or file for every mutation made.

Suggested diagnosis order:

```sh
systemctl status notehub --no-pager
journalctl -u notehub --since '-10 min' --no-pager
ss -lntp
sudo nft -a list ruleset
curl -sv http://127.0.0.1:8080/health
```

### Expected evidence

`evidence/d5/`:

- `status-before.txt`.
- `journal-before.txt`.
- `sockets-before.txt`.
- `nft-before.txt`.
- `recovery-command.txt`.
- `checker-recovered.json`.
- `app-patch.diff`.
- `checker-final.json`.
- `rollback.md`.

### Failure hints

1. If localhost succeeds but the remote checker cannot connect, the application process may not be the failing layer.
2. List nftables with handles. A handle lets you delete a specific rule instead of flushing the complete ruleset.
3. Preserve evidence before mutation. "I restarted things until it worked" is not a diagnosable recovery process.
4. Blocking the scored service port is not a valid application-layer patch if legitimate clients require that service.

### Cleanup

Revert VM to the clean base snapshot. Do not leave the intentionally vulnerable VM running or bridged to another network.

### Optional deeper extension

Repeat with a second failure mode where the service is listening but create/update calls return 500 because a hardening change made the SQLite path read-only. Diagnose from `journalctl`, file ownership/mode, and a specific failing checker operation rather than from network state.

---

## Drill 6 - Team handoff with simultaneous priorities

**Target time:** 55 minutes. Optional extension: 20 minutes.

**Training objective:** Run a compressed attack-defend loop where discovery, exploitation evidence, defensive patching, checker health, monitoring, and written handoff happen concurrently.

### Prerequisites

- 3-5 participants recommended; works with 2 by combining roles.
- Completion of at least Drills 1-3.
- Docker Compose.
- Shared local notes directory or Git worktree.

### Isolated topology

```text
                    +------------------+
                    |   toy-checker    |---- checker-state volume
                    +---------+--------+
                              |
workbench/red  ---- isolated lab bridge ---- notehub:8080 ---- service volume
                              |
                    +---------+--------+
                    | attack-simulator |
                    +------------------+
```

The attack simulator sends only requests defined by the fixture. It cannot reach the host, Docker socket, Internet, or other networks.

### Initial roles

For four people:

- **Service owner:** maps source, owns patch/rollback.
- **Observer:** checker, logs, timestamps, evidence.
- **Offense/reproducer:** turns suspicious requests into a deterministic PoC against the lab fixture.
- **Coordinator:** prioritization, shared state, handoff quality.

For three, coordinator also observes. For two, one owns service/observer and one offense/coordinator.

### Setup

```sh
cd fixtures/d6-rehearsal
./reset.sh
docker compose up -d
python3 ../../checker/toy_checker.py --base-url http://notehub:8080 cycle --repeat 45
```

Facilitator starts `./injections/run.sh`. It has a fixed timeline and writes its own ground-truth log outside the participant share.

### Participant tasks

The team gets only:

```text
Keep the service functioning. Determine whether observed hostile requests are effective.
Patch proven vulnerabilities narrowly. Preserve checker-visible workflows and state.
At minute 28, the current service owner must hand the service to another person using written notes plus at most 90 seconds of voice.
```

Required team artifacts:

1. `STATUS.md`, continuously updated with:
   - service health;
   - known listeners/routes;
   - proven/possible vulnerabilities;
   - current patch and rollback;
   - next action;
   - evidence paths.
2. At least one deterministic exploit/reproducer request.
3. One minimal defensive diff.
4. Checker results before and after the patch.
5. One handoff entry written before role transfer.
6. An incident timeline with monotonic or wall-clock timestamps.

### Fixed rehearsal events

Participants are not told exact times in advance.

- **Minute 0:** vulnerable service healthy; checker cycles begin.
- **Minute 7:** attack simulator begins benign enumeration mixed with the real authorization probe.
- **Minute 18:** simulator increases the real probe frequency. No destructive requests.
- **Minute 28:** mandatory service-owner handoff.
- **Minute 36:** a facilitator injects a small availability regression in a configuration value. This does not change source code and has a documented rollback.
- **Minute 45:** simulator stops sending the exploit but checker continues.
- **Minute 55:** freeze changes and submit evidence.

### Expected evidence

`evidence/d6/`:

- `STATUS.md`.
- `timeline.md`.
- `poc.http`.
- `patch.diff`.
- `rollback.md`.
- `checker.jsonl`.
- `handoff.md`.
- `final-state.txt` with current container/service state and commit/diff hash.

### Failure hints

Facilitator may issue one at a time:

1. Checker failure and exploit success are different signals. Track them separately.
2. Do not patch from a suspicious log line alone. Reproduce the behavior against the local fixture.
3. If a new failure appears with no source diff, compare runtime/config state before rewriting code.
4. A handoff should let the next operator answer: what is broken, what changed, how do I verify, how do I roll back?

### Cleanup

```sh
docker compose down -v --remove-orphans
git restore --source=HEAD --staged --worktree .
```

### Optional deeper extension

Run the same timeline with all participants rotating roles at minute 28. Compare diagnosis time, checker downtime, and evidence quality to the first run.

---

# Part B - Facilitator answer keys

Do not distribute this section with participant sheets during a scored rehearsal.

## Answer key - Drill 1

### Intentionally vulnerable behavior

`switchboard` has two services:

- TCP/8081: small health/inventory HTTP endpoint.
- TCP/19090: line-oriented `RJNOTE/1` record service.

Normal protocol:

```text
HELP
LOGIN <username> <token>
PUT <label> <text>
GET <id>
EXPORT <id>
QUIT
```

The service validates record ownership in `GET` but the `EXPORT` path looks up a record by numeric ID only.

### Synthetic ground truth

- Alice trainee account owns record 1001.
- Bob seeded account owns record 1002 containing `RJLAB{map_then_probe}`.
- Alice's token must not authorize Bob's record.
- `GET 1002` after Alice login returns `ERR forbidden`.
- Vulnerable `EXPORT 1002` returns Bob's body.

### Reproducible attack path

After finding TCP/19090:

```sh
nc target 19090
HELP
LOGIN alice alice-lab-token
GET 1002
EXPORT 1002
```

Expected vulnerable result: `GET` is denied, `EXPORT` returns the foreign record.

The point is not the flag string. Evidence should show an inconsistent authorization decision between two operations on the same object.

### Defensive change

In the export handler, resolve the record using both object ID and authenticated owner, or load then compare `record.owner == session.user` before serializing. Reuse the same authorization helper as `GET` if available.

Do not:

- remove `EXPORT`;
- block TCP/19090;
- rely on hard-to-guess record IDs;
- accept a client-supplied owner name as authority.

### Why legitimate operations remain possible

Alice can still `EXPORT 1001`. Bob can export Bob's record using Bob's session. Only cross-owner export changes from success to forbidden/not-found.

### Evaluator checks

- Full port list found, including nonstandard 19090.
- Protocol identified from interaction, not just Nmap guess.
- At least one normal request per service recorded.
- Cross-owner failure reproduced with minimum input.
- Patch hypothesis names the missing ownership check.

### Build detail

Use Python `socketserver.ThreadingTCPServer` and `http.server.ThreadingHTTPServer` so the fixture is stdlib-only. Bind only inside the Compose network.

---

## Answer key - Drill 2

### Intentionally vulnerable behavior

NoteHub requires a valid session to call `GET /api/notes?id=N`, but its query is conceptually:

```python
row = db.execute(
    "SELECT id, owner, body FROM notes WHERE id = ?",
    (note_id,),
).fetchone()
```

Authentication exists; object ownership does not participate in selection or authorization.

### Synthetic ground truth

Seed data:

```text
alice / alice-lab-pass -> note 1: "alice baseline"
bob   / bob-lab-pass   -> note 2: "RJLAB{authn_is_not_authz}"
```

Alice can legitimately read note 1. The bug is that Alice can change `id=1` to `id=2` and receive note 2.

### Reproducible attack path

Use the service's cookie jar/session mechanism:

```sh
curl -sS -c cookies.txt -X POST http://notehub:8080/login \
  -d 'username=alice&password=alice-lab-pass'

curl -sS -b cookies.txt 'http://notehub:8080/api/notes?id=1'
curl -sS -b cookies.txt 'http://notehub:8080/api/notes?id=2'
```

Exact content type may be form or JSON, but keep it consistent across the fixture.

### Source diagnosis

Expected path:

```text
request query parameter id
 -> authenticated session user
 -> get_note(note_id)
 -> SELECT ... WHERE id = ?
 -> response serializer
```

Missing invariant: returned note must be owned by the authenticated principal, unless the application deliberately exposes a separate share capability.

### Defensive change

Preferred minimal query:

```python
row = db.execute(
    "SELECT id, owner, body FROM notes WHERE id = ? AND owner = ?",
    (note_id, session_user),
).fetchone()
```

Use bound parameters for both values. Python's official `sqlite3` documentation explicitly recommends placeholders instead of string formatting for user-controlled values.

### Why legitimate operations remain possible

The route is unchanged. An owner still reads their own note by ID. The only removed behavior is reading another owner's private object through the private-note route.

### Evaluator checks

- Participant distinguishes authenticated request from authorized object access.
- Root cause points to the query/control point, not numeric IDs as a concept.
- Proposed regression list includes persistence/restart, not only a single HTTP 200.

---

## Answer key - Drill 3

### Synthetic ground truth

Same object model as Drill 2. Before patch:

- own read succeeds;
- cross-owner read succeeds incorrectly;
- checker ordinary flows succeed.

After correct patch:

- own read succeeds;
- cross-owner read returns 404 or 403 consistently;
- create/list/read continue;
- checker can retrieve the canary created on the previous cycle after NoteHub restart.

### Expected patch shape

The preferred diff changes one retrieval query or central authorization helper. Example conceptual diff:

```diff
- WHERE id = ?
+ WHERE id = ? AND owner = ?
```

with parameters `(note_id, session_user)`.

Do not award full credit for:

```python
if note_id != 1:
    deny()
```

or route removal, blanket firewalling, filtering the literal flag, or client-side hiding.

### Attack verification

Replay the exact pre-patch request. It should now fail because the authenticated user cannot satisfy the ownership predicate.

### Legitimate-workflow regression set

Toy checker must cover:

1. health;
2. register unique user;
3. login;
4. create note with 80-160 bytes;
5. retrieve own note;
6. list own notes and see it;
7. create a second note and ensure the first still exists;
8. retrieve a previous-cycle canary using credentials and ID persisted in checker state;
9. on patched drills only, try cross-owner retrieval and require denial.

### Why this mirrors useful real attack-defend practice

The published FAUST 2024 Todo checker tests multiple normal actions, places flag state under generated credentials, stores those credentials as checker state, and later logs back in to confirm the flag still exists. Its published patch narrows the dangerous deserialization behavior instead of deleting the overall import feature. The lab's simpler checker copies this operational principle, not FAUST's implementation.

### Evaluator checks

- Patch diff is narrow and source-level.
- Same exploit request is blocked after patch.
- Ordinary checker is green.
- Post-restart persistence check is green.
- Participant can name a rollback: `git restore <file>` + rebuild/restart, or revert the specific commit.

---

## Answer key - Drill 4

### Intentionally vulnerable behavior

Synthetic support application issues a reusable export token in a legitimate user's response. The export route accepts only `GET /export/<token>` and does not mark the token used after the first successful download.

The capture contains:

1. legitimate client requests an export;
2. server issues token `exp-lab-7f3a`;
3. legitimate client downloads `/export/exp-lab-7f3a`;
4. a second synthetic client replays the same path and receives the same object;
5. unrelated noise traffic includes a conspicuous CTF-like string.

This is intentionally plain HTTP to teach stream reconstruction. Do not claim it models a secure production transport.

### Synthetic ground truth

Main server: `10.77.0.10:8088`.

Legitimate client: `10.77.0.20`.

Replay client: `10.77.0.21`.

Noise server/client: `10.77.0.11:8000` / `10.77.0.30`.

Exported object: `support-case-17.zip` containing:

```text
case.json
attachment.txt
```

`attachment.txt` contains `RJLAB{streams_before_strings}`.

`case.json` identifies the synthetic support case and expected filename. The facilitator keeps its expected SHA-256 in the sealed answer directory.

Decoy/noise response contains `FLAG-looking-NOT-ANSWER` and must not be treated as primary evidence because it belongs to the unrelated static host/stream and does not participate in the support export transaction.

### Reconstruction path

Expected efficient path:

```sh
tshark -r working.pcapng -q -z conv,tcp

tshark -r working.pcapng -Y http.request \
  -T fields -e frame.number -e tcp.stream -e ip.src \
  -e http.host -e http.request.method -e http.request.uri

tshark -r working.pcapng -q -z 'follow,tcp,ascii,<candidate-stream>'

tshark -r working.pcapng -d tcp.port==8088,http --export-objects http,objects
file objects/*
sha256sum objects/*
unzip -l objects/support-case-17.zip
```

TShark's official manual documents both `-z follow,<protocol>,...` stream reconstruction and `--export-objects <protocol>,<destdir>`.

### Defensive change

On successful export:

1. require the authenticated user's current session to own the export job;
2. atomically change token state from `ready` to `consumed` while returning the object;
3. reject subsequent use with deterministic 404/410;
4. give tokens short expiry and high entropy;
5. in a real deployment, protect session/token confidentiality in transit with TLS.

Do not treat hiding the URL or changing the token prefix as a fix.

### Why legitimate operations remain possible

The owner still receives one successful download for a ready export. The change removes replay, not export. If the product requires repeated downloads, implement an explicit authenticated "regenerate/reissue export" action instead of silently allowing bearer replay forever.

### Evaluator checks

- Candidate stream identified from metadata, not keyword hunting alone.
- Artifact exported and hashed.
- Participant distinguishes first authorized use from replay.
- Decoy rejected with stream/provenance reasoning.
- Proposed fix has an atomic one-use transition or equivalent replay control.

---

## Answer key - Drill 5

### Intentionally vulnerable behavior

The underlying NoteHub image begins with the same cross-owner private-note read from Drills 2/3.

The snapshot `d5-broken` additionally contains a defender-created nftables rule that drops remote TCP/8080 traffic while leaving the service process healthy and localhost access working.

Example lab-only bad rule:

```text
table inet rjprep {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 8080 drop comment "emergency block - breaks checker"
  }
}
```

The exact handle is assigned by nftables and must be discovered, not hard-coded into participant instructions.

### Synthetic ground truth

Expected observations:

- `systemctl status notehub`: active.
- `ss -lntp`: listening on 0.0.0.0:8080.
- `curl http://127.0.0.1:8080/health`: 200.
- remote curl/checker: timeout or connection failure depending on lab network behavior.
- `nft -a list ruleset`: drop rule on 8080 with a handle.

### Safe recovery

Capture rules first:

```sh
sudo nft -a list ruleset | tee ~/nft-before.txt
```

Delete only the offending rule by its actual handle:

```sh
sudo nft delete rule inet rjprep input handle <HANDLE>
```

The official nftables documentation exposes handles with `-a` and supports deleting an individual rule by handle. Avoid `nft flush ruleset`: it destroys unrelated firewall policy and is not a narrow recovery.

Verify remotely, then patch the application ownership query as in Drill 3.

### Rollback

For network mutation, restore the exact pre-exercise ruleset only if required in the disposable VM:

```sh
sudo nft -f /root/rjprep/prechange.nft
```

For source mutation, revert the specific patch commit/file, rebuild, and restart the unit. Record both commands before making a second change.

### Why legitimate operations remain possible

Removing the accidental port-wide drop restores the service's network contract. The application patch then blocks only cross-owner reads. Ordinary clients still connect to TCP/8080 and perform allowed operations.

### Evaluator checks

- Layered diagnosis: process -> listener -> localhost application -> remote path -> firewall.
- Evidence collected before mutation.
- Specific rule deleted by handle; no full ruleset flush.
- Checker restored before deeper hardening continues.
- App exploit blocked by code-level authorization fix.
- Rollback is specific and executable.

### Extension ground truth

Second snapshot can set `/var/lib/notehub` read-only for the service user. Health/read calls work, create fails with SQLite "readonly database" evidence in the journal. Correct response is restore only required write permission/ownership for the data path, not `chmod -R 777`.

---

## Answer key - Drill 6

### Ground-truth injection timeline

Use an injection script with deterministic event IDs:

| Time | Event | Ground truth |
|---|---|---|
| 00:00 | `E0` baseline | Service healthy, cross-owner bug present |
| 07:00 | `E1` mixed probes | 80% harmless `/health`, `/`, malformed IDs; 20% real cross-owner read attempts |
| 18:00 | `E2` exploit frequency increase | Real probe every 10 s; still non-destructive |
| 28:00 | `E3` handoff | No technical change; tests documentation quality |
| 36:00 | `E4` config regression | Set `MAX_NOTE_BYTES=64` while checker creates a 96-128 byte canary; create returns 413/validation failure |
| 45:00 | `E5` attacks stop | Checker continues; team must not confuse lower hostile traffic with service recovery |
| 55:00 | stop | Freeze state and score |

`E4` must be injected using a reversible `.env`/Compose override change, not hidden source tampering. The rollback is restore `MAX_NOTE_BYTES=256` (or the documented default) and restart only NoteHub.

### Expected team priorities

1. Establish checker baseline and ownership of service state.
2. Separate suspicious requests from confirmed exploit behavior.
3. Reproduce and patch the authorization defect.
4. Keep the checker green and retain canaries across restart.
5. At handoff, preserve current diff, verification command, rollback, and open question.
6. When E4 occurs, recognize that the new outage is a legitimate-workflow/config regression, not necessarily renewed exploitation.

### Defensive change

Same narrow owner-bound note retrieval used in Drill 3. The exercise intentionally rewards reuse of a known safe patch pattern and fast verification, not novelty.

### Why legitimate operations remain possible

Private-note ownership is enforced while the route remains available. Restoring the documented body-size bound returns normal checker note creation without weakening ownership checks.

### Evaluator checks

- Time to first accurate service map.
- Time from first effective attack to confirmed diagnosis.
- Checker downtime caused by team changes.
- Whether exploit is reproduced before patch.
- Whether every mutation has a rollback.
- Handoff completeness.
- Final checker persistence.
- Evidence traceability from claim to request/log/diff/checker cycle.

---

# Toy checker specification

This checker is intentionally generic and **is not a replica, emulator, or prediction of the Raymond James checker**. No public claim is made about how Raymond James checks availability, places flags, scores persistence, or handles service semantics.

Its sole purpose is to force the team to preserve ordinary user workflows while changing a vulnerable local service.

## Checker architecture

Implement `checker/toy_checker.py` with Python stdlib only where practical (`urllib.request`, `http.cookiejar`, `json`, `sqlite3` or a JSON state file). Avoid a mandatory `requests` dependency.

State path:

```text
/state/checker.sqlite3
```

The checker runs outside the service container and never mounts the service data volume.

### Persistent state schema

```sql
CREATE TABLE cycles (
  cycle_id INTEGER PRIMARY KEY,
  created_at TEXT NOT NULL,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  note_id INTEGER NOT NULL,
  canary_sha256 TEXT NOT NULL
);
```

The checker may store synthetic lab credentials because they exist only inside the isolated fixture. Do not copy this storage pattern to production secrets.

## Operations per cycle

Run in this order with a per-request timeout of 2 seconds and an overall cycle budget of 8 seconds:

1. `health`: require expected health response.
2. `register`: create `check-<cycle>-<random>`.
3. `login`: establish a fresh authenticated session.
4. `create`: add a random printable 96-128 byte canary.
5. `own_get`: retrieve it directly and hash normalized body.
6. `list`: verify it appears in the user's own-note list.
7. `persistence`: if a prior cycle exists, authenticate as that prior user and retrieve its prior canary.
8. `authz_probe` in patched-mode only: create a second account and verify it cannot retrieve the first account's note by ID.

Do not make the availability score depend on the attack probe. Report functional and security results separately.

## Deterministic JSONL output

One line per cycle:

```json
{"cycle":12,"health":true,"register":true,"login":true,"create":true,"own_get":true,"list":true,"persistence":true,"authz_probe":"blocked","duration_ms":342,"error":null}
```

Requirements:

- stable key ordering;
- UTC timestamp in a separate field if added;
- no raw password/canary body in stdout;
- nonzero process status when a required functional check fails;
- distinguish timeout, transport error, HTTP failure, parse error, and semantic mismatch;
- keep prior state after a failed cycle;
- state writes committed only after create/get verification succeeds.

## Checker modes

```text
baseline  - one full ordinary-function cycle; does not require exploit blocked
patched   - ordinary function cycle + authz probe
cycle     - one cycle using persisted prior state
repeat N  - run one cycle approximately every N seconds until interrupted
```

For rehearsal automation, `repeat 45` is enough. Do not run high-rate traffic that masks participant observations.

## Persistence test

The key training property is cross-check persistence:

- Cycle N creates canary A and stores its user/password/note ID in checker state.
- Service may restart.
- Cycle N+1 must log back in as user N and retrieve canary A.

A patch that deletes the database, recreates all users, or changes object semantics will therefore fail even if `/health` remains green.

---

# Small timed rehearsal format

Drill 6 is the main rehearsal, but a smaller 25-minute repetition can be run after the six drills.

## 25-minute loop

| Minute | Required action |
|---:|---|
| 0-4 | Discover: ports/routes/process and checker baseline |
| 4-9 | Diagnose: reproduce one real unauthorized operation and locate source path |
| 9-15 | Patch: smallest source/config change with rollback prepared first |
| 15-19 | Verify: exact exploit, ordinary checker, restart/persistence |
| 19-22 | Observe: inspect logs for expected attack and no new regression |
| 22-25 | Handoff: another teammate executes verification only from written notes |

No bonus for rushing a patch before reproducible evidence. A 90-second slower diagnosis is preferable to a patch that breaks the service.

## Scoring rubric, 100 points

### Availability - 30

- 30: checker reachable/healthy for >=95% of scored cycles.
- 24: >=90%.
- 18: >=80%.
- 10: >=60%.
- 0: <60% or team intentionally disables the service as its primary defense.

### Functional correctness - 20

- 8: register/login/create/own-read/list all preserved.
- 8: previous-cycle canary persists across at least one restart.
- 4: deterministic handling of unauthorized/nonexistent object reads.

### Time to accurate diagnosis - 15

Measured from first relevant signal to a written, reproducible root cause:

- 15: <=8 min.
- 12: <=12 min.
- 8: <=16 min.
- 4: <=20 min.
- 0: no supported diagnosis.

Do not award this category for a guessed patch that happens to work.

### Safe recovery/change control - 15

- 5: evidence captured before mutation.
- 5: narrow change with explicit rollback.
- 5: recovery verified layer-by-layer and unrelated state preserved.

### Evidence quality and handoff - 15

- 5: timestamped timeline.
- 5: claims point to request/log/diff/checker artifacts.
- 5: handoff lets another person verify and roll back without oral reconstruction.

### Offensive objective - 5

- 5: team produces a minimal, deterministic PoC showing the unauthorized operation before patch.
- 0: no PoC.

This deliberately prevents "got the flag" from dominating the score. A team that captures a synthetic secret but destroys availability should score poorly.

---

# Secondary exercises

These are short satellites. Keep them under 15-20 minutes each and do not replace web/PCAP/attack-defend repetitions with them.

## Secondary A - Reverse engineering: `tokencheck`

**Time:** 15-20 minutes.

Original fixture:

- tiny C program compiled as an x86-64 ELF;
- reads exactly 8 bytes;
- transforms each byte with a fixed XOR and compares against an embedded 8-byte array;
- prints only `ok` or `no`;
- no network, persistence, shell execution, or anti-debugging.

Participant receives only the stripped binary and SHA-256.

Tasks:

```sh
file tokencheck
strings -a tokencheck
objdump -d tokencheck | less
# or
gdb -q ./tokencheck
```

Goal: recover the expected 8-byte input and explain the compare loop.

Facilitator source can be compiled reproducibly with:

```sh
cc -O0 -fno-pie -no-pie -s tokencheck.c -o tokencheck
```

Evidence: recovered input, function/offset of transform loop, one screenshot/text trace of a comparison. The lesson is recognizing a simple transform quickly, not advanced reversing.

## Secondary B - Encodings: `transform-chain.txt`

**Time:** 10-15 minutes.

Original synthetic chain:

```text
plaintext -> XOR each byte with 0x21 -> hex -> URL-safe Base64
```

Participant receives only final text plus the hint "encoding is not encryption."

Tasks:

1. identify the outer alphabet;
2. reverse one layer at a time;
3. record each intermediate representation;
4. stop when bytes become meaningful instead of applying random decoders.

Expected plaintext for facilitator: `RJLAB{transform_not_encrypt}`.

Allowed: Python stdlib, `xxd`, offline CyberChef. Evidence should show the pipeline, not only the final string.

---

# Validation matrix

The following matrix defines what the build agent should validate automatically and what must remain VM-only.

| Test | Container-capable | Disposable VM required | Validation criterion |
|---|:---:|:---:|---|
| D1 external port discovery | Yes | No | Workbench can reach only fixture target; both intended listeners detected |
| D1 custom protocol authorization bug | Yes | No | Own export succeeds; cross-owner export succeeds only in vulnerable revision and fails after patch |
| D1 local `ss` process mapping extension | Yes, if inspecting container namespace | No | Listener maps to expected PID/process |
| D2 NoteHub login/create/own read | Yes | No | Deterministic 2xx and persisted object |
| D2 cross-owner read | Yes | No | Vulnerable image leaks seeded foreign note |
| D3 narrow patch | Yes | No | Same foreign read denied; no route removal |
| D3 ordinary regression checker | Yes | No | All ordinary operations green |
| D3 restart persistence | Yes | No | Prior-cycle canary survives service restart without checker-state reset |
| D4 capture parsing | Yes/offline file only | No | TShark parses capture and enumerates expected HTTP transactions |
| D4 object export | Yes/offline file only | No | Exported ZIP hash equals sealed answer hash |
| D4 distractor discrimination | Manual/evaluator | No | Participant cites stream/provenance reason, not keyword alone |
| D5 systemd unit health | No | Yes | `systemctl`/journal behavior matches snapshot ground truth |
| D5 nftables failed hardening | No | Yes | Local service works while remote 8080 is dropped |
| D5 narrow firewall recovery | No | Yes | Specific rule removed by handle; unrelated rules preserved |
| D5 readonly-data extension | No | Yes | Journal exposes write failure; targeted permission rollback restores create |
| D6 attack simulator isolation | Yes | No | No host Docker socket, no Internet route, only lab network reachable |
| D6 checker repetition | Yes | No | JSONL cycles remain parseable/deterministic under restarts |
| D6 config regression injection | Yes | No | Documented runtime config change creates expected functional checker failure |
| D6 handoff quality | Manual/evaluator | No | New operator can verify/rollback using written handoff |
| Reverse binary | Yes | No | Binary runs in workbench; expected input stable across rebuild toolchain target |
| Encoding chain | Yes | No | Reference decoder deterministically recovers expected plaintext |

## Automated pre-release validation

Before giving the fixtures to the team, run a clean-room build on a machine with no access to author working state:

```text
1. Clone/copy fixture repository.
2. Verify all expected local images/packages are cached.
3. Run each container reset from a clean Docker state.
4. Run facilitator exploit against vulnerable revisions.
5. Apply reference patch and run exploit again.
6. Run toy checker for at least three cycles with one service restart between cycles 1 and 2.
7. Parse PCAP and verify sealed artifact SHA-256.
8. Revert VM snapshot and run D5 expected-state script.
9. Assert fixture networks have no route requirement to the public Internet.
10. Search repository for forbidden material: real credentials, event tokens, SSH private keys, captured cookies, production hostnames.
```

Suggested release gate:

```text
[ ] clean setup succeeds twice
[ ] clean reset succeeds twice
[ ] vulnerable behavior reproducible
[ ] reference patch blocks exact PoC
[ ] legitimate checker stays green
[ ] data survives expected service restart
[ ] cleanup removes lab state
[ ] answer directory absent from participant pack
[ ] all fixture code/assets have license provenance
[ ] no Internet dependency after pre-cache
[ ] VM-only mutations never run on host workstation
```

---

# Implementation notes for the build agent

## Keep fixtures intentionally small

Do not turn NoteHub into a realistic product. A single `server.py`, `db.py`, HTML/API responses, and SQLite database are enough. The training value is the operational loop:

```text
observe -> reproduce -> locate -> patch -> verify -> monitor -> hand off
```

A larger framework increases setup/debug burden and gives the team unrelated clues.

## Use safe query construction even in deliberately vulnerable fixtures

The primary NoteHub bug is broken object-level authorization, not SQL injection. Keep SQL values parameterized everywhere so participants learn to isolate the actual trust-boundary defect. Python's official SQLite docs recommend placeholders instead of string formatting to avoid SQL injection.

If a later standalone SQLi drill is desired, make it an explicitly separate fixture so the intended vulnerability is not confused with accidental injection elsewhere.

## Deterministic IDs and seeds

For facilitator ground truth, use fixed initial object IDs and fixture-owned random seeds. For checker-created content, derive an ID from the checker cycle plus cryptographic random bytes but record only hashes in evidence. Do not make success depend on wall-clock races unless a drill explicitly teaches a race.

## Timeouts

- Discovery command examples: cap individual scans at 2-3 minutes.
- HTTP checker requests: 2 s each.
- Checker cycle: 8 s total.
- Attack simulator request: 2 s.
- Setup health gate: 10 s maximum before reset reports failure.

A hung fixture should fail closed with a clear setup error, not consume the drill period.

## Evidence naming

Use sortable timestamps and stable event IDs:

```text
20260911T173012Z-E1-http-request.txt
20260911T173107Z-E2-patch.diff
```

Do not embed raw session secrets in filenames.

## Offline packaging

Before the team session:

- save/pin container images locally or in an offline OCI archive;
- package fixture source and docs;
- include local man pages/PDF docs only where their licenses permit redistribution, otherwise include URLs plus locally installed tool help;
- include the PCAP and hashes;
- include a VM snapshot separately;
- run the no-network release gate.

The training sequence should still work if every external URL in this document is unavailable on drill day.

---

# Recommended order across two short sessions

## Session 1 - discovery, web, patching (about 2.5 hours)

1. Drill 1 - 40 min.
2. 10 min review.
3. Drill 2 - 45 min.
4. Drill 3 - 50 min.
5. Optional reversing satellite - 15 min.

## Session 2 - forensics, recovery, team operation (about 2.5 hours)

1. Drill 4 - 45 min.
2. Optional encoding satellite - 10 min.
3. Drill 5 - 50 min.
4. Drill 6 - 55 min.

If only one rehearsal is possible, run Drills 2, 4, 5, and 6. They most directly exercise the web + network/forensics + attack-defend priority in the supplied brief.

## Success criteria for a first-time team

By the end of the sequence, a participant should be able to:

- produce a useful service map in under 10 minutes;
- turn an HTTP symptom into an exact source-level authorization diagnosis;
- patch an identified bug without deleting the affected workflow;
- use a checker result as regression evidence rather than as an oracle;
- reconstruct an HTTP stream and export/hash an artifact from a PCAP;
- recover from a bad defender change without indiscriminate reset/flush actions;
- state what changed, how it was verified, and how to roll it back in a handoff another teammate can execute.

Those are more valuable rehearsal outcomes than memorizing a larger list of exploit classes.
