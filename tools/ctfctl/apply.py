"""Transactional mutation engine and verifiers.

Guarantees:

  * one writer at a time (fcntl.flock when available, exclusive-create fallback);
  * every mutation has preconditions, a bounded pre-image backup, syntax
    validation, atomic replace, health checks and a rollback record;
  * a stale plan is refused instead of applied over a teammate's edit;
  * a failed verification rolls back *only this transaction's own files*;
  * rollback refuses to clobber changes made after the transaction;
  * the audit record stores hashes and metadata, never secret values;
  * verifiers distinguish liveness from the legitimate service workflow;
  * nothing here ever restores a volume, database, or user data.

This is deliberately not a general configuration management system.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import actions as actions_mod
from . import plan as plan_mod
from . import util

TX_DIRNAME = os.path.join("state", "tx")
LOCK_REL = os.path.join("state", "lock")
AUDIT_REL = os.path.join("state", "audit.jsonl")
JOURNAL_LIMIT = 400

PHASES = ("PLANNED", "PREPARED", "FILE_REPLACED", "SERVICE_APPLIED", "VERIFYING",
          "COMMITTED", "ROLLING_BACK", "ROLLED_BACK", "FAILED", "CONFLICTED")


# --------------------------------------------------------------------------
# Locking
# --------------------------------------------------------------------------
class WriterLock:
    """Single-writer lock. flock where available; exclusive create otherwise."""

    def __init__(self, root: Optional[str] = None) -> None:
        self.root = root or util.repo_root()
        self.path = os.path.join(self.root, LOCK_REL)
        self._fd: Optional[int] = None
        self._created = False
        self.mode = "unknown"

    def acquire(self) -> None:
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        try:
            import fcntl

            self._fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(self._fd)
                self._fd = None
                raise util.CtfError(
                    "another ctfctl writer holds the lock",
                    hint=f"lock file: {self.path}. Wait for it to finish; do not delete the lock.",
                )
            os.ftruncate(self._fd, 0)
            os.write(self._fd, f"pid={os.getpid()} at={util.iso_now()}\n".encode())
            self.mode = "flock"
            return
        except ImportError:
            pass
        for attempt in (0, 1):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                break
            except FileExistsError:
                # A crashed run cannot hold a lock. On platforms without flock the
                # file is the only signal, so a lock left by a dead process must be
                # reclaimable, or one killed run blocks every future mutation.
                if attempt or not self._stale():
                    raise util.CtfError(
                        "another ctfctl writer holds the lock",
                        hint=f"lock file: {self.path}. If no ctfctl process is running, "
                             "remove it.",
                    )
                try:
                    os.unlink(self.path)
                except OSError:
                    raise util.CtfError(
                        "another ctfctl writer holds the lock",
                        hint=f"lock file: {self.path}. If no ctfctl process is running, "
                             "remove it.",
                    )
        os.write(fd, f"pid={os.getpid()} at={util.iso_now()}\n".encode())
        os.close(fd)
        self._created = True
        self.mode = "exclusive-create"

    LOCK_STALE_SECONDS = 120.0

    def _stale(self) -> bool:
        """True when the lock file names a dead pid and is old enough to trust that."""
        try:
            age = time.time() - os.path.getmtime(self.path)
            with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(200)
        except OSError:
            return False
        if age < self.LOCK_STALE_SECONDS:
            return False
        match = re.search(r"pid=(\d+)", text)
        if not match:
            return age >= self.LOCK_STALE_SECONDS * 2
        return not util.pid_alive(int(match.group(1)))

    def release(self) -> None:
        if self._fd is not None:
            try:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except Exception:
                pass
            os.close(self._fd)
            self._fd = None
        if self._created:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            self._created = False

    def __enter__(self) -> "WriterLock":
        self.acquire()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.release()


# --------------------------------------------------------------------------
# Transaction
# --------------------------------------------------------------------------
def tx_root(root: Optional[str] = None) -> str:
    return os.path.join(root or util.repo_root(), TX_DIRNAME)


@dataclass
class FileChange:
    index: int
    action_key: str
    action_id: str
    path: str
    pre_sha256: str
    post_sha256: str = ""
    pre_backup: str = ""
    pre_state: Dict[str, Any] = field(default_factory=dict)
    metadata_warnings: List[str] = field(default_factory=list)
    replaced: bool = False
    effects: List[Dict[str, Any]] = field(default_factory=list)
    #: True for a file this transaction created (rollback removes it instead of
    #: restoring a pre-image, and there is no pre-image hash to compare against).
    created: bool = False


@dataclass
class Transaction:
    tx_id: str
    plan_id: str
    started_at: str
    phase: str
    directory: str
    changes: List[FileChange] = field(default_factory=list)
    verification: List[Dict[str, Any]] = field(default_factory=list)
    effects_run: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    restored_paths: List[str] = field(default_factory=list)
    actor_uid: int = -1
    lock_mode: str = "unknown"
    dry_run: bool = False

    # -- journal ---------------------------------------------------------
    @property
    def journal_path(self) -> str:
        return os.path.join(self.directory, "journal.jsonl")

    def journal(self, phase: str, **extra: Any) -> None:
        self.phase = phase
        record = {"at": util.iso_now(), "phase": phase, "tx_id": self.tx_id, **extra}
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        with open(self.journal_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def write_record(self) -> None:
        payload = {
            "tx_id": self.tx_id,
            "plan_id": self.plan_id,
            "started_at": self.started_at,
            "phase": self.phase,
            "actor_uid": self.actor_uid,
            "lock_mode": self.lock_mode,
            "dry_run": self.dry_run,
            "changes": [change.__dict__ for change in self.changes],
            "verification": self.verification,
            "effects_run": self.effects_run,
            "errors": self.errors,
            "restored_paths": self.restored_paths,
            "notice": (
                "Audit record. Contains paths, hashes and status only; no secret values, no "
                "request or response bodies. Pre-images live in pre/ (mode 0600) and are the "
                "only place a file's previous content is stored."
            ),
        }
        util.write_text_atomic(os.path.join(self.directory, "tx.json"),
                               util.dump_json(payload), mode=0o600)

    def append_audit(self, root: str, phase: str, summary: str) -> None:
        record = {
            "at": util.iso_now(),
            "tx_id": self.tx_id,
            "plan_id": self.plan_id,
            "profile": "",
            "phase": phase,
            "summary": util.printable(summary, 300),
            "actor_uid": self.actor_uid,
            "files": [
                {"path": c.path, "pre": c.pre_sha256[:12], "post": c.post_sha256[:12],
                 "replaced": c.replaced}
                for c in self.changes
            ],
            "verification_passed": all(v.get("ok") for v in self.verification) if
            self.verification else None,
        }
        path = os.path.join(root, AUDIT_REL)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")


def new_transaction(root: str, plan: plan_mod.Plan, *, lock_mode: str,
                    dry_run: bool = False) -> Transaction:
    tx_id = f"tx-{util.utc_stamp()}-{os.getpid()}"
    directory = os.path.join(tx_root(root), tx_id)
    os.makedirs(os.path.join(directory, "pre"), mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    return Transaction(
        tx_id=tx_id, plan_id=plan.plan_id, started_at=util.iso_now(), phase="PLANNED",
        directory=directory, actor_uid=_euid(), lock_mode=lock_mode, dry_run=dry_run,
    )


def _euid() -> int:
    if hasattr(os, "geteuid"):
        try:
            return int(os.geteuid())
        except OSError:
            return -1
    return -1


# --------------------------------------------------------------------------
# Apply
# --------------------------------------------------------------------------
def apply_plan(plan: plan_mod.Plan, *, root: Optional[str] = None, yes: bool = False,
               include_review: bool = False, dry_run: bool = False,
               run_verifiers: bool = True, functional: bool = True) -> Transaction:
    root = root or util.repo_root()
    lock = WriterLock(root)
    errors: List[str] = []
    with lock:
        stale = plan_mod.check_stale(plan, root)
        if stale:
            already = _plan_already_satisfied(plan, root)
            if already:
                raise util.CtfError(
                    "this plan was already applied (the targets already match the "
                    "intended state)",
                    hint="nothing to do; re-run `ctfctl plan` if you want a fresh plan",
                )
            raise util.CtfError(
                "refusing to apply a stale plan (preconditions changed after planning)",
                hint=" | ".join(stale) + " -- re-run `ctfctl plan`",
            )
        allowed, reason = plan.can_mutate()
        selected = plan.automatic_actions()
        if include_review:
            selected = selected + plan.review_actions()
        if not selected:
            if plan.review_actions() and not include_review:
                raise util.CtfError(
                    "this plan contains only review-only actions",
                    hint=f"re-run with --approve-review after reading the diff. {reason}",
                )
            raise util.CtfError(f"nothing to apply: {reason}")
        if not allowed:
            raise util.CtfError(
                "authorization check failed: " + reason,
                hint="read-only work is unaffected; declare the target to enable mutations",
            )
        capacity = _check_capacity(root, plan, selected)
        if capacity:
            raise util.CtfError("insufficient local capacity for a safe transaction: " + capacity)

        tx = new_transaction(root, plan, lock_mode=lock.mode, dry_run=dry_run)
        tx.journal("PLANNED", plan=plan.plan_id, actions=[a.key for a in selected])
        try:
            _prepare_and_replace(tx, plan, selected, root, dry_run=dry_run)
            if not dry_run:
                _run_effects(tx, selected, errors)
                tx.journal("SERVICE_APPLIED")
            if run_verifiers and not dry_run:
                tx.journal("VERIFYING")
                readiness = readiness_gate(plan)
                if readiness and not all(r["ok"] for r in readiness):
                    tx.verification = readiness
                    tx.errors.append(
                        "the service did not become live after the change: " + "; ".join(
                            f"{r.get('verifier')}: {r.get('detail')}" for r in readiness
                        )
                    )
                    tx.journal("VERIFYING", failed=[r.get("verifier") for r in readiness])
                    _rollback_files(tx, root, reason="service did not become live")
                    tx.phase = "ROLLED_BACK"
                    tx.write_record()
                    tx.append_audit(root, "ROLLED_BACK", tx.errors[-1])
                    raise util.CtfError(
                        "the service did not come back after the change; the transaction was "
                        "rolled back",
                        hint=f"{tx.errors[-1]} | transaction: {tx.tx_id}",
                    )
                results = readiness + run_verifier_set(plan, functional=functional)
                tx.verification = results
                failures = [r for r in results if not r.get("ok") and r.get("required")]
                if failures:
                    tx.errors.append(
                        "verification failed: " + "; ".join(
                            f"{f.get('verifier')}: {f.get('detail')}" for f in failures
                        )
                    )
                    tx.journal("VERIFYING", failed=[f.get("verifier") for f in failures])
                    _rollback_files(tx, root, reason="verification failed")
                    tx.phase = "ROLLED_BACK"
                    tx.write_record()
                    tx.append_audit(root, "ROLLED_BACK", tx.errors[-1])
                    raise util.CtfError(
                        "verification failed; the transaction was rolled back",
                        hint=f"{tx.errors[-1]} | transaction: {tx.tx_id}",
                    )
            tx.journal("COMMITTED")
            tx.phase = "COMMITTED"
            tx.write_record()
            tx.append_audit(root, "COMMITTED", "applied " + ", ".join(a.key for a in selected))
        except util.CtfError:
            raise
        except Exception as exc:  # unexpected: attempt a narrow rollback
            tx.errors.append(f"unexpected error: {type(exc).__name__}: {exc}")
            tx.journal("FAILED", error=str(exc))
            try:
                _rollback_files(tx, root, reason="unexpected error")
            finally:
                tx.phase = "ROLLED_BACK"
                tx.write_record()
            raise util.CtfError(f"apply failed and was rolled back: {exc}") from exc
    return tx


def _plan_already_satisfied(plan: plan_mod.Plan, root: str) -> bool:
    """True when every live action would now be a no-op (i.e. already applied)."""
    live = [a for a in plan.actions if not a.skipped_reason]
    if not live:
        return False
    for entry in live:
        path = entry.target_path
        if not path or not os.path.isfile(path):
            return False
        try:
            action = actions_mod.get(entry.action_id)
            text, newline = util.read_text_preserving(path, 4 * 1024 * 1024)
            ctx = actions_mod.ActionContext(
                root=root, target_path=path, pre_text=text, pre_newline=newline,
                pre_state=util.capture_file_state(path), profile_id=plan.profile_id,
            )
            if action.render(ctx, entry.params) is not None:
                return False
        except (util.CtfError, actions_mod.ActionError):
            return False
    return True


def _check_capacity(root: str, plan: plan_mod.Plan, selected: Sequence[plan_mod.PlanAction]) -> str:
    needed = 0
    for entry in selected:
        if entry.target_path and os.path.isfile(entry.target_path):
            try:
                needed += os.path.getsize(entry.target_path) * 3
            except OSError:
                continue
    needed += 64 * 1024
    targets = {os.path.dirname(os.path.abspath(e.target_path)) or root
               for e in selected if e.target_path} or {root}
    for path in targets:
        try:
            free = util.disk_free(path)
        except OSError:
            continue
        if free.get("free_bytes", 0) < needed:
            return (f"{path} has {util.human_bytes(free.get('free_bytes', 0))} free; "
                    f"~{util.human_bytes(needed)} is required for a safe backup + temp write")
        if free.get("free_inodes", -1) not in (-1, 0) and free.get("free_inodes", 1) < 8:
            return f"{path} has fewer than 8 free inodes"
    return ""


def _prepare_and_replace(tx: Transaction, plan: plan_mod.Plan,
                         selected: Sequence[plan_mod.PlanAction], root: str,
                         dry_run: bool) -> None:
    for index, entry in enumerate(selected):
        action = actions_mod.get(entry.action_id)
        target = entry.target_path
        if not target:
            raise util.CtfError(f"action {entry.key} has no target path")
        if os.path.islink(target):
            raise util.CtfError(
                f"refusing to patch a symlink target: {target}",
                hint="resolve the real configuration file and re-plan against that path",
            )
        creating = False
        if not os.path.isfile(target):
            # Only an action that explicitly declares it creates new files may do
            # so, and its rollback is a deletion rather than a restore.
            if action.kind != "file_create":
                raise util.CtfError(f"target file disappeared: {target}")
            creating = True
        real_root = os.path.realpath(os.path.dirname(os.path.abspath(target)))
        if not os.path.isdir(real_root):
            raise util.CtfError(
                f"the target directory does not exist: {real_root}",
                hint="create the directory first, or point the plan at an existing one",
            )
        if creating:
            pre_state = util.FileState(path=target, exists=False)
            pre_text, pre_newline = "", "\n"
        else:
            pre_state = util.capture_file_state(target)
            pre_text, pre_newline = util.read_text_preserving(target, 4 * 1024 * 1024)
        planned_pre = (entry.pre_state or {}).get("sha256")
        if planned_pre and pre_state.sha256 != planned_pre:
            raise util.CtfError(
                f"target changed between planning and apply: {target}",
                hint="re-run `ctfctl plan`; a teammate may have edited this file",
            )
        change = FileChange(
            index=index, action_key=entry.key, action_id=entry.action_id, path=target,
            pre_sha256=pre_state.sha256, pre_state=pre_state.as_dict(),
            effects=entry.effects, created=creating,
        )
        tx.changes.append(change)
        if dry_run:
            tx.journal("PREPARED", index=index, path=target, dry_run=True)
            continue

        # 1. bounded pre-image backup (none exists for a file we are creating)
        if not creating:
            backup = os.path.join(tx.directory, "pre", f"{index:02d}-{os.path.basename(target)}")
            shutil.copyfile(target, backup)
            os.chmod(backup, 0o600)
            change.pre_backup = os.path.relpath(backup, root)
            tx.journal("PREPARED", index=index, path=target, pre_sha256=pre_state.sha256[:12],
                       backup=change.pre_backup)
        else:
            tx.journal("PREPARED", index=index, path=target, created=True)

        # 2. re-render against live content, then validate the candidate
        ctx = actions_mod.ActionContext(
            root=root, target_path=target, pre_text=pre_text, pre_state=pre_state,
            pre_newline=pre_newline, profile_id=plan.profile_id,
        )
        candidate = action.render(ctx, entry.params)
        if candidate is None:
            tx.journal("PREPARED", index=index, note="candidate is a no-op; skipping")
            continue
        checks = action.validate(ctx, entry.params, candidate)
        failed = [c for c in checks if c.required and not c.ok]
        if failed:
            raise util.CtfError(
                f"candidate failed validation at apply time: {entry.key}",
                hint="; ".join(f"{c.name}: {c.detail}" for c in failed),
            )

        # 3. temp file in the same directory, fsync, metadata, atomic replace
        temp = os.path.join(real_root, f".{os.path.basename(target)}.ctfctl{os.getpid()}")
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, pre_state.mode or 0o644)
            # Binary write: the candidate already carries the target file's own line
            # endings, so no text-mode translation may be applied to it.
            payload = util.encode_with_newline(candidate.new_text, ctx.pre_newline)
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            warnings = _metadata_before_replace(temp, pre_state)
            change.metadata_warnings = warnings
            util.os_replace(temp, target)
        finally:
            if os.path.exists(temp):
                try:
                    os.unlink(temp)
                except OSError:
                    pass
        post_state = util.capture_file_state(target)
        change.post_sha256 = post_state.sha256
        change.replaced = True
        tx.journal("FILE_REPLACED", index=index, path=target, post_sha256=post_state.sha256[:12],
                   notes=candidate.notes, metadata_warnings=change.metadata_warnings)
        tx.write_record()


def _metadata_before_replace(temp: str, pre_state: util.FileState) -> List[str]:
    warnings: List[str] = []
    if not hasattr(os, "chown"):
        warnings.append(
            "ownership is not preserved on this platform (no os.chown): the file keeps the "
            "identity of the process that wrote it"
        )
    if pre_state.uid >= 0 and hasattr(os, "chown"):
        try:
            os.chown(temp, pre_state.uid, pre_state.gid)
        except (PermissionError, OSError) as exc:
            warnings.append(f"ownership not preserved on the new file: {exc}")
    if pre_state.mode:
        try:
            os.chmod(temp, pre_state.mode)
        except OSError as exc:
            warnings.append(f"mode not preserved: {exc}")
    if pre_state.xattrs and hasattr(os, "setxattr"):
        for name, hexval in pre_state.xattrs.items():
            try:
                os.setxattr(temp, name, bytes.fromhex(hexval))
            except (OSError, ValueError):
                warnings.append(f"xattr {name} not preserved")
    return warnings


def _run_effects(tx: Transaction, selected: Sequence[plan_mod.PlanAction],
                 errors: List[str]) -> None:
    for entry in selected:
        for effect in entry.effects:
            argv = effect.get("argv") or []
            kind = effect.get("kind")
            if kind == "none" or not argv:
                continue
            if not _effect_allowed(kind, argv):
                errors.append(f"refused non-allowlisted effect: {kind} {argv}")
                tx.journal("SERVICE_APPLIED", refused={"kind": kind, "argv": argv})
                continue
            tool = argv[0]
            if not util.which(tool):
                errors.append(f"effect requires {tool}, which is not installed")
                continue
            tx.journal("SERVICE_APPLIED", running=argv, description=effect.get("description"))
            res = util.run(argv, timeout=float(effect.get("timeout") or 120.0),
                           max_output=128 * 1024)
            record = {
                "argv": argv,
                "ok": res.ok,
                "returncode": res.returncode,
                "duration_s": round(res.duration_s, 2),
                "stderr_tail": util.printable(util.redact(res.stderr.strip()), 300),
            }
            tx.effects_run.append(record)
            if not res.ok:
                errors.append(
                    f"effect failed: {' '.join(argv)} -> {record['stderr_tail'] or res.returncode}"
                )
                tx.journal("SERVICE_APPLIED", effect_failed=record)
            else:
                tx.journal("SERVICE_APPLIED", effect_ok=record)


def _nft_effect_allowed(tokens: Sequence[str]) -> bool:
    """`nft -f <our file>` or `nft delete table <family> <name>`. Nothing else."""
    if len(tokens) == 3 and tokens[0] == "nft" and tokens[1] == "-f":
        return re.fullmatch(r"/etc/[A-Za-z0-9._-]{1,64}\.nft", tokens[2]) is not None
    if len(tokens) == 5 and tuple(tokens[:3]) == ("nft", "delete", "table"):
        return tokens[3] in ("inet", "ip", "ip6", "arp", "bridge") and \
            re.fullmatch(r"[a-z][a-z0-9_]{2,31}", tokens[4]) is not None
    return False


def _effect_allowed(kind: str, argv: Sequence[str]) -> bool:
    """Allowlist by kind and argv shape. No free-form commands, ever."""
    if not argv:
        return False
    tokens = [str(a) for a in argv]
    binary = tokens[0]
    if kind in ("nft_load_file", "nft_delete_table"):
        return _nft_effect_allowed(tokens)
    if binary not in ("docker", "docker-compose", "systemctl"):
        return False
    # Destructive subcommands are never a valid effect, whatever the kind says.
    forbidden = {"down", "rm", "prune", "volume", "volumes", "kill", "--volumes", "-v",
                 "--force", "-f/-force"}
    if any(token in forbidden for token in tokens):
        return False
    if any(token.startswith("--volumes") for token in tokens):
        return False
    if kind == "compose_restart":
        if binary == "docker-compose":
            return len(tokens) >= 3 and tokens[1] == "restart"
        return len(tokens) >= 4 and "compose" in tokens[1:3] and "restart" in tokens
    if kind == "compose_up":
        if "up" not in tokens:
            return False
        if not any(token in ("-d", "--detach") for token in tokens):
            return False
        if binary == "docker-compose":
            return tokens[1] == "up"
        return "compose" in tokens[1:3]
    if kind == "systemd_reload":
        return tokens == ["systemctl", "daemon-reload"]
    if kind == "systemd_restart":
        return (len(tokens) == 3 and tokens[:2] == ["systemctl", "restart"]
                and re.fullmatch(r"[A-Za-z0-9@._\-]+", tokens[2]) is not None)
    return False


# --------------------------------------------------------------------------
# Rollback
# --------------------------------------------------------------------------
def _rollback_files(tx: Transaction, root: str, *, reason: str) -> Tuple[List[str], List[str]]:
    """Restore this transaction's files. Returns (problems, restored_paths)."""
    problems: List[str] = []
    restored: List[str] = []
    tx.journal("ROLLING_BACK", reason=reason)
    for change in reversed(tx.changes):
        if not change.replaced:
            continue
        if change.created:
            # The pre-image was "no file". Remove exactly what we wrote, and only
            # if it still matches: a teammate's later edit must not be deleted.
            current = util.capture_file_state(change.path)
            if not current.exists:
                tx.journal("ROLLING_BACK", already_removed=change.path)
                change.replaced = False
                continue
            if change.post_sha256 and current.sha256 != change.post_sha256:
                problems.append(
                    f"{change.path} changed after this transaction: refusing to delete it. "
                    "Resolve by hand.",
                )
                tx.journal("ROLLING_BACK", conflict=change.path, created=True)
                continue
            try:
                os.unlink(change.path)
            except OSError as exc:
                problems.append(f"could not remove created file {change.path}: {exc}")
                continue
            tx.journal("ROLLING_BACK", removed=change.path, created=True)
            restored.append(change.path)
            continue
        current = util.capture_file_state(change.path)
        if current.sha256 == change.pre_sha256:
            # Already at the pre-image (a previous rollback, or an identical
            # manual edit). Nothing to do, and definitely not a conflict.
            tx.journal("ROLLING_BACK", already_restored=change.path)
            change.replaced = False
            continue
        if current.sha256 != change.post_sha256:
            change_conflict = (
                f"{change.path} changed after this transaction (expected post-image "
                f"{change.post_sha256[:12]}..., found {current.sha256[:12]}...): refusing to "
                "overwrite. Resolve by hand."
            )
            problems.append(change_conflict)
            tx.journal("ROLLING_BACK", conflict=change_conflict)
            continue
        backup = os.path.join(root, change.pre_backup)
        if not os.path.isfile(backup):
            problems.append(f"pre-image missing for {change.path}: cannot roll back")
            continue
        if util.sha256_file(backup) != change.pre_sha256:
            problems.append(f"pre-image hash mismatch for {change.path}: refusing to restore")
            continue
        directory = os.path.dirname(os.path.abspath(change.path)) or "."
        temp = os.path.join(directory, f".{os.path.basename(change.path)}.rollback{os.getpid()}")
        try:
            shutil.copyfile(backup, temp)
            state = util.FileState.from_dict(change.pre_state)
            warnings = util.apply_file_metadata(temp, state)
            change.metadata_warnings.extend(warnings)
            util.os_replace(temp, change.path)
        finally:
            if os.path.exists(temp):
                try:
                    os.unlink(temp)
                except OSError:
                    pass
        restored_hash = util.sha256_file(change.path)
        tx.journal("ROLLING_BACK", restored=change.path, sha256=restored_hash[:12],
                   matches_pre=restored_hash == change.pre_sha256)
        if restored_hash != change.pre_sha256:
            problems.append(f"restored content mismatch for {change.path}")
        else:
            restored.append(change.path)
    if problems:
        tx.errors.extend(problems)
        tx.phase = "CONFLICTED"
    return problems, restored


def rollback_tx(tx_id: str, *, root: Optional[str] = None, yes: bool = False,
                verify: bool = True) -> Transaction:
    root = root or util.repo_root()
    directory = os.path.join(tx_root(root), tx_id)
    if not os.path.isdir(directory):
        raise util.CtfError(f"transaction not found: {tx_id}",
                            hint="list transactions with: ctfctl rollback --list")
    record = util.load_json(os.path.join(directory, "tx.json"), {})
    tx = _tx_from_record(record, directory)
    if tx.phase not in ("COMMITTED", "ROLLED_BACK", "CONFLICTED", "FAILED"):
        raise util.CtfError(
            f"transaction {tx_id} is in phase {tx.phase}; it may still be running",
            hint="if no ctfctl process is running, inspect the journal and recover with "
                 "`ctfctl apply --recover`",
        )
    with WriterLock(root) as lock:
        tx.lock_mode = lock.mode
        problems, restored = _rollback_files(tx, root, reason="operator requested rollback")
        # Apply-time verification results are stale after a rollback; never present
        # them as if they described the restored state.
        tx.verification = []
        tx.restored_paths = restored
        if not problems:
            # Restoring the file is not enough: the running process still holds
            # the patched code. Re-run the transaction's own effects (a restart or
            # reload is its own inverse) and wait for readiness again.
            if restored:
                _run_recorded_effects(tx)
            tx.phase = "ROLLED_BACK"
        tx.write_record()
        tx.append_audit(root, tx.phase, "operator rollback of " + tx_id)
    if not problems and restored and verify:
        plan = _load_plan_quietly(tx.plan_id, root)
        if plan is not None:
            readiness = readiness_gate(plan)
            tx.verification = readiness + run_verifier_set(plan)
            tx.write_record()
    return tx


def _load_plan_quietly(plan_id: str, root: str) -> Optional[plan_mod.Plan]:
    if not plan_id:
        return None
    try:
        return plan_mod.load_plan(plan_id, root)
    except util.CtfError:
        return None


def _run_recorded_effects(tx: Transaction) -> None:
    """Re-run the recorded follow-up commands (restart/reload are involutive)."""
    seen = set()
    for change in tx.changes:
        for effect in change.effects or []:
            # A rollback uses the recorded inverse when the action supplies one
            # (loading a firewall table is not its own inverse; deleting it is).
            argv = [str(a) for a in (effect.get("rollback_argv") or effect.get("argv") or [])]
            kind = str(effect.get("kind") or "")
            key = (kind, tuple(argv))
            if not argv or kind == "none" or key in seen:
                continue
            seen.add(key)
            if not _effect_allowed(kind, argv):
                tx.errors.append(f"refused non-allowlisted rollback effect: {kind} {argv}")
                continue
            if not util.which(argv[0]):
                tx.errors.append(f"rollback effect requires {argv[0]}, which is not installed")
                continue
            res = util.run(argv, timeout=float(effect.get("timeout") or 120.0),
                           max_output=128 * 1024)
            tx.journal("ROLLING_BACK", effect=argv, ok=res.ok, returncode=res.returncode)
            tx.effects_run.append({
                "argv": argv, "ok": res.ok, "returncode": res.returncode,
                "phase": "rollback",
                "stderr_tail": util.printable(util.redact(res.stderr.strip()), 200),
            })


def _tx_from_record(record: Dict[str, Any], directory: str) -> Transaction:
    changes = []
    for item in record.get("changes") or []:
        changes.append(FileChange(
            index=int(item.get("index", 0)),
            action_key=str(item.get("action_key", "")),
            action_id=str(item.get("action_id", "")),
            path=str(item.get("path", "")),
            pre_sha256=str(item.get("pre_sha256", "")),
            post_sha256=str(item.get("post_sha256", "")),
            pre_backup=str(item.get("pre_backup", "")),
            pre_state=item.get("pre_state") or {},
            metadata_warnings=list(item.get("metadata_warnings") or []),
            replaced=bool(item.get("replaced")),
            effects=list(item.get("effects") or []),
            created=bool(item.get("created")),
        ))
    return Transaction(
        tx_id=str(record.get("tx_id", os.path.basename(directory))),
        plan_id=str(record.get("plan_id", "")),
        started_at=str(record.get("started_at", "")),
        phase=str(record.get("phase", "UNKNOWN")),
        directory=directory,
        changes=changes,
        verification=list(record.get("verification") or []),
        effects_run=list(record.get("effects_run") or []),
        errors=list(record.get("errors") or []),
        restored_paths=list(record.get("restored_paths") or []),
        actor_uid=int(record.get("actor_uid", -1)),
    )


def list_transactions(root: Optional[str] = None) -> List[Dict[str, Any]]:
    root = root or util.repo_root()
    base = tx_root(root)
    out: List[Dict[str, Any]] = []
    if not os.path.isdir(base):
        return out
    for name in sorted(os.listdir(base), reverse=True):
        path = os.path.join(base, name, "tx.json")
        if not os.path.isfile(path):
            continue
        record = util.load_json(path, {})
        out.append({
            "tx_id": record.get("tx_id", name),
            "plan_id": record.get("plan_id", ""),
            "phase": record.get("phase", "UNKNOWN"),
            "started_at": record.get("started_at", ""),
            "files": [c.get("path") for c in record.get("changes") or []],
            "errors": record.get("errors") or [],
        })
    return out


def recover(root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Inspect interrupted transactions. Never guesses; reports and recommends."""
    root = root or util.repo_root()
    findings: List[Dict[str, Any]] = []
    base = tx_root(root)
    if not os.path.isdir(base):
        return findings
    for name in sorted(os.listdir(base)):
        directory = os.path.join(base, name)
        record_path = os.path.join(directory, "tx.json")
        journal_path = os.path.join(directory, "journal.jsonl")
        if not os.path.isdir(directory):
            continue
        record = util.load_json(record_path, {})
        if record.get("phase") in ("COMMITTED", "ROLLED_BACK", "CONFLICTED"):
            continue
        phases = []
        if os.path.isfile(journal_path):
            for entry in util.load_jsonl(journal_path):
                phases.append(entry.get("phase"))
        finding = {
            "tx_id": name,
            "phase": record.get("phase") or (phases[-1] if phases else "UNKNOWN"),
            "journal_phases": phases[-6:],
            "requires": "",
            "files": [],
        }
        stale_conflict = False
        for change in record.get("changes") or []:
            path = change.get("path") or ""
            current = util.capture_file_state(path)
            replaced = bool(change.get("replaced"))
            post = change.get("post_sha256") or ""
            if not replaced:
                continue
            if current.sha256 == post:
                finding["files"].append({"path": path, "state": "post-image present",
                                         "action": "verify or roll back"})
            else:
                stale_conflict = True
                finding["files"].append({
                    "path": path, "state": "changed since apply",
                    "action": "do not roll back automatically",
                })
        if stale_conflict:
            finding["requires"] = "manual review: files changed after the interrupted apply"
        elif finding["files"]:
            finding["requires"] = (
                f"run `ctfctl rollback {name}` to restore the pre-images, or "
                "`ctfctl verify` first if the service looks healthy"
            )
        else:
            finding["requires"] = "no file was replaced; safe to remove with --clean"
        findings.append(finding)
    return findings


# --------------------------------------------------------------------------
# Verifiers
# --------------------------------------------------------------------------
@dataclass
class VerifyResult:
    verifier: str
    tier: str
    ok: bool
    detail: str
    required: bool = True
    evidence: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "verifier": self.verifier,
            "tier": self.tier,
            "ok": self.ok,
            "required": self.required,
            "detail": util.printable(self.detail, 400),
            "evidence": self.evidence,
        }


def tcp_connect(host: str, port: int, timeout: float = 3.0) -> VerifyResult:
    started = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return VerifyResult("tcp.connect", "liveness", True,
                                f"TCP connect to {host}:{port} succeeded",
                                evidence={"host": host, "port": port,
                                          "duration_ms": round((time.time() - started) * 1000)})
    except OSError as exc:
        return VerifyResult("tcp.connect", "liveness", False,
                            f"TCP connect to {host}:{port} failed: {exc}")


def http_request(url: str, *, method: str = "GET", body: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None, expect_status: Any = 200,
                 expect_contains: Optional[Sequence[str]] = None,
                 expect_contains_any: Optional[Sequence[str]] = None,
                 must_not_contain: Optional[Sequence[str]] = None,
                 timeout: float = 5.0, allow_redirects: bool = False,
                 insecure: bool = False, retries: int = 2) -> VerifyResult:
    """One bounded HTTP request. Body content is never stored in the audit record."""
    expected = expect_status if isinstance(expect_status, (list, tuple)) else [expect_status]
    last_error = ""
    for attempt in range(max(1, retries)):
        request = urllib.request.Request(
            url, method=method,
            data=body.encode("utf-8") if body is not None else None,
            headers={"User-Agent": "ctfctl-verify/0.1", **(headers or {})},
        )
        context = ssl._create_unverified_context() if insecure else None  # noqa: SLF001
        opener = urllib.request.build_opener()
        if not allow_redirects:
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args: Any, **kwargs: Any):
                    return None

            opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=timeout) as response:
                status = response.status
                text = response.read(256 * 1024).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                text = exc.read(64 * 1024).decode("utf-8", "replace")
            except Exception:
                text = ""
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.4 * (attempt + 1))
            continue
        ok = status in expected
        detail = f"{method} {url} -> {status} (expected {expected})"
        if ok and expect_contains:
            missing = [needle for needle in expect_contains if needle not in text]
            if missing:
                ok = False
                detail += f"; response missing {missing}"
            else:
                detail += f"; found {list(expect_contains)}"
        if ok and expect_contains_any:
            if not any(needle in text for needle in expect_contains_any):
                ok = False
                detail += f"; response contained none of {list(expect_contains_any)}"
        if ok and must_not_contain:
            present = [needle for needle in must_not_contain if needle in text]
            if present:
                ok = False
                detail += f"; response unexpectedly contains {present}"
        return VerifyResult(
            "http.request", "protocol", ok, detail,
            evidence={"status": status, "bytes": len(text), "url": url, "method": method,
                      "sha256": util.sha256_text(text) if text else ""},
        )
    return VerifyResult("http.request", "protocol", False,
                        f"{method} {url} failed after {retries} attempt(s): {last_error}")


def _substitute_extracted(text: str, extracted: Dict[str, Any]) -> str:
    out = text
    for key, value in extracted.items():
        out = out.replace("{" + key + "}", str(value))
    return out


def run_http_workflow(steps: Sequence[Dict[str, Any]], *, timeout: float = 5.0) -> VerifyResult:
    """Full workflow with JSON extraction, done in one pass over live responses."""
    extracted: Dict[str, str] = {}
    transcript: List[str] = []
    for index, step in enumerate(steps):
        name = str(step.get("name") or f"step{index}")
        url = _substitute_extracted(str(step.get("url") or ""), extracted)
        body = step.get("body")
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = _substitute_extracted(body, extracted)
        headers = {k: _substitute_extracted(str(v), extracted)
                   for k, v in (step.get("headers") or {}).items()}
        if body is not None and "Content-Type" not in headers:
            headers["Content-Type"] = step.get("content_type", "application/json")
        status, text, error = _raw_http(
            url, method=str(step.get("method", "GET")), body=body, headers=headers,
            timeout=timeout,
        )
        if error:
            transcript.append(f"{name}: transport error {error}")
            return VerifyResult("http.workflow", "functional", False, " | ".join(transcript))
        expected = step.get("expect_status", 200)
        expected_list = expected if isinstance(expected, (list, tuple)) else [expected]
        if status not in expected_list:
            transcript.append(f"{name}: status {status} not in {expected_list}")
            return VerifyResult("http.workflow", "functional", False, " | ".join(transcript),
                                evidence={"status": status})
        for needle in step.get("expect_contains") or []:
            if _substitute_extracted(str(needle), extracted) not in text:
                transcript.append(f"{name}: response did not contain {needle!r}")
                return VerifyResult("http.workflow", "functional", False,
                                    " | ".join(transcript))
        for name_key, spec in (step.get("extract") or {}).items():
            value = _json_path(text, str(spec))
            if value is None:
                transcript.append(f"{name}: could not extract {name_key} via {spec}")
                return VerifyResult("http.workflow", "functional", False,
                                    " | ".join(transcript))
            extracted[name_key] = value
        transcript.append(f"{name}: {status} ok")
    return VerifyResult("http.workflow", "functional", True, " | ".join(transcript),
                        evidence={"steps": len(steps), "extracted": sorted(extracted)})


def _json_path(text: str, path: str) -> Optional[str]:
    try:
        payload = json.loads(text)
    except ValueError:
        return None
    current: Any = payload
    for part in path.strip("$.").split("."):
        if not part:
            continue
        if isinstance(current, list):
            if not part.isdigit() or int(part) >= len(current):
                return None
            current = current[int(part)]
        elif isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        else:
            return None
    return None if current is None else str(current)


def _raw_http(url: str, *, method: str, body: Optional[str],
              headers: Dict[str, str], timeout: float) -> Tuple[int, str, str]:
    request = urllib.request.Request(
        url, method=method,
        data=body.encode("utf-8") if body is not None else None,
        headers={"User-Agent": "ctfctl-verify/0.1", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(128 * 1024).decode("utf-8", "replace"), ""
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(64 * 1024).decode("utf-8", "replace"), ""
        except Exception:
            return exc.code, "", ""
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, "", f"{type(exc).__name__}: {exc}"


def file_check(path: str, *, contains: Optional[str] = None,
               not_contains: Optional[str] = None, exists: Optional[bool] = None) -> VerifyResult:
    present = os.path.isfile(path)
    if exists is not None and present != exists:
        return VerifyResult("file.check", "static", False,
                            f"{path} exists={present}, expected {exists}")
    if not present:
        return VerifyResult("file.check", "static", exists is False,
                            f"{path} is absent")
    text = util.read_text(path, 4 * 1024 * 1024)
    if contains and contains not in text:
        return VerifyResult("file.check", "static", False, f"{path} does not contain {contains!r}")
    if not_contains and not_contains in text:
        return VerifyResult("file.check", "static", False, f"{path} still contains {not_contains!r}")
    return VerifyResult("file.check", "static", True,
                        f"{path} content checks passed",
                        evidence={"sha256": util.sha256_text(text)})


VERIFIERS = {
    "tcp.connect": lambda params, **kw: tcp_connect(
        str(params.get("host", "127.0.0.1")), int(params["port"]),
        float(params.get("timeout", 3.0))),
    "http.request": lambda params, **kw: http_request(
        str(params["url"]), method=str(params.get("method", "GET")),
        body=params.get("body"), headers=params.get("headers"),
        expect_status=params.get("expect_status", 200),
        expect_contains=params.get("expect_contains"),
        expect_contains_any=params.get("expect_contains_any"),
        must_not_contain=params.get("must_not_contain"),
        timeout=float(params.get("timeout", 5.0))),
    "http.workflow": lambda params, **kw: run_http_workflow(
        params.get("steps") or [], timeout=float(params.get("timeout", 5.0))),
    "container.running": lambda params, **kw: _container_running(str(params["name"])),
    "file.check": lambda params, **kw: file_check(
        str(params["path"]), contains=params.get("contains"),
        not_contains=params.get("not_contains"), exists=params.get("exists")),
    "compose.config": lambda params, **kw: _compose_config(str(params["file"])),
    "nft.table": lambda params, **kw: nft_table_present(
        table=str(params["table"]), family=str(params.get("family", "inet"))),
    "sshd.option": lambda params, **kw: sshd_option(
        option=str(params["option"]), value=str(params["value"]),
        config=str(params.get("config", ""))),
}


def _container_running(name: str) -> VerifyResult:
    docker = util.which("docker")
    if not docker:
        return VerifyResult("container.running", "liveness", False, "docker is not installed")
    res = util.run([docker, "inspect", "--format", "{{.State.Running}}", name], timeout=20)
    if not res.ok:
        return VerifyResult("container.running", "liveness", False,
                            f"container {name} not inspectable: "
                            f"{util.printable(res.stderr.strip(), 120)}")
    running = res.stdout.strip() == "true"
    return VerifyResult("container.running", "liveness", running,
                        f"container {name} running={running}")


def nft_table_present(*, table: str, family: str = "inet") -> VerifyResult:
    """Prove the lockdown table is loaded in the *running* ruleset."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{2,31}", table) or family not in (
        "inet", "ip", "ip6", "arp", "bridge", "netdev"
    ):
        return VerifyResult("nft.table", False, f"invalid table reference {family} {table}")
    if not util.which("nft"):
        return VerifyResult("nft.table", False, "nft is not installed on this host")
    res = util.run(["nft", "list", "table", family, table], timeout=20, max_output=128 * 1024)
    return VerifyResult(
        "nft.table", "protocol", res.ok,
        f"`nft list table {family} {table}` says the table is loaded" if res.ok
        else (util.printable((res.stderr or res.stdout).strip(), 200)
              or f"table {family} {table} is not loaded"),
    )


def sshd_option(*, option: str, value: str, config: str = "") -> VerifyResult:
    """Check an effective sshd setting with `sshd -T` (includes drop-in files)."""
    if not re.fullmatch(r"[A-Za-z]{3,64}", option) or not re.fullmatch(r"[A-Za-z0-9-]{1,32}", value):
        return VerifyResult("sshd.option", False, "invalid option/value pair")
    if not util.which("sshd"):
        return VerifyResult("sshd.option", False, "sshd is not installed on this host")
    argv = ["sshd", "-T"] + (["-f", config] if config else [])
    res = util.run(argv, timeout=20, max_output=512 * 1024)
    if not res.ok:
        return VerifyResult("sshd.option", False,
                            util.printable(res.stderr.strip(), 200) or "sshd -T failed")
    needle = f"{option.lower()} {value.lower()}"
    ok = needle in res.stdout.lower()
    return VerifyResult(
        "sshd.option", "protocol", ok,
        f"`{' '.join(argv)}` reports {option}={value}" if ok
        else f"the effective config does not report {needle}",
    )


def _compose_config(path: str) -> VerifyResult:
    if not util.which("docker"):
        return VerifyResult("compose.config", "static", False, "docker is not installed")
    directory = os.path.dirname(os.path.abspath(path)) or "."
    res = util.run(["docker", "compose", "-f", path, "config", "--quiet"], timeout=45,
                   cwd=directory)
    return VerifyResult("compose.config", "static", res.ok,
                        util.printable((res.stdout + res.stderr).strip(), 200)
                        or "compose config valid")


def readiness_gate(plan: plan_mod.Plan, *, timeout: float = 60.0,
                   poll: float = 1.5) -> List[Dict[str, Any]]:
    """Wait (bounded) for the declared liveness and protocol checks to pass.

    `docker compose restart` and `systemctl restart` return as soon as the
    restart is *initiated*, and a reverse proxy keeps accepting connections
    while its upstream is still booting (a 502, not a connection refusal).
    Verifying immediately would therefore report a false failure and roll back a
    perfectly good patch. Liveness *and* protocol checks are polled first; the
    functional workflow and the negative exploit probe are deliberately excluded
    so they still test the finished state. The budget is bounded, so a genuinely
    broken service still fails the transaction.
    """
    liveness = [v for v in plan.verifiers
                if str(v.get("tier")) in ("liveness", "protocol")]
    results: List[Dict[str, Any]] = []
    if not liveness:
        return results
    deadline = time.time() + max(1.0, timeout)
    while True:
        results = []
        for item in liveness:
            fn = VERIFIERS.get(str(item.get("verifier")))
            if fn is None:
                continue
            payload = fn(item.get("params") or {}).as_dict()
            payload["tier"] = "readiness"
            payload["required"] = False
            results.append(payload)
        if results and all(r["ok"] for r in results):
            return results
        if time.time() >= deadline:
            for item in results:
                item["detail"] = (
                    str(item.get("detail")) + f" (readiness wait of {int(timeout)}s expired)"
                )
            return results
        time.sleep(poll)


def run_verifier_set(plan: plan_mod.Plan, *, functional: bool = True,
                     only: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for item in plan.verifiers:
        name = str(item.get("verifier"))
        tier = str(item.get("tier", "protocol"))
        if tier == "functional" and not functional:
            results.append({"verifier": name, "tier": tier, "ok": True, "required": False,
                            "detail": "skipped (--no-functional)", "evidence": {}})
            continue
        fn = VERIFIERS.get(name)
        if fn is None:
            results.append({"verifier": name, "tier": tier, "ok": False, "required": True,
                            "detail": f"unknown verifier {name!r}", "evidence": {}})
            continue
        result = fn(item.get("params") or {})
        payload = result.as_dict()
        payload["required"] = bool(item.get("required", True))
        results.append(payload)
    if plan.exploit_probe:
        name = str(plan.exploit_probe.get("verifier"))
        fn = VERIFIERS.get(name)
        if fn is not None:
            payload = fn(plan.exploit_probe.get("params") or {}).as_dict()
            payload["tier"] = "negative"
            payload["required"] = True
            results.append(payload)
    return results
