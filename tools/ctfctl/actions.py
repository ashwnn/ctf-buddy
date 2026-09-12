"""Typed action registry.

Every mutation this toolkit can perform is an entry in ACTIONS below. A profile
(and therefore a plan) references an action by ID plus *structured* parameters.
Nothing in a plan, inventory or report is ever interpreted as shell code: there
is no code path here that runs a string from a JSON document.

Each action provides:

  preflight(params)            -> list of problems that make the action invalid
  render(context, params)      -> Candidate(new_text, diff, notes) or None (no-op)
  validate(context, params, candidate) -> list[Check]
  effects                      -> ordered, allowlisted follow-up commands
  impact / conditions / rollback text for the human plan

Everything is deliberately narrow. A broad "harden the service" action does not
exist and will not be added.
"""

from __future__ import annotations

import ast
import difflib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import util

# --------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------
@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    command: str = ""
    required: bool = True

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail,
                "command": self.command, "required": self.required}


@dataclass
class Candidate:
    path: str
    new_text: str
    diff: str
    notes: List[str] = field(default_factory=list)
    extra_files: Dict[str, str] = field(default_factory=dict)


@dataclass
class Effect:
    """An allowlisted follow-up command. argv only; never a shell string."""

    kind: str            # systemd_reload | systemd_restart | compose_restart | compose_up
    argv: List[str]
    description: str
    timeout: float = 60.0
    requires: str = ""   # tool that must exist
    rollback_argv: List[str] = field(default_factory=list)


class ActionError(util.CtfError):
    pass


class Action:
    id: str = ""
    kind: str = "file_edit"
    summary: str = ""
    impact: str = ""
    conditions: List[str] = field(default_factory=list)
    rollback_text: str = ""
    eligibility: str = "review-only"  # auto | review-only | refused
    required_params: Tuple[str, ...] = ()
    optional_params: Tuple[str, ...] = ()
    verifier_kind: str = "generic"

    # -- parameter validation -------------------------------------------------
    def preflight(self, params: Dict[str, Any]) -> List[str]:
        problems: List[str] = []
        for name in self.required_params:
            if not params.get(name) and params.get(name) != 0:
                problems.append(f"missing required parameter '{name}'")
        for name in params:
            if name not in self.required_params and name not in self.optional_params:
                problems.append(f"unknown parameter '{name}' for action {self.id}")
        return problems

    def describe(self, params: Dict[str, Any]) -> str:
        return f"{self.id} {json.dumps(params, sort_keys=True)}"

    # -- candidate generation (pure) -----------------------------------------
    def render(self, ctx: "ActionContext", params: Dict[str, Any]) -> Optional[Candidate]:
        raise NotImplementedError

    # -- validation -----------------------------------------------------------
    def validate(self, ctx: "ActionContext", params: Dict[str, Any],
                 candidate: Candidate) -> List[Check]:
        return []

    # -- follow-up effects ----------------------------------------------------
    def effects(self, ctx: "ActionContext", params: Dict[str, Any]) -> List[Effect]:
        return []

    def rollback_effects(self, ctx: "ActionContext", params: Dict[str, Any]) -> List[Effect]:
        return []


@dataclass
class ActionContext:
    root: str
    target_path: str = ""
    pre_text: str = ""
    pre_newline: str = chr(10)
    pre_state: Optional[util.FileState] = None
    strict: bool = False
    profile_id: str = ""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def unified_diff(path: str, before: str, after: str, label: str = "a") -> str:
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"{label}/{os.path.basename(path)}",
        tofile=f"b/{os.path.basename(path)}",
        n=3,
    )
    return "".join(diff)


def _require_file(ctx: ActionContext, path: str, params: Dict[str, Any]) -> Optional[str]:
    if not os.path.isfile(path):
        raise ActionError(f"target file does not exist: {path}")
    expected = params.get("expect_sha256")
    if expected:
        actual = util.sha256_file(path)
        if actual != expected:
            raise ActionError(
                f"target changed since the plan was made: {path}",
                hint=f"expected sha256 {expected[:12]}..., found {actual[:12]}... "
                     "re-run `ctfctl discover` and produce a new plan",
            )
    return expected


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


# --------------------------------------------------------------------------
# 1. Python: flask send_file(os.path.join(ROOT, name)) -> send_from_directory
# --------------------------------------------------------------------------
class FlaskSendFromDirectory(Action):
    id = "file.python_flask_send_from_directory"
    summary = "Replace one send_file(os.path.join(ROOT, name)) call with send_from_directory"
    impact = (
        "One call site in one Python source file. The route, its decorators, its default "
        "arguments and the response options are preserved; only the file-serving helper changes."
    )
    conditions = [
        "the exact call shape send_file(os.path.join(<ROOT>, <NAME>)) appears exactly once",
        "<ROOT> is a module-level constant or a simple name bound in the same module",
        "Flask is the framework providing the call (send_file imported from flask)",
        "the source file is static on disk (not generated at boot)",
    ]
    rollback_text = (
        "Restore the recorded pre-image of the file only if it still hashes to the tool's "
        "post-image; any later teammate edit makes rollback refuse and report a conflict."
    )
    required_params = ("path",)
    optional_params = ("expect_sha256", "root_expr", "flask_module", "allow_import_edit")

    def render(self, ctx: ActionContext, params: Dict[str, Any]) -> Optional[Candidate]:
        source = ctx.pre_text
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise ActionError(f"target is not valid Python: {exc}") from exc

        calls = self._find_calls(tree, params.get("root_expr"), source)
        if not calls:
            return None
        if len(calls) > 1:
            raise ActionError(
                f"found {len(calls)} matching send_file(os.path.join(...)) calls; this action "
                "only rewrites a single unambiguous call site",
                hint="split this into separate reviewed edits by hand",
            )
        node, root_expr, name_expr, extra_kwargs = calls[0]

        replacement = (
            f"send_from_directory({root_expr}, {name_expr}"
            + (f", {extra_kwargs}" if extra_kwargs else "")
            + ")"
        )
        lines = source.splitlines(keepends=True)
        start = (node.lineno - 1, node.col_offset)
        end = (node.end_lineno - 1, node.end_col_offset)
        if start[0] != end[0]:
            # Multi-line call: rebuild from the original source segments of the arguments.
            raise ActionError(
                "the matching call spans multiple lines; rewrite it manually so the diff stays "
                "reviewable"
            )
        line = lines[start[0]]
        new_line = line[: start[1]] + replacement + line[end[1]:]
        lines[start[0]] = new_line
        new_text = "".join(lines)

        notes = [f"rewrote one call site at line {node.lineno}"]
        edited_import = self._ensure_import(lines, params)
        if edited_import:
            new_text = "".join(lines)
            notes.append(edited_import)

        return Candidate(
            path=ctx.target_path,
            new_text=new_text,
            diff=unified_diff(ctx.target_path, source, new_text),
            notes=notes,
        )

    @staticmethod
    def _find_calls(tree: ast.AST, root_expr: Optional[str], source: str):
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name) or node.func.id != "send_file":
                continue
            if not node.args:
                continue
            inner = node.args[0]
            if not (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "join"):
                continue
            dotted = FlaskSendFromDirectory._dotted(inner.func.value)
            if dotted not in ("os.path", "path"):
                continue
            if len(inner.args) < 2:
                continue
            root_src = ast.get_source_segment(source, inner.args[0])
            name_src = ast.get_source_segment(source, inner.args[1])
            if root_src is None or name_src is None:
                continue
            if root_expr and root_src != root_expr:
                continue
            kwargs = [ast.get_source_segment(source, kw) or "" for kw in node.keywords]
            found.append((node, root_src, name_src, ", ".join(k for k in kwargs if k)))
        return found

    @staticmethod
    def _dotted(node: ast.AST) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def _ensure_import(self, lines: List[str], params: Dict[str, Any]) -> str:
        source = "".join(lines)
        tree = ast.parse(source)
        module = params.get("flask_module", "flask")
        already = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == module:
                if any(alias.name == "send_from_directory" for alias in node.names):
                    already = True
                    break
        if already:
            return ""
        for index, node in enumerate(tree.body):
            if isinstance(node, ast.ImportFrom) and node.module == module:
                if any(alias.name == "send_file" for alias in node.names):
                    names = [f"{a.name} as {a.asname}" if a.asname else a.name for a in node.names]
                    names.append("send_from_directory")
                    line_index = node.lineno - 1
                    indent = " " * _indent_of(lines[line_index])
                    lines[line_index] = f"{indent}from {module} import {', '.join(sorted(names))}\n"
                    return f"added send_from_directory to the existing `from {module} import ...`"
        if not params.get("allow_import_edit", True):
            raise ActionError(
                "send_from_directory is not imported and allow_import_edit is false",
                hint="add the import by hand, then re-plan",
            )
        # Insert a new import after the last top-level import.
        insert_at = 0
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
        lines.insert(insert_at, f"from {module} import send_from_directory\n")
        return f"inserted `from {module} import send_from_directory` after the import block"

    def validate(self, ctx: ActionContext, params: Dict[str, Any],
                 candidate: Candidate) -> List[Check]:
        checks: List[Check] = []
        try:
            ast.parse(candidate.new_text)
            checks.append(Check("python-parse", True, "candidate parses as Python"))
        except SyntaxError as exc:
            checks.append(Check("python-parse", False, f"candidate does not parse: {exc}"))
        tree = ast.parse(candidate.new_text)
        remaining = [n for n in ast.walk(tree)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                     and n.func.id == "send_file"]
        checks.append(Check(
            "vulnerable-call-gone",
            not remaining or len(self._find_calls(tree, params.get("root_expr"),
                                                  candidate.new_text)) == 0,
            f"{len(remaining)} send_file call(s) remain in the file"
            + (" (other call sites are untouched by design)" if remaining else ""),
            required=False,
        ))
        new_calls = [n for n in ast.walk(tree)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                     and n.func.id == "send_from_directory"]
        checks.append(Check("safe-helper-present", len(new_calls) == 1,
                            f"{len(new_calls)} send_from_directory call(s) in the candidate"))
        imported = any(
            (isinstance(n, ast.ImportFrom) and any(a.name == "send_from_directory" for a in n.names))
            for n in ast.walk(tree)
        )
        checks.append(Check("helper-imported", imported,
                            "send_from_directory is imported in the candidate"))
        return checks


# --------------------------------------------------------------------------
# 2. PHP: guarded single-line replacement (canonicalisation before filesystem use)
# --------------------------------------------------------------------------
class PhpGuardedPathUse(Action):
    id = "file.php_canonicalize_path_use"
    summary = "Insert one realpath()-based containment guard before a filesystem read"
    impact = (
        "One function body in one PHP file gains a containment check. The function still "
        "serves the same directory; only paths that escape the intended root are rejected."
    )
    conditions = [
        "the exact vulnerable statement appears exactly once",
        "the intended root expression is a literal string or a constant defined in the file",
        "php -l is available locally so the candidate can be syntax-checked before replacement",
    ]
    rollback_text = (
        "Restore the recorded pre-image if the file still matches the post-image hash; a "
        "teammate edit makes rollback refuse and report a conflict."
    )
    required_params = ("path", "root_expr", "guard_var")
    optional_params = ("expect_sha256", "statement", "php_binary")

    DEFAULT_STATEMENT = "$content = file_get_contents($path);"

    def render(self, ctx: ActionContext, params: Dict[str, Any]) -> Optional[Candidate]:
        source = ctx.pre_text
        statement = params.get("statement") or self.DEFAULT_STATEMENT
        occurrences = source.count(statement)
        if occurrences == 0:
            return None
        if occurrences > 1:
            raise ActionError(
                f"the target statement appears {occurrences} times; a single-line action cannot "
                "safely choose one"
            )
        root = params["root_expr"]
        guard_var = params["guard_var"]
        if not re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", guard_var):
            raise ActionError(f"guard_var must be a PHP variable name, got {guard_var!r}")
        line_index = None
        lines = source.splitlines(keepends=True)
        for index, line in enumerate(lines):
            if statement in line:
                line_index = index
                break
        if line_index is None:
            return None
        indent = " " * _indent_of(lines[line_index])
        guard = (
            f"{indent}$__prep_real = realpath($path);\n"
            f"{indent}{guard_var} = realpath({root});\n"
            f"{indent}if ($__prep_real === false || {guard_var} === false\n"
            f"{indent}    || strncmp($__prep_real, {guard_var} . DIRECTORY_SEPARATOR, "
            f"strlen({guard_var}) + 1) !== 0) {{\n"
            f"{indent}    http_response_code(404);\n"
            f"{indent}    exit;\n"
            f"{indent}}}\n"
        )
        lines.insert(line_index, guard)
        new_text = "".join(lines)
        return Candidate(
            path=ctx.target_path,
            new_text=new_text,
            diff=unified_diff(ctx.target_path, source, new_text),
            notes=[f"inserted containment guard before the filesystem read at line {line_index + 1}"],
        )

    def validate(self, ctx: ActionContext, params: Dict[str, Any],
                 candidate: Candidate) -> List[Check]:
        checks: List[Check] = []
        php = params.get("php_binary") or util.which("php")
        if not php:
            checks.append(Check(
                "php-lint", False,
                "php binary not found: the candidate cannot be syntax-checked, so this action "
                "refuses to replace the file",
            ))
            return checks
        if isinstance(php, list):
            # Validator runs inside the service container, reading the candidate
            # from stdin so nothing has to be copied into the container.
            argv = [str(a) for a in php] + ["-l", "/dev/stdin"]
            res = util.run(argv, timeout=30, input_text=candidate.new_text)
            checks.append(Check(
                "php-lint", res.ok,
                util.printable((res.stdout + res.stderr).strip(), 200)
                or "php -l accepted the candidate (via container)",
                command=" ".join(argv),
            ))
        else:
            import tempfile

            with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False,
                                             encoding="utf-8") as fh:
                fh.write(candidate.new_text)
                temp_path = fh.name
            try:
                res = util.run([str(php), "-l", temp_path], timeout=20)
                checks.append(Check(
                    "php-lint", res.ok,
                    util.printable((res.stdout + res.stderr).strip(), 200) or "php -l passed",
                    command="php -l <candidate>",
                ))
            finally:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
        checks.append(Check("guard-present", params["guard_var"] in candidate.new_text,
                            "containment guard is present in the candidate"))
        checks.append(Check("original-statement-preserved",
                            (params.get("statement") or self.DEFAULT_STATEMENT)
                            in candidate.new_text,
                            "the original read statement is preserved after the guard"))
        return checks


# --------------------------------------------------------------------------
# 3. Compose: remove or rebind one published port
# --------------------------------------------------------------------------
def _split_port_mapping(value: str) -> Tuple[Optional[str], Optional[str]]:
    """Split a Compose port entry into (host_port, container_port).

    Handles "80", "8080:80", "127.0.0.1:8080:80", "8080:80/tcp" and the IPv6
    form "[::1]:8080:80". Returns (None, container) when no host port is given.
    """
    text = value.split("/", 1)[0].strip()
    if text.startswith("["):
        closing = text.find("]")
        if closing == -1:
            return None, None
        remainder = text[closing + 1:].lstrip(":")
        parts = [p for p in remainder.split(":") if p != ""]
    else:
        parts = [p for p in text.split(":") if p != ""]
    if not parts:
        return None, None
    if len(parts) == 1:
        return None, parts[0]
    return parts[-2], parts[-1]


class ComposePortChange(Action):
    id = "compose.port_publication"
    summary = "Remove or restrict one published port for one Compose service"
    impact = (
        "One line in one Compose file. Container-internal networking is unchanged; only the "
        "host-side publication of that port changes. Named volumes are never touched."
    )
    conditions = [
        "the Compose file parses with `docker compose config` before and after",
        "the effective config difference is exactly the intended port change",
        "no other service depends on reaching this port through the host",
        "the evaluator/checker contract is known not to use this port",
    ]
    rollback_text = "Restore the pre-image Compose file and recreate only the affected service."
    required_params = ("file", "service")
    optional_params = ("port", "mode", "expect_sha256", "compose_argv", "bind_address")

    def render(self, ctx: ActionContext, params: Dict[str, Any]) -> Optional[Candidate]:
        source = ctx.pre_text
        port = str(params.get("port") or "")
        mode = params.get("mode", "remove")  # remove | loopback
        if mode not in ("remove", "loopback"):
            raise ActionError(f"unsupported mode {mode!r}")
        lines = source.splitlines(keepends=True)
        span, item_index = self._locate_port(lines, params["service"], port)
        if span is None:
            return None
        start, end = span
        if mode == "remove":
            new_lines = lines[:start] + lines[end:]
            notes = [f"removed the published port {port or '(only entry)'} from service "
                     f"{params['service']}"]
        else:
            original = lines[item_index]
            indent = " " * _indent_of(original)
            value = original.strip().lstrip("-").strip().strip('"').strip("'")
            bind = params.get("bind_address", "127.0.0.1")
            host_part, container_part = _split_port_mapping(value)
            if host_part is not None:
                # Already bound to a specific host address: a no-op when it is the
                # requested address, a refusal when it is a different one.
                if host_part == bind and container_part:
                    return None
                raise ActionError(
                    f"the port entry already has host address {host_part!r}; this action only "
                    f"binds an unrestricted publication to {bind}, so edit it by hand"
                )
            new_lines = list(lines)
            new_lines[item_index] = f'{indent}- "{bind}:{value}"\n'
            notes = [f"rebound published port {value} to {bind}"]
        new_text = "".join(new_lines)
        return Candidate(path=ctx.target_path, new_text=new_text,
                         diff=unified_diff(ctx.target_path, source, new_text), notes=notes)

    @staticmethod
    def _locate_port(lines: List[str], service: str, port: str):
        """Find the line span to remove for one service's port entry.

        Understands only the common Compose shapes:
            services:
              <service>:
                ports:
                  - "5432:5432"
        Anything else returns (None, None) so the caller refuses instead of guessing.
        """
        service_re = re.compile(rf"^\s{{0,8}}{re.escape(service)}\s*:\s*(#.*)?$")
        service_start = None
        for index, line in enumerate(lines):
            if service_re.match(line.rstrip("\n")):
                service_start = index
                break
        if service_start is None:
            raise ActionError(f"service {service!r} not found at the top level of the file")
        service_indent = _indent_of(lines[service_start])
        ports_index = None
        block_end = len(lines)
        for index in range(service_start + 1, len(lines)):
            line = lines[index]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = _indent_of(line)
            if indent <= service_indent and line.strip():
                block_end = index
                break
            if re.match(r"^\s*ports\s*:", line):
                ports_index = index
                break
        if ports_index is None:
            return None, None
        ports_indent = _indent_of(lines[ports_index])
        entries: List[int] = []
        for index in range(ports_index + 1, block_end):
            line = lines[index]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = _indent_of(line)
            if indent <= ports_indent:
                block_end = index
                break
            if line.lstrip().startswith("-"):
                entries.append(index)
        if not port:
            if len(entries) != 1:
                raise ActionError(
                    f"service {service!r} publishes {len(entries)} ports; specify which one with "
                    "the 'port' parameter"
                )
            chosen = entries[0]
        else:
            chosen = None
            for index in entries:
                value = lines[index].strip().lstrip("-").strip().strip('"').strip("'")
                host_part, container_part = _split_port_mapping(value)
                # The `port` parameter is a HOST port (that is what the profile's
                # host_port fact resolves to); a bare container-only mapping also
                # matches when it is the only form present.
                if host_part == port or (container_part == port and host_part is None):
                    chosen = index
                    break
            if chosen is None:
                return None, None
        span_start = chosen
        span_end = chosen + 1
        if len(entries) == 1 and not port:
            span_start = ports_index
            span_end = chosen + 1
        elif len(entries) == 1 and port:
            span_start = ports_index
            span_end = chosen + 1
        return (span_start, span_end), chosen

    def validate(self, ctx: ActionContext, params: Dict[str, Any],
                 candidate: Candidate) -> List[Check]:
        checks: List[Check] = []
        compose_argv = params.get("compose_argv") or []
        docker = util.which("docker")
        if not compose_argv:
            if docker:
                compose_argv = ["docker", "compose"]
            else:
                checks.append(Check(
                    "compose-validate", False,
                    "docker compose is unavailable: the candidate Compose file cannot be parsed, "
                    "so this action refuses to replace the file",
                ))
                return checks
        checks.append(self._validate_candidate(candidate, compose_argv))
        checks.append(self._effective_diff_check(candidate, compose_argv, params))
        return checks

    def _validate_candidate(self, candidate: Candidate, compose_argv: List[str]) -> Check:
        directory = os.path.dirname(os.path.abspath(candidate.path)) or "."
        temp_path = os.path.join(directory, f".compose-candidate-{os.getpid()}.yaml")
        try:
            with open(temp_path, "w", encoding="utf-8") as fh:
                fh.write(candidate.new_text)
            res = util.run(compose_argv + ["-f", temp_path, "config", "--quiet"],
                           timeout=45, cwd=directory)
            detail = util.printable((res.stdout + res.stderr).strip(), 300)
            return Check("compose-validate", res.ok,
                         detail or "docker compose config --quiet accepted the candidate",
                         command="docker compose -f <candidate> config --quiet")
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    def _effective_diff_check(self, candidate: Candidate, compose_argv: List[str],
                              params: Dict[str, Any]) -> Check:
        """Compare resolved config before/after: only the intended port may differ."""
        directory = os.path.dirname(os.path.abspath(candidate.path)) or "."
        before = self._resolved(compose_argv, candidate.path, directory)
        after_temp = os.path.join(directory, f".compose-candidate-{os.getpid()}.yaml")
        try:
            with open(after_temp, "w", encoding="utf-8") as fh:
                fh.write(candidate.new_text)
            after = self._resolved(compose_argv, after_temp, directory)
        finally:
            try:
                os.unlink(after_temp)
            except OSError:
                pass
        if before is None or after is None:
            return Check("effective-config-diff", False,
                         "could not resolve the Compose configuration to compare before/after")
        before_ports = self._ports_of(before, params["service"])
        after_ports = self._ports_of(after, params["service"])
        others_before = {k: v for k, v in before.get("services", {}).items()
                         if k != params["service"]}
        others_after = {k: v for k, v in after.get("services", {}).items()
                        if k != params["service"]}
        unchanged = json.dumps(others_before, sort_keys=True) == json.dumps(others_after,
                                                                           sort_keys=True)
        volumes_before = before.get("volumes")
        volumes_after = after.get("volumes")
        return Check(
            "effective-config-diff",
            unchanged and volumes_before == volumes_after,
            f"ports {before_ports} -> {after_ports}; other services unchanged={unchanged}; "
            f"volumes unchanged={volumes_before == volumes_after}",
            command="docker compose config --format json (before vs candidate)",
        )

    @staticmethod
    def _resolved(compose_argv: List[str], path: str, directory: str) -> Optional[Dict[str, Any]]:
        res = util.run(compose_argv + ["-f", path, "config", "--format", "json"],
                       timeout=45, cwd=directory, max_output=4 * 1024 * 1024)
        if not res.ok:
            return None
        try:
            return json.loads(res.stdout)
        except ValueError:
            return None

    @staticmethod
    def _ports_of(config: Dict[str, Any], service: str) -> List[Any]:
        entry = (config.get("services") or {}).get(service) or {}
        return entry.get("ports") or []

    def effects(self, ctx: ActionContext, params: Dict[str, Any]) -> List[Effect]:
        argv = params.get("compose_argv") or []
        if not argv:
            return []
        directory = os.path.dirname(os.path.abspath(ctx.target_path)) or "."


# --------------------------------------------------------------------------
# 4. systemd unit: rewrite one ExecStart argument (review-only)
# --------------------------------------------------------------------------
class SystemdUnitArgEdit(Action):
    id = "systemd.unit_exec_arg_edit"
    summary = "Rewrite one argument in a systemd unit's ExecStart line"
    impact = (
        "One argument in one unit file. The service must be reloaded and restarted for the "
        "change to take effect, which briefly interrupts availability."
    )
    conditions = [
        "systemd-analyze verify accepts the candidate unit",
        "the argument being changed is unambiguous (appears exactly once in ExecStart)",
        "the evaluator is not known to contact the old binding directly",
        "a working rollback path exists for the unit and the service restarts cleanly",
    ]
    rollback_text = "Restore the pre-image unit file, daemon-reload, restart, re-verify."
    eligibility = "review-only"
    required_params = ("path", "old_arg", "new_arg")
    optional_params = ("expect_sha256", "unit_name")

    def render(self, ctx: ActionContext, params: Dict[str, Any]) -> Optional[Candidate]:
        source = ctx.pre_text
        old_arg, new_arg = params["old_arg"], params["new_arg"]
        matches = [line for line in source.splitlines() if "ExecStart" in line and old_arg in line]
        if not matches:
            return None
        if len(matches) > 1:
            raise ActionError("multiple ExecStart lines contain the target argument; refusing")
        for line in matches:
            if line.count(old_arg) != 1:
                raise ActionError(f"argument {old_arg!r} is not unique within its ExecStart line")
        new_text = source.replace(old_arg, new_arg, 1)
        return Candidate(
            path=ctx.target_path,
            new_text=new_text,
            diff=unified_diff(ctx.target_path, source, new_text),
            notes=[f"rewrote {old_arg!r} -> {new_arg!r} in ExecStart"],
        )

    def validate(self, ctx: ActionContext, params: Dict[str, Any],
                 candidate: Candidate) -> List[Check]:
        checks: List[Check] = []
        if not util.which("systemd-analyze"):
            checks.append(Check("systemd-verify", False,
                                "systemd-analyze is unavailable: unit syntax cannot be validated, "
                                "so this action refuses to replace the file"))
            return checks
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".service", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(candidate.new_text)
            temp_path = fh.name
        try:
            res = util.run(["systemd-analyze", "verify", temp_path], timeout=30)
            checks.append(Check("systemd-verify", res.ok,
                                util.printable((res.stdout + res.stderr).strip(), 300)
                                or "systemd-analyze verify passed"))
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        checks.append(Check("arg-present", params["new_arg"] in candidate.new_text,
                            "new argument is present in the candidate"))
        return checks


# --------------------------------------------------------------------------
# 5. firewall: additive nftables allowlist table (review-only, file_create)
# --------------------------------------------------------------------------
_NFT_PATH_RE = re.compile(r"^/etc/[A-Za-z0-9._-]{1,64}\.nft$")
_NFT_TABLE_RE = re.compile(r"^[a-z][a-z0-9_]{2,31}$")
_CIDR_RE = re.compile(r"^[0-9A-Fa-f:.]+/[0-9]{1,3}$")


class FirewallNftLockdownTable(Action):
    """Create a *separate* nftables table that drops non-allowlisted inbound traffic.

    Deliberately additive: it never flushes the ruleset and never edits another
    table, so Docker NAT rules and anything the image shipped keep working. The
    operator's own SSH source address is mandatory in the allowlist, which is
    what keeps the change from locking the team out of the box.
    """

    id = "firewall.nft_lockdown_table"
    kind = "file_create"
    summary = "Create an additive nftables table that drops non-allowlisted inbound traffic"
    impact = (
        "Adds one drop-only base chain at a later priority than the existing rules. "
        "Established connections, loopback, ICMP and the allowlisted sources/ports keep "
        "working; everything else inbound is dropped. No other table is flushed or edited. "
        "A missing allowlist entry (for example the checker's source address) becomes a "
        "silent score loss, so this is review-only and must be read before it is applied."
    )
    conditions = [
        "the event rules permit host firewall changes on this box",
        "the operator's own SSH source CIDR is in the allowlist (added automatically, never optional)",
        "every port the organizer checker uses is either in allow_tcp_ports or comes from the allowlist",
        "an out-of-band console (VNC/serial/provider) is available before applying",
        "`nft -c -f` accepts the generated ruleset",
    ]
    rollback_text = (
        "Delete the table (`nft delete table inet <table>`) and remove the generated file. "
        "Rollback re-runs the delete so the running ruleset is clean even though the "
        "pre-image file never existed."
    )
    eligibility = "review-only"
    required_params = ("path", "allow_cidrs", "operator_cidr", "allow_tcp_ports")
    optional_params = ("table", "allow_udp_ports", "log_drops", "note")
    verifier_kind = "nft_table"

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _cidrs(raw: str) -> List[str]:
        import ipaddress

        out: List[str] = []
        for item in str(raw).replace(";", ",").split(","):
            item = item.strip()
            if not item:
                continue
            if not _CIDR_RE.match(item):
                raise ActionError(f"allowlist entry {item!r} is not a CIDR (for example 10.0.0.0/24)")
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ActionError(f"allowlist entry {item!r} is not a valid network: {exc}")
            if network.prefixlen == 0:
                raise ActionError(
                    f"allowlist entry {item!r} allows the whole internet, which defeats the "
                    "lockdown; list the team and checker ranges instead"
                )
            out.append(str(network))
        return out

    @staticmethod
    def _ports(raw: str) -> List[int]:
        out: List[int] = []
        for item in str(raw).replace(";", ",").split(","):
            item = item.strip()
            if not item or item.lower() in ("none", "-", "off"):
                continue
            if not item.isdigit() or not 0 < int(item) <= 65535:
                raise ActionError(f"port {item!r} is not a valid TCP/UDP port")
            out.append(int(item))
        return sorted(set(out))

    def preflight(self, params: Dict[str, Any]) -> List[str]:
        problems = super().preflight(params)
        if problems:
            return problems
        if not _NFT_PATH_RE.match(str(params.get("path"))):
            problems.append("path must be a plain nftables file under /etc (e.g. /etc/ctfctl-lockdown.nft)")
        table = str(params.get("table") or "ctfctl_lockdown")
        if not _NFT_TABLE_RE.match(table):
            problems.append(f"table name {table!r} must be a lowercase nftables identifier")
        try:
            cidrs = self._cidrs(params["allow_cidrs"])
            self._ports(params["allow_tcp_ports"])
        except ActionError as exc:
            problems.append(str(exc))
            return problems
        operator = str(params["operator_cidr"])
        if not cidrs:
            problems.append("allow_cidrs is empty: refusing to build a default-deny table with no allowlist")
        elif not any(
            self._contains(entry, operator) for entry in cidrs
        ):
            problems.append(
                f"operator_cidr {operator} is not covered by allow_cidrs, which would cut off "
                "the operator's own SSH session"
            )
        return problems

    @staticmethod
    def _contains(cidr: str, value: str) -> bool:
        import ipaddress

        try:
            if "/" in value:
                return ipaddress.ip_network(value, strict=False).subnet_of(
                    ipaddress.ip_network(cidr, strict=False)
                )
            return ipaddress.ip_address(value) in ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            return False

    def _ruleset(self, params: Dict[str, Any]) -> str:
        table = str(params.get("table") or "ctfctl_lockdown")
        cidrs = self._cidrs(params["allow_cidrs"])
        tcp = self._ports(params["allow_tcp_ports"])
        udp = self._ports(params.get("allow_udp_ports") or "")
        v4 = [c for c in cidrs if ":" not in c]
        v6 = [c for c in cidrs if ":" in c]
        note = str(params.get("note") or "")
        lines = [
            "# ctfctl lockdown table -- review-only, generated change.",
            "# Remove it with `ctfctl remote lockdown <host> --revert` (or the transaction rollback).",
            "# This table only drops traffic that is not allowlisted. It flushes and edits nothing.",
        ]
        if note:
            lines.append("# note: " + util.printable(note, 200))
        lines += [
            f"table inet {table} {{",
            "    chain input {",
            "        type filter hook input priority filter + 10; policy accept;",
            "        ct state established,related accept",
            "        ct state invalid drop",
            "        iif lo accept",
            "        ip protocol icmp accept",
            "        ip6 nexthdr ipv6-icmp accept",
        ]
        if tcp:
            lines.append("        tcp dport { " + ", ".join(str(p) for p in tcp) + " } accept")
        if udp:
            lines.append("        udp dport { " + ", ".join(str(p) for p in udp) + " } accept")
        if v4:
            lines.append("        ip saddr { " + ", ".join(v4) + " } accept")
        if v6:
            lines.append("        ip6 saddr { " + ", ".join(v6) + " } accept")
        if params.get("log_drops"):
            lines.append(
                '        log prefix "ctfctl-drop " limit rate 10/second counter drop'
            )
        else:
            lines.append("        counter drop")
        lines += ["    }", "}"]
        return "\n".join(lines) + "\n"

    def render(self, ctx: ActionContext, params: Dict[str, Any]) -> Optional[Candidate]:
        text = self._ruleset(params)
        if ctx.pre_text.strip() == text.strip():
            return None
        if ctx.pre_text and str(params.get("table") or "ctfctl_lockdown") in ctx.pre_text:
            raise ActionError(
                f"{ctx.target_path} already contains a '{params.get('table', 'ctfctl_lockdown')}' "
                "table but with different content: edit it by hand instead of overwriting"
            )
        label = "a" if ctx.pre_text else "/dev/null"
        return Candidate(
            path=ctx.target_path,
            new_text=text,
            diff=unified_diff(ctx.target_path, ctx.pre_text, text, label=label),
            notes=[
                "additive nftables table; no other table is flushed or changed",
                "the operator's SSH source CIDR is in the allowlist by construction",
            ],
        )

    def validate(self, ctx: ActionContext, params: Dict[str, Any],
                 candidate: Candidate) -> List[Check]:
        import tempfile

        checks: List[Check] = []
        table = str(params.get("table") or "ctfctl_lockdown")
        operator = str(params["operator_cidr"])
        checks.append(Check("operator-reachable", operator in candidate.new_text,
                            f"operator CIDR {operator} is present in the ruleset"))
        if not util.which("nft"):
            checks.append(Check(
                "nft-syntax", False,
                "nft is not installed on this host: the ruleset cannot be validated, so this "
                "action refuses to create it",
            ))
            return checks
        directory = os.path.dirname(ctx.target_path) or "/"
        if not os.path.isdir(directory):
            checks.append(Check("target-directory", False,
                                f"{directory} does not exist on this host"))
            return checks
        with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(candidate.new_text)
            temp_path = fh.name
        try:
            res = util.run(["nft", "-c", "-f", temp_path], timeout=30)
            checks.append(Check("nft-syntax", res.ok,
                                util.printable((res.stdout + res.stderr).strip(), 300)
                                or f"nft -c -f accepted {os.path.basename(temp_path)}"))
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        checks.append(Check("table-name", f"table inet {table} {{" in candidate.new_text,
                            f"ruleset declares table inet {table}"))
        return checks

    def effects(self, ctx: ActionContext, params: Dict[str, Any]) -> List[Effect]:
        table = str(params.get("table") or "ctfctl_lockdown")
        return [Effect(
            kind="nft_load_file",
            argv=["nft", "-f", ctx.target_path],
            description=f"load the additive lockdown table from {ctx.target_path}",
            timeout=30.0,
            requires="nft",
            rollback_argv=["nft", "delete", "table", "inet", table],
        )]


# --------------------------------------------------------------------------
# 6. sshd: disable password authentication when a key is proven present
# --------------------------------------------------------------------------
SSHD_OPTIONS = ("PasswordAuthentication", "KbdInteractiveAuthentication",
                "PermitRootLogin")


class SshdHardenAuthenticatedKeys(Action):
    """Turn off sshd password auth -- only when an authorized key is proven to exist.

    A lockout here costs the whole event, so the action refuses unless the
    candidate config passes `sshd -t` **and** `sshd -T` reports the hardened
    value, and it refuses outright when the file contains a `Match` block (an
    appended directive would silently land inside that block).
    """

    id = "sshd.harden_authenticated_keys"
    kind = "file_edit"
    summary = "Disable sshd password authentication while an authorized key exists"
    impact = (
        "Appends hardening directives to the sshd configuration. The current SSH session "
        "survives, but the *next* login must use a key or the console. Without a proven key "
        "and a console this is a self-inflicted denial of service, which is why it is "
        "review-only."
    )
    conditions = [
        "a non-empty authorized_keys entry exists for the account that must keep access",
        "the event rules permit SSH configuration changes",
        "an out-of-band console (VNC/serial/provider) is available before applying",
        "`sshd -t` and `sshd -T` accept the candidate configuration",
    ]
    rollback_text = "Restore the pre-image sshd_config and restart the service."
    eligibility = "review-only"
    required_params = ("path", "authorized_keys_path")
    optional_params = ("permit_root_login", "disable_password_auth",
                       "disable_keyboard_interactive", "service_unit")
    verifier_kind = "sshd_option"

    def preflight(self, params: Dict[str, Any]) -> List[str]:
        problems = super().preflight(params)
        if problems:
            return problems
        for key in ("path", "authorized_keys_path"):
            value = str(params.get(key) or "")
            if not value.startswith("/"):
                problems.append(f"{key} must be an absolute path (got {value!r})")
        root_login = str(params.get("permit_root_login") or "prohibit-password")
        if root_login not in ("prohibit-password", "no"):
            problems.append(
                "permit_root_login must be 'prohibit-password' or 'no' "
                "(this action never re-enables root login)"
            )
        unit = str(params.get("service_unit") or "ssh")
        if not re.fullmatch(r"[A-Za-z0-9@._-]{1,64}", unit):
            problems.append(f"service_unit {unit!r} is not a valid unit name")
        return problems

    def _desired(self, params: Dict[str, Any]) -> List[Tuple[str, str]]:
        wanted: List[Tuple[str, str]] = []
        if bool(params.get("disable_password_auth", True)):
            wanted.append(("PasswordAuthentication", "no"))
        if bool(params.get("disable_keyboard_interactive", True)):
            wanted.append(("KbdInteractiveAuthentication", "no"))
        wanted.append(("PermitRootLogin", str(params.get("permit_root_login") or "prohibit-password")))
        return wanted

    marker = "# ctfctl lockdown: appended by `ctfctl lockdown` (review-only change)."

    def render(self, ctx: ActionContext, params: Dict[str, Any]) -> Optional[Candidate]:
        source = ctx.pre_text
        if not source.strip():
            raise ActionError(f"{ctx.target_path} is empty; refusing to invent an sshd config")
        if re.search(r"^\s*Match\b", source, re.MULTILINE):
            raise ActionError(
                "the sshd config contains a Match block; an appended directive would land "
                "inside it. Edit the file by hand and re-run the plan"
            )
        wanted = self._desired(params)
        # A previous run of this action may have appended a managed block; drop
        # the whole block (blank line + comment + directives) before rebuilding it
        # so a second apply is a no-op rather than a duplicate block.
        base_lines = source.splitlines()
        if self.marker in base_lines:
            index = base_lines.index(self.marker)
            if index and not base_lines[index - 1].strip():
                index -= 1
            base_lines = base_lines[:index]
        keep: List[str] = []
        for line in base_lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and \
                    any(stripped.split()[0].lower() == name.lower() for name, _ in wanted):
                continue  # replaced by the block below
            keep.append(line)
        block = [
            "",
            self.marker,
            "# Remove this block to restore password authentication.",
        ] + [f"{name} {value}" for name, value in wanted]
        new_text = "\n".join(keep).rstrip("\n") + "\n" + "\n".join(block) + "\n"
        if new_text == source:
            return None
        return Candidate(
            path=ctx.target_path,
            new_text=new_text,
            diff=unified_diff(ctx.target_path, source, new_text),
            notes=[f"appended {len(wanted)} hardening directive(s); no other setting changed"],
        )

    def validate(self, ctx: ActionContext, params: Dict[str, Any],
                 candidate: Candidate) -> List[Check]:
        import tempfile

        checks: List[Check] = []
        keys_path = str(params["authorized_keys_path"])
        keys = util.read_text(keys_path, 64 * 1024) if os.path.isfile(keys_path) else ""
        usable = [line for line in keys.splitlines()
                  if line.strip() and not line.strip().startswith("#")]
        checks.append(Check(
            "authorized-key-present", bool(usable),
            f"{keys_path} has {len(usable)} usable key line(s)" if usable
            else f"{keys_path} is missing or empty: without a key this would lock everyone out",
        ))
        if not util.which("sshd"):
            checks.append(Check("sshd-syntax", False,
                                "sshd is not installed here: the candidate cannot be validated"))
            return checks
        with tempfile.NamedTemporaryFile("w", suffix="_sshd_config", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(candidate.new_text)
            temp_path = fh.name
        try:
            syntax = util.run(["sshd", "-t", "-f", temp_path], timeout=30)
            checks.append(Check("sshd-syntax", syntax.ok,
                                util.printable((syntax.stdout + syntax.stderr).strip(), 300)
                                or "sshd -t accepted the candidate"))
            effective = util.run(["sshd", "-T", "-f", temp_path], timeout=30,
                                 max_output=512 * 1024)
            if not effective.ok:
                checks.append(Check(
                    "sshd-effective", False,
                    "sshd -T could not read the candidate: "
                    + (util.printable(effective.stderr.strip(), 200) or "no output"),
                ))
            else:
                lowered = effective.stdout.lower()
                problems: List[str] = []
                for name, value in self._desired(params):
                    if f"{name.lower()} {value.lower()}" not in lowered:
                        problems.append(f"{name} is not effectively {value}")
                checks.append(Check(
                    "sshd-effective", not problems,
                    "; ".join(problems) if problems
                    else "sshd -T reports every hardened value (drop-in files included)",
                ))
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        return checks

    def effects(self, ctx: ActionContext, params: Dict[str, Any]) -> List[Effect]:
        # Restart only when systemd is genuinely the init system. A container or
        # chroot has the binary without the manager; restarting there would fail
        # and (correctly) roll the safe change back for no reason.
        if not util.which("systemctl") or not os.path.isdir("/run/systemd/system"):
            return []
        unit = str(params.get("service_unit") or "ssh")
        return [Effect(
            kind="systemd_restart",
            argv=["systemctl", "restart", unit],
            description=f"restart {unit} so the hardened config is live",
            timeout=60.0,
            requires="systemctl",
        )]


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------
ACTIONS: Dict[str, Action] = {
    action.id: action
    for action in (
        FlaskSendFromDirectory(),
        PhpGuardedPathUse(),
        ComposePortChange(),
        SystemdUnitArgEdit(),
        FirewallNftLockdownTable(),
        SshdHardenAuthenticatedKeys(),
    )
}


def get(action_id: str) -> Action:
    action = ACTIONS.get(action_id)
    if action is None:
        raise ActionError(
            f"unknown action id {action_id!r}",
            hint="actions are dispatched from a fixed registry; see docs/support-matrix.md",
        )
    return action


def catalogue() -> List[Dict[str, Any]]:
    return [
        {
            "action_id": action.id,
            "kind": action.kind,
            "summary": action.summary,
            "eligibility": action.eligibility,
            "required_params": list(action.required_params),
            "optional_params": list(action.optional_params),
            "impact": action.impact,
            "conditions": action.conditions,
            "rollback": action.rollback_text,
        }
        for action in sorted(ACTIONS.values(), key=lambda a: a.id)
    ]


