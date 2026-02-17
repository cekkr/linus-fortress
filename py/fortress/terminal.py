import errno
import fcntl
import os
import pty
import pwd
import struct
import subprocess
import termios
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import HTTPException

from fortress.system import run_command

DEFAULT_ALLOWED_SHELLS = (
    "/bin/bash",
    "/bin/sh",
    "/bin/dash",
    "/bin/zsh",
    "/usr/bin/bash",
    "/usr/bin/zsh",
)


def _parse_positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _parse_shell_list_env(name: str, fallback: List[str]) -> List[str]:
    raw = os.environ.get(name)
    if raw is None:
        return list(fallback)
    values: List[str] = []
    seen: Set[str] = set()
    for chunk in raw.split(","):
        shell = normalize_shell_path(chunk)
        if not shell or shell in seen:
            continue
        values.append(shell)
        seen.add(shell)
    return values or list(fallback)


def normalize_shell_path(value: Optional[str]) -> str:
    if not value:
        return ""
    shell = value.strip()
    if not shell:
        return ""
    if not shell.startswith("/"):
        return ""
    if any(ch.isspace() for ch in shell):
        return ""
    return shell


def normalize_unix_username(value: Optional[str]) -> str:
    if value is None:
        return ""
    candidate = value.strip()
    if not candidate:
        return ""
    if len(candidate) > 32:
        return ""
    first = candidate[0]
    if not (first.islower() or first == "_"):
        return ""
    for ch in candidate[1:]:
        if not (ch.islower() or ch.isdigit() or ch in ("_", "-")):
            return ""
    return candidate


@dataclass
class TerminalSession:
    session_id: str
    owner_id: str
    actor: str
    target: str
    os_user: str
    shell: str
    process: subprocess.Popen
    master_fd: int
    created_at: float
    last_activity: float
    container_name: Optional[str] = None
    input_bytes: int = 0
    output_bytes: int = 0


class TerminalSessionManager:
    def __init__(self) -> None:
        self.max_sessions = _parse_positive_int_env("FORTRESS_TERMINAL_MAX_SESSIONS", 24)
        self.idle_timeout_seconds = _parse_positive_int_env("FORTRESS_TERMINAL_IDLE_TIMEOUT_SECONDS", 900)
        self.read_chunk_bytes = _parse_positive_int_env("FORTRESS_TERMINAL_READ_CHUNK_BYTES", 8192)
        self.read_limit_bytes = _parse_positive_int_env("FORTRESS_TERMINAL_READ_LIMIT_BYTES", 262144)
        self.write_limit_bytes = _parse_positive_int_env("FORTRESS_TERMINAL_WRITE_LIMIT_BYTES", 65536)
        self._allowed_shells = _parse_shell_list_env("FORTRESS_TERMINAL_ALLOWED_SHELLS", list(DEFAULT_ALLOWED_SHELLS))
        self._sessions: Dict[str, TerminalSession] = {}
        self._lock = threading.RLock()

    def list_allowed_shells(self) -> List[str]:
        return list(self._allowed_shells)

    def _now(self) -> float:
        return time.time()

    def _set_winsize(self, fd: int, cols: int, rows: int) -> None:
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

    def _normalize_dimensions(self, cols: int, rows: int) -> tuple[int, int]:
        if cols < 20 or cols > 400:
            raise HTTPException(status_code=400, detail="cols must be between 20 and 400")
        if rows < 5 or rows > 240:
            raise HTTPException(status_code=400, detail="rows must be between 5 and 240")
        return cols, rows

    def _effective_shell_allowlist(self, policy_shells: Optional[List[str]]) -> Set[str]:
        global_allow = set(self._allowed_shells)
        if not policy_shells:
            return global_allow
        policy_set: Set[str] = set()
        for item in policy_shells:
            normalized = normalize_shell_path(item)
            if normalized:
                policy_set.add(normalized)
        return global_allow.intersection(policy_set)

    def validate_shell(self, requested_shell: Optional[str], policy_shells: Optional[List[str]] = None) -> str:
        shell = normalize_shell_path(requested_shell)
        if not shell:
            raise HTTPException(status_code=400, detail="Shell path must be an absolute executable path")
        allowed = self._effective_shell_allowlist(policy_shells)
        if not allowed:
            raise HTTPException(status_code=403, detail="No shells are allowed by the terminal policy")
        if shell not in allowed:
            raise HTTPException(status_code=403, detail="Requested shell is not allowed by terminal policy")
        return shell

    def _spawn_pty(
        self,
        command: List[str],
        *,
        cols: int,
        rows: int,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        preexec_fn=None,
    ) -> tuple[subprocess.Popen, int]:
        master_fd, slave_fd = pty.openpty()
        self._set_winsize(master_fd, cols, rows)
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        try:
            proc = subprocess.Popen(
                command,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=env,
                cwd=cwd,
                preexec_fn=preexec_fn,
                start_new_session=True,
                text=False,
            )
        except Exception:
            os.close(master_fd)
            os.close(slave_fd)
            raise
        finally:
            try:
                os.close(slave_fd)
            except OSError:
                pass
        return proc, master_fd

    def _terminate_process(self, proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=1.0)
            return
        except Exception:
            pass
        try:
            proc.kill()
            proc.wait(timeout=1.0)
        except Exception:
            pass

    def _close_locked(self, session_id: str, reason: Optional[str] = None) -> Optional[Dict[str, Any]]:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return None
        exit_code = session.process.poll()
        if exit_code is None:
            self._terminate_process(session.process)
            exit_code = session.process.poll()
        try:
            os.close(session.master_fd)
        except OSError:
            pass
        return {
            "session_id": session.session_id,
            "target": session.target,
            "container_name": session.container_name,
            "actor": session.actor,
            "os_user": session.os_user,
            "shell": session.shell,
            "exit_code": exit_code,
            "input_bytes": session.input_bytes,
            "output_bytes": session.output_bytes,
            "closed_reason": reason or "closed",
            "closed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _sweep_locked(self) -> None:
        now = self._now()
        expired: List[str] = []
        for session_id, session in self._sessions.items():
            idle_seconds = now - session.last_activity
            if idle_seconds >= self.idle_timeout_seconds:
                expired.append(session_id)
                continue
            if session.process.poll() is not None and idle_seconds >= 30:
                expired.append(session_id)
        for session_id in expired:
            self._close_locked(session_id, reason="expired")

    def _assert_owner_locked(self, session: TerminalSession, owner_id: str, allow_any: bool) -> None:
        if allow_any:
            return
        if session.owner_id != owner_id:
            raise HTTPException(status_code=404, detail="Terminal session not found")

    def _create_session_locked(
        self,
        owner_id: str,
        actor: str,
        target: str,
        os_user: str,
        shell: str,
        process: subprocess.Popen,
        master_fd: int,
        container_name: Optional[str],
    ) -> Dict[str, Any]:
        session_id = os.urandom(18).hex()
        now = self._now()
        session = TerminalSession(
            session_id=session_id,
            owner_id=owner_id,
            actor=actor,
            target=target,
            os_user=os_user,
            shell=shell,
            process=process,
            master_fd=master_fd,
            created_at=now,
            last_activity=now,
            container_name=container_name,
        )
        self._sessions[session_id] = session
        return self.describe(session_id, owner_id, allow_any=True)

    def create_host_session(
        self,
        *,
        owner_id: str,
        actor: str,
        os_user: str,
        shell: str,
        cols: int,
        rows: int,
        cwd: Optional[str] = None,
        policy_shells: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        resolved_cols, resolved_rows = self._normalize_dimensions(cols, rows)
        shell = self.validate_shell(shell, policy_shells)
        if not os.path.isabs(shell):
            raise HTTPException(status_code=400, detail="Shell path must be absolute")
        try:
            os_user_entry = pwd.getpwnam(os_user)
        except KeyError:
            raise HTTPException(status_code=403, detail=f"Mapped OS user '{os_user}' does not exist on host")

        launch_cwd = cwd.strip() if cwd else ""
        if launch_cwd and not os.path.isabs(launch_cwd):
            raise HTTPException(status_code=400, detail="cwd must be an absolute path")
        if not launch_cwd:
            launch_cwd = os_user_entry.pw_dir or "/"
        if not os.path.isdir(launch_cwd):
            raise HTTPException(status_code=400, detail=f"cwd does not exist: {launch_cwd}")

        current_uid = os.geteuid()
        preexec = None
        if current_uid == 0:
            target_uid = os_user_entry.pw_uid
            target_gid = os_user_entry.pw_gid

            def _demote() -> None:
                os.setgid(target_gid)
                os.initgroups(os_user_entry.pw_name, target_gid)
                os.setuid(target_uid)

            preexec = _demote
        elif os_user_entry.pw_uid != current_uid:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Host terminal cannot switch OS users when fortress server is not running as root. "
                    "Configure a matching os_user mapping."
                ),
            )

        env = {
            "TERM": "xterm-256color",
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "HOME": os_user_entry.pw_dir or "/",
            "USER": os_user_entry.pw_name,
            "LOGNAME": os_user_entry.pw_name,
            "SHELL": shell,
            "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        }

        command = [shell, "-l"]
        with self._lock:
            self._sweep_locked()
            if len(self._sessions) >= self.max_sessions:
                raise HTTPException(status_code=429, detail="Maximum concurrent terminal sessions reached")
            try:
                process, master_fd = self._spawn_pty(
                    command,
                    cols=resolved_cols,
                    rows=resolved_rows,
                    env=env,
                    cwd=launch_cwd,
                    preexec_fn=preexec,
                )
            except HTTPException:
                raise
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"Failed to start host terminal: {exc}")
            return self._create_session_locked(
                owner_id=owner_id,
                actor=actor,
                target="host",
                os_user=os_user,
                shell=shell,
                process=process,
                master_fd=master_fd,
                container_name=None,
            )

    def create_container_session(
        self,
        *,
        owner_id: str,
        actor: str,
        container_name: str,
        os_user: str,
        shell: str,
        cols: int,
        rows: int,
        policy_shells: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        resolved_cols, resolved_rows = self._normalize_dimensions(cols, rows)
        shell = self.validate_shell(shell, policy_shells)
        container_name = container_name.strip()
        if not container_name:
            raise HTTPException(status_code=400, detail="container_name is required for container terminal sessions")

        # Validate user and shell inside the container before opening the PTY.
        if os_user != "root":
            run_command(["lxc", "exec", container_name, "--", "id", "-u", os_user])
        run_command(["lxc", "exec", container_name, "--", "test", "-x", shell])

        command: List[str]
        if os_user == "root":
            command = ["lxc", "exec", container_name, "--", "env", "TERM=xterm-256color", shell, "-l"]
        else:
            command = [
                "lxc",
                "exec",
                container_name,
                "--",
                "env",
                "TERM=xterm-256color",
                "su",
                "-l",
                os_user,
                "-s",
                shell,
            ]

        with self._lock:
            self._sweep_locked()
            if len(self._sessions) >= self.max_sessions:
                raise HTTPException(status_code=429, detail="Maximum concurrent terminal sessions reached")
            try:
                process, master_fd = self._spawn_pty(command, cols=resolved_cols, rows=resolved_rows)
            except HTTPException:
                raise
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"Failed to start container terminal: {exc}")
            return self._create_session_locked(
                owner_id=owner_id,
                actor=actor,
                target="container",
                os_user=os_user,
                shell=shell,
                process=process,
                master_fd=master_fd,
                container_name=container_name,
            )

    def describe(self, session_id: str, owner_id: str, *, allow_any: bool = False) -> Dict[str, Any]:
        with self._lock:
            self._sweep_locked()
            session = self._sessions.get(session_id)
            if session is None:
                raise HTTPException(status_code=404, detail="Terminal session not found")
            self._assert_owner_locked(session, owner_id, allow_any)
            created_at = datetime.fromtimestamp(session.created_at, tz=timezone.utc).isoformat()
            last_activity_at = datetime.fromtimestamp(session.last_activity, tz=timezone.utc).isoformat()
            exit_code = session.process.poll()
            return {
                "session_id": session.session_id,
                "target": session.target,
                "container_name": session.container_name,
                "actor": session.actor,
                "os_user": session.os_user,
                "shell": session.shell,
                "running": exit_code is None,
                "exit_code": exit_code,
                "created_at": created_at,
                "last_activity_at": last_activity_at,
                "input_bytes": session.input_bytes,
                "output_bytes": session.output_bytes,
            }

    def read(self, session_id: str, owner_id: str, *, allow_any: bool = False) -> Dict[str, Any]:
        with self._lock:
            self._sweep_locked()
            session = self._sessions.get(session_id)
            if session is None:
                raise HTTPException(status_code=404, detail="Terminal session not found")
            self._assert_owner_locked(session, owner_id, allow_any)

            output = bytearray()
            while len(output) < self.read_limit_bytes:
                want = min(self.read_chunk_bytes, self.read_limit_bytes - len(output))
                try:
                    chunk = os.read(session.master_fd, want)
                except BlockingIOError:
                    break
                except OSError as exc:
                    if exc.errno in (errno.EIO, errno.EBADF):
                        break
                    raise HTTPException(status_code=500, detail=f"Terminal read failed: {exc}")
                if not chunk:
                    break
                output.extend(chunk)

            if output:
                session.output_bytes += len(output)
                session.last_activity = self._now()
            exit_code = session.process.poll()
            return {
                "session_id": session.session_id,
                "output": bytes(output),
                "running": exit_code is None,
                "exit_code": exit_code,
            }

    def write(self, session_id: str, owner_id: str, data: bytes, *, allow_any: bool = False) -> Dict[str, Any]:
        if len(data) > self.write_limit_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Input exceeds write limit of {self.write_limit_bytes} bytes",
            )
        with self._lock:
            self._sweep_locked()
            session = self._sessions.get(session_id)
            if session is None:
                raise HTTPException(status_code=404, detail="Terminal session not found")
            self._assert_owner_locked(session, owner_id, allow_any)
            if session.process.poll() is not None:
                raise HTTPException(status_code=409, detail="Terminal session is no longer running")
            try:
                written = os.write(session.master_fd, data)
            except OSError as exc:
                raise HTTPException(status_code=500, detail=f"Terminal write failed: {exc}")
            session.input_bytes += written
            session.last_activity = self._now()
            return {"session_id": session.session_id, "written": written}

    def resize(self, session_id: str, owner_id: str, cols: int, rows: int, *, allow_any: bool = False) -> Dict[str, Any]:
        resolved_cols, resolved_rows = self._normalize_dimensions(cols, rows)
        with self._lock:
            self._sweep_locked()
            session = self._sessions.get(session_id)
            if session is None:
                raise HTTPException(status_code=404, detail="Terminal session not found")
            self._assert_owner_locked(session, owner_id, allow_any)
            try:
                self._set_winsize(session.master_fd, resolved_cols, resolved_rows)
            except OSError as exc:
                raise HTTPException(status_code=500, detail=f"Failed to resize terminal: {exc}")
            session.last_activity = self._now()
            return {"session_id": session.session_id, "cols": resolved_cols, "rows": resolved_rows}

    def close(self, session_id: str, owner_id: str, *, allow_any: bool = False) -> Dict[str, Any]:
        with self._lock:
            self._sweep_locked()
            session = self._sessions.get(session_id)
            if session is None:
                raise HTTPException(status_code=404, detail="Terminal session not found")
            self._assert_owner_locked(session, owner_id, allow_any)
            payload = self._close_locked(session_id, reason="closed_by_client")
            if payload is None:
                raise HTTPException(status_code=404, detail="Terminal session not found")
            return payload

    def cleanup(self) -> None:
        with self._lock:
            self._sweep_locked()

    def shutdown(self) -> None:
        with self._lock:
            session_ids = list(self._sessions.keys())
            for session_id in session_ids:
                self._close_locked(session_id, reason="manager_shutdown")
