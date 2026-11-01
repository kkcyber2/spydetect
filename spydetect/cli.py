"""spydetect CLI - host surveillance detection.

Two modes:
  --from-json FILE   analyse a snapshot you already collected (portable, safe)
  --live             collect from this host, then analyse

The live collector is read-only: it reads /proc and never signals, kills or
modifies anything.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .core import Connection, Process, analyse


# --------------------------------------------------------------------------
# snapshot I/O
# --------------------------------------------------------------------------

def load_snapshot(path: Path) -> tuple[list[Process], list[Connection]]:
    """Read a JSON snapshot: {"processes": [...], "connections": [...]}."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("snapshot must be a JSON object")

    procs: list[Process] = []
    for i, raw in enumerate(data.get("processes", [])):
        try:
            procs.append(Process(
                pid=int(raw["pid"]),
                name=str(raw["name"]),
                exe_path=str(raw.get("exe_path", "")),
                cmdline=str(raw.get("cmdline", "")),
                user=str(raw.get("user", "")),
                parent_pid=int(raw.get("parent_pid", 0)),
                signed=raw.get("signed", None),
                open_devices=tuple(raw.get("open_devices", ())),
                start_time=float(raw.get("start_time", 0.0)),
            ))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"processes[{i}]: {exc}") from exc

    conns: list[Connection] = []
    for i, raw in enumerate(data.get("connections", [])):
        try:
            conns.append(Connection(
                pid=int(raw["pid"]),
                local_port=int(raw["local_port"]),
                remote_addr=str(raw.get("remote_addr", "")),
                remote_port=int(raw.get("remote_port", 0)),
                state=str(raw.get("state", "ESTABLISHED")),
            ))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"connections[{i}]: {exc}") from exc

    return procs, conns


# --------------------------------------------------------------------------
# live collector (read-only, Linux /proc)
# --------------------------------------------------------------------------

def collect_live() -> tuple[list[Process], list[Connection]]:
    """Read /proc. Never writes, never signals. Linux only."""
    if not Path("/proc").is_dir():
        raise RuntimeError("live collection requires Linux (/proc not found)")

    procs: list[Process] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            name = (entry / "comm").read_text().strip()
        except OSError:
            continue

        exe_path = ""
        try:
            exe_path = os.readlink(entry / "exe")
        except OSError:
            pass

        cmdline = ""
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                "utf-8", "replace").strip()
        except OSError:
            pass

        devices: list[str] = []
        try:
            for fd in (entry / "fd").iterdir():
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                if target.startswith("/dev/"):
                    devices.append(target)
        except OSError:
            pass

        procs.append(Process(
            pid=pid, name=name, exe_path=exe_path, cmdline=cmdline,
            open_devices=tuple(sorted(set(devices))),
        ))

    conns: list[Connection] = []
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        p = Path(table)
        if not p.exists():
            continue
        try:
            lines = p.read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                local_port = int(parts[1].split(":")[1], 16)
                remote_hex, remote_port_hex = parts[2].split(":")
                remote_port = int(remote_port_hex, 16)
                state = "LISTEN" if parts[3] == "0A" else "ESTABLISHED"
                inode = parts[9]
            except (IndexError, ValueError):
                continue
            pid = _pid_for_inode(inode)
            if pid is None:
                continue
            conns.append(Connection(
                pid=pid, local_port=local_port,
                remote_addr=_hex_to_ip(remote_hex),
                remote_port=remote_port, state=state,
            ))

    return procs, conns


def _hex_to_ip(hexaddr: str) -> str:
    """Convert /proc/net/tcp little-endian hex to dotted quad."""
    if len(hexaddr) != 8:
        return ""
    try:
        octets = [int(hexaddr[i:i + 2], 16) for i in range(0, 8, 2)]
    except ValueError:
        return ""
    return ".".join(str(o) for o in reversed(octets))


def _pid_for_inode(inode: str) -> int | None:
    """Map a socket inode to a pid by scanning /proc/*/fd. Best effort."""
    if inode in ("", "0"):
        return None
    needle = f"socket:[{inode}]"
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            for fd in (entry / "fd").iterdir():
                try:
                    if os.readlink(fd) == needle:
                        return int(entry.name)
                except OSError:
                    continue
        except OSError:
            continue
    return None


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def render_text(findings) -> str:
    if not findings:
        return "No surveillance indicators found above the threshold.\n"
    lines = []
    for f in findings:
        lines.append(f"[{f.score:5.1f}] {f.severity.upper():9s} pid {f.pid:<7d} {f.name}")
        for reason in f.reasons:
            lines.append(f"          - {reason}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="spydetect",
        description="Detect host surveillance indicators. Read-only, defensive use only.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-json", type=Path, metavar="FILE",
                     help="analyse a collected snapshot instead of this host")
    src.add_argument("--live", action="store_true",
                     help="collect from this host (Linux, read-only)")
    p.add_argument("--min-score", type=float, default=25.0, help="report threshold (default 25)")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--fail-on", type=float, default=None,
                   help="exit 1 if any process scores at or above this value")
    args = p.parse_args(argv)

    try:
        if args.live:
            procs, conns = collect_live()
        else:
            procs, conns = load_snapshot(args.from_json)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = analyse(procs, conns, min_score=args.min_score)

    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    else:
        print(render_text(findings))

    if args.fail_on is not None and any(f.score >= args.fail_on for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
