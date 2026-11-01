"""Host surveillance detection.

Looks for the fingerprints that spyware, stalkerware and hidden-camera tooling
leave on a machine: processes whose names match known surveillance families,
processes holding camera or microphone device handles, binaries running from
odd locations or unsigned, and listeners on ports that should not be listening.

Every check is a pure function over injected data. Nothing here reads the live
OS by itself - the collector does that, and the collector is deliberately
separate so the detection logic can be tested without a compromised host.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Iterable, Sequence

__all__ = [
    "Process",
    "Connection",
    "Finding",
    "SUSPICIOUS_NAMES",
    "CAMERA_MIC_DEVICES",
    "EXPECTED_LISTENERS",
    "score_process",
    "score_connection",
    "analyse",
    "shannon_entropy",
]


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Process:
    """One running process, as observed by the collector."""

    pid: int
    name: str
    exe_path: str = ""
    cmdline: str = ""
    user: str = ""
    parent_pid: int = 0
    signed: bool | None = None          # None = unknown, not "unsigned"
    open_devices: tuple[str, ...] = ()  # e.g. ("/dev/video0", "/dev/snd/pcmC0D0c")
    start_time: float = 0.0


@dataclass(frozen=True)
class Connection:
    """One socket owned by a process."""

    pid: int
    local_port: int
    remote_addr: str = ""
    remote_port: int = 0
    state: str = "ESTABLISHED"


@dataclass
class Finding:
    pid: int
    name: str
    score: float
    severity: str
    reasons: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "score": round(self.score, 1),
            "severity": self.severity,
            "reasons": list(self.reasons),
            "metrics": {k: (round(v, 4) if isinstance(v, float) else v)
                        for k, v in self.metrics.items()},
        }


# --------------------------------------------------------------------------
# knowledge bases
# --------------------------------------------------------------------------

# Names seen in stalkerware, commercial spyware and hidden-camera tooling.
# Matched case-insensitively as substrings, because families rename binaries
# but rarely rename the internal component.
SUSPICIOUS_NAMES: tuple[str, ...] = (
    # commercial stalkerware families
    "flexispy", "mspy", "spyzie", "hoverwatch", "cocospy", "spyic",
    "kidsguard", "thetruthspy", "cerberus", "mobiletrack", "xnspy",
    # generic surveillance tooling
    "keylog", "keystroke", "screenshot", "screengrab", "spyagent",
    "remotedesktop", "hiddencam", "webcamspy", "camcapture",
    # RAT families commonly seen on endpoints
    "njrat", "darkcomet", "quasar", "remcos", "nanocore", "asyncrat",
    "venomrat", "orcus", "warzone", "dcrat",
    # credential and screen capture
    "mimikatz", "lazagne", "browserpassview", "mailpassview",
)

# Device nodes that mean "this process can see or hear you".
CAMERA_MIC_DEVICES: tuple[str, ...] = (
    "/dev/video",       # V4L2 camera
    "/dev/snd/pcm",     # ALSA capture/playback
    "/dev/dsp",         # OSS audio
    "/dev/audio",
)

# Ports that are normal to listen on. Anything else listening is worth a look.
EXPECTED_LISTENERS: frozenset[int] = frozenset({
    22, 80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9000, 27017,
})

# Directories a legitimate long-running binary rarely lives in.
SUSPICIOUS_PATH_MARKERS: tuple[str, ...] = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/",
    "\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\",
)

# Paths that are normal for system binaries.
TRUSTED_PATH_PREFIXES: tuple[str, ...] = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/",
    "/opt/homebrew/bin/", "/system/", "/usr/local/bin/",
    "c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\program files\\",
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    """Bits per character. Random-looking names score high."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def _matches_suspicious_name(name: str) -> str | None:
    low = name.lower()
    for needle in SUSPICIOUS_NAMES:
        if needle in low:
            return needle
    return None


def _is_trusted_path(path: str) -> bool:
    if not path:
        return False
    low = path.lower()
    return any(low.startswith(p) for p in TRUSTED_PATH_PREFIXES)


def _in_suspicious_path(path: str) -> str | None:
    if not path:
        return None
    low = path.lower()
    for marker in SUSPICIOUS_PATH_MARKERS:
        if marker in low:
            return marker
    return None


def _looks_random(name: str) -> bool:
    """A long name with no vowels and high entropy is usually generated.

    Threshold calibrated against real names: "xkqjvbzr" (8 distinct chars,
    entropy 3.00) must flag; "firefox" and "systemd" must not.
    """
    stem = re.sub(r"\.[a-z0-9]{1,4}$", "", name.lower())
    if len(stem) < 8:
        return False
    vowels = sum(1 for c in stem if c in "aeiou")
    if vowels / len(stem) > 0.25:
        return False
    return shannon_entropy(stem) > 2.8


# --------------------------------------------------------------------------
# process scoring
# --------------------------------------------------------------------------

def score_process(proc: Process, conns: Sequence[Connection] = ()) -> Finding:
    """Score one process. Higher means more surveillance-like."""
    score = 0.0
    reasons: list[str] = []
    metrics: dict = {"pid": proc.pid}

    # --- 1. known surveillance family (0-70) -----------------------------
    # A confirmed family name is close to a positive identification, so it is
    # weighted to reach "critical" on its own. Everything else is corroboration.
    hit = _matches_suspicious_name(proc.name)
    if hit:
        score += 70
        reasons.append(f"name matches known surveillance family '{hit}'")

    # --- 2. camera or microphone access (0-30) ---------------------------
    devices = [d for d in proc.open_devices
               if any(d.startswith(prefix) for prefix in CAMERA_MIC_DEVICES)]
    if devices:
        metrics["devices"] = len(devices)
        if _is_trusted_path(proc.exe_path):
            score += 8
            reasons.append(
                f"holds {len(devices)} camera/mic device(s) but runs from a "
                f"trusted path - likely legitimate"
            )
        else:
            score += 30
            reasons.append(
                f"holds {len(devices)} camera/mic device(s) from an untrusted "
                f"path: {', '.join(devices[:3])}"
            )

    # --- 3. unsigned binary (0-15) ---------------------------------------
    if proc.signed is False:
        score += 15
        reasons.append("binary is unsigned")
    elif proc.signed is None and proc.exe_path:
        score += 4
        reasons.append("signature status unknown")

    # --- 4. odd execution path (0-15) ------------------------------------
    marker = _in_suspicious_path(proc.exe_path)
    if marker:
        score += 15
        reasons.append(f"runs from a temp/volatile path ({marker.strip('/')})")
    elif proc.exe_path and not _is_trusted_path(proc.exe_path):
        score += 6
        reasons.append(f"runs from a non-standard path: {proc.exe_path}")

    # --- 5. deleted or missing binary (0-12) -----------------------------
    if proc.exe_path and ("(deleted)" in proc.exe_path or proc.exe_path.endswith(" (deleted)")):
        score += 12
        reasons.append("binary was deleted while still running - classic hiding move")
    elif not proc.exe_path:
        score += 5
        reasons.append("no executable path reported")

    # --- 6. random-looking name (0-10) -----------------------------------
    if _looks_random(proc.name):
        score += 10
        reasons.append(f"name looks machine-generated (entropy {shannon_entropy(proc.name):.2f})")

    # --- 7. unexpected listener (0-15) -----------------------------------
    listeners = [c for c in conns if c.pid == proc.pid and c.state.upper() == "LISTEN"]
    odd = [c for c in listeners if c.local_port not in EXPECTED_LISTENERS]
    if odd:
        score += 15
        reasons.append(
            f"listening on unexpected port(s): {', '.join(str(c.local_port) for c in odd[:4])}"
        )
        metrics["odd_listen_ports"] = len(odd)

    # --- 8. outbound to a raw IP on a non-standard port (0-10) -----------
    raw_ip = [
        c for c in conns
        if c.pid == proc.pid
        and c.remote_addr
        and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", c.remote_addr)
        and c.remote_port not in (80, 443)
    ]
    if raw_ip:
        score += 10
        reasons.append(
            f"{len(raw_ip)} outbound connection(s) to a bare IP on a non-web port"
        )

    score = max(0.0, min(100.0, score))

    if score >= 70:
        severity = "critical"
    elif score >= 45:
        severity = "high"
    elif score >= 25:
        severity = "medium"
    elif score > 0:
        severity = "low"
    else:
        severity = "clean"

    return Finding(
        pid=proc.pid, name=proc.name, score=score,
        severity=severity, reasons=reasons, metrics=metrics,
    )


def score_connection(conn: Connection) -> Finding:
    """Score a single connection in isolation (used for orphan sockets)."""
    score = 0.0
    reasons: list[str] = []
    if conn.state.upper() == "LISTEN" and conn.local_port not in EXPECTED_LISTENERS:
        score += 15
        reasons.append(f"unexpected listening port {conn.local_port}")
    if conn.remote_addr and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", conn.remote_addr):
        if conn.remote_port not in (80, 443):
            score += 10
            reasons.append(f"bare-IP connection to port {conn.remote_port}")
    severity = ("high" if score >= 45 else "medium" if score >= 25
                else "low" if score > 0 else "clean")
    return Finding(pid=conn.pid, name=f"pid:{conn.pid}", score=score,
                   severity=severity, reasons=reasons)


def analyse(processes: Iterable[Process],
            connections: Iterable[Connection] = (),
            min_score: float = 25.0) -> list[Finding]:
    """Score every process, worst first."""
    conns = list(connections)
    by_pid: dict[int, list[Connection]] = {}
    for c in conns:
        by_pid.setdefault(c.pid, []).append(c)

    findings = [score_process(p, by_pid.get(p.pid, [])) for p in processes]
    findings = [f for f in findings if f.score >= min_score]
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings
