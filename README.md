# spydetect

Detect host surveillance indicators — stalkerware, spyware, hidden-camera
tooling and keyloggers — on a machine you own or are authorised to inspect.

It scores each running process on the fingerprints surveillance software
leaves behind, and **explains every point it awards**, so you can disagree with
the reasoning instead of trusting a black box.

## What it looks for

| Signal | Max points | Why it matters |
|---|---|---|
| Known surveillance family name | 70 | A confirmed family name is close to a positive identification |
| Camera / microphone device handles | 30 | A process holding `/dev/video*` or `/dev/snd/pcm*` can see or hear you |
| Unsigned binary | 15 | Commercial software is signed; stalkerware usually is not |
| Temp / volatile execution path | 15 | `/tmp`, `/dev/shm`, `%TEMP%` — where droppers land |
| Deleted binary still running | 12 | A classic hiding move |
| Machine-generated name | 10 | `xkqjvbzr` is not a product name |
| Unexpected listening port | 15 | A remote viewer needs a door |
| Bare-IP connection on a non-web port | 10 | C2 and exfil rarely use 80/443 to a raw IP |

Total capped at 100. Severity: `critical` ≥ 70, `high` ≥ 45, `medium` ≥ 25,
`low` > 0.

**Camera access from a trusted path is deliberately discounted** (8 points
instead of 30). Firefox holding `/dev/video0` is a video call, not spyware.
That discount is the difference between a usable tool and one that cries wolf
on every laptop.

## Install

```bash
pip install -e ".[dev]"
```

No runtime dependencies — standard library only.

## Usage

Two modes. The snapshot mode is the safe default: it analyses data you already
collected and never touches the host.

```bash
# analyse a snapshot
spydetect --from-json snapshot.json

# collect from this host (Linux, read-only /proc)
spydetect --live

# machine-readable, and fail the run if anything is critical
spydetect --from-json snapshot.json --json --fail-on 70
```

### Snapshot format

```json
{
  "processes": [
    {"pid": 4242, "name": "mspy-agent", "exe_path": "/tmp/.hidden/agent",
     "signed": false, "open_devices": ["/dev/video0", "/dev/snd/pcmC0D0c"]}
  ],
  "connections": [
    {"pid": 4242, "local_port": 31337, "state": "LISTEN"},
    {"pid": 4242, "local_port": 50000, "remote_addr": "45.9.1.2", "remote_port": 4444}
  ]
}
```

Only `pid` and `name` are required per process. `signed` is `true`, `false`, or
`null` for unknown — unknown is scored lower than explicitly unsigned, because
"we could not check" is not the same as "we checked and it failed".

### Real output

```
[100.0] CRITICAL  pid 4242    mspy-agent
          - name matches known surveillance family 'mspy'
          - holds 2 camera/mic device(s) from an untrusted path: /dev/video0, /dev/snd/pcmC0D0c
          - binary is unsigned
          - runs from a temp/volatile path (tmp)
          - name looks machine-generated (entropy 3.32)
          - listening on unexpected port(s): 31337
          - 1 outbound connection(s) to a bare IP on a non-web port

[ 29.0] MEDIUM    pid 5150    xkqjvbzr
          - signature status unknown
          - runs from a temp/volatile path (tmp)
          - name looks machine-generated (entropy 3.00)
```

In the same snapshot, `firefox` holding `/dev/video0` from `/usr/bin/firefox`
did **not** appear — it scored below the threshold, which is correct.

## Use as a library

```python
from spydetect.core import Process, Connection, analyse

procs = [Process(pid=4242, name="mspy-agent", exe_path="/tmp/agent",
                 signed=False, open_devices=("/dev/video0",))]
conns = [Connection(pid=4242, local_port=31337, state="LISTEN")]

for f in analyse(procs, conns, min_score=25):
    print(f.pid, f.name, f.score, f.severity)
    for reason in f.reasons:
        print("  -", reason)
```

## Tests

```bash
python -m pytest -q
```

**45 tests, all passing.** Covers: known family scores critical, clean system
process scores zero, camera access discounted from trusted paths, audio devices
count but block devices do not, unsigned scores above unknown, temp and deleted
paths flagged, entropy calibration (`xkqjvbzr` flags, `firefox` does not),
listener and bare-IP detection, connections attributed by pid, score bounds,
snapshot loader error reporting, `/proc/net/tcp` hex-to-IP conversion, and CLI
exit codes.

## Limitations — read these

- **It is a triage tool, not an antivirus.** It reads names, paths, signatures
  and device handles. It does not scan memory, inspect binaries, or detect
  kernel-level rootkits that hide their own processes.
- **The name list is finite.** A renamed binary defeats the 70-point signal
  entirely. The other signals still apply, which is why they exist.
- **`--live` is Linux-only** and reads `/proc`. It is read-only: it never
  signals, kills, or modifies anything. On macOS or Windows, collect a snapshot
  with your own tooling and use `--from-json`.
- **Signature checking is not performed.** `signed` must be supplied by the
  collector. `--live` leaves it `null`, so live runs score lower than a
  snapshot with real signature data.
- **Socket-to-pid mapping is best-effort.** It scans `/proc/*/fd`, which needs
  permission to read other users' file descriptors. Run as root for full
  coverage, and expect gaps otherwise.
- **False positives are expected on developer machines.** Debuggers, screen
  recorders, OBS, and unsigned local builds will score. Read the reasons.
- **No persistence, no history, no alerting.** It is a point-in-time check.

## Legal and authorised use

Use this only on systems you own or have **explicit written authorisation** to
inspect. Reading another person's process list without consent may be unlawful
in your jurisdiction, and installing monitoring software on someone else's
device is a crime in most of them.

This tool is defensive: it detects surveillance, it does not perform it. There
is no capability here to capture keystrokes, screenshots, camera frames, or
audio.

## Licence

MIT
