"""Tests for spydetect detection logic. Run: python -m pytest -q"""

from __future__ import annotations

import json

import pytest

from spydetect.core import (
    Connection,
    Process,
    analyse,
    score_connection,
    score_process,
    shannon_entropy,
)


def proc(**kw):
    base = dict(pid=1000, name="nginx", exe_path="/usr/sbin/nginx", signed=True)
    base.update(kw)
    return Process(**base)


# --- the core claim -------------------------------------------------------

def test_known_stalkerware_scores_critical():
    f = score_process(proc(name="mspy-agent", exe_path="/opt/mspy/agent"))
    assert f.score >= 70, f.reasons
    assert f.severity == "critical"


def test_clean_system_process_scores_zero():
    f = score_process(proc())
    assert f.score == 0.0
    assert f.severity == "clean"


def test_surveillance_outranks_clean():
    bad = score_process(proc(name="flexispy", exe_path="/tmp/x"))
    good = score_process(proc())
    assert bad.score > good.score


# --- camera / microphone --------------------------------------------------

def test_camera_access_from_untrusted_path_is_high():
    f = score_process(proc(name="helper", exe_path="/tmp/helper",
                           open_devices=("/dev/video0",)))
    assert f.score >= 45, f.reasons
    assert any("camera/mic" in r for r in f.reasons)


def test_camera_access_from_trusted_path_is_discounted():
    trusted = score_process(proc(name="cheese", exe_path="/usr/bin/cheese",
                                 open_devices=("/dev/video0",)))
    untrusted = score_process(proc(name="cheese", exe_path="/tmp/cheese",
                                   open_devices=("/dev/video0",)))
    assert trusted.score < untrusted.score
    assert trusted.severity in ("low", "medium")


def test_audio_device_also_counts():
    f = score_process(proc(name="rec", exe_path="/tmp/rec",
                           open_devices=("/dev/snd/pcmC0D0c",)))
    assert any("camera/mic" in r for r in f.reasons)


def test_non_media_device_does_not_count():
    f = score_process(proc(name="disk", exe_path="/tmp/disk",
                           open_devices=("/dev/sda",)))
    assert not any("camera/mic" in r for r in f.reasons)


# --- signing and path -----------------------------------------------------

def test_unsigned_adds_score():
    signed = score_process(proc(signed=True))
    unsigned = score_process(proc(signed=False))
    assert unsigned.score > signed.score


def test_unknown_signature_adds_less_than_unsigned():
    unknown = score_process(proc(signed=None))
    unsigned = score_process(proc(signed=False))
    assert unknown.score < unsigned.score


def test_temp_path_flagged():
    f = score_process(proc(exe_path="/tmp/payload"))
    assert any("temp/volatile" in r for r in f.reasons)


def test_deleted_binary_flagged():
    f = score_process(proc(exe_path="/usr/bin/thing (deleted)"))
    assert any("deleted" in r for r in f.reasons)


def test_missing_exe_path_flagged():
    f = score_process(proc(exe_path=""))
    assert any("no executable path" in r for r in f.reasons)


# --- name heuristics ------------------------------------------------------

def test_random_name_flagged():
    f = score_process(proc(name="xkqjvbzr", exe_path="/usr/bin/xkqjvbzr"))
    assert any("machine-generated" in r for r in f.reasons)


def test_normal_name_not_flagged_as_random():
    f = score_process(proc(name="firefox", exe_path="/usr/bin/firefox"))
    assert not any("machine-generated" in r for r in f.reasons)


def test_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaa") == 0.0


def test_entropy_of_empty_is_zero():
    assert shannon_entropy("") == 0.0


# --- network --------------------------------------------------------------

def test_unexpected_listener_flagged():
    conns = [Connection(pid=1000, local_port=31337, state="LISTEN")]
    f = score_process(proc(), conns)
    assert any("unexpected port" in r for r in f.reasons)


def test_expected_listener_not_flagged():
    conns = [Connection(pid=1000, local_port=443, state="LISTEN")]
    f = score_process(proc(), conns)
    assert not any("unexpected port" in r for r in f.reasons)


def test_bare_ip_non_web_port_flagged():
    conns = [Connection(pid=1000, local_port=50000, remote_addr="45.9.1.2",
                        remote_port=4444)]
    f = score_process(proc(), conns)
    assert any("bare IP" in r for r in f.reasons)


def test_bare_ip_on_443_not_flagged():
    conns = [Connection(pid=1000, local_port=50000, remote_addr="45.9.1.2",
                        remote_port=443)]
    f = score_process(proc(), conns)
    assert not any("bare IP" in r for r in f.reasons)


def test_connections_are_attributed_by_pid():
    conns = [Connection(pid=9999, local_port=31337, state="LISTEN")]
    f = score_process(proc(pid=1000), conns)
    assert not any("unexpected port" in r for r in f.reasons)


def test_score_connection_standalone():
    f = score_connection(Connection(pid=1, local_port=31337, state="LISTEN"))
    assert f.score > 0
    assert f.reasons


# --- bounds and shape -----------------------------------------------------

def test_score_bounded():
    worst = score_process(proc(
        name="mspy", exe_path="/tmp/x (deleted)", signed=False,
        open_devices=("/dev/video0", "/dev/snd/pcmC0D0c"),
    ), [Connection(pid=1000, local_port=31337, state="LISTEN")])
    assert 0.0 <= worst.score <= 100.0


def test_every_finding_has_reasons_when_scored():
    f = score_process(proc(name="mspy"))
    assert f.reasons
    assert all(isinstance(r, str) and r for r in f.reasons)


def test_as_dict_is_json_safe():
    f = score_process(proc(name="mspy"))
    json.dumps(f.as_dict())


# --- analyse --------------------------------------------------------------

def test_analyse_sorts_worst_first():
    procs = [proc(pid=1), proc(pid=2, name="mspy", exe_path="/tmp/m")]
    out = analyse(procs, min_score=0)
    assert out[0].pid == 2


def test_analyse_respects_threshold():
    procs = [proc(pid=1), proc(pid=2, name="mspy", exe_path="/tmp/m")]
    out = analyse(procs, min_score=70)
    assert all(f.score >= 70 for f in out)
    assert len(out) == 1


def test_analyse_empty_input():
    assert analyse([], []) == []


def test_analyse_clean_host_returns_nothing():
    procs = [proc(pid=1, name="systemd", exe_path="/usr/lib/systemd/systemd"),
             proc(pid=2, name="sshd", exe_path="/usr/sbin/sshd")]
    assert analyse(procs, [], min_score=25) == []
