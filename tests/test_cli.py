"""Tests for the spydetect CLI and snapshot loader."""

from __future__ import annotations

import json

import pytest

from spydetect.cli import _hex_to_ip, load_snapshot, main


def write(tmp_path, obj, name="snap.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


CLEAN = {
    "processes": [
        {"pid": 1, "name": "systemd", "exe_path": "/usr/lib/systemd/systemd", "signed": True},
        {"pid": 2, "name": "sshd", "exe_path": "/usr/sbin/sshd", "signed": True},
    ],
    "connections": [],
}

DIRTY = {
    "processes": [
        {"pid": 1, "name": "systemd", "exe_path": "/usr/lib/systemd/systemd", "signed": True},
        {"pid": 4242, "name": "mspy-agent", "exe_path": "/tmp/.hidden/agent",
         "signed": False, "open_devices": ["/dev/video0"]},
    ],
    "connections": [
        {"pid": 4242, "local_port": 31337, "state": "LISTEN"},
        {"pid": 4242, "local_port": 50000, "remote_addr": "45.9.1.2", "remote_port": 4444},
    ],
}


# --- loader ---------------------------------------------------------------

def test_load_snapshot_reads_processes(tmp_path):
    procs, conns = load_snapshot(write(tmp_path, CLEAN))
    assert len(procs) == 2
    assert procs[0].name == "systemd"
    assert conns == []


def test_load_snapshot_reads_connections(tmp_path):
    _, conns = load_snapshot(write(tmp_path, DIRTY))
    assert len(conns) == 2
    assert conns[0].local_port == 31337


def test_load_snapshot_defaults_optional_fields(tmp_path):
    procs, _ = load_snapshot(write(tmp_path, {"processes": [{"pid": 5, "name": "x"}]}))
    assert procs[0].exe_path == ""
    assert procs[0].open_devices == ()
    assert procs[0].signed is None


def test_load_snapshot_rejects_non_object(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_snapshot(p)


def test_load_snapshot_reports_bad_process_index(tmp_path):
    with pytest.raises(ValueError, match=r"processes\[0\]"):
        load_snapshot(write(tmp_path, {"processes": [{"name": "no-pid"}]}))


def test_load_snapshot_reports_bad_connection_index(tmp_path):
    with pytest.raises(ValueError, match=r"connections\[0\]"):
        load_snapshot(write(tmp_path, {"connections": [{"pid": 1}]}))


# --- hex ip conversion ----------------------------------------------------

def test_hex_to_ip_little_endian():
    # 0100007F is 127.0.0.1 in /proc/net/tcp byte order
    assert _hex_to_ip("0100007F") == "127.0.0.1"


def test_hex_to_ip_rejects_wrong_length():
    assert _hex_to_ip("0100") == ""


def test_hex_to_ip_rejects_non_hex():
    assert _hex_to_ip("ZZZZZZZZ") == ""


# --- CLI ------------------------------------------------------------------

def test_cli_clean_snapshot_says_so(tmp_path, capsys):
    rc = main(["--from-json", str(write(tmp_path, CLEAN))])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No surveillance indicators" in out


def test_cli_flags_surveillance(tmp_path, capsys):
    rc = main(["--from-json", str(write(tmp_path, DIRTY))])
    out = capsys.readouterr().out
    assert rc == 0
    assert "mspy-agent" in out
    assert "CRITICAL" in out


def test_cli_json_output(tmp_path, capsys):
    rc = main(["--from-json", str(write(tmp_path, DIRTY)), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload[0]["name"] == "mspy-agent"
    assert payload[0]["score"] >= 70


def test_cli_fail_on_triggers(tmp_path):
    assert main(["--from-json", str(write(tmp_path, DIRTY)), "--fail-on", "70"]) == 1


def test_cli_fail_on_clean_host_passes(tmp_path):
    assert main(["--from-json", str(write(tmp_path, CLEAN)), "--fail-on", "70"]) == 0


def test_cli_missing_file_exits_2(tmp_path, capsys):
    rc = main(["--from-json", str(tmp_path / "nope.json")])
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_cli_requires_a_source():
    with pytest.raises(SystemExit):
        main([])
