# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""`tracct install` and `tracct uninstall` in a scratch root, with a fake systemctl;
unprivileged, and never touches the system.
"""

import io
import subprocess

import pytest

from tracct import install
from tracct.install import PACKAGED_COMMAND, tracct_command, uninstall
from tracct.install import install as run

UNIT = "etc/systemd/system/tracct.service"
CONFIG = "etc/opt/tracct/config.toml"


class Terminal(io.StringIO):
    """Standard input as a terminal, with the answers typed in advance."""

    def isatty(self):
        return True


def test_install_into_root(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", Terminal("y\n"))
    assert run(tmp_path, force=False, conntrack=False, yes=False) == 0
    out = capsys.readouterr().out
    assert out.startswith("This will:\n")
    assert "Continue? [y/N]" in out
    for path in install.FILES.values():
        assert (tmp_path / path).is_file()
        assert f"  write {tmp_path / path}\n" in out
        assert f"wrote {tmp_path / path}\n" in out
        assert (tmp_path / path).stat().st_mode & 0o777 == 0o644
    assert f"  create {tmp_path / install.DROP_INS}/" in out
    assert (tmp_path / install.DROP_INS).is_dir()
    assert not (tmp_path / "etc/modprobe.d").exists()
    unit = (tmp_path / UNIT).read_text()
    assert PACKAGED_COMMAND not in unit
    assert f"ExecStart={tracct_command()} run" in unit
    # --root is for packaging: no next steps for the system.
    assert "systemctl" not in out


@pytest.mark.parametrize("answer", ["\n", "n\n", ""])
def test_install_declined(tmp_path, monkeypatch, capsys, answer):
    """Nothing is written unless the answer is yes; Enter and end of input mean no."""
    monkeypatch.setattr("sys.stdin", Terminal(answer))
    assert run(tmp_path, force=False, conntrack=False, yes=False) == 1
    assert "Nothing changed." in capsys.readouterr().out
    assert not (tmp_path / "etc").exists()


def test_install_without_terminal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    assert run(tmp_path, force=False, conntrack=False, yes=False) == 1
    assert "no terminal to ask on" in capsys.readouterr().out
    assert not (tmp_path / "etc").exists()


def test_install_again_keeps_or_forces(tmp_path, capsys):
    run(tmp_path, force=False, conntrack=False, yes=True)
    capsys.readouterr()
    # Everything in place: nothing to ask about.
    assert run(tmp_path, force=False, conntrack=False, yes=False) == 0
    out = capsys.readouterr().out
    assert f"  {tmp_path / CONFIG} (already in place)" in out
    assert "Nothing to write." in out
    assert "Continue?" not in out
    (tmp_path / CONFIG).write_text("[database]\nraw_retention_days = 7\n")
    (tmp_path / install.DROP_INS / "50-local.toml").write_text(
        "[record]\nports = false\n"
    )
    assert run(tmp_path, force=False, conntrack=False, yes=True) == 0
    assert f"  {tmp_path / CONFIG} (differs; -f replaces it)" in (
        capsys.readouterr().out
    )
    assert "raw_retention_days = 7" in (tmp_path / CONFIG).read_text()
    assert run(tmp_path, force=True, conntrack=False, yes=True) == 0
    out = capsys.readouterr().out
    assert f"  replace {tmp_path / CONFIG}" in out
    assert f"wrote {tmp_path / CONFIG}" in out
    assert "raw_retention_days = 30" in (tmp_path / CONFIG).read_text()
    assert (tmp_path / install.DROP_INS / "50-local.toml").read_text() == (
        "[record]\nports = false\n"
    )


def test_install_conntrack(tmp_path):
    run(tmp_path, force=False, conntrack=True, yes=True)
    assert (
        (tmp_path / "etc/modules-load.d/tracct.conf")
        .read_text()
        .endswith("nf_conntrack\n")
    )
    assert (
        "options nf_conntrack acct=1"
        in (tmp_path / "etc/modprobe.d/tracct.conf").read_text()
    )


@pytest.mark.parametrize("root", [True, False])
def test_install_unwritable(tmp_path, monkeypatch, capsys, caplog, root):
    """A target that cannot be written stops it before the question, with nothing
    written; for the system the error says to run as root.
    """
    monkeypatch.setattr(install, "writable", lambda path: "systemd" not in str(path))
    monkeypatch.setattr("sys.stdin", Terminal("y\n"))
    if root:
        assert run(tmp_path, force=False, conntrack=False, yes=False) == 1
    else:
        assert run(None, force=False, conntrack=False, yes=False, system=tmp_path) == 1
    out = capsys.readouterr().out
    assert f"  write {tmp_path / UNIT}" in out
    assert "Continue?" not in out
    assert f"cannot write {tmp_path / 'etc/systemd/system/tracct-query.service'}" in (
        caplog.text
    )
    assert ("run as root" in caplog.text) is not root
    assert not (tmp_path / "etc").exists()


@pytest.fixture
def systemd(monkeypatch):
    """A systemctl with every unit loaded, recording what it is asked to do."""
    calls = []

    def systemctl(*args):
        if args[0] == "show":
            blocks = ["LoadState=loaded\nActiveState=active"] * len(install.UNITS)
            return subprocess.CompletedProcess(args, 0, "\n\n".join(blocks) + "\n", "")
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(install, "systemctl", systemctl)
    return calls


@pytest.mark.parametrize("answer", ["\n", "n\n", "yes please\n", ""])
def test_uninstall_declined(tmp_path, monkeypatch, capsys, systemd, answer):
    """Nothing changes unless the answer is yes; Enter and end of input mean no."""
    run(tmp_path, force=False, conntrack=False, yes=True)
    capsys.readouterr()
    monkeypatch.setattr("sys.stdin", Terminal(answer))
    assert uninstall(purge=False, yes=False, system=tmp_path) == 1
    out = capsys.readouterr().out
    assert "stop and disable tracct.service tracct-query.socket" in out
    assert "stop tracct-query.service" in out
    assert f"remove {tmp_path / UNIT}" in out
    assert f"remove {tmp_path / install.DROP_INS}/" in out
    assert "Continue? [y/N]" in out
    assert "Nothing changed." in out
    assert systemd == []
    assert (tmp_path / UNIT).is_file()


def test_uninstall_without_terminal(tmp_path, monkeypatch, capsys, systemd):
    run(tmp_path, force=False, conntrack=False, yes=True)
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    assert uninstall(purge=False, yes=False, system=tmp_path) == 1
    assert "no terminal to ask on" in capsys.readouterr().out
    assert systemd == []
    assert (tmp_path / UNIT).is_file()


def test_uninstall_keeps_drop_ins_and_database(tmp_path, monkeypatch, capsys, systemd):
    run(tmp_path, force=False, conntrack=False, yes=True)
    (tmp_path / install.DROP_INS / "50-local.toml").write_text(
        "[record]\nports = false\n"
    )
    (tmp_path / install.STATE).mkdir(parents=True)
    (tmp_path / install.STATE / "tracct.db").write_bytes(b"")
    capsys.readouterr()
    monkeypatch.setattr("sys.stdin", Terminal("y\n"))
    assert uninstall(purge=False, yes=False, system=tmp_path) == 0
    out = capsys.readouterr().out
    for path in install.FILES.values():
        assert not (tmp_path / path).exists()
        assert f"removed {tmp_path / path}" in out
    assert (tmp_path / install.DROP_INS / "50-local.toml").is_file()
    assert "with 50-local.toml (--purge removes them)" in out
    assert (tmp_path / install.STATE / "tracct.db").is_file()
    assert f"the database in {tmp_path / install.STATE}/" in out
    assert systemd == [
        ("disable", "--now", "tracct.service", "tracct-query.socket"),
        ("stop", "tracct-query.service"),
        ("daemon-reload",),
    ]


def test_uninstall_purge(tmp_path, capsys, systemd):
    run(tmp_path, force=False, conntrack=True, yes=True)
    (tmp_path / install.DROP_INS / "50-local.toml").write_text(
        "[record]\nports = false\n"
    )
    (tmp_path / install.STATE).mkdir(parents=True)
    (tmp_path / install.STATE / "tracct.db").write_bytes(b"")
    (tmp_path / "var/lib/tracct").symlink_to(tmp_path / install.STATE)
    capsys.readouterr()
    assert uninstall(purge=True, yes=True, system=tmp_path) == 0
    out = capsys.readouterr().out
    assert f"remove {tmp_path / install.DROP_INS}/ with 50-local.toml" in out
    assert f"remove {tmp_path / install.STATE}/ and everything in it" in out
    assert "Continue?" not in out
    assert not (tmp_path / "etc/opt/tracct").exists()
    assert not (tmp_path / "etc/modprobe.d/tracct.conf").exists()
    assert not (tmp_path / install.STATE).exists()
    assert not (tmp_path / "var/lib/tracct").is_symlink()


def test_uninstall_unwritable(tmp_path, monkeypatch, caplog, systemd):
    """A file that cannot be removed stops it before the question and the units."""
    run(tmp_path, force=False, conntrack=False, yes=True)
    monkeypatch.setattr(install, "removable", lambda path: "systemd" not in str(path))
    monkeypatch.setattr("sys.stdin", Terminal("y\n"))
    assert uninstall(purge=False, yes=False, system=tmp_path) == 1
    assert "run as root" in caplog.text
    assert systemd == []
    assert (tmp_path / CONFIG).is_file()


def test_uninstall_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(install, "systemctl", lambda *args: None)
    assert uninstall(purge=True, yes=False, system=tmp_path) == 0
    assert "Nothing to uninstall." in capsys.readouterr().out
