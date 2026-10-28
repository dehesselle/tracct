# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""`tracct status` of a scratch root, with a fake systemctl and fake sysfs and procfs
files; unprivileged.
"""

import subprocess

import pytest

from tracct import install
from tracct.conntrack import ACCT_SYSCTL
from tracct.install import install as run_install
from tracct.status import MODULE_ACCT, status

UNIT = "etc/systemd/system/tracct.service"
CONFIG = "etc/opt/tracct/config.toml"
SINCE = "Wed 2026-10-28 10:00:00 UTC"


def fake_systemctl(monkeypatch, returncode, stdout, stderr=""):
    monkeypatch.setattr(
        install,
        "systemctl",
        lambda *args: subprocess.CompletedProcess(args, returncode, stdout, stderr),
    )


def test_status_files_drop_ins_and_units(tmp_path, monkeypatch, capsys):
    run_install(tmp_path, force=False, conntrack=False, yes=True)
    (tmp_path / CONFIG).write_text("[database]\nraw_retention_days = 7\n")
    (tmp_path / install.DROP_INS / "50-local.toml").write_text("[log]\nports = false\n")
    (tmp_path / install.DROP_INS / "README").write_text("notes\n")
    socket_drop_in = "/etc/systemd/system/tracct-query.socket.d/override.conf"
    fake_systemctl(
        monkeypatch,
        0,
        f"LoadState=loaded\nActiveState=active\nSubState=running\n"
        f"UnitFileState=enabled\nFragmentPath={tmp_path / UNIT}\n"
        f"ActiveEnterTimestamp={SINCE}\n\n"
        f"LoadState=loaded\nActiveState=active\nSubState=listening\n"
        f"UnitFileState=enabled\n"
        f"FragmentPath=/usr/lib/systemd/system/tracct-query.socket\n"
        f"DropInPaths={socket_drop_in}\n\n"
        f"LoadState=not-found\nActiveState=inactive\n",
    )
    capsys.readouterr()
    assert status(tmp_path) == 0
    out = capsys.readouterr().out
    assert f"  same      {tmp_path / UNIT}" in out
    assert f"  modified  {tmp_path / CONFIG}" in out
    assert f"  missing   {tmp_path / 'etc/modprobe.d/tracct.conf'}" in out
    assert "install -f replaces it" in out
    assert "  50-local.toml\n" in out
    assert "  README (ignored, not a *.toml file)" in out
    assert f"  {'tracct.service':20}  enabled, active (running) since {SINCE}" in out
    assert f"  {'tracct-query.socket':20}  enabled, active (listening)\n" in out
    assert "from /usr/lib/systemd/system/tracct-query.socket" in out
    assert f"drop-in {socket_drop_in}" in out
    # The service's own unit file is where install puts it.
    assert out.count("  from ") == 1
    assert f"  {'tracct-query.service':20}  not found" in out
    assert "  nf_conntrack module: not loaded\n" in out
    assert f"{tmp_path / install.STATE / 'tracct.db'}: not found" in out


@pytest.mark.parametrize(
    "module_acct, acct, config, lines",
    [
        (
            "N",
            "1",
            "",
            [
                "  net.netfilter.nf_conntrack_acct (sysctl): 1",
                "  acct (nf_conntrack module parameter): N",
            ],
        ),
        (
            "Y",
            "0",
            "[monitoring]\nconntrack = false\n",
            [
                "  net.netfilter.nf_conntrack_acct (sysctl): 0",
                "  acct (nf_conntrack module parameter): Y",
            ],
        ),
        (None, None, "", ["  nf_conntrack module: not loaded"]),
    ],
)
def test_status_conntrack(
    tmp_path, monkeypatch, capsys, module_acct, acct, config, lines
):
    """The kernel's values are shown as it has them."""
    files = {MODULE_ACCT: module_acct, ACCT_SYSCTL.lstrip("/"): acct}
    files[f"{install.DROP_INS}/50-local.toml"] = config
    for path, value in files.items():
        if value is not None:
            (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / path).write_text(value + "\n")
    monkeypatch.setattr(install, "systemctl", lambda *args: None)
    assert status(tmp_path) == 0
    out = capsys.readouterr().out
    section = out.split("\nConntrack\n")[1].split("\n\n")[0].splitlines()
    enabled = "false" if config else "true"
    assert section == [f"  [monitoring] conntrack = {enabled}", *lines]
    assert "unknown: systemctl not found" in out


def test_status_without_systemd_and_database_size(tmp_path, monkeypatch, capsys):
    fake_systemctl(
        monkeypatch,
        1,
        "",
        "System has not been booted with systemd as init system (PID 1).\n"
        "Failed to connect to bus: Host is down\n",
    )
    (tmp_path / install.STATE).mkdir(parents=True)
    (tmp_path / install.STATE / "tracct.db").write_bytes(b"\0" * 2_000_000)
    (tmp_path / install.STATE / "tracct.db-wal").write_bytes(b"\0" * 500_000)
    assert status(tmp_path) == 0
    out = capsys.readouterr().out
    assert "unknown: System has not been booted with systemd" in out
    assert "Host is down" not in out
    assert "  no such directory" in out
    assert f"{tmp_path / install.STATE / 'tracct.db'}: 2.5 MB" in out
