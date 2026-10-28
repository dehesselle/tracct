# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""`tracct install` into a scratch root; unprivileged, and never writes to the system."""

import tempfile

import pytest

from tracct import install
from tracct.install import PACKAGED_COMMAND, tracct_command
from tracct.install import install as run

UNIT = "etc/systemd/system/tracct.service"
CONFIG = "etc/opt/tracct/config.toml"


def test_install_into_root(tmp_path, capsys):
    assert run(tmp_path, force=False, conntrack=False) == 0
    out = capsys.readouterr().out
    for path in install.FILES.values():
        assert (tmp_path / path).is_file()
        assert f"wrote  {tmp_path / path}" in out
        assert (tmp_path / path).stat().st_mode & 0o777 == 0o644
    assert (tmp_path / install.DROP_INS).is_dir()
    assert not (tmp_path / "etc/modprobe.d").exists()
    unit = (tmp_path / UNIT).read_text()
    assert PACKAGED_COMMAND not in unit
    assert f"ExecStart={tracct_command()} run" in unit
    # --root is for packaging: no next steps for the system.
    assert "systemctl" not in out


def test_install_again_keeps_or_forces(tmp_path, capsys):
    run(tmp_path, force=False, conntrack=False)
    capsys.readouterr()
    assert run(tmp_path, force=False, conntrack=False) == 0
    assert f"same   {tmp_path / CONFIG}" in capsys.readouterr().out
    (tmp_path / CONFIG).write_text("[database]\nraw_retention_days = 7\n")
    (tmp_path / install.DROP_INS / "50-local.toml").write_text("[log]\nports = false\n")
    assert run(tmp_path, force=False, conntrack=False) == 0
    assert f"kept   {tmp_path / CONFIG} (differs; -f replaces it)" in (
        capsys.readouterr().out
    )
    assert "raw_retention_days = 7" in (tmp_path / CONFIG).read_text()
    assert run(tmp_path, force=True, conntrack=False) == 0
    assert f"wrote  {tmp_path / CONFIG}" in capsys.readouterr().out
    assert "raw_retention_days = 30" in (tmp_path / CONFIG).read_text()
    assert (tmp_path / install.DROP_INS / "50-local.toml").read_text() == (
        "[log]\nports = false\n"
    )


def test_install_conntrack(tmp_path):
    run(tmp_path, force=False, conntrack=True)
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
def test_install_unwritable(tmp_path, monkeypatch, capsys, root):
    """Nothing reaches a target that can't be written: with --root that is an error,
    for the system every file goes to a new temporary tree instead.
    """
    system = tmp_path / "system"
    (system / "etc/opt/tracct").mkdir(parents=True)
    (system / CONFIG).write_text("[viewer]\ngroup = 'mine'\n")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(install, "writable", lambda path: "systemd" not in str(path))
    if root:
        assert run(system, force=False, conntrack=False) == 1
        assert not (system / "etc/sysusers.d").exists()
        return
    assert run(None, force=False, conntrack=False, system=system) == 0
    out = capsys.readouterr().out
    assert not (system / "etc/sysusers.d").exists()
    (staged,) = tmp_path.glob("tracct-install-*")
    assert "Cannot write /etc/systemd/system/tracct-query.service and 2 more" in out
    assert (staged / UNIT).is_file()
    assert f"install -D -m 644 {staged / UNIT} /{UNIT}" in out
    assert f"install -d -m 755 /{install.DROP_INS}" in out
    # The differing config is kept, so it is neither staged nor copied.
    assert f"kept   {system / CONFIG}" in out
    assert not (staged / CONFIG).exists()
    assert "systemctl daemon-reload" in out
