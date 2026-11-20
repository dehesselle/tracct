# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Hatchling build hook to compile BPF program during wheel build.

It also cuts the viewer's sections out of docs/MANUAL.md into the package, for
`tracct view` to show.
"""

import os
import platform
import re
import subprocess
import sys

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

#: The sections of docs/MANUAL.md the viewer shows, by their headings' titles.
MANUAL_SECTIONS = ["The viewer", "Remote viewing"]

_HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*$")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")


def extract_sections(text: str, titles: list[str]) -> str:
    """Return the sections of a Markdown text with these headings, in this order.

    A section runs from its heading to the next heading of the same or a higher
    level. Headings are promoted so the highest of the sections taken becomes `#`.
    Lines in fenced code blocks are never headings. Raises ValueError for a title
    that no heading has.
    """
    lines = text.splitlines()
    levels: dict[int, int] = {}  # line index of each heading: its level
    names: dict[str, int] = {}  # title of each heading: its first line index
    fence = None
    for index, line in enumerate(lines):
        if match := _FENCE.match(line):
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is None and (match := _HEADING.match(line)):
            levels[index] = len(match.group(1))
            names.setdefault(match.group(2), index)

    sections = []
    for title in titles:
        if title not in names:
            raise ValueError(f"no heading {title!r}")
        start = names[title]
        end = next(
            (i for i in levels if i > start and levels[i] <= levels[start]),
            len(lines),
        )
        sections.append(range(start, end))
    shift = min(levels[section.start] for section in sections) - 1

    parts = []
    for section in sections:
        part = [lines[i][shift:] if i in levels else lines[i] for i in section]
        parts.append("\n".join(part).strip())
    return "\n\n".join(parts) + "\n"


class BPFBuildHook(BuildHookInterface):
    PLUGIN_NAME = "bpf-build"

    def initialize(self, version, build_data):
        if self.target_name != "wheel":
            return

        # Editable installs too, so a checkout's viewer has it.
        self._build_manual(version, build_data)

        # Skip BPF compilation for editable installs (used by `uv sync` /
        # dev workflows). The BPF object is only needed for runtime, not
        # for importing the package during development or testing.
        if version == "editable" or os.environ.get("TRACCT_SKIP_BPF_BUILD"):
            return

        if sys.platform != "linux":
            self.app.abort(f"tracct builds on Linux only, not on {sys.platform}")

        # The wheel has no C extension linked against glibc -- it ships a precompiled
        # BPF object (kernel bytecode, no userspace linkage) plus pure-Python code that
        # dlopen's libbpf.so via ctypes at runtime.
        arch = os.environ.get("TRACCT_BPF_TARGET_ARCH", platform.machine())
        plat_tags = {
            "x86_64": "manylinux_2_34_x86_64",
            "aarch64": "manylinux_2_34_aarch64",
        }
        if arch not in plat_tags:
            self.app.abort(f"Unsupported arch for BPF build: {arch}")
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{plat_tags[arch]}"

        bpf_src_dir = os.path.join(self.root, "src", "tracct", "bpf")
        bpf_src = os.path.join(bpf_src_dir, "tracct.bpf.c")
        bpf_obj = os.path.join(bpf_src_dir, "tracct.bpf.o")

        def register(obj_path):
            build_data.setdefault("force_include", {})[obj_path] = (
                "tracct/bpf/tracct.bpf.o"
            )

        if not os.path.exists(bpf_src):
            if os.path.exists(bpf_obj):
                # No source, but a pre-built object exists (e.g. CI provided it).
                register(bpf_obj)
                return
            raise RuntimeError(f"BPF source not found: {bpf_src}")

        if os.path.exists(bpf_obj) and os.path.getmtime(bpf_obj) >= os.path.getmtime(
            bpf_src
        ):
            # Object up to date with source; reuse it.
            register(bpf_obj)
            return

        # Kernel-style target arch name (matches arch/* in the kernel tree and libbpf's
        # __TARGET_ARCH_* macro from bpf_tracing.h).
        bpf_target_arch = {"x86_64": "x86", "aarch64": "arm64"}[arch]

        # Select vmlinux.h with this precedence:
        #   1. An existing src/tracct/bpf/vmlinux.h
        #   2. Our vendored per-arch header
        #   3. bpftool BTF dump from the running kernel
        vmlinux_h = os.path.join(bpf_src_dir, "vmlinux.h")
        vendored_vmlinux = os.path.join(bpf_src_dir, f"vmlinux_{bpf_target_arch}.h")
        if os.path.exists(vmlinux_h):
            pass
        elif os.path.exists(vendored_vmlinux):
            import shutil

            shutil.copyfile(vendored_vmlinux, vmlinux_h)
        else:
            if not os.path.exists("/sys/kernel/btf/vmlinux"):
                raise RuntimeError(
                    f"Cannot compile BPF: no vendored vmlinux_{bpf_target_arch}.h and "
                    "/sys/kernel/btf/vmlinux not available.\n"
                    "Either provide a pre-compiled bpf/tracct.bpf.o or build "
                    "on a kernel with CONFIG_DEBUG_INFO_BTF=y"
                )
            result = subprocess.run(
                [
                    "bpftool",
                    "btf",
                    "dump",
                    "file",
                    "/sys/kernel/btf/vmlinux",
                    "format",
                    "c",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            with open(vmlinux_h, "w") as f:
                f.write(result.stdout)

        # Compile.
        subprocess.run(
            [
                "clang",
                "-g",
                "-O2",
                "-target",
                "bpf",
                f"-D__TARGET_ARCH_{bpf_target_arch}",
                "-Wall",
                "-Werror",
                f"-ffile-prefix-map={self.root}=.",
                # Anonymous forward decls inside structs in libbpf's curated vmlinux.h
                # trip -Wmissing-declarations; harmless for BPF compilation.
                "-Wno-missing-declarations",
                f"-I{bpf_src_dir}",
                "-c",
                bpf_src,
                "-o",
                bpf_obj,
            ],
            check=True,
        )

        # Strip debug info (optional, non-fatal).
        try:
            subprocess.run(
                ["llvm-strip", "-g", bpf_obj], capture_output=True, check=True
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass

        register(bpf_obj)

    def _build_manual(self, version, build_data):
        """Write the viewer's sections of the manual to src/tracct/viewer/manual.md."""
        source = os.path.join(self.root, "docs", "MANUAL.md")
        target = os.path.join(self.root, "src", "tracct", "viewer", "manual.md")
        try:
            with open(source, encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            self.app.abort(f"{source} is missing; the viewer's manual is cut from it")
        try:
            manual = extract_sections(text, MANUAL_SECTIONS)
        except ValueError as e:
            self.app.abort(f"{source}: {e}; see MANUAL_SECTIONS in hatch_build.py")
        with open(target, "w", encoding="utf-8", newline="\n") as f:
            f.write(manual)
        if version != "editable":
            # Ignored by git, so hatch would leave it out of the wheel.
            build_data.setdefault("force_include", {})[target] = (
                "tracct/viewer/manual.md"
            )
