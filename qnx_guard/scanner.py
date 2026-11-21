"""Scanner engine for QNX Sentinel (qnx-guard)."""

import os
from pathlib import Path
from typing import List, Set
from qnx_guard.models import ScanSummary
from qnx_guard.rules.neutrino import check_neutrino_rules
from qnx_guard.rules.buildfile import check_buildfile_rules
from qnx_guard.rules.toolchain import check_toolchain_rules

IGNORE_DIRS: Set[str] = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "build",
    "dist",
    ".idea",
    ".vscode",
}

SOURCE_EXTENSIONS: Set[str] = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
BUILDFILE_EXTENSIONS: Set[str] = {".bld", ".build"}
TOOLCHAIN_FILES: Set[str] = {"makefile", "cmakelists.txt"}


class Scanner:
    def __init__(self, root_path: Path):
        self.root_path = root_path

    def scan(self) -> ScanSummary:
        summary = ScanSummary()

        if self.root_path.is_file():
            summary.total_files = 1
            self._scan_file(self.root_path, summary)
            return summary

        for root, dirs, files in os.walk(self.root_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

            for file in files:
                summary.total_files += 1
                file_path = Path(root) / file
                self._scan_file(file_path, summary)

        return summary

    def _scan_file(self, file_path: Path, summary: ScanSummary) -> None:
        name_lower = file_path.name.lower()
        suffix_lower = file_path.suffix.lower()

        is_source = suffix_lower in SOURCE_EXTENSIONS
        is_buildfile = suffix_lower in BUILDFILE_EXTENSIONS or "buildfile" in name_lower
        is_toolchain = name_lower in TOOLCHAIN_FILES or suffix_lower in {".mk", ".sh"}

        if not (is_source or is_buildfile or is_toolchain):
            return

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        summary.scanned_files += 1
        rel_path = str(file_path.relative_to(self.root_path) if self.root_path.is_dir() else file_path)

        # Apply C/C++ Neutrino rules
        if is_source:
            for finding in check_neutrino_rules(content, rel_path):
                summary.add_finding(finding)

        # Apply Buildfile rules
        if is_buildfile or "[+script]" in content or "[image=" in content:
            for finding in check_buildfile_rules(content, rel_path):
                summary.add_finding(finding)

        # Apply Toolchain rules
        if is_toolchain or "qcc" in content.lower():
            for finding in check_toolchain_rules(content, rel_path):
                summary.add_finding(finding)
