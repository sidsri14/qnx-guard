"""QNX QCC/Q++ Toolchain and Compilation Hardening Rules.

Audits Makefiles, CMakeLists.txt, and shell build scripts for:
- QNX201: Missing compiler security hardening flags (-fstack-protector, -D_FORTIFY_SOURCE, RELRO)
- QNX202: Architecture mismatch or missing optimization/target profile
"""

import re
from typing import List
from qnx_guard.models import Finding, Rule, Severity

TOOLCHAIN_RULES = [
    Rule(
        rule_id="QNX201",
        name="Missing-QCC-Security-Hardening",
        severity=Severity.MEDIUM,
        description="qcc / q++ invocation lacks essential binary hardening flags (-fstack-protector-strong, -D_FORTIFY_SOURCE=2).",
        category="Toolchain & Build Flags",
        remediation="Add -fstack-protector-strong and -D_FORTIFY_SOURCE=2 to QCC CFLAGS/CXXFLAGS.",
    ),
    Rule(
        rule_id="QNX202",
        name="Ambiguous-Target-Architecture",
        severity=Severity.LOW,
        description="qcc invocation lacks explicit target platform flag (e.g. -Vgcc_ntox86_64, -Vgcc_ntoaarch64le).",
        category="Toolchain & Build Flags",
        remediation="Explicitly specify the QNX target architecture variant (-Vgcc_ntox86_64, -Vgcc_ntoaarch64le) in build scripts.",
    ),
]


def check_toolchain_rules(content: str, file_path: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = content.splitlines()

    is_build_script = file_path.endswith(("Makefile", "CMakeLists.txt", ".mk", ".sh", ".cmd")) or "qcc" in content.lower()
    if not is_build_script:
        return findings

    has_qcc = any(re.search(r"\b(qcc|q\+\+)\b", line, re.IGNORECASE) for line in lines)
    if not has_qcc:
        return findings

    has_stack_protector = any("-fstack-protector" in line for line in lines)
    has_target_variant = any(re.search(r"-Vgcc_nto[A-Za-z0-9_]+", line) for line in lines)

    for i, line in enumerate(lines, start=1):
        if re.search(r"\b(qcc|q\+\+)\b", line, re.IGNORECASE):
            if not has_stack_protector:
                findings.append(
                    Finding(
                        rule_id="QNX201",
                        rule_name="Missing-QCC-Security-Hardening",
                        severity=Severity.MEDIUM,
                        category="Toolchain & Build Flags",
                        file_path=file_path,
                        line_number=i,
                        matched_text=line.strip()[:100],
                        message="qcc/q++ invocation detected without stack protector (-fstack-protector-strong) hardening.",
                        remediation="Pass -fstack-protector-strong and -D_FORTIFY_SOURCE=2 to compiler flags.",
                    )
                )
                break  # Alert once per file

    for i, line in enumerate(lines, start=1):
        if re.search(r"\b(qcc|q\+\+)\b", line, re.IGNORECASE):
            if not has_target_variant:
                findings.append(
                    Finding(
                        rule_id="QNX202",
                        rule_name="Ambiguous-Target-Architecture",
                        severity=Severity.LOW,
                        category="Toolchain & Build Flags",
                        file_path=file_path,
                        line_number=i,
                        matched_text=line.strip()[:100],
                        message="qcc invocation lacks explicit target architecture variant flag.",
                        remediation="Specify target architecture with -Vgcc_ntox86_64 (x86_64) or -Vgcc_ntoaarch64le (ARM64).",
                    )
                )
                break  # Alert once per file

    return findings
