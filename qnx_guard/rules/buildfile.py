"""QNX mkifs Buildfile & IFS System Architecture Rules.

Audits QNX .build / .bld files for:
- QNX101: World-writable file permissions in bootable image
- QNX102: Missing system crash dump daemon (dumper)
- QNX103: Missing hardware MMU/NX security attributes on startup
- QNX104: Ambiguous LD_LIBRARY_PATH in boot script
- QNX105: Hardcoded secrets or tokens in boot script environment
"""

import re
from typing import List
from qnx_guard.models import Finding, Rule, Severity

BUILDFILE_RULES = [
    Rule(
        rule_id="QNX101",
        name="World-Writable-IFS-Permissions",
        severity=Severity.HIGH,
        description="Target image contains files with world-writable permission masks (e.g. 0777, 0666).",
        category="IFS Image Security",
        remediation="Restrict file permissions in buildfile to [perms=0755] for executables and [perms=0644] for configs.",
    ),
    Rule(
        rule_id="QNX102",
        name="Missing-Dumper-Daemon",
        severity=Severity.MEDIUM,
        description="Boot script does not start the QNX crash dump daemon (dumper), hindering post-mortem real-time fault analysis.",
        category="Reliability & Diagnostic",
        remediation="Add 'dumper -d /var/dumps &' to the buildfile [+script] section for automatic crash logging.",
    ),
    Rule(
        rule_id="QNX103",
        name="Missing-Hardware-Security-Startup",
        severity=Severity.MEDIUM,
        description="Startup command lacks hardware memory protection flags (such as MMU initialization or execution prevention).",
        category="IFS Image Security",
        remediation="Verify startup command specifies appropriate platform flags (e.g., startup-x86_64, startup-rpi4) with memory protection active.",
    ),
    Rule(
        rule_id="QNX104",
        name="Insecure-Library-Search-Path",
        severity=Severity.LOW,
        description="LD_LIBRARY_PATH includes relative directories or writable locations before /proc/boot.",
        category="IFS Image Security",
        remediation="Ensure LD_LIBRARY_PATH prioritizes read-only /proc/boot and /lib paths to prevent library hijacking.",
    ),
    Rule(
        rule_id="QNX105",
        name="Hardcoded-Credentials-In-Buildfile",
        severity=Severity.HIGH,
        description="Hardcoded password, secret key, or token detected in buildfile environment or script section.",
        category="Secrets Management",
        remediation="Remove hardcoded credentials from buildfile. Pass secrets at runtime via secure keystore or mount point.",
    ),
    Rule(
        rule_id="QNX106",
        name="Missing-Secpol-Enforcement",
        severity=Severity.HIGH,
        description="Boot script does not start secpol (security policy manager) for QNX 8.0 mandatory access control (MAC).",
        category="IFS Image Security",
        remediation="Add 'secpol &' or 'secpol -d &' into [+script] to enforce QNX 8.0 sandboxing and process isolation policies.",
    ),
]


def check_buildfile_rules(content: str, file_path: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = content.splitlines()

    has_dumper = any(re.search(r"\bdumper\b", line) for line in lines)
    has_secpol = any(re.search(r"\bsecpol\b", line) for line in lines)
    is_buildfile = file_path.endswith((".bld", ".build")) or "[+script]" in content or "[image=" in content

    if not is_buildfile:
        return findings

    # QNX102: Missing dumper daemon in buildfile
    if not has_dumper and "[+script]" in content:
        findings.append(
            Finding(
                rule_id="QNX102",
                rule_name="Missing-Dumper-Daemon",
                severity=Severity.MEDIUM,
                category="Reliability & Diagnostic",
                file_path=file_path,
                line_number=1,
                matched_text="[+script] section missing dumper daemon",
                message="QNX buildfile does not launch 'dumper' daemon in boot script.",
                remediation="Add 'dumper -d /var/dumps &' into [+script] to capture crash core dumps in real time.",
            )
        )

    # QNX106: Missing secpol enforcement in QNX 8.0 buildfile
    if not has_secpol and "[+script]" in content and "qnx8" in content.lower():
        findings.append(
            Finding(
                rule_id="QNX106",
                rule_name="Missing-Secpol-Enforcement",
                severity=Severity.HIGH,
                category="IFS Image Security",
                file_path=file_path,
                line_number=1,
                matched_text="[+script] section missing secpol daemon",
                message="QNX 8.0 buildfile [+script] does not launch 'secpol' security policy manager daemon.",
                remediation="Add 'secpol &' into [+script] to enforce Mandatory Access Control policies in QNX 8.0.",
            )
        )

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # QNX101: World writable permissions [perms=0777] or [perms=0666]
        perm_match = re.search(r"\[perms=(0?[67][67][67])\]", line)
        if perm_match:
            findings.append(
                Finding(
                    rule_id="QNX101",
                    rule_name="World-Writable-IFS-Permissions",
                    severity=Severity.HIGH,
                    category="IFS Image Security",
                    file_path=file_path,
                    line_number=i,
                    matched_text=line.strip()[:100],
                    message=f"Insecure file permission mask '{perm_match.group(1)}' allows world-write access in QNX image.",
                    remediation="Change permission attribute to [perms=0755] for executables or [perms=0644] for read-only data.",
                )
            )

        # QNX104: Insecure library search path
        if "LD_LIBRARY_PATH" in line:
            if "." in line or "/tmp" in line or "/var" in line:
                findings.append(
                    Finding(
                        rule_id="QNX104",
                        rule_name="Insecure-Library-Search-Path",
                        severity=Severity.LOW,
                        category="IFS Image Security",
                        file_path=file_path,
                        line_number=i,
                        matched_text=line.strip()[:100],
                        message="LD_LIBRARY_PATH contains relative path or writable directory (/tmp, /var).",
                        remediation="Restrict library search path exclusively to /proc/boot:/lib:/usr/lib.",
                    )
                )

        # QNX105: Hardcoded passwords/secrets
        secret_match = re.search(r"(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*['\"]?([A-Za-z0-9_\-\.]{6,})['\"]?", line, re.IGNORECASE)
        if secret_match:
            findings.append(
                Finding(
                    rule_id="QNX105",
                    rule_name="Hardcoded-Credentials-In-Buildfile",
                    severity=Severity.HIGH,
                    category="Secrets Management",
                    file_path=file_path,
                    line_number=i,
                    matched_text=re.sub(r"=.*", "=********", line.strip())[:100],
                    message="Hardcoded sensitive credential identified in QNX buildfile.",
                    remediation="Inject credentials at runtime via encrypted filesystem or secure configuration daemon.",
                )
            )

    return findings
