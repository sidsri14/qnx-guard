"""QNX Neutrino Microkernel IPC & Real-Time Safety Rules.

Audits C/C++ source code for:
- QNX001: Synchronous MsgSend deadlock risk (missing timeout or non-blocking intent)
- QNX002: Pulse code collision with QNX system-reserved pulse range
- QNX003: Channel creation missing priority inheritance / fixed priority
- QNX004: Resource manager handler missing status return or proper reply handling
- QNX005: Unrestricted root privileges / missing privilege drop after initialization
- QNX006: Buffer length discrepancy on MsgReceive
"""

import re
from typing import List
from qnx_guard.models import Finding, Rule, Severity

NEUTRINO_RULES = [
    Rule(
        rule_id="QNX001",
        name="Unbounded-MsgSend-Deadlock-Risk",
        severity=Severity.HIGH,
        description="Synchronous MsgSend called without TimerTimeout guard or non-blocking intent, risking indefinite thread deadlock.",
        category="Neutrino IPC Safety",
        remediation="Use TimerTimeout() with _NTO_TIMEOUT_SEND before invoking MsgSend(), or implement asynchronous pulses via MsgSendPulse().",
    ),
    Rule(
        rule_id="QNX002",
        name="System-Pulse-Code-Collision",
        severity=Severity.HIGH,
        description="Pulse code value falls inside the QNX system reserved range (_PULSE_CODE_MINAVAIL to _PULSE_CODE_MAXAVAIL must be used).",
        category="Neutrino IPC Safety",
        remediation="User pulse codes must be defined between _PULSE_CODE_MINAVAIL (0) and _PULSE_CODE_MAXAVAIL (127). Negative codes are reserved for kernel notifications.",
    ),
    Rule(
        rule_id="QNX003",
        name="Channel-Priority-Inversion-Risk",
        severity=Severity.MEDIUM,
        description="ChannelCreate called with flags=0 instead of specifying priority inheritance or fixed priority.",
        category="Real-Time Scheduling",
        remediation="Pass _NTO_CHF_FIXED_PRIORITY or configure priority inheritance to avoid unbounded priority inversion in real-time dispatch.",
    ),
    Rule(
        rule_id="QNX004",
        name="Resource-Manager-Improper-Reply",
        severity=Severity.MEDIUM,
        description="Resource manager handler uses return without replying or returning _RESMGR_DEFAULT / _RESMGR_NOREPLY.",
        category="Resource Managers",
        remediation="Return _RESMGR_DEFAULT, _RESMGR_NOREPLY (if deferred via MsgReply), or an explicit POSIX errno.",
    ),
    Rule(
        rule_id="QNX005",
        name="Insecure-Root-Privilege-Retention",
        severity=Severity.MEDIUM,
        description="Process initializes root capabilities (procmgr_ability or setuid) without dropping privileges or confining abilities.",
        category="Process Security",
        remediation="Drop superuser privileges after attaching resources using setuid() / setgid() or configure PROCMGR_ADN_NONROOT capabilities.",
    ),
    Rule(
        rule_id="QNX006",
        name="Unchecked-MsgReceive-Buffer",
        severity=Severity.LOW,
        description="MsgReceive uses fixed small buffer without verifying rcvid or message header size.",
        category="Neutrino IPC Safety",
        remediation="Inspect message header struct and handle pulses (rcvid == 0) separately from standard messages (rcvid > 0).",
    ),
]


def check_neutrino_rules(content: str, file_path: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = content.splitlines()

    has_timer_timeout = any("TimerTimeout" in line for line in lines)

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip comment lines
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        # QNX001: MsgSend called without TimerTimeout in the module
        if re.search(r"\bMsgSend\s*\(", line):
            if not has_timer_timeout and "MsgSendPulse" not in line:
                findings.append(
                    Finding(
                        rule_id="QNX001",
                        rule_name="Unbounded-MsgSend-Deadlock-Risk",
                        severity=Severity.HIGH,
                        category="Neutrino IPC Safety",
                        file_path=file_path,
                        line_number=i,
                        matched_text=line.strip()[:100],
                        message="MsgSend() called synchronously without a preceding TimerTimeout() guard.",
                        remediation="Add TimerTimeout(_NTO_TIMEOUT_SEND, ...) or migrate to non-blocking MsgSendPulse().",
                    )
                )

        # QNX002: Pulse code collision (negative pulse code or reserved pulse values like -1, -2, etc. defined by user)
        # Check pulse definitions like: #define MY_PULSE -1 or MsgSendPulse(..., code, ...)
        pulse_def_match = re.search(r"#define\s+[A-Za-z0-9_]*PULSE[A-Za-z0-9_]*\s+(-[0-9]+)", line)
        if pulse_def_match:
            findings.append(
                Finding(
                    rule_id="QNX002",
                    rule_name="System-Pulse-Code-Collision",
                    severity=Severity.HIGH,
                    category="Neutrino IPC Safety",
                    file_path=file_path,
                    line_number=i,
                    matched_text=line.strip()[:100],
                    message=f"Negative pulse code '{pulse_def_match.group(1)}' conflicts with QNX kernel-reserved pulse codes.",
                    remediation="Use positive pulse codes in the range _PULSE_CODE_MINAVAIL (0) to _PULSE_CODE_MAXAVAIL (127).",
                )
            )

        # QNX003: ChannelCreate(0) without flags
        if re.search(r"\bChannelCreate\s*\(\s*0\s*\)", line):
            findings.append(
                Finding(
                    rule_id="QNX003",
                    rule_name="Channel-Priority-Inversion-Risk",
                    severity=Severity.MEDIUM,
                    category="Real-Time Scheduling",
                    file_path=file_path,
                    line_number=i,
                    matched_text=line.strip()[:100],
                    message="ChannelCreate() called with flags=0. Channel lacks priority inheritance or fixed-priority scheduling.",
                    remediation="Configure _NTO_CHF_FIXED_PRIORITY or priority inheritance flags on real-time service channels.",
                )
            )

        # QNX004: Resource manager handler missing _RESMGR_ return pattern
        if "io_read" in line or "io_write" in line:
            if re.search(r"int\s+io_(read|write)\s*\(", line):
                # Search forward in function body for _RESMGR_ return
                func_body = "\n".join(lines[i-1:i+25])
                if "_RESMGR_DEFAULT" not in func_body and "_RESMGR_NOREPLY" not in func_body and "MsgReply" not in func_body:
                    findings.append(
                        Finding(
                            rule_id="QNX004",
                            rule_name="Resource-Manager-Improper-Reply",
                            severity=Severity.MEDIUM,
                            category="Resource Managers",
                            file_path=file_path,
                            line_number=i,
                            matched_text=line.strip()[:100],
                            message="Resource manager handler may not return _RESMGR_DEFAULT or execute MsgReply().",
                            remediation="Ensure all resource manager execution branches return _RESMGR_DEFAULT, _RESMGR_NOREPLY, or execute MsgReply().",
                        )
                    )

        # QNX005: procmgr_ability without capability confinement
        if "procmgr_ability" in line and ("PROCMGR_ADN_NONROOT" not in line and "PROCMGR_AOP_DENY" not in line):
            findings.append(
                Finding(
                    rule_id="QNX005",
                    rule_name="Insecure-Root-Privilege-Retention",
                    severity=Severity.MEDIUM,
                    category="Process Security",
                    file_path=file_path,
                    line_number=i,
                    matched_text=line.strip()[:100],
                    message="Elevated procmgr_ability granted without explicit non-root restrictions or ability dropping.",
                    remediation="Lock down abilities using PROCMGR_ADN_NONROOT or drop permissions after initialization.",
                )
            )

        # QNX006: MsgReceive with raw sizeof check
        if re.search(r"\bMsgReceive\s*\(", line):
            if "rcvid == 0" not in "\n".join(lines[max(0, i-5):min(len(lines), i+15)]):
                findings.append(
                    Finding(
                        rule_id="QNX006",
                        rule_name="Unchecked-MsgReceive-Buffer",
                        severity=Severity.LOW,
                        category="Neutrino IPC Safety",
                        file_path=file_path,
                        line_number=i,
                        matched_text=line.strip()[:100],
                        message="MsgReceive() invoked without explicit check for pulse events (rcvid == 0).",
                        remediation="Always test if rcvid == 0 to handle QNX kernel pulses separately from synchronous messages.",
                    )
                )

    return findings
