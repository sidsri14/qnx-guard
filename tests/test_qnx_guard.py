"""Unit tests for QNX Sentinel (qnx-guard)."""

import json
import unittest
from pathlib import Path
from qnx_guard.models import Finding, ScanSummary, Severity
from qnx_guard.rules.neutrino import check_neutrino_rules
from qnx_guard.rules.buildfile import check_buildfile_rules
from qnx_guard.rules.toolchain import check_toolchain_rules
from qnx_guard.scanner import Scanner
from qnx_guard.reporters import render_terminal, render_json, render_sarif, render_html


class TestNeutrinoRules(unittest.TestCase):
    def test_qnx001_unbounded_msgsend(self):
        code = """
        #include <sys/neutrino.h>
        int send_data(int coid, void *smsg, void *rmsg) {
            return MsgSend(coid, smsg, 10, rmsg, 10);
        }
        """
        findings = check_neutrino_rules(code, "test_ipc.c")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX001", rule_ids)

    def test_qnx001_safe_msgsend_with_timeout(self):
        code = """
        #include <sys/neutrino.h>
        int send_data(int coid, void *smsg, void *rmsg) {
            TimerTimeout(CLOCK_REALTIME, _NTO_TIMEOUT_SEND, NULL, NULL, NULL);
            return MsgSend(coid, smsg, 10, rmsg, 10);
        }
        """
        findings = check_neutrino_rules(code, "safe_ipc.c")
        rule_ids = [f.rule_id for f in findings]
        self.assertNotIn("QNX001", rule_ids)

    def test_qnx002_pulse_code_collision(self):
        code = """
        #define MY_BAD_PULSE -2
        """
        findings = check_neutrino_rules(code, "bad_pulse.c")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX002", rule_ids)

    def test_qnx003_channel_create_no_flags(self):
        code = """
        int chid = ChannelCreate(0);
        """
        findings = check_neutrino_rules(code, "channel.c")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX003", rule_ids)

    def test_qnx004_resource_manager_missing_reply(self):
        code = """
        int io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb) {
            int status = check_status();
            return status;
        }
        """
        findings = check_neutrino_rules(code, "resmgr.c")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX004", rule_ids)

    def test_qnx005_root_privilege_retention(self):
        code = """
        procmgr_ability(0, PROCMGR_ADN_ROOT | PROCMGR_AOP_ALLOW, PROCMGR_AID_MEM_PHYS, PROCMGR_AID_EOL);
        """
        findings = check_neutrino_rules(code, "root_setup.c")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX005", rule_ids)

    def test_qnx006_unchecked_msgreceive(self):
        code = """
        int rcvid = MsgReceive(chid, &msg, sizeof(msg), NULL);
        handle_payload(&msg);
        """
        findings = check_neutrino_rules(code, "receiver.c")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX006", rule_ids)

    def test_qnx007_insecure_name_attach(self):
        code = """
        name_attach_t *attach = name_attach(NULL, "my_service", 0);
        """
        findings = check_neutrino_rules(code, "service.c")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX007", rule_ids)

    def test_qnx008_unsafe_interrupt_attach(self):
        code = """
        int iid = InterruptAttach(10, isr_handler, NULL, 0, 0);
        """
        findings = check_neutrino_rules(code, "driver.c")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX008", rule_ids)


class TestBuildfileRules(unittest.TestCase):
    def test_qnx101_world_writable_permissions(self):
        bld = """
        [image=0x100000]
        [+script] {
            procmgr-slink &
        }
        [perms=0777] /bin/bad_tool = /target/bad_tool
        """
        findings = check_buildfile_rules(bld, "image.bld")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX101", rule_ids)

    def test_qnx102_missing_dumper_daemon(self):
        bld = """
        [image=0x100000]
        [+script] {
            procmgr-slink &
            devc-ser8250 &
        }
        """
        findings = check_buildfile_rules(bld, "image.bld")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX102", rule_ids)

    def test_qnx104_insecure_library_path(self):
        bld = """
        [+script] {
            LD_LIBRARY_PATH=/tmp:/proc/boot
        }
        """
        findings = check_buildfile_rules(bld, "image.bld")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX104", rule_ids)

    def test_qnx105_hardcoded_secrets(self):
        bld = """
        [+script] {
            API_KEY=AKIA1234567890SECRETKEY
        }
        """
        findings = check_buildfile_rules(bld, "image.bld")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX105", rule_ids)

    def test_qnx106_missing_secpol_enforcement(self):
        bld = """
        [image=0x100000]
        # QNX8 target buildfile
        [+script] {
            dumper -d /var/dumps &
            procmgr-slink &
        }
        """
        findings = check_buildfile_rules(bld, "qnx8_image.bld")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX106", rule_ids)


class TestToolchainRules(unittest.TestCase):
    def test_qnx201_missing_stack_protector(self):
        mk = """
        CC = qcc
        CFLAGS = -O2 -Wall
        target: main.c
        \t$(CC) $(CFLAGS) -o target main.c
        """
        findings = check_toolchain_rules(mk, "Makefile")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX201", rule_ids)

    def test_qnx202_ambiguous_target_architecture(self):
        mk = """
        CC = qcc
        CFLAGS = -O2 -fstack-protector-strong
        target: main.c
        \t$(CC) $(CFLAGS) -o target main.c
        """
        findings = check_toolchain_rules(mk, "Makefile")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("QNX202", rule_ids)

    def test_qnx_hardened_makefile_clean(self):
        mk = """
        CC = qcc -Vgcc_ntox86_64
        CFLAGS = -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
        target: main.c
        \t$(CC) $(CFLAGS) -o target main.c
        """
        findings = check_toolchain_rules(mk, "Makefile")
        self.assertEqual(len(findings), 0)


class TestReporters(unittest.TestCase):
    def setUp(self):
        self.summary = ScanSummary(total_files=2, scanned_files=2)
        self.summary.add_finding(
            Finding(
                rule_id="QNX001",
                rule_name="Unbounded-MsgSend-Deadlock-Risk",
                severity=Severity.HIGH,
                category="Neutrino IPC Safety",
                file_path="src/service.c",
                line_number=42,
                matched_text="MsgSend(coid, ...)",
                message="Unbounded MsgSend deadlock risk.",
                remediation="Use TimerTimeout.",
            )
        )

    def test_render_terminal(self):
        out = render_terminal(self.summary)
        self.assertIn("QNX Sentinel", out)
        self.assertIn("QNX001", out)
        self.assertIn("Total Findings:   1", out)

    def test_render_json(self):
        out = render_json(self.summary)
        data = json.loads(out)
        self.assertEqual(data["total_findings"], 1)
        self.assertEqual(data["high_severity"], 1)

    def test_render_sarif(self):
        out = render_sarif(self.summary)
        data = json.loads(out)
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(len(data["runs"][0]["results"]), 1)

    def test_render_html(self):
        out = render_html(self.summary)
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("QNX001", out)


if __name__ == "__main__":
    unittest.main()
