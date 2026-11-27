# QNX Sentinel (`qnx-guard`)

> Real-Time Static Safety & Security Linter for QNX SDP 8.0 Neutrino Systems.

[![CI](https://github.com/sidsri14/qnx-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/sidsri14/qnx-guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`qnx-guard` is a zero-dependency host tool that validates QNX Neutrino real-time source code, `mkifs` bootfiles (`.bld`), and compiler hardening flags across automotive, robotics, and safety-critical embedded systems.

---

## Capabilities & Rule Catalog

### 1. Neutrino Real-Time & IPC Safety (`QNX001` - `QNX006`)
- **QNX001**: Synchronous `MsgSend` deadlock detection (flags unconstrained blocking sends lacking `TimerTimeout`).
- **QNX002**: Pulse code collision detection (identifies negative user pulse definitions that conflict with kernel pulses).
- **QNX003**: Channel priority inversion risk (identifies `ChannelCreate(0)` calls lacking priority inheritance).
- **QNX004**: Resource manager reply validation (verifies `_RESMGR_DEFAULT`, `_RESMGR_NOREPLY`, and `MsgReply`).
- **QNX005**: Root privilege retention auditor (ensures non-root capability confinement).
- **QNX006**: Message receive buffer integrity.

### 2. IFS Bootfile & System Architecture (`QNX101` - `QNX105`)
- **QNX101**: World-writable IFS file permission detection (`0777` / `0666`).
- **QNX102**: System crash dump daemon audit (ensures `dumper` is configured in `[+script]`).
- **QNX104**: Library search path security (audits `LD_LIBRARY_PATH` against relative or writable paths).
- **QNX105**: Hardcoded credential and secret scanning in boot scripts.

### 3. Toolchain & Compilation Hardening (`QNX201` - `QNX202`)
- **QNX201**: Validates `qcc`/`q++` compiler flags for stack canary protection (`-fstack-protector-strong`) and source fortification.
- **QNX202**: Architecture variant specification check (`-Vgcc_ntox86_64`, `-Vgcc_ntoaarch64le`).

---

## Quickstart

Run directly on your QNX project:

```bash
# Scan current directory
python -m qnx_guard.cli .

# Export report to SARIF format for CI/CD integration
python -m qnx_guard.cli . --format sarif -o qnx-audit.sarif

# Export interactive HTML visual scorecard
python -m qnx_guard.cli . --format html -o qnx-audit.html
```

---

## GitHub Action Integration

```yaml
- name: Audit QNX Real-Time Safety
  uses: sidsri14/qnx-guard@v0.1.0
  with:
    path: '.'
    fail-on-high: 'true'
```

---

## Verification & Test Suite

The test suite runs with Python standard library with zero external dependencies:

```bash
python -m unittest discover -s tests -v
```

## Paid services (fixed scope)

Bounded software services via no-signup Contra checkout: multi-repo CI reliability sprint (up to 5 repos, USD5,000 for one agreed milestone), checkout-link consistency gate (USD100), token-2022 CI/fee-math repair (USD150), BullMQ token-budget retrofit (USD300), one bounded OSS issue plus regression PR (USD75), and web3 starter CI harness (USD150).

All offers: https://sidsri14.github.io/implementation-packages.html | Request work (no signup): https://sidsri14.github.io/request-work.html

Proof: 25 merged upstream PRs / 30 total merged GitHub PRs; 201 passing tests across 15 owned repos. Independent, AI-assisted work; BCA student at Manipal University Jaipur, expected 2027, Lucknow, India. Advertised offers only, not received income; scope and written terms are agreed before any work starts.