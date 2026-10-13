"""eBPF kernel probe integration with graceful fallback for network socket tracing."""

from __future__ import annotations

import logging
import os
import platform
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# BPF C program for tracing IPv4 TCP connection attempts
BPF_TCP_CONNECT_PROG = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_PERF_OUTPUT(ipv4_events);

struct ipv4_data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};

int trace_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ipv4_data_t data = {};
    data.pid = pid;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    ipv4_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


class BPFProbe:
    def __init__(self):
        self.is_linux = sys.platform.startswith("linux")
        self.is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
        self.bcc_module = self._try_import_bcc()
        self._bpf_instance = None

    @staticmethod
    def _try_import_bcc():
        try:
            import bcc
            return bcc
        except ImportError:
            return None

    def check_status(self) -> Dict[str, Any]:
        """Inspect and return readiness of eBPF kernel subsystem."""
        tracefs = Path("/sys/kernel/debug/tracing").exists() or Path("/sys/kernel/tracing").exists()
        kernel = platform.release()
        bcc_installed = self.bcc_module is not None

        available = self.is_linux and self.is_root and bcc_installed and tracefs

        recs = []
        if not self.is_linux:
            recs.append("eBPF socket tracing is only supported on Linux kernels.")
        if not bcc_installed:
            recs.append(
                "python-bcc module not installed. Install via: "
                "Ubuntu/Debian: 'sudo apt install python3-bpfcc bpfcc-tools' | "
                "Fedora/RHEL: 'sudo dnf install python3-bcc bcc-tools'"
            )
        if not self.is_root:
            recs.append("Root privileges required to load eBPF kernel probes (run with sudo).")
        if not tracefs:
            recs.append("Kernel tracefs is not mounted or debugfs permissions are restricted.")

        status_desc = "Ready (Zero-latency eBPF kernel monitoring active)" if available else "Fallback mode (Polling)"

        return {
            "available": available,
            "bcc_installed": bcc_installed,
            "is_root": self.is_root,
            "kernel_version": kernel,
            "tracefs_mounted": tracefs,
            "status_description": status_desc,
            "recommendation": " | ".join(recs) if recs else None,
        }

    def start(self) -> Tuple[bool, str]:
        """Attempt to compile and attach eBPF probe. Gracefully fall back if unavailable."""
        status = self.check_status()
        if not status["available"]:
            return False, f"eBPF not available: {status.get('recommendation') or 'Requirements not met'}"

        try:
            bpf = self.bcc_module.BPF(text=BPF_TCP_CONNECT_PROG)
            bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect")
            self._bpf_instance = bpf
            logger.info("eBPF probe successfully attached to tcp_v4_connect.")
            return True, "eBPF probe attached successfully"
        except Exception as e:
            logger.warning("Failed to attach eBPF probe: %s. Falling back to socket polling.", e)
            return False, f"Failed to attach eBPF probe: {e}"

    def stop(self) -> None:
        """Detach BPF probes and cleanup resources."""
        if self._bpf_instance is not None:
            try:
                self._bpf_instance.cleanup()
            except Exception:
                pass
            self._bpf_instance = None
