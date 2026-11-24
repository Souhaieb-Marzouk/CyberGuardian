"""
Live traffic monitoring for the Studio interface.

Sniffnet-style visibility without requiring a packet-capture driver: the monitor
polls Windows connection tables (psutil), attributes each connection to its
process, tracks per-process throughput and flags connections that deserve a
second look.  Raw PCAP capture would require Npcap; this layer focuses on the
questions an analyst asks first: which program, talking to which host, how much,
and is it normal?
"""

from __future__ import annotations

import ipaddress
import os
import queue
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import psutil

from utils.config import APP_DIR
from utils.logging_utils import get_logger

logger = get_logger("core.live_traffic")

SERVICE_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "SQL Server", 1521: "Oracle",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB",
}

SUSPICIOUS_PORTS = {
    21, 22, 23, 135, 137, 138, 139, 445, 1433, 1521, 3306, 3389, 4444, 5555,
    5900, 6379, 1337, 31337, 6667, 9001, 9050,
}

USER_WRITABLE_HINTS = ("\\temp\\", "\\downloads\\", "\\users\\public\\")


@dataclass
class ProcessContext:
    pid: int
    name: str
    exe: str
    username: str
    started: str
    ppid: int = 0
    parent: str = ""
    cmdline: str = ""


@dataclass
class ConnectionView:
    key: str
    pid: int
    app: str
    exe: str
    username: str
    ppid: int
    parent: str
    cmdline: str
    started: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str
    state: str
    family: str
    domain: str
    service: str
    age: float
    first_seen: float
    is_public: bool
    is_lan: bool
    risk: str
    reasons: List[str] = field(default_factory=list)
    down_rate: float = 0.0
    up_rate: float = 0.0
    blocked_down: bool = False
    blocked_up: bool = False

    @property
    def remote_label(self) -> str:
        if self.remote_ip:
            host = self.domain or self.remote_ip
            port = self.remote_port
            return f"{host}:{port}" if port else host
        return "—"

    @property
    def local_label(self) -> str:
        return f"{self.local_ip}:{self.local_port}"

    @property
    def blockable(self) -> bool:
        if not self.remote_ip or self.state in ("LISTEN", "NONE"):
            return False
        try:
            address = ipaddress.ip_address(self.remote_ip)
        except ValueError:
            return False
        return not (address.is_loopback or address.is_unspecified)


@dataclass
class TrafficSnapshot:
    connections: List[ConnectionView]
    download_bps: float
    upload_bps: float
    total_download: int
    total_upload: int
    adapter: str
    adapters: List[str]
    timestamp: float
    suspicious: int = 0


def _is_public(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast or address.is_unspecified)


def _service(port: int) -> str:
    return SERVICE_PORTS.get(port, "")


class TrafficMonitor:
    """Poll Windows connection tables and compute rates and risk hints."""

    def __init__(self, blacklist_path: Optional[Path] = None):
        self._blacklist_path = Path(blacklist_path) if blacklist_path else Path(APP_DIR) / "data" / "ip_blacklist.txt"
        self._blacklist = self._load_blacklist()
        self._blacklist_mtime = self._blacklist_path.stat().st_mtime if self._blacklist_path.exists() else 0
        self._first_seen: Dict[str, float] = {}
        self._last_seen: Dict[str, float] = {}
        self._proc_cache: Dict[int, ProcessContext] = {}
        self._proc_checked: Dict[int, float] = {}
        self._io_cache: Dict[int, Tuple[float, int, int]] = {}
        self._proc_rates: Dict[int, Tuple[float, float]] = {}
        self._adapter = ""
        self._adapter_counters: Optional[Tuple[float, int, int]] = None
        self._last_total = (0, 0)
        self._resolver_queue: "queue.Queue[str]" = queue.Queue()
        self._resolver_cache: Dict[str, str] = {}
        self._resolver_started = False
        self._resolver_lock = threading.Lock()

    # ------------------------------------------------------------------ setup
    def adapters(self) -> List[str]:
        names = ["Toutes les interfaces"]
        try:
            for name in psutil.net_io_counters(pernic=True):
                if name and not name.lower().startswith("loopback"):
                    names.append(name)
        except Exception:
            pass
        return names

    def set_adapter(self, name: str):
        self._adapter = "" if name.startswith("Toutes") or name == "All interfaces" else name
        self._adapter_counters = None

    def _load_blacklist(self) -> set:
        entries = set()
        try:
            if self._blacklist_path.exists():
                for line in self._blacklist_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.add(line)
        except OSError:
            pass
        return entries

    def _blacklisted(self, ip: str) -> bool:
        if not self._blacklist:
            return False
        try:
            address = ipaddress.ip_address(ip)
            for entry in self._blacklist:
                if "/" in entry:
                    try:
                        if address in ipaddress.ip_network(entry, strict=False):
                            return True
                    except ValueError:
                        continue
                elif entry == ip:
                    return True
        except ValueError:
            return False
        return False

    # ------------------------------------------------------------- processes
    def _process(self, pid: int) -> ProcessContext:
        now = time.time()
        cached = self._proc_cache.get(pid)
        if cached and now - self._proc_checked.get(pid, 0) < 10:
            return cached
        context = ProcessContext(pid=pid, name="?", exe="", username="", started="")
        try:
            proc = psutil.Process(pid)
            context.name = proc.name() or "?"
            context.exe = proc.exe() or ""
            try:
                context.username = proc.username() or ""
            except Exception:
                context.username = ""
            try:
                context.started = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(proc.create_time())
                )
            except Exception:
                context.started = ""
            try:
                context.ppid = proc.ppid() or 0
                context.parent = psutil.Process(context.ppid).name() if context.ppid else ""
            except Exception:
                context.parent = ""
            try:
                context.cmdline = " ".join(proc.cmdline())
            except Exception:
                context.cmdline = ""
        except Exception:
            pass
        self._proc_cache[pid] = context
        self._proc_checked[pid] = now
        if len(self._proc_cache) > 500:
            cut = now - 60
            self._proc_cache = {
                key: value for key, value in self._proc_cache.items()
                if self._proc_checked.get(key, 0) > cut
            }
        return context

    def _process_rates(self, pid: int, now: float):
        try:
            proc = psutil.Process(pid)
            info = proc.io_counters()
        except Exception:
            return (0.0, 0.0)
        previous = self._io_cache.get(pid)
        self._io_cache[pid] = (now, info.read_bytes, info.write_bytes)
        if not previous:
            return (0.0, 0.0)
        elapsed = max(0.001, now - previous[0])
        read_rate = max(0.0, (info.read_bytes - previous[1]) / elapsed)
        write_rate = max(0.0, (info.write_bytes - previous[2]) / elapsed)
        self._proc_rates[pid] = (read_rate, write_rate)
        return (read_rate, write_rate)

    # --------------------------------------------------------------- resolver
    def _start_resolver(self):
        if self._resolver_started:
            return
        self._resolver_started = True
        thread = threading.Thread(target=self._resolver_loop, daemon=True)
        thread.start()

    def _resolver_loop(self):
        while True:
            ip = self._resolver_queue.get()
            try:
                with self._resolver_lock:
                    if ip in self._resolver_cache:
                        continue
                host = ""
                try:
                    host = socket.gethostbyaddr(ip)[0]
                except Exception:
                    host = ""
                with self._resolver_lock:
                    self._resolver_cache[ip] = host
            finally:
                self._resolver_queue.task_done()

    def _resolve(self, ip: str) -> str:
        if not ip:
            return ""
        self._start_resolver()
        with self._resolver_lock:
            cached = self._resolver_cache.get(ip)
        if cached is not None:
            return cached
        try:
            self._resolver_queue.put_nowait(ip)
        except queue.Full:
            pass
        return ""

    # ------------------------------------------------------------------ poll
    def _rates(self, now: float) -> Tuple[float, float, int, int]:
        try:
            counters = psutil.net_io_counters(pernic=True)
        except Exception:
            return (0.0, 0.0, 0, 0)
        if self._adapter:
            counter = counters.get(self._adapter)
            if counter is None:
                self._adapter = ""
                return (0.0, 0.0, 0, 0)
            sent, recv = counter.bytes_sent, counter.bytes_recv
        else:
            sent = sum(item.bytes_sent for item in counters.values())
            recv = sum(item.bytes_recv for item in counters.values())
        previous = self._adapter_counters
        self._adapter_counters = (now, sent, recv)
        if not previous:
            return (0.0, 0.0, sent, recv)
        elapsed = max(0.001, now - previous[0])
        down = max(0.0, (recv - previous[2]) / elapsed)
        up = max(0.0, (sent - previous[1]) / elapsed)
        return (down, up, sent, recv)

    def snapshot(self) -> TrafficSnapshot:
        now = time.time()
        try:
            mtime = self._blacklist_path.stat().st_mtime if self._blacklist_path.exists() else 0
            if mtime != self._blacklist_mtime:
                self._blacklist = self._load_blacklist()
                self._blacklist_mtime = mtime
        except OSError:
            pass
        down, up, sent, recv = self._rates(now)
        raw = []
        try:
            raw = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            logger.debug("Connection table requires administrator rights")
        except Exception as exc:
            logger.debug(f"Could not read connections: {exc}")

        connections: List[ConnectionView] = []
        seen_keys = set()
        for conn in raw:
            key = "|".join((
                str(conn.pid or 0), conn.laddr.ip if conn.laddr else "",
                str(conn.laddr.port if conn.laddr else 0),
                conn.raddr.ip if conn.raddr else "",
                str(conn.raddr.port if conn.raddr else 0),
                "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            ))
            seen_keys.add(key)
            first = self._first_seen.setdefault(key, now)
            self._last_seen[key] = now
            pid = conn.pid or 0
            proc = self._process(pid) if pid else ProcessContext(0, "?", "", "", "")
            # Per-connection byte counters need packet capture; system-wide rates
            # are accurate, per-process disk I/O is not network traffic.
            read_rate, write_rate = 0.0, 0.0
            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0
            local_ip = conn.laddr.ip if conn.laddr else ""
            local_port = conn.laddr.port if conn.laddr else 0
            public = _is_public(remote_ip)
            lan = False
            if remote_ip and not public:
                try:
                    lan = not ipaddress.ip_address(remote_ip).is_loopback
                except ValueError:
                    lan = False
            reasons: List[str] = []
            risk = "info"
            # Kernel/system rows have no process context and no remote endpoint;
            # flagging them produced a wall of meaningless "to review" rows.
            system_row = pid in (0, 4) or not proc.name or proc.name == "?"
            if not system_row and remote_ip:
                if self._blacklisted(remote_ip):
                    reasons.append("blacklist")
                    risk = "high"
                if public and remote_port in SUSPICIOUS_PORTS:
                    reasons.append("suspicious_port")
                    risk = "high"
                exe = (proc.exe or "").lower()
                if exe and any(hint in exe for hint in USER_WRITABLE_HINTS):
                    reasons.append("user_writable")
                    risk = "medium" if risk == "info" else risk
                if not proc.exe and public:
                    reasons.append("unknown_process")
                    risk = "medium" if risk == "info" else risk
            elif not system_row and conn.status == "LISTEN":
                if local_ip in ("0.0.0.0", "::", "") and local_port in (3389, 5900, 23):
                    reasons.append("exposed_listener")
                    risk = "medium"

            app_name = proc.name if not system_row else ("System" if pid in (0, 4) else "Unknown")
            if system_row and pid not in (0, 4):
                app_name = "Unknown"

            connections.append(ConnectionView(
                key=key, pid=pid, app=app_name,
                exe=proc.exe, username=proc.username,
                ppid=proc.ppid, parent=proc.parent, cmdline=proc.cmdline,
                started=proc.started,
                local_ip=local_ip, local_port=local_port,
                remote_ip=remote_ip, remote_port=remote_port,
                protocol="TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                state=conn.status or ("LISTEN" if not remote_ip else ""),
                family="IPv6" if ":" in (local_ip or remote_ip) else "IPv4",
                domain=self._resolve(remote_ip) if public else "",
                service=_service(remote_port) or _service(local_port),
                age=max(0.0, now - first), first_seen=first,
                is_public=public, is_lan=lan, risk=risk, reasons=reasons,
                down_rate=read_rate, up_rate=write_rate,
            ))

        # drop state for connections gone for a while
        for key in list(self._first_seen):
            if key not in seen_keys and now - self._last_seen.get(key, now) > 60:
                self._first_seen.pop(key, None)
                self._last_seen.pop(key, None)

        connections.sort(key=lambda item: (
            {"high": 0, "medium": 1, "info": 2}.get(item.risk, 3),
            -max(item.down_rate, item.up_rate), item.app.lower(),
        ))
        suspicious = sum(1 for item in connections if item.risk != "info")
        return TrafficSnapshot(
            connections=connections, download_bps=down, upload_bps=up,
            total_download=recv, total_upload=sent, adapter=self._adapter,
            adapters=self.adapters(), timestamp=now, suspicious=suspicious,
        )
