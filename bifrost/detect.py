"""Live detection: which addresses Overwatch talks to, read from the Windows Firewall log.

With logging switched on, Windows writes one line each time a new UDP flow is allowed or dropped.
We keep the lines that belong to Overwatch (its process id when the log has it, else its UDP ports),
then match the remote address against the server list.
"""
import os
import threading
import time

import core

RECENT_PORTS_S = 15 * 60
FLOW_KEEP_S = 2 * 60 * 60


class LogTail:
    """Reads the lines appended to a file since the last call; survives rotation and truncation."""

    def __init__(self, path):
        self.path = path
        self.pos = None
        self.fields = list(core.DEFAULT_LOG_FIELDS)

    def read_new(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []
        if self.pos is None or size < self.pos:
            self.pos = size if self.pos is None else 0
            self._read_header()
        if size == self.pos:
            return []
        with open(self.path, "rb") as f:
            f.seek(self.pos)
            chunk = f.read(4 * 1024 * 1024)
        end = chunk.rfind(b"\n")
        if end < 0:
            return []  # wait until the line is complete
        self.pos += end + 1
        out = []
        for line in chunk[:end].decode("utf-8", errors="ignore").splitlines():
            if line.startswith("#Fields:"):
                self.fields = line[len("#Fields:"):].split()
                continue
            rec = core.parse_firewall_log_line(line, self.fields)
            if rec:
                out.append(rec)
        return out

    def _read_header(self):
        try:
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in range(10):
                    line = f.readline()
                    if line.startswith("#Fields:"):
                        self.fields = line[len("#Fields:"):].split()
                        return
        except OSError:
            pass


class Detector:
    def __init__(self, get_db, get_process):
        self.get_db = get_db
        self.get_process = get_process
        self.tails = []
        self.lock = threading.Lock()
        self.flows = {}        # remote ip -> dict(first, last, allow, drop)
        self.ports = {}        # local UDP port of Overwatch -> last time seen
        self.pid = None
        self.process = None
        self.lines_read = 0
        self.matched = 0
        self.error = None

    def set_log_files(self, paths):
        with self.lock:
            self.tails = [LogTail(p) for p in paths]

    def poll(self):
        now = time.time()
        try:
            proc = self.get_process()
        except Exception as e:  # psutil hiccups must not stop detection
            proc, self.error = None, f"processus : {e}"
        with self.lock:
            self.process = proc
            if proc:
                if proc["pid"] != self.pid:
                    self.pid = proc["pid"]
                for port in proc["udp_ports"]:
                    self.ports[port] = now
            self.ports = {p: t for p, t in self.ports.items() if now - t < RECENT_PORTS_S}
            for tail in self.tails:
                for rec in tail.read_new():
                    self.lines_read += 1
                    self._consider(rec, now)
            self.flows = {ip: f for ip, f in self.flows.items() if now - f["last"] < FLOW_KEEP_S}

    def _consider(self, rec, now):
        proto = rec.get("protocol", "").upper()
        if proto not in ("UDP", "ICMP"):
            return
        path = rec.get("path", "").upper()
        src, dst = rec.get("src-ip", ""), rec.get("dst-ip", "")
        if path == "SEND":
            remote, lport = dst, rec.get("src-port")
        elif path == "RECEIVE":
            remote, lport = src, rec.get("dst-port")
        else:
            remote, lport = (dst, rec.get("src-port")) if core.is_private(src) else (src, rec.get("dst-port"))
        if ":" in remote or core.is_private(remote):
            return
        pid_field = rec.get("pid", "")
        if pid_field.isdigit() and self.pid:
            mine = int(pid_field) == self.pid
        else:
            mine = proto == "UDP" and lport and lport.isdigit() and int(lport) in self.ports
        if not mine:
            return
        self.matched += 1
        flow = self.flows.setdefault(remote, dict(first=now, last=now, allow=0, drop=0))
        flow["last"] = now
        if rec.get("action", "").upper() == "DROP":
            flow["drop"] += 1
        else:
            flow["allow"] += 1

    def snapshot(self):
        """What the interface shows: last game server, blocked attempts, unknown addresses to learn."""
        db = self.get_db()
        now = time.time()
        with self.lock:
            flows = sorted(self.flows.items(), key=lambda kv: kv[1]["last"], reverse=True)
            proc = self.process
            tcp = list(proc["tcp"]) if proc else []
        items, drops, unknown = [], {}, []
        current = None
        for ip, f in flows[:40]:
            sid = db.server_for_ip(ip)
            rid = db.region_for_ip(ip)
            item = dict(ip=ip, server=sid, region=rid, allow=f["allow"], drop=f["drop"], ago=int(now - f["last"]))
            items.append(item)
            if f["drop"] and sid:
                drops[sid] = drops.get(sid, 0) + f["drop"]
            if f["allow"] and current is None and sid:
                current = item
            if f["allow"] and not sid and len(unknown) < 5:
                unknown.append(item)
        battlenet = [c for c in tcp if c["port"] in (443, 1119) and c["status"] == "ESTABLISHED"]
        lobby = [c for c in tcp if c["port"] == 3724 and c["status"] == "ESTABLISHED"]
        return dict(running=bool(proc), pid=proc["pid"] if proc else None, current=current, drops=drops,
                    unknown=unknown, flows=items, battlenet=battlenet[:3], lobby=lobby[:3],
                    lines_read=self.lines_read, matched=self.matched, error=self.error)
