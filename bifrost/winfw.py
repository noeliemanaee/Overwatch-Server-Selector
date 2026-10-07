"""Everything that talks to Windows: firewall rules, firewall logging, ICMP ping, Overwatch's process.

Imported only on Windows (pywin32 and psutil are Windows dependencies of the build).
"""
import collections
import ctypes
import json
import os
import socket
import struct
import subprocess
from ctypes import wintypes

GROUP = "Bifrost (NOEVALKY)"
CREATE_NO_WINDOW = 0x08000000
ACTION_BLOCK = 0
ALL_PROFILES = 0x7FFFFFFF


# ---------------------------------------------------------------- firewall rules (COM, as the original app)

def _policy():
    import pythoncom
    import win32com.client
    pythoncom.CoInitialize()
    return win32com.client.Dispatch("HNetCfg.FwPolicy2")


def _new_rule():
    import win32com.client
    return win32com.client.Dispatch("HNetCfg.FWRule")


class Firewall:
    def __init__(self, group=GROUP):
        self.group = group

    def status(self):
        """Is Windows Firewall on for the network profile(s) in use right now?"""
        pol = _policy()
        current = pol.CurrentProfileTypes
        names = {1: "domaine", 2: "privé", 4: "public"}
        return {names[bit]: bool(pol.FirewallEnabled(bit)) for bit in (1, 2, 4) if current & bit}

    def our_rules(self):
        pol = _policy()
        out = []
        for r in pol.Rules:
            try:
                if r.Grouping == self.group:
                    out.append(r.Name)
            except Exception:
                continue
        return out

    def add(self, spec):
        pol = _policy()
        rule = _new_rule()
        rule.Name = spec["name"]
        rule.Description = "Ajoutée par Bifröst (NOEVALKY). Retirée par « Tout débloquer »."
        rule.Protocol = spec["protocol"]  # before ports/addresses
        rule.RemoteAddresses = ",".join(spec["addresses"])
        rule.Direction = spec["direction"]
        rule.Action = ACTION_BLOCK
        if spec.get("app"):
            rule.ApplicationName = spec["app"]
        rule.Grouping = self.group
        rule.Profiles = ALL_PROFILES
        rule.Enabled = True
        pol.Rules.Add(rule)

    def remove_all(self):
        pol = _policy()
        for _ in range(3):
            counts = collections.Counter(self.our_rules())
            if not counts:
                return
            for name, n in counts.items():
                for _ in range(n):
                    try:
                        pol.Rules.Remove(name)
                    except Exception:
                        break

    def apply(self, specs):
        """Replace all Bifröst rules with `specs`; on any failure, leave nothing half-applied."""
        self.remove_all()
        try:
            for spec in specs:
                self.add(spec)
        except Exception:
            self.remove_all()
            raise
        return len(self.our_rules())


# ---------------------------------------------------------------- firewall logging (PowerShell NetSecurity)

def _ps(command, timeout=40):
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
                       capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:500])
    return r.stdout


def logging_state():
    out = _ps("Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name = \"$($_.Name)\"; "
              "LogAllowed = \"$($_.LogAllowed)\"; LogBlocked = \"$($_.LogBlocked)\"; "
              "LogFileName = \"$($_.LogFileName)\" } } | ConvertTo-Json -Compress")
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def enable_logging():
    _ps("Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True")


def restore_logging(saved):
    allowed = {"True", "False", "NotConfigured"}
    for p in saved or []:
        name, la, lb = p.get("Name"), p.get("LogAllowed"), p.get("LogBlocked")
        if name in ("Domain", "Private", "Public") and la in allowed and lb in allowed:
            _ps(f"Set-NetFirewallProfile -Name {name} -LogAllowed {la} -LogBlocked {lb}")


def log_files(saved_state):
    paths = []
    for p in saved_state or []:
        path = os.path.expandvars(p.get("LogFileName") or r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log")
        if path not in paths:
            paths.append(path)
    return paths or [os.path.expandvars(r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log")]


# ---------------------------------------------------------------- ICMP ping (iphlpapi, no admin rights needed)

class _IPOptions(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]


class _EchoReply(ctypes.Structure):
    _fields_ = [("Address", wintypes.ULONG), ("Status", wintypes.ULONG), ("RoundTripTime", wintypes.ULONG),
                ("DataSize", wintypes.USHORT), ("Reserved", wintypes.USHORT), ("Data", ctypes.c_void_p),
                ("Options", _IPOptions)]


_iphlp = None


def _icmp():
    global _iphlp
    if _iphlp is None:
        lib = ctypes.WinDLL("iphlpapi")
        lib.IcmpCreateFile.restype = wintypes.HANDLE
        lib.IcmpSendEcho.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
                                     ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        lib.IcmpSendEcho.restype = wintypes.DWORD
        lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        _iphlp = lib
    return _iphlp


def ping(host, timeout_ms=1200):
    """Round-trip time in ms, or None when there is no answer."""
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return None
    lib = _icmp()
    addr = struct.unpack("<L", socket.inet_aton(ip))[0]
    payload = b"bifrost-noevalky"
    size = ctypes.sizeof(_EchoReply) + len(payload) + 64
    buf = ctypes.create_string_buffer(size)
    handle = lib.IcmpCreateFile()
    try:
        n = lib.IcmpSendEcho(handle, addr, payload, len(payload), None, buf, size, timeout_ms)
        if not n:
            return None
        reply = _EchoReply.from_buffer_copy(buf)
        return int(reply.RoundTripTime) if reply.Status == 0 else None
    finally:
        lib.IcmpCloseHandle(handle)


# ---------------------------------------------------------------- Overwatch's process

def overwatch_process():
    """pid, path, local UDP ports and remote TCP endpoints of the running game, or None."""
    import psutil
    proc = None
    for p in psutil.process_iter(["name", "pid"]):
        if (p.info.get("name") or "").lower() == "overwatch.exe":
            proc = p
            break
    if proc is None:
        return None
    try:
        exe = proc.exe()
    except Exception:
        exe = None
    udp, tcp = set(), []
    try:
        conns = proc.net_connections(kind="inet4") if hasattr(proc, "net_connections") else proc.connections(kind="inet4")
    except Exception:
        conns = []
    for c in conns:
        if c.type == socket.SOCK_DGRAM and c.laddr:
            udp.add(c.laddr.port)
        elif c.type == socket.SOCK_STREAM and c.raddr:
            tcp.append({"ip": c.raddr.ip, "port": c.raddr.port, "status": c.status})
    return {"pid": proc.info["pid"], "exe": exe, "udp_ports": sorted(udp), "tcp": tcp}


def find_overwatch_exe():
    """Where Overwatch.exe is installed, even when the game is closed."""
    running = overwatch_process()
    if running and running.get("exe"):
        return running["exe"]
    candidates = []
    try:
        import winreg
        for root, key in ((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Overwatch"),
                          (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Overwatch"),
                          (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 2357570")):
            try:
                with winreg.OpenKey(root, key) as k:
                    loc = winreg.QueryValueEx(k, "InstallLocation")[0]
                    candidates += [os.path.join(loc, "_retail_", "Overwatch.exe"), os.path.join(loc, "Overwatch.exe")]
            except OSError:
                pass
    except ImportError:
        pass
    for drive in "CDEFGH":
        candidates += [rf"{drive}:\Program Files (x86)\Overwatch\_retail_\Overwatch.exe",
                       rf"{drive}:\Program Files\Overwatch\_retail_\Overwatch.exe",
                       rf"{drive}:\Overwatch\_retail_\Overwatch.exe",
                       rf"{drive}:\Program Files (x86)\Steam\steamapps\common\Overwatch\Overwatch.exe",
                       rf"{drive}:\SteamLibrary\steamapps\common\Overwatch\Overwatch.exe"]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def find_edge():
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")):
        if base:
            p = os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")
            if os.path.isfile(p):
                return p
    return None
