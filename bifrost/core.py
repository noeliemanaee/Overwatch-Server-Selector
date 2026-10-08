"""Pure logic of Bifröst: IP ranges, the server database, and turning a choice into firewall rules.

Nothing here touches Windows, so it can be tested anywhere.
"""
import ipaddress
import json

MAX_ADDR = 2 ** 32 - 1
ENTRIES_PER_RULE = 9000  # Windows accepts about 10,000 addresses per rule; keep a margin.
PROTO_ICMP = 1
PROTO_UDP = 17

# Never blocked, whatever the mode: home network, loopback, link-local, multicast, broadcast.
PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
           "224.0.0.0/4", "255.255.255.255/32", "100.64.0.0/10", "0.0.0.0/8"]


class UserError(ValueError):
    """A message for the user: `key` is looked up in the interface's translations, `params` fill it in.
    str(e) stays French, for logs and older interfaces."""

    def __init__(self, key, text, **params):
        super().__init__(text)
        self.key = key
        self.params = params


def ip_to_int(ip):
    return int(ipaddress.IPv4Address(ip))


def int_to_ip(n):
    return str(ipaddress.IPv4Address(n))


def parse_entry(entry):
    """'a.b.c.d', 'a.b.c.d/n' or 'a.b.c.d-e.f.g.h' -> (start, end) as integers."""
    entry = entry.strip()
    if "-" in entry:
        a, b = entry.split("-", 1)
        start, end = ip_to_int(a.strip()), ip_to_int(b.strip())
        return (min(start, end), max(start, end))
    net = ipaddress.IPv4Network(entry, strict=False)
    return (int(net.network_address), int(net.broadcast_address))


def merge(intervals):
    out = []
    for start, end in sorted(intervals):
        if out and start <= out[-1][1] + 1:
            if end > out[-1][1]:
                out[-1] = (out[-1][0], end)
        else:
            out.append((start, end))
    return out


def subtract(intervals, holes):
    """Parts of `intervals` not covered by `holes`."""
    holes = merge(holes)
    out = []
    for start, end in merge(intervals):
        cur = start
        for hs, he in holes:
            if he < cur or hs > end:
                continue
            if hs > cur:
                out.append((cur, hs - 1))
            cur = max(cur, he + 1)
            if cur > end:
                break
        if cur <= end:
            out.append((cur, end))
    return out


def complement(intervals):
    return subtract([(0, MAX_ADDR)], intervals)


def contains(intervals, ip_int):
    return any(s <= ip_int <= e for s, e in intervals)


def to_firewall(intervals):
    """Windows Firewall address strings: single addresses or 'start-end' ranges."""
    return [int_to_ip(s) if s == e else f"{int_to_ip(s)}-{int_to_ip(e)}" for s, e in intervals]


def slash24(ip):
    return str(ipaddress.IPv4Network(ip + "/24", strict=False))


def is_private(ip):
    try:
        n = ip_to_int(ip)
    except ValueError:
        return True
    return contains([parse_entry(p) for p in PRIVATE], n)


class ServerDB:
    """The server list shipped with the app, plus the addresses learned on this PC."""

    def __init__(self, data, learned=None):
        self.version = data.get("version", "")
        self.home = data.get("home", {"name": "Paris", "lonlat": [2.35, 48.86]})
        self.regions = {r["id"]: r for r in data["regions"]}
        self.region_order = [r["id"] for r in data["regions"]]
        self.servers = {s["id"]: s for s in data["servers"]}
        self.server_order = [s["id"] for s in data["servers"]]
        self.gcp = data.get("gcp_endpoints", {})
        self.learned = dict(learned or {})  # ip -> {"server": id, "at": iso}
        self._cache = {}

    @classmethod
    def load(cls, path, learned=None):
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f), learned)

    def set_learned(self, learned):
        self.learned = dict(learned)
        self._cache = {}

    def learned_for(self, server_id):
        return [ip for ip, info in self.learned.items() if info.get("server") == server_id]

    def server_intervals(self, server_id):
        key = ("s", server_id)
        if key not in self._cache:
            entries = list(self.servers[server_id]["ranges"]) + [slash24(ip) for ip in self.learned_for(server_id)]
            self._cache[key] = merge(parse_entry(e) for e in entries)
        return self._cache[key]

    def region_intervals(self, region_id):
        """A region's footprint, plus learned addresses of its servers or allowed for it directly
        (learned entries may carry only a "region", e.g. a relay or voice address)."""
        key = ("r", region_id)
        if key not in self._cache:
            entries = list(self.regions[region_id]["ranges"])
            for ip, info in self.learned.items():
                sid = info.get("server")
                rid = self.servers[sid]["region"] if sid in self.servers else info.get("region")
                if rid == region_id:
                    entries.append(slash24(ip))
            self._cache[key] = merge(parse_entry(e) for e in entries)
        return self._cache[key]

    def server_for_ip(self, ip):
        """Best guess of which server an address belongs to: learned first, then the most specific list."""
        if ip in self.learned and self.learned[ip].get("server"):
            return self.learned[ip]["server"]
        n = ip_to_int(ip)
        best, best_size = None, None
        for sid in self.server_order:
            for s, e in self.server_intervals(sid):
                if s <= n <= e and (best_size is None or e - s < best_size):
                    best, best_size = sid, e - s
        return best

    def region_for_ip(self, ip):
        info = self.learned.get(ip) or {}
        if info.get("server") in self.servers:
            return self.servers[info["server"]]["region"]
        if info.get("region") in self.regions:
            return info["region"]
        n = ip_to_int(ip)
        for rid in self.region_order:
            if contains(self.region_intervals(rid), n):
                return rid
        return None


def plan(db, regions=None, blocked=(), strict=True, overwatch_path=None, overwatch_only=True):
    """Turn the user's choice into rule specs.

    regions: the regions whose players you want to play with (None or all of them = no region cut).
    blocked: servers to avoid even inside those regions (a skull on the globe).
    strict:  when some regions are left out, cut *every* address outside the chosen regions for Overwatch,
             including addresses no list knows yet (needs Overwatch's path). Without it, only the known
             addresses of the left-out regions are cut.
    Only UDP and ICMP are blocked: TCP stays open, so Battle.net login and the game lobby always work.
    """
    all_regions = list(db.region_order)
    regions = [r for r in (regions if regions is not None else all_regions) if r in db.regions]
    if not regions:
        strict = True  # every region off: cut all of Overwatch's game traffic
    blocked = [b for b in blocked if b in db.servers]
    cut_servers = merge(i for sid in blocked for i in db.server_intervals(sid))
    private = [parse_entry(p) for p in PRIVATE]
    left_out = [r for r in all_regions if r not in regions]

    if not left_out:
        target = subtract(cut_servers, private)
        app = overwatch_path if (overwatch_only and overwatch_path) else None
        label = "Sans " + " ".join(blocked) if blocked else "Libre"
    elif strict:
        if not overwatch_path:
            raise UserError("err_need_ow_path", "Pour couper les autres régions, Bifröst doit savoir où est Overwatch.exe : "
                            "lance le jeu une fois.")
        allowed = subtract(merge(i for r in regions for i in db.region_intervals(r)), cut_servers)
        target = complement(merge(allowed + private))
        app = overwatch_path
        label = "Avec " + " ".join(regions) if regions else "Tout coupe"
    else:
        allowed = merge(i for r in regions for i in db.region_intervals(r))
        excluded = merge(i for r in left_out for i in db.region_intervals(r))
        target = subtract(merge(subtract(excluded, allowed) + cut_servers), private)
        app = overwatch_path if (overwatch_only and overwatch_path) else None
        label = "Sans " + " ".join(left_out + blocked)

    if not target:
        return []
    addresses = to_firewall(target)
    rules = []
    for i in range(0, len(addresses), ENTRIES_PER_RULE):
        chunk = addresses[i:i + ENTRIES_PER_RULE]
        part = f" ({i // ENTRIES_PER_RULE + 1})" if len(addresses) > ENTRIES_PER_RULE else ""
        for proto, pname in ((PROTO_UDP, "UDP"), (PROTO_ICMP, "ICMP")):
            for direction, dname in ((2, "sortant"), (1, "entrant")):
                rules.append(dict(name=f"Bifrost - {label} - {pname} {dname}{part}", protocol=proto,
                                  direction=direction, addresses=chunk, app=app))
    return rules


def parse_firewall_log_line(line, fields):
    """One pfirewall.log line -> dict keyed by the '#Fields:' header (None for comments/blank lines)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    if len(parts) < 8:
        return None
    rec = {f: (parts[i] if i < len(parts) else "") for i, f in enumerate(fields)}
    return rec


DEFAULT_LOG_FIELDS = ["date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port", "size",
                      "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path", "pid"]
