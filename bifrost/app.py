"""Bifröst — sélecteur de serveurs Overwatch, univers NOEVALKY.

Fork de MINA, le sélecteur de serveurs Overwatch de foryVERX : https://github.com/foryVERX/Overwatch-Server-Selector

Runs a small web server on 127.0.0.1 (reachable only from this PC) and opens the interface in an
Edge app window. The server needs administrator rights because it edits Windows Firewall rules.

    Bifrost.exe                 normal use
    Bifrost.exe --no-window     server only (open http://127.0.0.1:47815 yourself)
    Bifrost.exe --selftest R    checks firewall, logging, ping and API on this PC, writes report R
"""
import argparse
import concurrent.futures
import datetime
import http.server
import json
import mimetypes
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import webbrowser
from collections import deque

import core
import detect
import latency
import noetty

VERSION = "0.1.10"
PORT = 47815
ON_WINDOWS = os.name == "nt"
if ON_WINDOWS:
    import winfw

for _ext, _type in ((".js", "application/javascript"), (".json", "application/json"), (".webm", "video/webm"),
                    (".webp", "image/webp"), (".svg", "image/svg+xml"), (".html", "text/html")):
    mimetypes.add_type(_type, _ext)  # the Windows registry sometimes says text/plain

LANGS = ("fr", "en", "de", "es", "it", "ja", "ko", "sv", "zh")
# Windows primary language ids (LANGID & 0x3ff) of the languages Bifröst speaks.
WINDOWS_LANG = {0x0C: "fr", 0x09: "en", 0x07: "de", 0x0A: "es", 0x10: "it", 0x11: "ja", 0x12: "ko", 0x1D: "sv", 0x04: "zh"}
THEMES = ("nuit", "doux", "pixel")
NOE_EXT = (".png", ".webp", ".gif", ".jpg", ".jpeg")


def resource(*parts):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def data_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "Bifrost")
    os.makedirs(path, exist_ok=True)
    return path


def system_lang():
    """Windows display language as one of LANGS ('en' for any other language, None off Windows)."""
    if not ON_WINDOWS:
        return None
    try:
        import ctypes
        return WINDOWS_LANG.get(ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF, "en")
    except Exception:
        return None


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


class Store:
    def __init__(self, folder):
        self.folder = folder

    def load(self, name, default):
        try:
            with open(os.path.join(self.folder, name), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return default

    def save(self, name, value):
        tmp = os.path.join(self.folder, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False, indent=1)
        os.replace(tmp, os.path.join(self.folder, name))


DEFAULT_SETTINGS = dict(theme="nuit", lang=None, regions=None, blocked=[], strict=True, overwatch_only=True,
                        overwatch_path=None, mask_ip=True, detection=True)


def upgrade_settings(settings, db):
    """Settings saved by 0.1.x used Route/Normal modes; turn them into the region selection."""
    if "mode" in settings:
        mode, region = settings.pop("mode"), settings.pop("region", None)
        if settings.get("regions") is None:
            settings["regions"] = [region] if mode == "route" and region in db.regions else None
    if settings.get("regions") is None:
        settings["regions"] = list(db.region_order)
    settings["regions"] = [r for r in settings["regions"] if r in db.regions] or list(db.region_order)
    return settings


class App:
    def __init__(self, folder):
        self.folder = folder
        self.store = Store(folder)
        self.lock = threading.RLock()
        self.settings = {**DEFAULT_SETTINGS, **self.store.load("settings.json", {})}
        self.learned = self.store.load("learned.json", {})
        self.db = core.ServerDB.load(resource("data", "servers.json"), self.learned)
        self.settings = upgrade_settings(self.settings, self.db)
        old_applied = self.store.load("applied.json", None)
        if old_applied and "mode" in old_applied:  # saved by 0.1.x: describe it in today's terms
            self.store.save("applied.json", dict(unknown=True, rules=old_applied.get("rules", 0), at=old_applied.get("at")))
        self.applied = self.store.load("applied.json", None)
        self.pings = {}
        self.measuring = set()
        self.public_ip = None
        self.events = deque(maxlen=40)
        self.firewall_state = {}
        self.rule_count = None
        self.logging_saved = self.store.load("logging-original.json", None)
        self.logging_on = False
        self.logging_error = None
        self.last_heartbeat = time.time()
        self.stopping = threading.Event()
        self.system_lang = system_lang()
        self.fw = winfw.Firewall() if ON_WINDOWS else None
        self.detector = detect.Detector(lambda: self.db, winfw.overwatch_process if ON_WINDOWS else (lambda: None))
        self._cleanup_noe_folder(folder)
        noetty.cleanup(folder)

    # ------------------------------------------------------------ journal
    def event(self, key, params=None, level="info"):
        """A journal line: `key` names its text in the interface's translations (ui/i18n.js), `params` fill it in."""
        with self.lock:
            self.events.appendleft(dict(at=now_iso(), key=key, params=params or {}, level=level))

    # ------------------------------------------------------------ start / stop
    def start(self):
        threading.Thread(target=self._ping_loop, daemon=True).start()
        if ON_WINDOWS:
            threading.Thread(target=self._boot, daemon=True).start()
            threading.Thread(target=self._detect_loop, daemon=True).start()

    def _boot(self):
        try:
            self.firewall_state = self.fw.status()
            if not all(self.firewall_state.values()):
                self.event("ev_fw_off", None, "error")
        except Exception as e:
            self.event("ev_fw_read_error", dict(e=str(e)), "error")
        try:
            self.rule_count = len(self.fw.our_rules())
            if self.rule_count and not self.applied:
                self.applied = dict(unknown=True, rules=self.rule_count, at=now_iso())
        except Exception as e:
            self.event("ev_rules_list_error", dict(e=str(e)), "error")
        if not self.settings.get("overwatch_path"):
            self._find_overwatch()
        if self.settings.get("detection"):
            self.set_detection(True)

    def _find_overwatch(self):
        try:
            path = winfw.find_overwatch_exe()
        except Exception:
            path = None
        if path:
            with self.lock:
                self.settings["overwatch_path"] = path
                self.store.save("settings.json", self.settings)
            self.event("ev_ow_found", dict(path=path))
        return path

    def set_detection(self, on):
        with self.lock:
            self.settings["detection"] = bool(on)
            self.store.save("settings.json", self.settings)
        if not ON_WINDOWS:
            return
        try:
            if on and not self.logging_on:
                if not self.logging_saved:
                    self.logging_saved = winfw.logging_state()
                    self.store.save("logging-original.json", self.logging_saved)
                winfw.enable_logging()
                self.detector.set_log_files(winfw.log_files(self.logging_saved))
                self.logging_on, self.logging_error = True, None
                self.event("ev_detect_on")
            elif not on and self.logging_on:
                self._restore_logging()
                self.detector.set_log_files([])
                self.event("ev_detect_off")
        except Exception as e:
            self.logging_error = str(e)
            self.event("ev_detect_unavailable", dict(e=str(e)), "error")

    def _restore_logging(self):
        if self.logging_saved:
            winfw.restore_logging(self.logging_saved)
            try:
                os.remove(os.path.join(self.folder, "logging-original.json"))
            except OSError:
                pass
            self.logging_saved = None
        self.logging_on = False

    def shutdown(self):
        if self.stopping.is_set():
            return
        self.stopping.set()
        if ON_WINDOWS and self.logging_on:
            try:
                self._restore_logging()
            except Exception:
                pass

    def _detect_loop(self):
        while not self.stopping.is_set():
            try:
                self.detector.poll()
                proc = self.detector.process
                if proc and proc.get("exe") and proc["exe"] != self.settings.get("overwatch_path"):
                    with self.lock:
                        self.settings["overwatch_path"] = proc["exe"]
                        self.store.save("settings.json", self.settings)
            except Exception as e:
                self.detector.error = str(e)
            self.stopping.wait(1.5)

    def _probes(self, sid):
        """Ways to measure a server, best first: its real game addresses, then the probes of servers.json."""
        server = self.db.servers[sid]
        seen = [f["ip"] for f in self.detector.snapshot()["flows"] if f["server"] == sid]
        live = []
        for ip in seen[:2] + self.db.learned_for(sid)[-2:]:
            if ip not in [p["host"] for p in live]:
                live.append(dict(type="icmp", host=ip, exact=True))
        return live + list(server.get("probes", []))

    def _measure(self, probe):
        kind = probe["type"]
        if kind == "icmp":
            if not ON_WINDOWS:
                return None, None
            results = [r for r in (winfw.ping(probe["host"]), winfw.ping(probe["host"])) if r is not None]
            return (min(results) if results else None), probe["host"]
        if kind == "tcp":
            return latency.tcp_rtt(probe["host"], probe.get("port", 443)), probe["host"]
        if kind == "gcp":
            url = self.db.gcp.get(probe["region"])
            return (latency.gcp_rtt(url) if url else None), f"Google {probe['region']}"
        return None, None

    def _ping_one(self, sid):
        with self.lock:
            self.measuring.add(sid)
        try:
            for probe in self._probes(sid):
                ms, target = self._measure(probe)
                if ms is not None:
                    return sid, dict(ms=ms, target=target, method=probe["type"], exact=bool(probe.get("exact")),
                                     estimate=probe["type"] != "icmp", at=now_iso())
            return sid, None
        finally:
            with self.lock:
                self.measuring.discard(sid)

    def _ping_loop(self):
        while not self.stopping.is_set():
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                    for sid, result in pool.map(self._ping_one, list(self.db.servers)):
                        if result:
                            self.pings[sid] = result
                        elif sid in self.pings and not self.pings[sid].get("stale"):
                            self.pings[sid] = dict(self.pings[sid], stale=True)
            except Exception as e:
                self.event("ev_ping_error", dict(e=str(e)), "error")
            self.stopping.wait(60)

    # ------------------------------------------------------------ actions
    def apply(self, body):
        regions = [r for r in body.get("regions", self.settings["regions"]) if r in self.db.regions]
        blocked = [b for b in body.get("blocked", self.settings["blocked"]) if b in self.db.servers]
        strict = bool(body.get("strict", self.settings["strict"]))
        overwatch_only = bool(body.get("overwatch_only", self.settings["overwatch_only"]))
        path = self.settings.get("overwatch_path") or (self._find_overwatch() if ON_WINDOWS else None)
        specs = core.plan(self.db, regions=regions, blocked=blocked, strict=strict, overwatch_path=path,
                          overwatch_only=overwatch_only)
        with self.lock:
            self.settings.update(regions=regions, blocked=blocked, strict=strict, overwatch_only=overwatch_only)
            self.store.save("settings.json", self.settings)
        if not ON_WINDOWS:
            raise core.UserError("err_windows_only", "Bifröst ne peut modifier le pare-feu que sous Windows.")
        if not specs:
            self.fw.remove_all()
            count = 0
        else:
            count = self.fw.apply(specs)
        all_regions = len(regions) == len(self.db.region_order)
        self.rule_count = count
        self.applied = dict(regions=regions, blocked=blocked, strict=strict, rules=count,
                            overwatch_only=overwatch_only or (strict and not all_regions), at=now_iso())
        self.store.save("applied.json", self.applied)
        if not count:
            key = "ev_applied_free"
        elif all_regions:
            key = "ev_applied_avoided"
        else:
            key = "ev_applied_regions_without" if blocked else "ev_applied_regions"
        self.event(key, dict(regions=regions, servers=blocked), "ok")
        return self.applied

    def unblock(self):
        if ON_WINDOWS:
            self.fw.remove_all()
        self.rule_count = 0
        self.applied = None
        with self.lock:
            self.settings.update(regions=list(self.db.region_order), blocked=[])
            self.store.save("settings.json", self.settings)
        try:
            os.remove(os.path.join(self.folder, "applied.json"))
        except OSError:
            pass
        self.event("ev_unblocked", None, "ok")

    def learn(self, body):
        ip = body.get("ip", "")
        core.ip_to_int(ip)  # validates
        entry = dict(at=now_iso())
        if body.get("server") in self.db.servers:
            entry["server"] = body["server"]
        elif body.get("region") in self.db.regions:
            entry["region"] = body["region"]
        else:
            raise core.UserError("err_choose", "Choisis un serveur ou une région.")
        with self.lock:
            self.learned[ip] = entry
            self.store.save("learned.json", self.learned)
            self.db.set_learned(self.learned)
        self.event("ev_learned", dict(ip=ip, server=entry.get("server"), region=entry.get("region")), "ok")

    def forget(self, body):
        with self.lock:
            self.learned.pop(body.get("ip", ""), None)
            self.store.save("learned.json", self.learned)
            self.db.set_learned(self.learned)

    def update_settings(self, body):
        with self.lock:
            for key in ("theme", "mask_ip"):
                if key in body:
                    self.settings[key] = body[key]
            if "lang" in body:
                self.settings["lang"] = body["lang"] if body["lang"] in LANGS else None
            if body.get("overwatch_path"):
                path = body["overwatch_path"].strip().strip('"')
                if not path.lower().endswith("overwatch.exe") or not os.path.isfile(path):
                    raise core.UserError("err_bad_ow_path", "Ce chemin ne mène pas à Overwatch.exe.")
                self.settings["overwatch_path"] = path
            self.store.save("settings.json", self.settings)
        if "detection" in body:
            self.set_detection(body["detection"])

    def fetch_public_ip(self):
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=6) as r:
            self.public_ip = json.load(r).get("ip")
        return self.public_ip

    # ------------------------------------------------------------ NOE
    @staticmethod
    def _cleanup_noe_folder(base):
        """0.1.6 to 0.1.8 kept a noe folder in %LOCALAPPDATA%\\Bifrost; NOE is now built in. Remove what
        Bifröst put there (read-me, empty lines template), then the folder if nothing else is left."""
        folder = os.path.join(base, "noe")
        if not os.path.isdir(folder):
            return
        try:
            os.remove(os.path.join(folder, "LISEZ-MOI.txt"))
        except OSError:
            pass
        old_lines = os.path.join(folder, "repliques.json")
        try:
            with open(old_lines, encoding="utf-8") as f:
                empty = not any(json.load(f).values())
            if empty:
                os.remove(old_lines)
        except (OSError, ValueError, AttributeError):
            pass
        try:
            os.rmdir(folder)  # only succeeds when empty
        except OSError:
            pass

    @staticmethod
    def noe():
        """NOE's background for each theme, built into Bifröst: data/noe/fond-<theme>.*, else data/noe/fond.*."""
        try:
            names = sorted(os.listdir(resource("data", "noe")))
        except OSError:
            names = []
        found = {}
        for name in names:
            stem, ext = os.path.splitext(name)
            if ext.lower() in NOE_EXT and stem.lower().startswith("fond") and stem.lower() not in found:
                found[stem.lower()] = "/media/noe/" + urllib.parse.quote(name)
        return dict(backgrounds={t: found.get(f"fond-{t}") or found.get("fond") for t in THEMES
                                 if found.get(f"fond-{t}") or found.get("fond")})

    # ------------------------------------------------------------ state for the interface
    def static_db(self):
        return dict(version=self.db.version, home=self.db.home,
                    regions=[dict(id=r, name=self.db.regions[r]["name"], group=self.db.regions[r]["group"]) for r in self.db.region_order],
                    servers=[{k: self.db.servers[s][k] for k in ("id", "city", "country", "region", "lonlat", "provider")}
                             for s in self.db.server_order])

    def lang(self, asked=None):
        """The interface's language: the one it asks for, else the one chosen in Bifröst, else Windows'."""
        for lang in (asked, self.settings.get("lang"), self.system_lang):
            if lang in LANGS:
                return lang
        return "en"

    def state(self, lang=None):
        self.last_heartbeat = time.time()
        snap = self.detector.snapshot()
        lang = self.lang(lang)
        return dict(version=VERSION, lang=lang, system_lang=self.system_lang, settings=self.settings, applied=self.applied, rule_count=self.rule_count,
                    pings=self.pings, measuring=sorted(self.measuring), detection=snap, noe=self.noe(),
                    noetty=noetty.load(resource("data", "noetty"), lang),
                    learned=self.learned, firewall=self.firewall_state, logging_on=self.logging_on,
                    logging_error=self.logging_error, public_ip=self.public_ip, events=list(self.events),
                    windows=ON_WINDOWS)


# ---------------------------------------------------------------- web server

class Handler(http.server.BaseHTTPRequestHandler):
    app = None
    token = None
    port = PORT
    server_version = "Bifrost"

    def log_message(self, *args):
        pass

    def _host_ok(self):
        host = (self.headers.get("Host") or "").lower()
        return host in (f"127.0.0.1:{self.port}", f"localhost:{self.port}")

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _file(self, path, inject=None):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return self._send(404, {"error": "introuvable"})
        if inject:
            for k, v in inject.items():
                data = data.replace(k.encode(), v.encode())
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        self._send(200, data, ctype)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "hôte refusé"})
        url = urllib.parse.urlparse(self.path)
        p = url.path
        if p in ("/", "/index.html"):
            return self._file(resource("ui", "index.html"), {"__BIFROST_TOKEN__": self.token})
        if p.startswith("/ui/"):
            rel = os.path.normpath(urllib.parse.unquote(p[4:])).lstrip("\\/")
            if rel.startswith(".."):
                return self._send(403, {"error": "chemin refusé"})
            return self._file(resource("ui", rel))
        if p.startswith("/media/"):  # pictures built into Bifröst: /media/noetty/<file>, /media/noe/<file>
            kind, _, name = urllib.parse.unquote(p[7:]).partition("/")
            if kind in ("noetty", "noe"):
                sub = ("noetty", "img") if kind == "noetty" else ("noe",)
                return self._file(resource("data", *sub, os.path.basename(name)))
            return self._send(404, {"error": "introuvable"})
        if p.startswith("/api/"):
            return self._api("GET", p, dict(urllib.parse.parse_qsl(url.query)))
        self._send(404, {"error": "introuvable"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, {"error": "hôte refusé"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
        except ValueError:
            return self._send(400, {"error": "JSON invalide"})
        self._api("POST", urllib.parse.urlparse(self.path).path, body)

    def _api(self, method, path, body):
        if self.headers.get("X-Bifrost-Token") != self.token:
            return self._send(403, {"error": "jeton manquant"})
        app = self.app
        routes = {
            ("GET", "/api/state"): lambda: app.state(body.get("lang")),
            ("GET", "/api/db"): app.static_db,
            ("POST", "/api/apply"): lambda: app.apply(body),
            ("POST", "/api/unblock"): app.unblock,
            ("POST", "/api/learn"): lambda: app.learn(body),
            ("POST", "/api/forget"): lambda: app.forget(body),
            ("POST", "/api/settings"): lambda: app.update_settings(body),
            ("POST", "/api/publicip"): app.fetch_public_ip,
            ("POST", "/api/find-overwatch"): lambda: app._find_overwatch() if ON_WINDOWS else None,
            ("POST", "/api/quit"): lambda: threading.Timer(0.3, app.shutdown).start(),
        }
        fn = routes.get((method, path))
        if not fn:
            return self._send(404, {"error": "route inconnue"})
        try:
            self._send(200, {"ok": True, "result": fn()})
        except core.UserError as e:
            app.event(e.key, e.params, "error")
            self._send(400, {"ok": False, "error": str(e), "error_key": e.key, "params": e.params})
        except (ValueError, RuntimeError) as e:
            app.event("ev_error", dict(e=str(e)), "error")
            self._send(400, {"ok": False, "error": str(e)})
        except Exception as e:
            app.event("ev_error", dict(e=str(e)), "error")
            self._send(500, {"ok": False, "error": str(e), "trace": traceback.format_exc()[-1500:]})


def make_server(app, port):
    token = secrets.token_urlsafe(24)
    handler = type("BoundHandler", (Handler,), dict(app=app, token=token, port=port))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    return server, token


def open_window(url, folder):
    """Edge in app mode (a plain window, no tabs); falls back to the default browser."""
    edge = winfw.find_edge() if ON_WINDOWS else None
    if edge:
        profile = os.path.join(folder, "fenetre")
        args = [edge, f"--app={url}", f"--user-data-dir={profile}", "--window-size=1340,880", "--no-first-run",
                "--no-default-browser-check", "--disable-background-timer-throttling",
                "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows"]
        try:
            return subprocess.Popen(args)
        except OSError:
            pass
    webbrowser.open(url)
    return None


def run(no_window=False):
    folder = data_dir()
    try:
        probe = socket.create_connection(("127.0.0.1", PORT), timeout=0.5)
        probe.close()
        open_window(f"http://127.0.0.1:{PORT}/", folder)  # already running: just show it
        return 0
    except OSError:
        pass
    app = App(folder)
    server, _ = make_server(app, PORT)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    app.start()
    url = f"http://127.0.0.1:{PORT}/"
    window = None if no_window else open_window(url, folder)
    started = time.time()
    boot_heartbeat = app.last_heartbeat
    fallback = False
    try:
        while not app.stopping.is_set():
            time.sleep(1)
            if no_window:
                continue
            now = time.time()
            seen = app.last_heartbeat > boot_heartbeat
            idle = now - max(app.last_heartbeat, started)
            if window is not None and window.poll() is not None:  # the Edge window process ended
                if not seen and not fallback and now - started < 30:
                    webbrowser.open(url)  # Edge refused to open: use the default browser instead
                    fallback, window = True, None
                    continue
                if idle > 15:
                    break
            elif window is not None:  # Edge still running (it may linger in the background)
                if seen and idle > 90:
                    break
            elif idle > 600:  # default browser: quit 10 minutes after the page stops calling
                break
    except KeyboardInterrupt:
        pass
    app.shutdown()
    server.shutdown()
    return 0


# ---------------------------------------------------------------- self-test (run by GitHub on a Windows machine)

def selftest(report_path):
    results = []

    def step(name, fn, critical=True):
        t0 = time.time()
        try:
            value = fn()
            results.append(dict(step=name, ok=True, critical=critical, seconds=round(time.time() - t0, 2), detail=value))
        except Exception as e:
            results.append(dict(step=name, ok=False, critical=critical, seconds=round(time.time() - t0, 2),
                                error=f"{type(e).__name__}: {e}", trace=traceback.format_exc()[-1200:]))

    db = core.ServerDB.load(resource("data", "servers.json"))
    notepad = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
    step("plan Europe seule sans AMS1", lambda: len(core.plan(db, regions=["EU"], blocked=["AMS1"], overwatch_path=notepad)))
    step("plan crânes seuls", lambda: len(core.plan(db, blocked=["AMS1", "MES1"], overwatch_path=None, overwatch_only=False)))

    fw = winfw.Firewall(group="Bifrost selftest")
    step("état du pare-feu", fw.status)
    step("appliquer Europe seule (notepad)", lambda: fw.apply(core.plan(db, regions=["EU"], blocked=["AMS1"], overwatch_path=notepad)))
    step("règles visibles", lambda: sorted(fw.our_rules()))
    step("appliquer crânes (tout le PC)", lambda: fw.apply(core.plan(db, blocked=["AMS1", "MES1"], overwatch_only=False)))
    step("tout débloquer", lambda: (fw.remove_all(), fw.our_rules())[1])

    step("ping 1.1.1.1", lambda: winfw.ping("1.1.1.1"), critical=False)
    step("latence de chaque serveur", _latency_all, critical=False)
    step("psutil : ports UDP de ce processus", lambda: _own_udp_ports())
    step("Overwatch installé ?", winfw.find_overwatch_exe, critical=False)
    step("Edge", winfw.find_edge, critical=False)

    saved = []
    step("journal : état initial", lambda: saved.extend(winfw.logging_state()) or saved)
    step("journal : activer", winfw.enable_logging)
    step("journal : voit notre trafic UDP", lambda: _log_roundtrip(saved), critical=False)
    step("journal : restaurer", lambda: (winfw.restore_logging(saved), winfw.logging_state())[1])

    step("API web locale", _api_roundtrip)

    ok = all(r["ok"] for r in results if r["critical"])
    report = dict(version=VERSION, ok=ok, at=now_iso(), results=results)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1, default=str)
    print(json.dumps(report, ensure_ascii=False, indent=1, default=str))
    return 0 if ok else 1


def _latency_all():
    folder = os.path.join(data_dir(), "selftest")
    os.makedirs(folder, exist_ok=True)
    app = App(folder)
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for sid, result in pool.map(app._ping_one, list(app.db.servers)):
            out[sid] = f"{result['ms']} ms via {result['method']} {result['target']}" if result else None
    missing = [sid for sid, v in out.items() if v is None]
    if len(missing) > len(out) // 2:
        raise RuntimeError(f"pas de mesure pour {missing} : {out}")
    return out


def _own_udp_ports():
    import psutil
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    p = psutil.Process(os.getpid())
    conns = p.net_connections(kind="udp4") if hasattr(p, "net_connections") else p.connections(kind="udp4")
    found = port in [c.laddr.port for c in conns]
    s.close()
    if not found:
        raise RuntimeError("psutil ne voit pas notre socket UDP")
    return port


def _log_roundtrip(saved):
    paths = winfw.log_files(saved)
    tails = [detect.LogTail(p) for p in paths]
    for t in tails:
        t.read_new()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    det = detect.Detector(lambda: core.ServerDB.load(resource("data", "servers.json")),
                          lambda: dict(pid=os.getpid(), exe=None, udp_ports=[port], tcp=[]))
    det.tails = tails
    deadline = time.time() + 40
    seen = []
    while time.time() < deadline:
        for target in (("192.0.2.10", 9), ("198.51.100.20", 9), ("1.1.1.1", 53)):
            try:
                s.sendto(b"bifrost-selftest", target)
            except OSError:
                pass
        time.sleep(2)
        det.poll()
        seen = det.snapshot()["flows"]
        if seen:
            break
    s.close()
    if not seen:
        raise RuntimeError(f"aucune ligne de notre processus dans {paths} (lignes lues : {det.lines_read})")
    return dict(paths=paths, lines_read=det.lines_read, flows=seen[:5])


def _api_roundtrip():
    folder = os.path.join(data_dir(), "selftest")
    os.makedirs(folder, exist_ok=True)
    app = App(folder)
    port = 47899
    server, token = make_server(app, port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/state", headers={"X-Bifrost-Token": token})
        with urllib.request.urlopen(req, timeout=10) as r:
            state = json.load(r)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as r:
            page = r.read()
        if token.encode() not in page:
            raise RuntimeError("la page n'a pas reçu son jeton")
        return dict(keys=sorted(state["result"].keys()), page_bytes=len(page))
    finally:
        server.shutdown()
        app.shutdown()


def main():
    parser = argparse.ArgumentParser(description="Bifröst — sélecteur de serveurs Overwatch")
    parser.add_argument("--selftest", metavar="RAPPORT")
    parser.add_argument("--no-window", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest(args.selftest)
    return run(no_window=args.no_window)


if __name__ == "__main__":
    sys.exit(main())
