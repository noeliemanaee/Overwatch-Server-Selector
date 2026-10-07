"""Bifröst — sélecteur de serveurs Overwatch 2, univers NOEVALKY.

Fork de « MINA Overwatch 2 Server Selector » par foryVERX : https://github.com/foryVERX/Overwatch-Server-Selector

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
import unicodedata
import urllib.parse
import urllib.request
import webbrowser
from collections import deque

import core
import detect

VERSION = "0.1.0"
PORT = 47815
ON_WINDOWS = os.name == "nt"
if ON_WINDOWS:
    import winfw

for _ext, _type in ((".js", "application/javascript"), (".json", "application/json"), (".webm", "video/webm"),
                    (".webp", "image/webp"), (".svg", "image/svg+xml"), (".html", "text/html")):
    mimetypes.add_type(_type, _ext)  # the Windows registry sometimes says text/plain

MOODS = ["neutre", "souriante", "rieuse", "excitee", "surprise", "boudeuse", "triste", "genee"]
NOE_EXT = (".png", ".webp", ".gif", ".jpg", ".jpeg", ".webm")


def resource(*parts):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def data_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "Bifrost")
    os.makedirs(path, exist_ok=True)
    return path


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def plain(s):
    """'Excitée' -> 'excitee' (file names of NOE's moods)."""
    return "".join(c for c in unicodedata.normalize("NFD", s.lower()) if unicodedata.category(c) != "Mn")


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


DEFAULT_SETTINGS = dict(theme="nuit", mode="normal", region="EU", blocked=["AMS1"], overwatch_only=True,
                        overwatch_path=None, mask_ip=True, detection=True)


class App:
    def __init__(self, folder):
        self.folder = folder
        self.store = Store(folder)
        self.lock = threading.RLock()
        self.settings = {**DEFAULT_SETTINGS, **self.store.load("settings.json", {})}
        self.learned = self.store.load("learned.json", {})
        self.db = core.ServerDB.load(resource("data", "servers.json"), self.learned)
        self.applied = self.store.load("applied.json", None)
        self.pings = {}
        self.public_ip = None
        self.events = deque(maxlen=40)
        self.flash = None  # (mood, until)
        self.firewall_state = {}
        self.rule_count = None
        self.logging_saved = self.store.load("logging-original.json", None)
        self.logging_on = False
        self.logging_error = None
        self.last_heartbeat = time.time()
        self.stopping = threading.Event()
        self.fw = winfw.Firewall() if ON_WINDOWS else None
        self.detector = detect.Detector(lambda: self.db, winfw.overwatch_process if ON_WINDOWS else (lambda: None))
        self._prepare_noe_folder()

    # ------------------------------------------------------------ journal & mood
    def event(self, text, level="info", mood=None, seconds=6):
        with self.lock:
            self.events.appendleft(dict(at=now_iso(), text=text, level=level))
            if mood:
                self.flash = (mood, time.time() + seconds)

    def mood(self, snap):
        if self.flash and self.flash[1] > time.time():
            return self.flash[0]
        if snap.get("unknown"):
            return "surprise"
        if any(f["drop"] and f["ago"] < 120 for f in snap.get("flows", [])):
            return "boudeuse"
        if snap.get("running") and snap.get("current") and snap["current"]["ago"] < 1800:
            return "souriante"
        return "neutre"

    # ------------------------------------------------------------ start / stop
    def start(self):
        if ON_WINDOWS:
            threading.Thread(target=self._boot, daemon=True).start()
            threading.Thread(target=self._detect_loop, daemon=True).start()
            threading.Thread(target=self._ping_loop, daemon=True).start()

    def _boot(self):
        try:
            self.firewall_state = self.fw.status()
            if not all(self.firewall_state.values()):
                self.event("Le pare-feu Windows est désactivé sur ce réseau : aucun blocage ne peut marcher.", "error", "triste", 20)
        except Exception as e:
            self.event(f"Impossible de lire l'état du pare-feu : {e}", "error", "triste")
        try:
            self.rule_count = len(self.fw.our_rules())
            if self.rule_count and not self.applied:
                self.applied = dict(unknown=True, rules=self.rule_count, at=now_iso())
        except Exception as e:
            self.event(f"Impossible de lister les règles : {e}", "error")
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
            self.event(f"Overwatch trouvé : {path}")
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
                self.event("Détection en direct activée (journal du pare-feu).")
            elif not on and self.logging_on:
                self._restore_logging()
                self.detector.set_log_files([])
                self.event("Détection en direct désactivée.")
        except Exception as e:
            self.logging_error = str(e)
            self.event(f"Détection indisponible : {e}", "error", "triste")

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

    def _ping_targets(self, sid):
        server = self.db.servers[sid]
        seen = [f["ip"] for f in self.detector.snapshot()["flows"] if f["server"] == sid]
        return seen[:2] + self.db.learned_for(sid)[-2:] + list(server.get("ping", []))

    def _ping_one(self, sid):
        for target in self._ping_targets(sid):
            ms = winfw.ping(target)
            if ms is not None:
                return sid, dict(ms=ms, target=target, at=now_iso())
        return sid, None

    def _ping_loop(self):
        while not self.stopping.is_set():
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    for sid, result in pool.map(self._ping_one, list(self.db.servers)):
                        if result:
                            self.pings[sid] = result
            except Exception as e:
                self.event(f"Mesure des pings impossible : {e}", "error")
            self.stopping.wait(45)

    # ------------------------------------------------------------ actions
    def apply(self, body):
        mode = body.get("mode", self.settings["mode"])
        region = body.get("region", self.settings["region"])
        blocked = [b for b in body.get("blocked", self.settings["blocked"]) if b in self.db.servers]
        overwatch_only = bool(body.get("overwatch_only", self.settings["overwatch_only"]))
        path = self.settings.get("overwatch_path") or (self._find_overwatch() if ON_WINDOWS else None)
        specs = core.plan(self.db, mode, region=region, blocked=blocked, overwatch_path=path,
                          overwatch_only=overwatch_only)
        with self.lock:
            self.settings.update(mode=mode, region=region, blocked=blocked, overwatch_only=overwatch_only)
            self.store.save("settings.json", self.settings)
        if not ON_WINDOWS:
            raise RuntimeError("Bifröst ne peut modifier le pare-feu que sous Windows.")
        if not specs:
            self.fw.remove_all()
            count = 0
        else:
            count = self.fw.apply(specs)
        self.rule_count = count
        self.applied = dict(mode=mode, region=region, blocked=blocked, overwatch_only=overwatch_only or mode == "route",
                            rules=count, addresses=len(specs[0]["addresses"]) if specs else 0, at=now_iso())
        self.store.save("applied.json", self.applied)
        if mode == "route":
            name = self.db.regions[region]["name"]
            extra = f", sans {', '.join(blocked)}" if blocked else ""
            text = f"Route {name}{extra} appliquée. Relance Overwatch si une partie était en cours."
        else:
            text = (f"Liste noire appliquée : {', '.join(blocked)}." if blocked else "Aucun serveur bloqué.")
        self.event(text, "ok", "excitee", 6)
        return self.applied

    def unblock(self):
        if ON_WINDOWS:
            self.fw.remove_all()
        self.rule_count = 0
        self.applied = None
        try:
            os.remove(os.path.join(self.folder, "applied.json"))
        except OSError:
            pass
        self.event("Tout est débloqué : Overwatch choisit à nouveau seul.", "ok", "rieuse", 5)

    def learn(self, body):
        ip = body.get("ip", "")
        core.ip_to_int(ip)  # validates
        entry = dict(at=now_iso())
        if body.get("server") in self.db.servers:
            entry["server"] = body["server"]
        elif body.get("region") in self.db.regions:
            entry["region"] = body["region"]
        else:
            raise ValueError("Choisis un serveur ou une région.")
        with self.lock:
            self.learned[ip] = entry
            self.store.save("learned.json", self.learned)
            self.db.set_learned(self.learned)
        label = entry.get("server") or self.db.regions[entry["region"]]["name"]
        self.event(f"Retenu : {ip} → {label}. Pense à réappliquer pour que le blocage en tienne compte.", "ok", "rieuse", 5)

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
            if body.get("overwatch_path"):
                path = body["overwatch_path"].strip().strip('"')
                if not path.lower().endswith("overwatch.exe") or not os.path.isfile(path):
                    raise ValueError("Ce chemin ne mène pas à Overwatch.exe.")
                self.settings["overwatch_path"] = path
            self.store.save("settings.json", self.settings)
        if "detection" in body:
            self.set_detection(body["detection"])

    def fetch_public_ip(self):
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=6) as r:
            self.public_ip = json.load(r).get("ip")
        return self.public_ip

    # ------------------------------------------------------------ NOE
    def noe_folder(self):
        return os.path.join(self.folder, "noe")

    def _prepare_noe_folder(self):
        folder = self.noe_folder()
        os.makedirs(folder, exist_ok=True)
        readme = os.path.join(folder, "LISEZ-MOI.txt")
        if not os.path.exists(readme):
            with open(readme, "w", encoding="utf-8") as f:
                f.write("Dépose ici les images de NOE, une par humeur, nommées :\n"
                        + "\n".join(f"  {m}.png  (ou .webp, .gif, .webm)" for m in MOODS)
                        + "\n\nBifröst choisit l'humeur selon ce qui se passe (connectée, bloquée, inconnue...).\n"
                          "Les répliques de la bulle se mettent dans repliques.json, une liste de phrases par humeur.\n")
        lines = os.path.join(folder, "repliques.json")
        if not os.path.exists(lines):
            with open(lines, "w", encoding="utf-8") as f:
                json.dump({m: [] for m in MOODS}, f, ensure_ascii=False, indent=1)

    def noe(self):
        folder = self.noe_folder()
        images = {}
        try:
            for name in sorted(os.listdir(folder)):
                stem, ext = os.path.splitext(name)
                key = plain(stem)
                if ext.lower() in NOE_EXT and key in MOODS and key not in images:
                    images[key] = "/noe/" + urllib.parse.quote(name)
        except OSError:
            pass
        try:
            with open(os.path.join(folder, "repliques.json"), encoding="utf-8") as f:
                lines = {plain(k): [str(x) for x in v if str(x).strip()] for k, v in json.load(f).items() if isinstance(v, list)}
        except (OSError, ValueError, AttributeError):
            lines = {}
        return dict(images=images, lines=lines, folder=folder)

    # ------------------------------------------------------------ state for the interface
    def static_db(self):
        return dict(version=self.db.version, home=self.db.home,
                    regions=[dict(id=r, name=self.db.regions[r]["name"], group=self.db.regions[r]["group"]) for r in self.db.region_order],
                    servers=[{k: self.db.servers[s][k] for k in ("id", "city", "country", "region", "lonlat", "provider")}
                             for s in self.db.server_order])

    def state(self):
        self.last_heartbeat = time.time()
        snap = self.detector.snapshot()
        return dict(version=VERSION, settings=self.settings, applied=self.applied, rule_count=self.rule_count,
                    pings=self.pings, detection=snap, mood=self.mood(snap), noe=self.noe(),
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
        if p.startswith("/noe/"):
            name = os.path.basename(urllib.parse.unquote(p[5:]))
            return self._file(os.path.join(self.app.noe_folder(), name))
        if p.startswith("/api/"):
            return self._api("GET", p, {})
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
            ("GET", "/api/state"): app.state,
            ("GET", "/api/db"): app.static_db,
            ("POST", "/api/apply"): lambda: app.apply(body),
            ("POST", "/api/unblock"): app.unblock,
            ("POST", "/api/learn"): lambda: app.learn(body),
            ("POST", "/api/forget"): lambda: app.forget(body),
            ("POST", "/api/settings"): lambda: app.update_settings(body),
            ("POST", "/api/publicip"): app.fetch_public_ip,
            ("POST", "/api/find-overwatch"): lambda: app._find_overwatch() if ON_WINDOWS else None,
            ("POST", "/api/open-noe-folder"): lambda: os.startfile(app.noe_folder()) if ON_WINDOWS else None,
            ("POST", "/api/quit"): lambda: threading.Timer(0.3, app.shutdown).start(),
        }
        fn = routes.get((method, path))
        if not fn:
            return self._send(404, {"error": "route inconnue"})
        try:
            self._send(200, {"ok": True, "result": fn()})
        except (ValueError, RuntimeError) as e:
            app.event(str(e), "error", "triste", 8)
            self._send(400, {"ok": False, "error": str(e)})
        except Exception as e:
            app.event(f"Erreur : {e}", "error", "triste", 8)
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
    step("plan route EU sans AMS1", lambda: len(core.plan(db, "route", region="EU", blocked=["AMS1"], overwatch_path=notepad)))
    step("plan liste noire", lambda: len(core.plan(db, "normal", blocked=["AMS1", "MES1"], overwatch_path=None, overwatch_only=False)))

    fw = winfw.Firewall(group="Bifrost selftest")
    step("état du pare-feu", fw.status)
    step("appliquer route EU (notepad)", lambda: fw.apply(core.plan(db, "route", region="EU", blocked=["AMS1"], overwatch_path=notepad)))
    step("règles visibles", lambda: sorted(fw.our_rules()))
    step("appliquer liste noire (tout le PC)", lambda: fw.apply(core.plan(db, "normal", blocked=["AMS1", "MES1"], overwatch_only=False)))
    step("tout débloquer", lambda: (fw.remove_all(), fw.our_rules())[1])

    step("ping 1.1.1.1", lambda: winfw.ping("1.1.1.1"), critical=False)
    step("ping des serveurs", lambda: {s["id"]: {t: winfw.ping(t) for t in s["ping"]} for s in db.servers.values() if s["ping"]}, critical=False)
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
    parser = argparse.ArgumentParser(description="Bifröst — sélecteur de serveurs Overwatch 2")
    parser.add_argument("--selftest", metavar="RAPPORT")
    parser.add_argument("--no-window", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest(args.selftest)
    return run(no_window=args.no_window)


if __name__ == "__main__":
    sys.exit(main())
