"""Latency probes that work without ICMP: TCP connection time, and round trip to a Google Cloud data centre.

ICMP ping itself is in winfw.ping (Windows API). Every function returns milliseconds, or None.
"""
import http.client
import socket
import time
import urllib.parse


def tcp_rtt(host, port=443, tries=3, timeout=3.0):
    """Time to open a TCP connection = one network round trip to that address."""
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return None
    best = None
    for _ in range(tries):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        try:
            s.connect((ip, port))
            ms = (time.perf_counter() - t0) * 1000
            best = ms if best is None else min(best, ms)
        except OSError:
            pass
        finally:
            s.close()
    return round(best) if best is not None else None


def gcp_rtt(base_url, tries=3, timeout=5.0):
    """Round trip to a Google Cloud region (gcping endpoint).

    The first request opens the connection and wakes the service up; the next ones reuse that connection,
    so their time is the trip from here to the region and back, which is what a game server there would cost.
    """
    url = urllib.parse.urlparse(base_url)
    conn = http.client.HTTPSConnection(url.netloc, timeout=timeout)
    headers = {"User-Agent": "Bifrost (NOEVALKY)", "Connection": "keep-alive"}
    best = None
    try:
        conn.request("GET", "/api/ping", headers=headers)
        conn.getresponse().read()
        for _ in range(tries):
            t0 = time.perf_counter()
            conn.request("GET", "/api/ping", headers=headers)
            resp = conn.getresponse()
            resp.read()
            if resp.status == 200:
                ms = (time.perf_counter() - t0) * 1000
                best = ms if best is None else min(best, ms)
    except (OSError, http.client.HTTPException):
        return round(best) if best is not None else None
    finally:
        conn.close()
    return round(best) if best is not None else None
