"""Builds bifrost/data/servers.json from the foryVERX IP lists plus what we learned ourselves.

Run from the repository root:  python bifrost/tools/build_servers.py
Re-run it whenever ip_lists/ is updated; the app reads only the generated JSON.
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
LISTS = ROOT / "ip_lists"
OUT = ROOT / "bifrost" / "data" / "servers.json"

ENTRY = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2}|-\d{1,3}(\.\d{1,3}){3})?$")


def read_list(name):
    path = LISTS / name
    if not path.exists():
        return []
    out = []
    for token in re.split(r"\s+", path.read_text(encoding="utf-8", errors="ignore")):
        if ENTRY.match(token) and token not in out:
            out.append(token)
    return out


def cfg(label):
    return read_list(f"cfg - {label}.txt")


# Regions: the whole provider footprint of a region (used to *allow* it in Route mode).
REGIONS = [
    ("EU", "Europe", "Europe", "Ip_ranges_EU.txt"),
    ("ME", "Moyen-Orient", "Moyen-Orient", "Ip_ranges_ME.txt"),
    ("NA_EAST", "NA Est", "Amériques", "Ip_ranges_NA_East.txt"),
    ("NA_CENTRAL", "NA Centre", "Amériques", "Ip_ranges_NA_central.txt"),
    ("NA_WEST", "NA Ouest", "Amériques", "Ip_ranges_NA_West.txt"),
    ("BRAZIL", "Brésil", "Amériques", "Ip_ranges_Brazil.txt"),
    ("JAPAN", "Japon", "Asie · Océanie", "Ip_ranges_AS_Japan.txt"),
    ("KOREA", "Corée", "Asie · Océanie", "Ip_ranges_AS_Korea.txt"),
    ("TAIWAN", "Taïwan", "Asie · Océanie", "Ip_ranges_AS_Taiwan.txt"),
    ("SINGAPORE", "Singapour", "Asie · Océanie", "Ip_ranges_AS_Singapore.txt"),
    ("AUSTRALIA", "Australie", "Asie · Océanie", "Ip_ranges_Australia.txt"),
]

# Addresses seen in Noelie's own captures (Resource Monitor, 2026-10-08), not yet in the foryVERX lists.
SEEN_EU = ["66.40.191.0/24", "136.107.181.0/24"]

def icmp(host):
    return dict(type="icmp", host=host)


def tcp(host, port=443):
    return dict(type="tcp", host=host, port=port)


def gcp(region):
    return dict(type="gcp", region=region)


# Regional test endpoints of Google Cloud (github.com/GoogleCloudPlatform/gcping, listed by https://gcping.com/api/endpoints):
# a request there measures the round trip to that Google data centre, where most Overwatch servers run.
GCP_ENDPOINTS = {
    "europe-north1": "https://europe-north1-5tkroniexa-lz.a.run.app",
    "europe-west4": "https://europe-west4-5tkroniexa-ez.a.run.app",
    "me-central1": "https://me-central1-5tkroniexa-ww.a.run.app",
    "me-central2": "https://me-central2-5tkroniexa-wx.a.run.app",
    "us-east4": "https://us-east4-5tkroniexa-uk.a.run.app",
    "us-central1": "https://us-central1-5tkroniexa-uc.a.run.app",
    "us-west2": "https://us-west2-5tkroniexa-wl.a.run.app",
    "southamerica-east1": "https://southamerica-east1-5tkroniexa-rj.a.run.app",
    "asia-northeast1": "https://asia-northeast1-5tkroniexa-an.a.run.app",
    "asia-northeast3": "https://asia-northeast3-5tkroniexa-du.a.run.app",
    "asia-east1": "https://asia-east1-5tkroniexa-de.a.run.app",
    "asia-southeast1": "https://asia-southeast1-5tkroniexa-as.a.run.app",
    "australia-southeast1": "https://australia-southeast1-5tkroniexa-ts.a.run.app",
}

# Latency probes, best first: icmp = ping of a Blizzard address in the same data centre,
# gcp = Google data centre hosting the server (or the closest one), tcp = connection time to an AWS regional endpoint.
# Once a game address is learned or seen, Bifröst pings that address first.
# Servers: one entry per data-centre code shown in game with Ctrl+Shift+N.
# ranges = the server's own list when foryVERX has one, else its whole region list.
SERVERS = [
    dict(id="AMS1", city="Amsterdam", country="Pays-Bas", region="EU", lonlat=[4.90, 52.37], provider="Blizzard",
         ranges=cfg("EU - Netherlands - AMS1") + ["66.40.191.0/24"], probes=[icmp("185.60.114.159"), gcp("europe-west4")]),
    dict(id="GEN1", city="Hamina", country="Finlande", region="EU", lonlat=[27.20, 60.57], provider="Google",
         ranges=cfg("EU - Finland 2 - GEN1"), probes=[gcp("europe-north1")]),
    dict(id="MES1", city="Manama", country="Bahreïn", region="ME", lonlat=[50.58, 26.07], provider="AWS",
         ranges=cfg("Other - Bahrain - MES1"), probes=[tcp("dynamodb.me-south-1.amazonaws.com"), gcp("me-central2")]),
    dict(id="GMEC1", city="Doha", country="Qatar", region="ME", lonlat=[51.53, 25.29], provider="Google",
         ranges=cfg("Other - Qatar - GMEC1"), probes=[gcp("me-central1")]),
    dict(id="GMEC2", city="Dammam", country="Arabie saoudite", region="ME", lonlat=[50.10, 26.43], provider="Google",
         ranges=cfg("Other - KSA - GMEC2"), probes=[gcp("me-central2")]),
    dict(id="GUE4", city="Ashburn", country="États-Unis (Virginie)", region="NA_EAST", lonlat=[-77.49, 39.04], provider="Google",
         ranges=read_list("Ip_ranges_NA_East.txt"), probes=[gcp("us-east4")]),
    dict(id="ORD1", city="Chicago", country="États-Unis", region="NA_CENTRAL", lonlat=[-87.63, 41.88], provider="Blizzard",
         ranges=cfg("NA - USA Central - ORD1"), probes=[icmp("24.105.62.129"), gcp("us-central1")]),
    dict(id="LAX1", city="Los Angeles", country="États-Unis", region="NA_WEST", lonlat=[-118.24, 34.05], provider="Blizzard",
         ranges=cfg("NA - USA West - LAX1"), probes=[icmp("24.105.30.129"), gcp("us-west2")]),
    dict(id="GUW2", city="Los Angeles", country="États-Unis", region="NA_WEST", lonlat=[-117.6, 34.6], provider="Google",
         ranges=cfg("NA - USA West 2 - GUW2"), probes=[gcp("us-west2")]),
    dict(id="GBR1", city="São Paulo", country="Brésil", region="BRAZIL", lonlat=[-46.63, -23.55], provider="Google",
         ranges=cfg("Other - Brazil 2 - GBR1"), probes=[gcp("southamerica-east1")]),
    dict(id="GTK1", city="Tokyo", country="Japon", region="JAPAN", lonlat=[139.69, 35.69], provider="Google",
         ranges=cfg("Asia - Japan 2 - GTK1"), probes=[gcp("asia-northeast1")]),
    dict(id="ICN1", city="Séoul", country="Corée du Sud", region="KOREA", lonlat=[126.98, 37.57], provider="Blizzard",
         ranges=cfg("Asia - South Korea - ICN1"), probes=[icmp("211.234.110.1"), gcp("asia-northeast3")]),
    dict(id="GAN3", city="Séoul", country="Corée du Sud", region="KOREA", lonlat=[127.4, 37.1], provider="Google",
         ranges=cfg("Asia - South Korea 3 - GAN3"), probes=[gcp("asia-northeast3")]),
    dict(id="TPE1", city="Taipei", country="Taïwan", region="TAIWAN", lonlat=[121.56, 25.03], provider="Blizzard",
         ranges=cfg("Asia - Taiwan - TPE1"), probes=[gcp("asia-east1")]),
    dict(id="GSG1", city="Singapour", country="Singapour", region="SINGAPORE", lonlat=[103.82, 1.35], provider="Google",
         ranges=cfg("Asia - Singapore 2 - GSG1"), probes=[gcp("asia-southeast1")]),
    dict(id="SYD2", city="Sydney", country="Australie", region="AUSTRALIA", lonlat=[151.21, -33.87], provider="Google",
         ranges=cfg("Other - Australia 3 - SYD2"), probes=[gcp("australia-southeast1"), icmp("172.105.168.123")]),
]


def main():
    regions = []
    for rid, name, group, filename in REGIONS:
        ranges = read_list(filename)
        for s in SERVERS:
            if s["region"] == rid:
                ranges += [r for r in s["ranges"] if r not in ranges]
        if rid == "EU":
            ranges += [r for r in SEEN_EU if r not in ranges]
        regions.append(dict(id=rid, name=name, group=group, ranges=ranges))
    data = dict(
        version="2026.10.08",
        source="Listes foryVERX/Overwatch-Server-Selector (IP_version 0.5.7) + captures de Noelie",
        home=dict(name="Paris", lonlat=[2.35, 48.86]),
        regions=regions,
        servers=SERVERS,
        gcp_endpoints=GCP_ENDPOINTS,
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    for r in regions:
        print(f"{r['id']:11s} {len(r['ranges']):4d} plages")
    for s in SERVERS:
        print(f"  {s['id']:6s} {len(s['ranges']):4d} plages  sondes={[p.get('host') or p.get('region') for p in s['probes']]}")


if __name__ == "__main__":
    main()
