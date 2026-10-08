"""Nœtty, the NOEVALKY mascot floating next to the globe: her faces and the lines she says.

Everything is built into Bifröst (Noelie's own pictures and lines):
  data/noetty/img/<face>.webp   16 faces; plisse (squinted-eyes smile) is the one she floats with
  data/noetty/<lang>.json       her lines per situation, one file per language
A line may start with [face] to pick the face she makes. {region}, {ms}, {server} and {n} are filled in by the app.
"""
import hashlib
import json
import os
import shutil
import urllib.parse

IMAGE_EXT = (".png", ".webp", ".gif", ".jpg", ".jpeg")
LANGS = ("fr", "en", "de", "es", "it", "ja", "ko", "sv", "zh")
FACES = ("plisse", "rire", "sourire", "timide", "coeur", "clin", "malice", "mdr", "popcorn", "bleh",
         "inquiete", "supplie", "fachee", "boude", "triste", "ko")
IDLE = "plisse"

# 0.1.6 wrote its French defaults to noetty/repliques.json (this hash of the sorted JSON).
LEGACY_DEFAULTS_SHA256 = "da10afd6305b8452aa48db4d26259cd5ee0e66844d0e9eee7cc2b95e8de3278c"


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _canon(data):
    return hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def cleanup(base):
    """0.1.6 to 0.1.8 kept a noetty folder in %LOCALAPPDATA%\\Bifrost. Remove what Bifröst put there
    (read-me, templates, untouched lines), then the folder if nothing else is left in it."""
    path = os.path.join(base, "noetty")
    if not os.path.isdir(path):
        return
    for name in ("LISEZ-MOI.txt",):
        try:
            os.remove(os.path.join(path, name))
        except OSError:
            pass
    shutil.rmtree(os.path.join(path, "modeles"), ignore_errors=True)
    legacy = os.path.join(path, "repliques.json")
    data = _read(legacy)
    if data and _canon(data) == LEGACY_DEFAULTS_SHA256:
        try:
            os.remove(legacy)
        except OSError:
            pass
    try:
        os.rmdir(path)  # only succeeds when empty
    except OSError:
        pass


def load(data_dir, lang):
    """Her faces (face -> URL), the face she floats with, and her lines in `lang` (English for other languages)."""
    lang = lang if lang in LANGS else "en"
    images = {}
    try:
        for name in sorted(os.listdir(os.path.join(data_dir, "img"))):
            stem, ext = os.path.splitext(name)
            if stem in FACES and ext.lower() in IMAGE_EXT:
                images[stem] = "/media/noetty/" + urllib.parse.quote(name)
    except OSError:
        pass
    lines = _read(os.path.join(data_dir, f"{lang}.json")) or _read(os.path.join(data_dir, "en.json"))
    lines = {k: [str(x) for x in v] for k, v in lines.items() if isinstance(v, list)}
    return dict(images=images, idle=IDLE, lines=lines, lang=lang)
