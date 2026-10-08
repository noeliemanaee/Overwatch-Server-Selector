"""Nœtty, the NOEVALKY mascot floating next to the globe: her image(s) and the lines she says.

Her pictures are Noelie's own: 16 faces ship in data/noetty/img (plisse, the squinted-eyes smile, is the
one she floats with). A picture with the same name in %LOCALAPPDATA%\\Bifrost\\noetty replaces a face
(noetty.png counts as plisse, as in 0.1.6). A line may start with [face] to pick the face she makes.
Her lines ship in data/noetty/<lang>.json, one file per language. To change them, put a
repliques.<lang>.json in that folder (copies of the shipped ones sit in modeles/): each situation
listed there replaces the shipped list. {region}, {ms}, {server} and {n} are filled in by the app.
"""
import hashlib
import json
import os
import urllib.parse

IMAGE_EXT = (".png", ".webp", ".gif", ".jpg", ".jpeg", ".webm")
FACES = ("plisse", "rire", "sourire", "timide", "coeur", "clin", "malice", "mdr", "popcorn", "bleh",
         "inquiete", "supplie", "fachee", "boude", "triste", "ko")
IDLE = "plisse"
LANGS = ("fr", "en", "de", "es", "it", "ja", "ko", "sv", "zh")

# 0.1.6 wrote its French defaults to noetty/repliques.json. A file still equal to them (this hash of the
# sorted JSON) was never edited and is removed; an edited one becomes repliques.fr.json.
LEGACY_DEFAULTS_SHA256 = "da10afd6305b8452aa48db4d26259cd5ee0e66844d0e9eee7cc2b95e8de3278c"

README = """\
Nœtty
=====

Têtes
  Nœtty a 16 têtes intégrées : plisse (au repos), rire, sourire, timide, coeur, clin, malice, mdr,
  popcorn, bleh, inquiete, supplie, fachee, boude, triste, ko.
  Pour en remplacer une, pose ici une image du même nom (plisse.png, rire.webp, ko.gif...).
  noetty.png remplace plisse ; parle.png sert aux phrases qui ne choisissent pas de tête.

Phrases
  Bifröst a ses phrases dans chaque langue. Pour les changer, copie modeles\\repliques.fr.json
  (ou .en, .de, .es, .it, .ja, .ko, .sv, .zh) ici, à côté de ce fichier, et modifie-le.
  Chaque situation présente dans ta copie remplace celle d'origine ; les autres restent.
  {region}, {ms}, {server} et {n} sont remplis tout seuls.
  [tete] au début d'une phrase choisit la tête de Nœtty : « [mdr] Ton Hanzo tire aujourd'hui... »
  Le dossier modeles est réécrit à chaque démarrage : ne modifie pas les fichiers qui s'y trouvent.

---

Faces
  16 faces are built in (names above). Put a picture with the same name here to replace one.

Lines
  To change her lines, copy modeles\\repliques.<language>.json here, next to this file, and edit it.
  Each situation in your copy replaces the built-in one; the others stay.
  [face] at the start of a line picks her face.
  The modeles folder is rewritten at every start: don't edit the files inside it.
"""


def folder(base):
    return os.path.join(base, "noetty")


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _canon(data):
    return hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def defaults(lines_dir, lang):
    return _read(os.path.join(lines_dir, f"{lang}.json"))


def _write_if_changed(path, text):
    try:
        with open(path, encoding="utf-8") as f:
            if f.read() == text:
                return
    except OSError:
        pass
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def prepare(base, lines_dir):
    path = folder(base)
    os.makedirs(path, exist_ok=True)
    _write_if_changed(os.path.join(path, "LISEZ-MOI.txt"), README)
    models = os.path.join(path, "modeles")
    os.makedirs(models, exist_ok=True)
    for lang in LANGS:
        data = defaults(lines_dir, lang)
        if data:
            _write_if_changed(os.path.join(models, f"repliques.{lang}.json"), json.dumps(data, ensure_ascii=False, indent=1) + "\n")
    legacy = os.path.join(path, "repliques.json")
    if os.path.exists(legacy):
        data = _read(legacy)
        try:
            if data and _canon(data) == LEGACY_DEFAULTS_SHA256:
                os.remove(legacy)
            elif not os.path.exists(os.path.join(path, "repliques.fr.json")):
                os.replace(legacy, os.path.join(path, "repliques.fr.json"))
        except OSError:
            pass


def load(base, lines_dir, lang, img_dir=None):
    """Her faces (face -> URL), the face she floats with, and her lines in `lang`."""
    lang = lang if lang in LANGS else "en"
    path = folder(base)
    images = {}
    try:
        for name in sorted(os.listdir(img_dir or os.path.join(lines_dir, "img"))):
            stem, ext = os.path.splitext(name)
            if stem in FACES and ext.lower() in IMAGE_EXT:
                images[stem] = "/media/noetty/" + urllib.parse.quote(name)
    except OSError:
        pass
    local = set()
    try:
        for name in sorted(os.listdir(path)):
            stem, ext = os.path.splitext(name)
            key = {"noetty": IDLE}.get(stem.lower(), stem.lower())
            if ext.lower() in IMAGE_EXT and (key in FACES or key == "parle") and key not in local:
                images[key] = "/noetty/" + urllib.parse.quote(name)
                local.add(key)
    except OSError:
        pass
    lines = {k: [str(x) for x in v] for k, v in (defaults(lines_dir, lang) or defaults(lines_dir, "en")).items()
             if isinstance(v, list)}
    for k, v in _read(os.path.join(path, f"repliques.{lang}.json")).items():
        if isinstance(v, list):
            lines[k] = [str(x) for x in v if str(x).strip()]
    return dict(images=images, idle=IDLE, lines=lines, lang=lang)
