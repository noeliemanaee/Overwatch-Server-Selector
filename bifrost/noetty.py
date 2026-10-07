"""Nœtty, the NOEVALKY mascot floating next to the globe: her image(s) and the lines she says.

Her pictures are Noelie's own: Bifröst never draws her. Drop them in %LOCALAPPDATA%\\Bifrost\\noetty :
  noetty.png  (or .webp, .gif, .webm)  floating, smiling with squinted eyes
  parle.png   (optional)               shown while a bubble is open
Her lines live in repliques.json in that folder, created from the defaults below on first run and
then never overwritten: edit it freely. {region}, {ms}, {server} and {n} are filled in by the app.
"""
import json
import os
import urllib.parse

IMAGE_EXT = (".png", ".webp", ".gif", ".jpg", ".jpeg", ".webm")

DEFAULT_LINES = {
    "tout_coupe": [
        "Heeeu… tu pourras plus jouer à OW. Tu comptes aller toucher de l'herbe, c'est ça le plan ?",
        "Tout est coupé. Même Mercy ne peut plus te ressusciter, là.",
        "Zéro serveur. La pause la plus efficace de l'histoire d'Overwatch.",
        "Plus aucun serveur… On regarde les étoiles à la place ?",
    ],
    "tout_allume": [
        "Comportement par défaut d'OW, comme si l'appli n'avait rien fait.",
        "Tout est allumé : Overwatch choisit tout seul. Je me tourne les pouces.",
        "Cœurs partout ! Le monde entier peut venir jouer avec toi.",
        "Mode « je fais confiance au matchmaking ». Courageuse.",
    ],
    "ping_bon": [
        "{region} : {ms} ms. Tu vas voir les balles avant qu'elles partent.",
        "{ms} ms vers {region}… c'est presque de la télépathie.",
        "{region} répond en {ms} ms. Aucune excuse si tu rates tes headshots.",
        "Ping de {ms} ms en {region}. Ton bâton de Mercy va être d'une précision chirurgicale.",
    ],
    "ping_moyen": [
        "{region} : {ms} ms. Jouable, mais garde tes réflexes au chaud.",
        "{ms} ms vers {region}. Ça passe, tant que tu ne joues pas Genji contre un Winston.",
        "{region} à {ms} ms : un petit voyage, pas encore une expédition.",
    ],
    "ping_haut": [
        "Le ping de {region} est de {ms} ms. Tu vas rencontrer de nouvelles personnes, mais ça va lagger !",
        "{region} à {ms} ms… Je te conseille de jouer Reinhardt, ils verront pas que t'es aveugle.",
        "{ms} ms vers {region} : tes « Je suis là ! » arriveront un peu après toi.",
        "{ms} ms… Tes résurrections vont arriver avec un petit délai poétique.",
    ],
    "ping_enorme": [
        "Avec ton ping de {ms}, si tu comptais jouer Widow, t'attends pas à jouer comme Kenzo.",
        "{region} à {ms} ms. Tu ne joues plus, tu envoies des lettres.",
        "{ms} ms vers {region}… Ton Hanzo va tirer aujourd'hui et toucher demain.",
        "{region} : {ms} ms. Ça ne lag pas, c'est un ralenti cinématique.",
        "{ms} ms ? Le temps que ta balle arrive, la partie est finie.",
    ],
    "applique": [
        "C'est noté ! Relance Overwatch pour que je fasse effet.",
        "Règles posées. Le Bifröst est ouvert dans la bonne direction.",
        "Appliqué ! Je garde la porte, promis.",
    ],
    "bloque": [
        "{server} a essayé de t'attraper {n} fois. Raté !",
        "J'ai renvoyé {server} chez lui. {n} fois.",
        "{server} toque à la porte. Personne n'ouvre.",
    ],
    "partie": [
        "Tu joues sur {server}. Bonne game !",
        "En route vers {server}, {ms} ms. Que la force du soin soit avec toi.",
        "{server} trouvé ! Pense à t'hydrater entre deux games.",
    ],
    "inconnu": [
        "Oh ? Overwatch parle à une adresse que je ne connais pas. Tu me dis c'est quel serveur ?",
        "Nouvelle adresse repérée ! Fais Ctrl+Maj+N en jeu et dis-moi son nom.",
    ],
    "ow_ferme": [
        "Overwatch est fermé. Je t'attends ici, tranquille.",
        "Pas d'Overwatch à l'horizon. Tu peux préparer ta route avant de lancer le jeu.",
    ],
    "astuces": [
        "Attrape le globe pour le faire tourner !",
        "Clique un serveur sur le globe pour lui mettre un crâne… ou lui rendre son cœur.",
        "En jeu, Ctrl+Maj+N affiche le nom de ton serveur.",
        "Le petit viseur sous le globe te ramène à la maison.",
        "En mode « Une seule », un clic sur une tuile ne garde que cette région.",
        "Les pings avec ≈ sont des estimations. Passe ta souris dessus pour savoir d'où ils viennent.",
        "Après « Appliquer », relance Overwatch si une partie était en cours.",
        "Ton IP est masquée par défaut, pratique quand tu streames.",
        "La détection voit ton serveur environ 30 secondes après le début de la partie.",
        "Le Journal, en bas du panneau, liste les adresses qu'Overwatch a contactées.",
        "« Tout débloquer » rallume toutes les régions et retire toutes mes règles.",
        "Tu peux changer de thème en haut à droite : Nuit, Doux ou Pixel.",
        "Quand tu fermes la fenêtre, mes règles restent actives. « Tout débloquer » si tu veux revenir à la normale.",
        "Clique sur moi pour une autre bulle !",
    ],
}


def folder(base):
    return os.path.join(base, "noetty")


def prepare(base):
    path = folder(base)
    os.makedirs(path, exist_ok=True)
    readme = os.path.join(path, "LISEZ-MOI.txt")
    if not os.path.exists(readme):
        with open(readme, "w", encoding="utf-8") as f:
            f.write("Dépose ici l'image de Nœtty :\n"
                    "  noetty.png  (ou .webp, .gif, .webm) : elle flotte à côté du globe\n"
                    "  parle.png   (facultatif) : affichée pendant qu'elle parle\n\n"
                    "Ses phrases sont dans repliques.json, une liste par situation. Modifie-les librement :\n"
                    "Bifröst ne réécrit jamais ce fichier. {region}, {ms}, {server} et {n} sont remplis tout seuls.\n")
    lines = os.path.join(path, "repliques.json")
    if not os.path.exists(lines):
        with open(lines, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_LINES, f, ensure_ascii=False, indent=1)


def load(base):
    path = folder(base)
    images = {}
    try:
        for name in sorted(os.listdir(path)):
            stem, ext = os.path.splitext(name)
            key = stem.lower()
            if ext.lower() in IMAGE_EXT and key in ("noetty", "parle") and key not in images:
                images[key] = "/noetty/" + urllib.parse.quote(name)
    except OSError:
        pass
    lines = {k: list(v) for k, v in DEFAULT_LINES.items()}
    try:
        with open(os.path.join(path, "repliques.json"), encoding="utf-8") as f:
            for k, v in json.load(f).items():
                if isinstance(v, list):
                    lines[k] = [str(x) for x in v if str(x).strip()]
    except (OSError, ValueError, AttributeError):
        pass
    return dict(images=images, lines=lines)
