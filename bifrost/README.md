# Bifröst

Sélecteur de serveurs Overwatch 2 de l'univers NOEVALKY. Fork de
[MINA Overwatch 2 Server Selector](https://github.com/foryVERX/Overwatch-Server-Selector) par foryVERX,
dont il reprend les listes d'adresses.

## Choisir avec qui jouer

- **Les tuiles de régions** (« Je joue avec les joueurs de… ») sont toutes allumées au départ. Un clic éteint une région,
  un second la reprend. Le sélecteur « Une seule » garde seulement la région cliquée.
- **Un crâne sur un serveur** l'évite même si sa région est allumée (« Europe, mais pas AMS1 »).
- **« Couper aussi les adresses inconnues »** (conseillé) : quand une région est éteinte, tout le trafic de jeu d'Overwatch
  hors des régions allumées est coupé, y compris vers des adresses qu'aucune liste ne connaît encore.
- **« Tout débloquer »** retire les règles et rallume toutes les régions.

Seuls l'UDP et l'ICMP sont bloqués : la connexion Battle.net et le lobby (TCP) passent toujours.
Le blocage ne touche qu'à Overwatch.exe (forcé dès qu'une région est coupée strictement, au choix sinon).

## Détection en direct

Bifröst active le journal du pare-feu Windows pendant qu'elle tourne (et remet le réglage d'origine en partant),
y repère les adresses avec lesquelles Overwatch échange, et les reconnaît. Une adresse inconnue ? Elle demande
quel serveur c'est (le nom s'affiche en jeu avec Ctrl+Maj+N) et s'en souvient.

## NOE

Dépose les images de NOE dans `%LOCALAPPDATA%\Bifrost\noe` (bouton « Dossier de NOE »), une par humeur :
`neutre`, `souriante`, `rieuse`, `excitee`, `surprise`, `boudeuse`, `triste`, `genee` (`.png`, `.webp`, `.gif` ou `.webm`).
Les répliques de sa bulle vont dans `repliques.json`, à côté.

## Nœtty

Nœtty flotte à côté du globe et commente : régions toutes coupées, comportement par défaut, pings de chaque région,
serveur trouvé, tentatives bloquées, astuces. Clique sur elle pour une autre bulle.
Son image va dans `%LOCALAPPDATA%\Bifrost\noetty` : `noetty.png` (ou `.webp`, `.gif`, `.webm`), et `parle.png` en option
pendant qu'elle parle. Ses phrases sont dans `repliques.json` à côté, une liste par situation ; Bifröst ne réécrit jamais ce fichier.

## Fichiers

Tout ce que Bifröst retient est dans `%LOCALAPPDATA%\Bifrost` : réglages, adresses apprises (`learned.json`), images de NOE.
Ses règles sont dans le pare-feu Windows, groupe « Bifrost (NOEVALKY) » ; « Tout débloquer » les retire toutes.

## Développement

- `tools/build_servers.py` régénère `data/servers.json` à partir de `../ip_lists`.
- `app.py --no-window` lance seulement le serveur (http://127.0.0.1:47815).
- `app.py --selftest rapport.json` vérifie pare-feu, journal, ping et API sur la machine.
- À chaque push dans `bifrost/`, GitHub teste sur une vraie machine Windows, compile `Bifrost.exe` et publie une release.
