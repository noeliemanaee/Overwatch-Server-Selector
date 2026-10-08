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

## Langues

Bifröst parle français, anglais, allemand, espagnol, italien, japonais, coréen, suédois et chinois (simplifié).
Au démarrage elle prend la langue d'affichage de Windows (anglais si ce n'est aucune des neuf), et le menu en haut
à droite permet d'en choisir une autre, qu'elle retient. Les textes de l'interface sont dans `ui/i18n.js`.

## Détection en direct

Bifröst active le journal du pare-feu Windows pendant qu'elle tourne (et remet le réglage d'origine en partant),
y repère les adresses avec lesquelles Overwatch échange, et les reconnaît. Une adresse inconnue ? Elle demande
quel serveur c'est (le nom s'affiche en jeu avec Ctrl+Maj+N) et s'en souvient.

## NOE

NOE apparaît en fond, derrière le globe, sous un voile aux couleurs du thème. Son image va dans
`%LOCALAPPDATA%\Bifrost\noe` (bouton « Dossier des personnages ») : `fond.png` pour tous les thèmes, ou
`fond-nuit.png`, `fond-doux.png`, `fond-pixel.png` pour un thème précis. Format conseillé : 16:9, NOE dans le tiers
gauche, en bas, le centre calme pour le globe. Une image intégrée peut aussi être posée dans `data/noe/`.

## Nœtty

Nœtty flotte à côté du globe et commente : régions toutes coupées, comportement par défaut, pings de chaque région,
serveur trouvé, tentatives bloquées, astuces. Clique sur elle pour une autre bulle.
Ses 16 têtes sont intégrées (`data/noetty/img`) : `plisse` au repos, et pendant qu'elle parle celle que la phrase
choisit avec `[tête]` au début (`rire`, `sourire`, `timide`, `coeur`, `clin`, `malice`, `mdr`, `popcorn`, `bleh`,
`inquiete`, `supplie`, `fachee`, `boude`, `triste`, `ko`).
Ses phrases, une liste par situation, sont dans `data/noetty/<langue>.json`. Pour les changer sans recompiler, copie
`%LOCALAPPDATA%\Bifrost\noetty\modeles\repliques.<langue>.json` dans le dossier `noetty` et modifie la copie ;
une image du même nom qu'une tête (ex. `rire.png`) dans ce dossier remplace la tête intégrée.

## Fichiers

Tout ce que Bifröst retient est dans `%LOCALAPPDATA%\Bifrost` : réglages (dont la langue), adresses apprises
(`learned.json`), fond de NOE, images et phrases personnalisées de Nœtty.
Ses règles sont dans le pare-feu Windows, groupe « Bifrost (NOEVALKY) » ; « Tout débloquer » les retire toutes.

## Développement

- `tools/build_servers.py` régénère `data/servers.json` à partir de `../ip_lists`.
- `app.py --no-window` lance seulement le serveur (http://127.0.0.1:47815).
- `app.py --selftest rapport.json` vérifie pare-feu, journal, ping et API sur la machine.
- À chaque push dans `bifrost/`, GitHub teste sur une vraie machine Windows, compile `Bifrost.exe` et publie une release.
