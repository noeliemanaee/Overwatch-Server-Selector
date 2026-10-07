# Bifröst

Sélecteur de serveurs Overwatch 2 de l'univers NOEVALKY. Fork de
[MINA Overwatch 2 Server Selector](https://github.com/foryVERX/Overwatch-Server-Selector) par foryVERX,
dont il reprend les listes d'adresses.

## Les deux modes

- **Route** : tu choisis une région. Tout le trafic de jeu d'Overwatch vers le reste du monde est coupé,
  y compris vers des adresses qu'aucune liste ne connaît encore. Un crâne sur un serveur de la région l'évite aussi
  (« Europe, mais pas AMS1 »).
- **Normal** : rien n'est coupé, sauf les serveurs où tu mets un crâne.

Dans les deux cas, seuls l'UDP et l'ICMP sont bloqués : la connexion Battle.net et le lobby (TCP) passent toujours.
Le mode Route ne touche qu'à Overwatch.exe ; le mode Normal aussi, tant que « Seulement Overwatch » reste coché.

## Détection en direct

Bifröst active le journal du pare-feu Windows pendant qu'elle tourne (et remet le réglage d'origine en partant),
y repère les adresses avec lesquelles Overwatch échange, et les reconnaît. Une adresse inconnue ? Elle demande
quel serveur c'est (le nom s'affiche en jeu avec Ctrl+Maj+N) et s'en souvient.

## NOE

Dépose les images de NOE dans `%LOCALAPPDATA%\Bifrost\noe` (bouton « Dossier de NOE »), une par humeur :
`neutre`, `souriante`, `rieuse`, `excitee`, `surprise`, `boudeuse`, `triste`, `genee` (`.png`, `.webp`, `.gif` ou `.webm`).
Les répliques de sa bulle vont dans `repliques.json`, à côté.

## Fichiers

Tout ce que Bifröst retient est dans `%LOCALAPPDATA%\Bifrost` : réglages, adresses apprises (`learned.json`), images de NOE.
Ses règles sont dans le pare-feu Windows, groupe « Bifrost (NOEVALKY) » ; « Tout débloquer » les retire toutes.

## Développement

- `tools/build_servers.py` régénère `data/servers.json` à partir de `../ip_lists`.
- `app.py --no-window` lance seulement le serveur (http://127.0.0.1:47815).
- `app.py --selftest rapport.json` vérifie pare-feu, journal, ping et API sur la machine.
- À chaque push dans `bifrost/`, GitHub teste sur une vraie machine Windows, compile `Bifrost.exe` et publie une release.
