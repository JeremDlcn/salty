
# Salty
Salty est une application avec une interface graphique permet de hacher,  chiffré,  déchiffré et gérer ses clé AES en toute simplicité afin de sécuriser ses fichiers plus facilement.

## Installation des modules
Salty a besoin de différents modules afin de pouvoir fonctionné


**PySimpleGUI :** bibliothèque permettant de crée l'interface graphique  
*Pour l'installer, taper la commande suivante dans le terminal lancé depuis votre répertoire*
> pip install pysimplegui

**PyCryptoDome :** bibliothèque permettant de chiffré et dechiffré un fichier  
*Pour l'installer, taper la commande suivante dans le terminal lancé depuis votre répertoire*
> pip install pycryptodome

## Organisation des dossier
le dossier contient plusieurs dossiers et fichier qui sont utiles pour le projet
| - Salty.py
| - **source**  // contient les fichiers non chiffrés
| - **encrypted-files**  // contient les fichiers et leurs détails une fois chiffrés
| - **destination**  // contient les fichiers une fois déchiffrés par le logiciel
| - *logo.png*  // logo visible sur l'interface
| - *salty-icon.ico*  // icône de l'application (disponible uniquement sur Windows)
| - *close.ico*  //icône pour les messages d'erreurs
| - ***keys.json***  // fichier contenant les clés AES que l'on peut gérer dans le logiciel
