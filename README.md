
# Salty
Salty est une application avec une interface graphique permet de hacher,  chiffrer,  déchiffrer et gérer ses clé AES en toute simplicité afin de sécuriser ses fichiers plus facilement.

## Utilisation des executables
Salty sous forme d'executable fonctionne sans avoir besoin de python ou de tout autre programme


## Utilisation du fichier python
Si vous souhaitez utilisé le fichier python contenant le code, il faudra installer des modules
Salty.py a besoin de différents modules afin de pouvoir fonctionner

**PySimpleGUI :** bibliothèque permettant de créer l'interface graphique  
*Pour l'installer, taper la commande suivante dans le terminal lancé depuis votre répertoire*
> pip install pysimplegui

**PyCryptoDome :** bibliothèque permettant de chiffrer et dechiffrer un fichier  
*Pour l'installer, taper la commande suivante dans le terminal lancé depuis votre répertoire*
> pip install pycryptodome

## Organisation des dossier

```bash
├── close.ico 
├── executables
├── destination
├── encrypted-files
├── keys.json
├── logo.png
├── salty-icon.ico
├── salty.py
└── source
```

- **salty.py** : Le ficher Python contenant le code
- **executables**  // contient les executables pour Windows et MacOS
- **source**  // contient les fichiers non chiffrés
- **encrypted-files**  // contient les fichiers et leurs détails une fois chiffrés
- **destination**  // contient les fichiers une fois déchiffrés par le logiciel
- *logo.png*  // logo visible sur l'interface
- *salty-icon.ico*  // icône de l'application (disponible uniquement sur Windows)
- *close.ico*  //icône pour les messages d'erreurs
- ***keys.json***  // fichier contenant les clés AES que l'on peut gérer dans le logiciel
