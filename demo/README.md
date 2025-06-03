# SharkScan Demo

Ce dossier contient un script de démonstration pour SharkScan qui simule les résultats de manière sécurisée.

## Installation

1. Assurez-vous d'avoir Python 3.7+ installé
2. Installez les dépendances :
```bash
pip install rich
```

## Utilisation

Le script de démonstration peut être utilisé pour simuler les résultats de SharkScan sans effectuer de scans réels :

```bash
python demo.py <module> <target>
```

### Modules disponibles

- `lateral` : Détection des mouvements latéraux
- `lorenzini` : Scan de ports avancé
- `dents` : Évaluation des vulnérabilités
- `caudale` : Énumération des services
- `dermoid` : Détection du système d'exploitation
- `foie` : Cartographie réseau
- `olfactif` : Analyse du trafic
- `vision` : Cartographie visuelle

### Exemples

```bash
# Simuler un scan de ports
python demo.py lorenzini example.com

# Simuler une évaluation des vulnérabilités
python demo.py dents example.com

# Simuler une cartographie réseau
python demo.py foie example.com
```

## Fonctionnalités

- Interface utilisateur riche avec des tableaux et des arbres
- Simulation de progression du scan
- Résultats formatés pour chaque module
- Aucun scan réel n'est effectué

## Sécurité

Ce script est conçu pour la démonstration uniquement et ne fait aucun scan réel. Il utilise des données simulées pour montrer les capacités de SharkScan de manière sécurisée. 