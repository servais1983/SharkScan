![image](shark.png)


# 🦈 SharkScan - Professional Network Security Scanner

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://www.linux.org/)

## ⚠️ AVERTISSEMENT LÉGAL

**IMPORTANT**: SharkScan est un outil de sécurité professionnel conçu pour des audits de sécurité autorisés uniquement. L'utilisation de cet outil sur des systèmes ou réseaux sans autorisation explicite est illégale et contraire à l'éthique. Les utilisateurs sont responsables de s'assurer qu'ils disposent des autorisations appropriées avant d'utiliser cet outil.

## 📋 Description

SharkScan est un scanner de sécurité réseau professionnel inspiré de l'anatomie du requin. Chaque module représente une capacité biologique du requin traduite en fonctionnalité de cybersécurité. Conçu pour les professionnels SOC, pentesters et analystes réseau.

## 🦈 Modules Anatomiques

1. **Ligne Latérale** (`lateral.py`) - Détection passive de trafic réseau anormal
2. **Ampoules de Lorenzini** (`lorenzini.py`) - Découverte réseau via ARP Scan
3. **Dents** (`dents.py`) - Scan de vulnérabilités avancé avec nmap
4. **Nageoire Caudale** (`caudale.py`) - Scan rapide de ports TCP
5. **Peau Dermoïde** (`dermoid.py`) - Scan furtif évitant IDS/IPS
6. **Foie Géant** (`foie.py`) - Scan complet longue durée
7. **Système Olfactif** (`olfactif.py`) - Détection de fuites de données
8. **Vision** (`vision.py`) - Analyse DNS et détection de services

Chaque module est conçu pour être modulaire et extensible, suivant une architecture orientée objet avec une classe principale (ex: `VisionScanner`) qui implémente les méthodes `scan()` et `display_results()`.

## 🔧 Installation

### Prérequis

- Linux (Debian/Ubuntu recommandé)
- Python 3.10+
- Droits sudo pour certaines fonctionnalités
- nmap installé sur le système

### Installation

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/SharkScan.git
cd SharkScan

# Créer un environnement virtuel (recommandé)
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Installer les dépendances de développement (optionnel)
pip install -r requirements-dev.txt

# Installer nmap si nécessaire
sudo apt-get update
sudo apt-get install nmap
```

### Configuration

1. Créer un fichier `.env` à la racine du projet :
```bash
# Le fichier .env.example sera créé lors de l'installation
# Copier le template
cp .env.example .env

# Éditer le fichier avec vos paramètres
nano .env
```

2. Variables d'environnement disponibles :
```bash
# Configuration générale
DEBUG=false
LOG_LEVEL=INFO

# Configuration réseau
DEFAULT_TIMEOUT=5
MAX_THREADS=100
STEALTH_MODE=false

# Configuration des scans
DEFAULT_PORTS=80,443,8080
SCAN_DELAY=1
MAX_RETRIES=3

# Configuration de la sécurité
API_KEY=your_api_key_here
ALLOWED_IPS=192.168.1.0/24,10.0.0.0/8
```

Ces variables peuvent être modifiées selon vos besoins. Consultez la documentation pour plus de détails sur chaque option.

## 🚀 Utilisation

### Commandes de base

```bash
# Aide générale
python sharkscan.py -h

# Scan rapide d'un réseau local
sudo python sharkscan.py -t 192.168.1.0/24 -m caudale

# Découverte ARP du réseau local
sudo python sharkscan.py -t 192.168.1.0/24 -m lorenzini

# Scan de vulnérabilités sur une cible
python sharkscan.py -t example.com -m dents

# Scan furtif avec contournement IDS
sudo python sharkscan.py -t 10.0.0.1 -m dermoid --stealth

# Analyse DNS et services
python sharkscan.py -t example.com -m vision

# Détection de fuites de données
python sharkscan.py -t user@example.com -m olfactif

# Scan complet (longue durée)
sudo python sharkscan.py -t 192.168.1.0/24 -m foie --all-ports

# Export JSON des résultats
python sharkscan.py -t 192.168.1.1 -m caudale -o results.json
```

### Options avancées

```bash
# Mode verbeux
python sharkscan.py -t target -m module -v

# Threads personnalisés pour scan rapide
python sharkscan.py -t target -m caudale --threads 100

# Délai entre requêtes (mode furtif)
python sharkscan.py -t target -m dermoid --delay 2

# Scan de ports spécifiques
python sharkscan.py -t target -m caudale --ports 80,443,8080

# Timeout personnalisé
python sharkscan.py -t target -m vision --timeout 10
```

## 📊 Format de sortie

Les résultats peuvent être exportés en JSON pour intégration avec d'autres outils :

```json
{
  "scan_info": {
    "target": "192.168.1.1",
    "module": "caudale",
    "timestamp": "2025-05-31T20:00:00Z",
    "duration": "5.2s"
  },
  "results": {
    "open_ports": [22, 80, 443],
    "services": {
      "22": "SSH",
      "80": "HTTP",
      "443": "HTTPS"
    }
  }
}
```

## 🏗️ Architecture

```
SharkScan/
├── sharkscan.py          # Point d'entrée principal
├── src/
│   ├── __init__.py
│   ├── core/             # Core fonctionnalités
│   │   ├── __init__.py
│   │   ├── scanner.py    # Classe scanner de base
│   │   └── utils.py      # Utilitaires communs
│   └── modules/          # Modules anatomiques
│       ├── __init__.py
│       ├── lateral.py    # Détection passive
│       ├── lorenzini.py  # ARP Scan
│       ├── dents.py      # Vulnérabilités
│       ├── caudale.py    # Scan rapide
│       ├── dermoid.py    # Scan furtif
│       ├── foie.py       # Scan complet
│       ├── olfactif.py   # Fuites de données
│       └── vision.py     # Analyse DNS
├── utils/
│   ├── __init__.py
│   ├── colors.py         # Gestion des couleurs
│   ├── logger.py         # Système de logs
│   └── validators.py     # Validation d'entrées
├── requirements.txt
├── LICENSE
└── README.md
```

## 🔒 Sécurité et conformité

- Conforme aux bonnes pratiques de cybersécurité
- Respect du RGPD pour les données collectées
- Aucune exploitation automatisée sans consentement
- Logs d'audit pour traçabilité

## 📈 Cas d'usage professionnels

1. **Audit de sécurité réseau** - Identification des ports ouverts et services exposés
2. **Test d'intrusion** - Reconnaissance et énumération de cibles
3. **Surveillance SOC** - Détection d'anomalies réseau
4. **Conformité** - Vérification des configurations sécurisées
5. **Réponse à incident** - Analyse rapide d'infrastructure compromise

## 🛠️ Développement

### Contribution

Les contributions sont bienvenues ! Merci de :

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add AmazingFeature'`)
4. Push sur la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

### Tests

```bash
# Lancer les tests unitaires
python -m pytest tests/

# Vérifier la couverture
python -m pytest --cov=src tests/
```

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 👥 Support

Pour les questions de sécurité ou bugs critiques, contactez : security@example.com

## 🙏 Remerciements

- Communauté open source de cybersécurité
- Contributeurs et testeurs
- Inspiré par la nature fascinante des requins

---

**Note**: Cet outil est en développement actif. Utilisez toujours la dernière version pour bénéficier des correctifs de sécurité.
