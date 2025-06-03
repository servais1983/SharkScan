SharkScan Documentation
=====================

SharkScan est un scanner de sécurité réseau professionnel qui combine plusieurs techniques d'analyse pour fournir une vue complète de la sécurité de votre réseau.

.. toctree::
   :maxdepth: 2
   :caption: Contenu:

   installation
   usage
   modules
   api
   development
   security

Installation
-----------

Voir :doc:`installation` pour les instructions d'installation.

Utilisation Rapide
----------------

.. code-block:: bash

   # Scan rapide du réseau local
   sharkscan scan --quick

   # Découverte ARP
   sharkscan discover --arp

   # Scan de vulnérabilités
   sharkscan scan --vuln

   # Scan furtif
   sharkscan scan --stealth

   # Analyse DNS
   sharkscan analyze --dns

Modules
-------

SharkScan est composé de plusieurs modules spécialisés :

* **Ligne Latérale** : Détection passive du trafic
* **Ampoules de Lorenzini** : Découverte réseau via ARP Scan
* **Dents** : Scan de vulnérabilités avancé avec nmap
* **Nageoire Caudale** : Scan rapide des ports TCP
* **Peau Dermoïde** : Scan furtif pour éviter les IDS/IPS
* **Foie Géant** : Scan complet de longue durée
* **Système Olfactif** : Détection des fuites de données
* **Vision** : Analyse DNS et détection des services

Pour plus de détails, voir :doc:`modules`.

API
---

SharkScan fournit une API Python complète pour l'intégration dans vos propres outils.
Voir :doc:`api` pour la documentation de l'API.

Développement
------------

Instructions pour les développeurs souhaitant contribuer au projet.
Voir :doc:`development`.

Sécurité
--------

Politique de sécurité et bonnes pratiques.
Voir :doc:`security`.

Indices et tables
================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search` 