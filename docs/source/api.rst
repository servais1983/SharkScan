API Reference
============

Cette section documente l'API Python de SharkScan.

Core
----

.. automodule:: src.core.report_generator
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: src.core.scanner
   :members:
   :undoc-members:
   :show-inheritance:

Modules
-------

Ligne Latérale
~~~~~~~~~~~~~

.. automodule:: src.modules.lateral_line
   :members:
   :undoc-members:
   :show-inheritance:

Ampoules de Lorenzini
~~~~~~~~~~~~~~~~~~~

.. automodule:: src.modules.lorenzini
   :members:
   :undoc-members:
   :show-inheritance:

Dents
~~~~~

.. automodule:: src.modules.teeth
   :members:
   :undoc-members:
   :show-inheritance:

Nageoire Caudale
~~~~~~~~~~~~~~~

.. automodule:: src.modules.caudal_fin
   :members:
   :undoc-members:
   :show-inheritance:

Peau Dermoïde
~~~~~~~~~~~~

.. automodule:: src.modules.dermal_skin
   :members:
   :undoc-members:
   :show-inheritance:

Foie Géant
~~~~~~~~~

.. automodule:: src.modules.liver
   :members:
   :undoc-members:
   :show-inheritance:

Système Olfactif
~~~~~~~~~~~~~~

.. automodule:: src.modules.olfactory
   :members:
   :undoc-members:
   :show-inheritance:

Vision
~~~~~~

.. automodule:: src.modules.vision
   :members:
   :undoc-members:
   :show-inheritance:

Utilitaires
----------

.. automodule:: src.utils.logger
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: src.utils.config
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: src.utils.validators
   :members:
   :undoc-members:
   :show-inheritance:

Exemples d'Utilisation
--------------------

Scanner de Base
~~~~~~~~~~~~~

.. code-block:: python

   from src.core.scanner import Scanner
   from src.modules.teeth import TeethScanner

   # Créer une instance du scanner
   scanner = Scanner()

   # Ajouter le module de vulnérabilités
   scanner.add_module(TeethScanner())

   # Lancer le scan
   results = scanner.scan("192.168.1.0/24")

   # Analyser les résultats
   for host, data in results.items():
       print(f"Host: {host}")
       print(f"Vulnérabilités: {data['vulnerabilities']}")

Scan Furtif
~~~~~~~~~~

.. code-block:: python

   from src.core.scanner import Scanner
   from src.modules.dermal_skin import DermalSkinScanner

   # Créer une instance du scanner
   scanner = Scanner()

   # Ajouter le module furtif
   scanner.add_module(DermalSkinScanner())

   # Configurer le scan furtif
   scanner.configure(stealth=True, timing=5)

   # Lancer le scan
   results = scanner.scan("10.0.0.0/24")

Analyse DNS
~~~~~~~~~~

.. code-block:: python

   from src.core.scanner import Scanner
   from src.modules.vision import VisionScanner

   # Créer une instance du scanner
   scanner = Scanner()

   # Ajouter le module d'analyse DNS
   scanner.add_module(VisionScanner())

   # Lancer l'analyse
   results = scanner.analyze_dns("example.com")

   # Afficher les résultats
   print(f"Enregistrements DNS: {results['records']}")
   print(f"Services détectés: {results['services']}") 