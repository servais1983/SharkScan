import time
import pytest
from src.core.scanner import Scanner
from src.modules.teeth import TeethScanner
from src.modules.dermal_skin import DermalSkinScanner
from src.modules.vision import VisionScanner

def measure_time(func):
    """Décorateur pour mesurer le temps d'exécution."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"\nTemps d'exécution de {func.__name__}: {execution_time:.2f} secondes")
        return result
    return wrapper

class TestPerformance:
    @pytest.fixture
    def scanner(self):
        return Scanner()

    @measure_time
    def test_quick_scan_performance(self, scanner):
        """Test de performance du scan rapide."""
        scanner.add_module(TeethScanner())
        results = scanner.scan("127.0.0.1", quick=True)
        assert results is not None

    @measure_time
    def test_stealth_scan_performance(self, scanner):
        """Test de performance du scan furtif."""
        scanner.add_module(DermalSkinScanner())
        scanner.configure(stealth=True, timing=5)
        results = scanner.scan("127.0.0.1")
        assert results is not None

    @measure_time
    def test_dns_analysis_performance(self, scanner):
        """Test de performance de l'analyse DNS."""
        scanner.add_module(VisionScanner())
        results = scanner.analyze_dns("localhost")
        assert results is not None

    @measure_time
    def test_memory_usage(self, scanner):
        """Test de l'utilisation de la mémoire."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        scanner.add_module(TeethScanner())
        scanner.add_module(DermalSkinScanner())
        scanner.add_module(VisionScanner())
        
        results = scanner.scan("127.0.0.1")
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_used = final_memory - initial_memory
        
        print(f"\nUtilisation mémoire: {memory_used:.2f} MB")
        assert memory_used < 500  # Ne devrait pas utiliser plus de 500MB

    @measure_time
    def test_concurrent_scans(self, scanner):
        """Test de performance des scans concurrents."""
        import concurrent.futures
        
        def run_scan(target):
            s = Scanner()
            s.add_module(TeethScanner())
            return s.scan(target)
        
        targets = ["127.0.0.1"] * 5
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(run_scan, targets))
        
        assert len(results) == 5
        assert all(r is not None for r in results)

    @measure_time
    def test_large_network_scan(self, scanner):
        """Test de performance sur un grand réseau."""
        scanner.add_module(TeethScanner())
        scanner.configure(timeout=1)  # Timeout court pour le test
        
        # Simuler un scan de grand réseau
        results = scanner.scan("192.168.1.0/24")
        assert results is not None

    def test_resource_cleanup(self, scanner):
        """Test du nettoyage des ressources."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_connections = len(process.connections())
        
        scanner.add_module(TeethScanner())
        scanner.scan("127.0.0.1")
        
        # Attendre que les connexions soient fermées
        time.sleep(2)
        
        final_connections = len(process.connections())
        assert final_connections <= initial_connections 