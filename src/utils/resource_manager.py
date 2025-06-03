import psutil
import gc
import logging
from typing import Optional, Dict, Any
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class ResourceManager:
    """Gestionnaire de ressources pour optimiser l'utilisation de la mémoire et du CPU."""
    
    def __init__(self, max_memory_mb: int = 500, max_cpu_percent: int = 80):
        self.max_memory_mb = max_memory_mb
        self.max_cpu_percent = max_cpu_percent
        self.process = psutil.Process()
        self._initial_memory = self.process.memory_info().rss / 1024 / 1024
        
    def check_resources(self) -> bool:
        """Vérifie si les ressources sont disponibles."""
        current_memory = self.process.memory_info().rss / 1024 / 1024
        cpu_percent = psutil.cpu_percent()
        
        if current_memory > self.max_memory_mb:
            logger.warning(f"Utilisation mémoire élevée: {current_memory:.2f}MB")
            return False
            
        if cpu_percent > self.max_cpu_percent:
            logger.warning(f"Utilisation CPU élevée: {cpu_percent}%")
            return False
            
        return True
        
    def get_memory_usage(self) -> float:
        """Retourne l'utilisation actuelle de la mémoire en MB."""
        return self.process.memory_info().rss / 1024 / 1024
        
    def get_cpu_usage(self) -> float:
        """Retourne l'utilisation actuelle du CPU en pourcentage."""
        return psutil.cpu_percent()
        
    def cleanup(self):
        """Nettoie les ressources non utilisées."""
        gc.collect()
        
    @contextmanager
    def monitor_resources(self, operation_name: str):
        """Contexte pour surveiller l'utilisation des ressources pendant une opération."""
        start_memory = self.get_memory_usage()
        start_cpu = self.get_cpu_usage()
        
        try:
            yield
        finally:
            end_memory = self.get_memory_usage()
            end_cpu = self.get_cpu_usage()
            
            memory_diff = end_memory - start_memory
            cpu_diff = end_cpu - start_cpu
            
            logger.info(f"Opération {operation_name}:")
            logger.info(f"  - Mémoire: {memory_diff:+.2f}MB")
            logger.info(f"  - CPU: {cpu_diff:+.2f}%")
            
            if memory_diff > 100:  # Plus de 100MB utilisés
                logger.warning(f"Utilisation mémoire importante pour {operation_name}")
                self.cleanup()
                
    def optimize_memory(self, target_mb: Optional[float] = None):
        """Optimise l'utilisation de la mémoire."""
        if target_mb is None:
            target_mb = self._initial_memory
            
        current_memory = self.get_memory_usage()
        if current_memory > target_mb:
            logger.info(f"Optimisation mémoire: {current_memory:.2f}MB -> {target_mb:.2f}MB")
            self.cleanup()
            
    def get_resource_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques d'utilisation des ressources."""
        return {
            "memory_mb": self.get_memory_usage(),
            "cpu_percent": self.get_cpu_usage(),
            "connections": len(self.process.connections()),
            "threads": self.process.num_threads(),
            "open_files": len(self.process.open_files()),
        } 