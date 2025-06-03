"""
Optimized parallel scanning system for SharkScan
"""

import asyncio
import aiohttp
import socket
import time
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass
from .secure_logger import SecureLogger

@dataclass
class ScanTask:
    """Scan task configuration"""
    target: str
    port: Optional[int] = None
    protocol: str = 'tcp'
    timeout: float = 5.0
    retries: int = 2
    delay: float = 0.0

class ParallelScanner:
    """Optimized parallel scanning system"""
    
    def __init__(self, max_workers: int = 50, use_processes: bool = False):
        """
        Initialize parallel scanner
        
        Args:
            max_workers (int): Maximum number of concurrent workers
            use_processes (bool): Whether to use processes instead of threads
        """
        self.logger = SecureLogger("parallel_scanner")
        self.max_workers = max_workers
        self.use_processes = use_processes
        self.executor = ProcessPoolExecutor(max_workers=max_workers) if use_processes else ThreadPoolExecutor(max_workers=max_workers)
        self.session = None
        self._setup_logging()
        self._setup_connection_pool()
        
    def _setup_logging(self):
        """Setup logging configuration"""
        self.logger.info("Initializing parallel scanner", 
                        max_workers=self.max_workers,
                        use_processes=self.use_processes)
        
    def _setup_connection_pool(self):
        """Setup connection pool for better performance"""
        self.connection_pool = {
            'tcp': {},
            'http': {}
        }
        
    async def _create_session(self):
        """Create aiohttp session with optimized settings"""
        if not self.session:
            connector = aiohttp.TCPConnector(
                limit=self.max_workers,
                ttl_dns_cache=300,
                use_dns_cache=True,
                force_close=False,
                enable_cleanup_closed=True
            )
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=connector,
                headers={'User-Agent': 'SharkScan/1.0'}
            )
            
    async def _close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None
            
    def _get_connection(self, target: str, port: int, protocol: str) -> Optional[socket.socket]:
        """Get or create connection from pool"""
        key = f"{target}:{port}"
        if key in self.connection_pool[protocol]:
            conn = self.connection_pool[protocol][key]
            try:
                # Test if connection is still alive
                conn.getpeername()
                return conn
            except:
                del self.connection_pool[protocol][key]
        return None
        
    def _store_connection(self, target: str, port: int, protocol: str, conn: socket.socket):
        """Store connection in pool"""
        key = f"{target}:{port}"
        self.connection_pool[protocol][key] = conn
        
    async def scan_port(self, task: ScanTask) -> Dict[str, Any]:
        """
        Scan a single port with optimized connection handling
        
        Args:
            task (ScanTask): Scan task configuration
            
        Returns:
            Dict[str, Any]: Scan results
        """
        result = {
            'target': task.target,
            'port': task.port,
            'protocol': task.protocol,
            'status': 'closed',
            'error': None,
            'response_time': None,
            'banner': None
        }
        
        try:
            start_time = time.time()
            
            if task.protocol == 'tcp':
                # Try to get connection from pool
                sock = self._get_connection(task.target, task.port, 'tcp')
                
                if not sock:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(task.timeout)
                    
                for attempt in range(task.retries):
                    try:
                        if not sock.getpeername():
                            sock.connect((task.target, task.port))
                        result['status'] = 'open'
                        
                        # Try to get banner
                        try:
                            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                            banner = sock.recv(1024)
                            if banner:
                                result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                        except:
                            pass
                            
                        # Store connection in pool
                        self._store_connection(task.target, task.port, 'tcp', sock)
                        break
                        
                    except (socket.timeout, ConnectionRefusedError):
                        if attempt == task.retries - 1:
                            raise
                        time.sleep(task.delay)
                        
            elif task.protocol == 'http':
                await self._create_session()
                async with self.session.get(
                    f"http://{task.target}:{task.port}",
                    allow_redirects=True,
                    ssl=False
                ) as response:
                    result['status'] = 'open'
                    result['http_status'] = response.status
                    result['headers'] = dict(response.headers)
                    
                    # Try to get response body for analysis
                    try:
                        result['body'] = await response.text()
                    except:
                        pass
                        
            result['response_time'] = time.time() - start_time
            
        except Exception as e:
            result['error'] = str(e)
            self.logger.warning(f"Port scan failed: {str(e)}", 
                              target=task.target,
                              port=task.port,
                              protocol=task.protocol)
            
        return result
        
    async def scan_target(self, target: str, ports: List[int], protocol: str = 'tcp') -> List[Dict[str, Any]]:
        """
        Scan multiple ports on a target with optimized batching
        
        Args:
            target (str): Target to scan
            ports (List[int]): Ports to scan
            protocol (str): Protocol to use
            
        Returns:
            List[Dict[str, Any]]: Scan results
        """
        # Sort ports for better performance
        ports = sorted(ports)
        
        # Create tasks in batches
        batch_size = min(50, len(ports))
        results = []
        
        for i in range(0, len(ports), batch_size):
            batch_ports = ports[i:i + batch_size]
            tasks = [
                ScanTask(target=target, port=port, protocol=protocol)
                for port in batch_ports
            ]
            
            try:
                # Execute batch of scans
                batch_results = await asyncio.gather(*[self.scan_port(task) for task in tasks])
                results.extend(batch_results)
                
                # Log batch progress
                open_ports = [r for r in batch_results if r['status'] == 'open']
                self.logger.info("Batch scan completed",
                               target=target,
                               batch_size=len(batch_ports),
                               open_ports=len(open_ports))
                
            except Exception as e:
                self.logger.error(f"Batch scan failed: {str(e)}", 
                                target=target,
                                batch_start=i,
                                batch_size=batch_size)
                
        return results
        
    def scan_range(self, targets: List[str], ports: List[int], protocol: str = 'tcp') -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan multiple targets with optimized resource management
        
        Args:
            targets (List[str]): Targets to scan
            ports (List[int]): Ports to scan
            protocol (str): Protocol to use
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: Scan results by target
        """
        results = {}
        
        try:
            # Create event loop with optimized settings
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Configure event loop for better performance
            loop.set_debug(False)
            
            # Create scan tasks for each target
            scan_tasks = [
                self.scan_target(target, ports, protocol)
                for target in targets
            ]
            
            # Execute all scans with timeout
            target_results = loop.run_until_complete(
                asyncio.wait_for(
                    asyncio.gather(*scan_tasks),
                    timeout=300  # 5 minutes timeout
                )
            )
            
            # Organize results by target
            for target, result in zip(targets, target_results):
                results[target] = result
                
            # Log summary
            total_open = sum(len([r for r in res if r['status'] == 'open']) for res in results.values())
            self.logger.info("Range scan completed",
                           total_targets=len(targets),
                           total_ports=len(ports),
                           total_open=total_open)
            
        except asyncio.TimeoutError:
            self.logger.error("Range scan timed out")
        except Exception as e:
            self.logger.error(f"Range scan failed: {str(e)}")
            
        finally:
            # Cleanup
            loop.close()
            self._cleanup_connections()
            
        return results
        
    def _cleanup_connections(self):
        """Cleanup connection pool"""
        for protocol in self.connection_pool:
            for conn in self.connection_pool[protocol].values():
                try:
                    conn.close()
                except:
                    pass
            self.connection_pool[protocol].clear()
            
    def __del__(self):
        """Cleanup on object destruction"""
        self._cleanup_connections()
        if self.executor:
            self.executor.shutdown(wait=False) 