"""
Olfactory Module - Data leak detection
Detects exposed credentials and sensitive data leaks
"""

import re
import json
import time
import hashlib
import requests
from datetime import datetime
from rich.table import Table
from rich.panel import Panel

from src.core.scanner import BaseScanner


class OlfactoryScanner(BaseScanner):
    """Scanner for detecting data leaks and exposed credentials"""
    
    def __init__(self, args):
        super().__init__(args)
        self.timeout = args.timeout or 30
        
        # API endpoints (using public/free services)
        self.hibp_api = "https://api.pwnedpasswords.com/range/"
        self.breach_api = "https://haveibeenpwned.com/api/v3/"
        
    def check_email_breach(self, email: str) -> dict:
        """Check if email has been in known breaches"""
        result = {
            'email': email,
            'breached': False,
            'breach_count': 0,
            'breaches': [],
            'paste_count': 0,
            'pastes': []
        }
        
        # Note: HIBP API requires API key for email searches
        # This is a demonstration of the structure
        # In production, you would need to implement proper API authentication
        
        # For demonstration, we'll check the email format and provide guidance
        if self._is_valid_email(email):
            result['status'] = 'Email format valid'
            result['recommendation'] = 'Use Have I Been Pwned API with authentication for real checks'
        else:
            result['status'] = 'Invalid email format'
            
        return result
    
    def check_password_breach(self, password: str) -> dict:
        """Check if password has been exposed in breaches"""
        result = {
            'password_hash': self._hash_password(password),
            'breached': False,
            'occurrences': 0
        }
        
        try:
            # Hash the password
            sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]
            
            # Query the API
            response = requests.get(f"{self.hibp_api}{prefix}", timeout=self.timeout)
            
            if response.status_code == 200:
                # Check if our suffix appears in the response
                for line in response.text.splitlines():
                    if ':' in line:
                        found_suffix, count = line.split(':')
                        if found_suffix == suffix:
                            result['breached'] = True
                            result['occurrences'] = int(count)
                            break
            
        except Exception as e:
            self.logger.error(f"Error checking password: {str(e)}")
            result['error'] = str(e)
        
        return result
    
    def check_dns_leaks(self, domain: str) -> dict:
        """Check for DNS configuration leaks"""
        import dns.resolver
        
        result = {
            'domain': domain,
            'dns_leaks': [],
            'exposed_records': []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            
            # Check various DNS record types
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    for rdata in answers:
                        record_data = {
                            'type': record_type,
                            'value': str(rdata)
                        }
                        result['exposed_records'].append(record_data)
                        
                        # Check for potential leaks
                        if record_type == 'TXT':
                            leak_check = self._check_txt_record_leak(str(rdata))
                            if leak_check:
                                result['dns_leaks'].append(leak_check)
                                
                except dns.resolver.NXDOMAIN:
                    pass
                except dns.resolver.NoAnswer:
                    pass
                except Exception as e:
                    self.logger.debug(f"Error checking {record_type} record: {str(e)}")
            
        except Exception as e:
            self.logger.error(f"Error checking DNS: {str(e)}")
            result['error'] = str(e)
        
        return result
    
    def check_git_exposure(self, url: str) -> dict:
        """Check for exposed .git directories"""
        result = {
            'url': url,
            'git_exposed': False,
            'config_exposed': False,
            'sensitive_files': []
        }
        
        # Common exposed paths
        paths = [
            '.git/config',
            '.git/HEAD',
            '.git/index',
            '.env',
            '.env.local',
            '.env.production',
            'config.php',
            'wp-config.php',
            'configuration.php',
            '.htaccess',
            '.htpasswd',
            'web.config',
            '.DS_Store',
            'Thumbs.db',
            'composer.json',
            'package.json',
            '.npmrc',
            'yarn.lock',
            'Gemfile.lock',
            'requirements.txt'
        ]
        
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        base_url = url.rstrip('/')
        
        for path in paths:
            try:
                check_url = f"{base_url}/{path}"
                response = requests.get(check_url, timeout=5, allow_redirects=False)
                
                if response.status_code == 200:
                    result['sensitive_files'].append({
                        'path': path,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
                    
                    if path.startswith('.git'):
                        result['git_exposed'] = True
                    elif 'config' in path:
                        result['config_exposed'] = True
                        
            except Exception as e:
                self.logger.debug(f"Error checking {check_url}: {str(e)}")
        
        return result
    
    def _check_txt_record_leak(self, txt_record: str) -> dict:
        """Check TXT record for potential sensitive data"""
        sensitive_patterns = [
            (r'(api[_-]?key|apikey)\s*[:=]\s*[\w-]+', 'API Key'),
            (r'(secret|token)\s*[:=]\s*[\w-]+', 'Secret/Token'),
            (r'(password|passwd|pwd)\s*[:=]\s*[\w-]+', 'Password'),
            (r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}', 'Email'),
            (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP Address')
        ]
        
        for pattern, leak_type in sensitive_patterns:
            if re.search(pattern, txt_record, re.IGNORECASE):
                return {
                    'type': leak_type,
                    'record': txt_record[:100] + '...' if len(txt_record) > 100 else txt_record
                }
        
        return None
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _hash_password(self, password: str) -> str:
        """Create a hash representation of password for display"""
        return hashlib.sha256(password.encode()).hexdigest()[:8] + '...'
    
    def scan(self, target: str):
        """Perform data leak detection scan"""
        results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'checks_performed': [],
            'leaks_found': [],
            'recommendations': []
        }
        
        # Determine scan type based on target
        if self._is_valid_email(target):
            # Email breach check
            self.logger.info(f"Checking email breaches for {target}")
            breach_result = self.check_email_breach(target)
            results['checks_performed'].append('email_breach')
            results['email_breach'] = breach_result
            
        elif target.startswith(('http://', 'https://')) or '.' in target:
            # Website/domain checks
            self.logger.info(f"Checking website exposure for {target}")
            
            # Git exposure check
            git_result = self.check_git_exposure(target)
            results['checks_performed'].append('git_exposure')
            results['git_exposure'] = git_result
            
            if git_result['git_exposed']:
                results['leaks_found'].append('Git repository exposed')
                results['recommendations'].append('Remove or protect .git directory')
            
            # DNS leak check
            domain = target.replace('https://', '').replace('http://', '').split('/')[0]
            dns_result = self.check_dns_leaks(domain)
            results['checks_performed'].append('dns_leaks')
            results['dns_leaks'] = dns_result
            
            if dns_result['dns_leaks']:
                results['leaks_found'].extend([f"DNS {leak['type']} leak" for leak in dns_result['dns_leaks']])
                results['recommendations'].append('Review and sanitize DNS TXT records')
                
        else:
            # Assume it's a password
            self.logger.info("Checking password breach status")
            password_result = self.check_password_breach(target)
            results['checks_performed'].append('password_breach')
            results['password_breach'] = password_result
            
            if password_result['breached']:
                results['leaks_found'].append('Password found in breach databases')
                results['recommendations'].append('Change this password immediately')
                results['recommendations'].append('Use a unique password for each service')
                results['recommendations'].append('Enable two-factor authentication')
        
        return results
    
    def display_results(self, results):
        """Display scan results"""
        from rich.console import Console
        console = Console()
        
        # Header
        summary = f"""🎯 Target: {results['target']}
🕰️ Scan Time: {results['scan_time']}
🔍 Checks Performed: {', '.join(results['checks_performed'])}
⚠️  Leaks Found: {len(results['leaks_found'])}"""
        
        console.print(Panel(summary, title="🦈 Olfactory Data Leak Detection", border_style="blue"))
        
        # Email breach results
        if 'email_breach' in results:
            email_data = results['email_breach']
            console.print(f"\n[cyan]Email Breach Check:[/cyan]")
            console.print(f"  • Email: {email_data['email']}")
            console.print(f"  • Status: {email_data['status']}")
            if 'recommendation' in email_data:
                console.print(f"  • Note: {email_data['recommendation']}")
        
        # Password breach results
        if 'password_breach' in results:
            pwd_data = results['password_breach']
            console.print(f"\n[cyan]Password Breach Check:[/cyan]")
            console.print(f"  • Password Hash: {pwd_data['password_hash']}")
            if pwd_data['breached']:
                console.print(f"  • [red]BREACHED![/red] Found {pwd_data['occurrences']:,} times in breach databases")
            else:
                console.print(f"  • [green]Not found in breach databases[/green]")
        
        # Git exposure results
        if 'git_exposure' in results:
            git_data = results['git_exposure']
            console.print(f"\n[cyan]Git/Config Exposure Check:[/cyan]")
            console.print(f"  • URL: {git_data['url']}")
            
            if git_data['sensitive_files']:
                console.print(f"  • [red]Exposed files found:[/red]")
                for file in git_data['sensitive_files']:
                    console.print(f"    - {file['path']} (Size: {file['size']} bytes)")
            else:
                console.print(f"  • [green]No exposed files found[/green]")
        
        # DNS leak results
        if 'dns_leaks' in results:
            dns_data = results['dns_leaks']
            console.print(f"\n[cyan]DNS Configuration:[/cyan]")
            console.print(f"  • Domain: {dns_data['domain']}")
            
            if dns_data['dns_leaks']:
                console.print(f"  • [yellow]Potential leaks in DNS records:[/yellow]")
                for leak in dns_data['dns_leaks']:
                    console.print(f"    - {leak['type']}: {leak['record']}")
            
            # Show record count
            record_types = {}
            for record in dns_data['exposed_records']:
                record_types[record['type']] = record_types.get(record['type'], 0) + 1
            
            if record_types:
                console.print(f"  • DNS Records found: {', '.join([f'{k}({v})' for k, v in record_types.items()])}")
        
        # Recommendations
        if results['recommendations']:
            console.print(f"\n[yellow]💡 Recommendations:[/yellow]")
            for rec in results['recommendations']:
                console.print(f"  • {rec}")
        
        # Security tips
        console.print(f"\n[blue]🔒 General Security Tips:[/blue]")
        console.print("  • Use unique, strong passwords for each service")
        console.print("  • Enable 2FA wherever possible")
        console.print("  • Regularly monitor for data breaches")
        console.print("  • Keep sensitive files out of public directories")
        console.print("  • Review and audit DNS records regularly")