#!/usr/bin/env python3
"""
Staged Nuclei Scanner for Nmap Output

A service-aware vulnerability scanner that seamlessly continues from staged_nmap.py:
1. Parses Nmap scan results (open_ports_summary.txt or XML from 03_enum/)
2. For each service, runs technology detection (tech-detect.yaml)
3. If technology detected, runs targeted tag-based scans
4. Ingests findings to database using ctem-ingester
5. Segregates results by service category within the same output directory

Workflow per target:
- Known services (MongoDB, MySQL, etc.) -> Direct tag-based scan
- Web/Unknown services -> tech-detect.yaml -> tag-based scan
- All findings -> database ingestion

Results are placed in the nmap output directory (04_db/, 05_network/, 06_web/, etc.)
"""

import argparse
import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set, Tuple
import logging
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


# Service categorization based on port and service name
# Optimized to use specific template directories from https://github.com/projectdiscovery/nuclei-templates
SERVICE_CATEGORIES = {
    'web': {
        'ports': [80, 81, 443, 8000, 8002, 8080, 8081, 8443, 8888, 3000, 4343, 4443, 5000, 7001, 8008, 8009, 9000, 9090, 9443],
        'services': ['http', 'https', 'http-proxy', 'ssl/http', 'http-alt', 'http-rpc-epmap'],
        'templates': [
            # DETECTION & EXPOSURE IDENTIFICATION ONLY
            'http/exposed-panels/',      # ✅ Detect exposed admin panels (MikroTik, Aruba, etc.)
            'http/technologies/',        # ✅ Fingerprint technology stack
            'http/exposures/apis/',      # ✅ Exposed API documentation
            'http/exposures/configs/',   # ✅ Exposed configuration files
            'http/exposures/files/',     # ✅ Sensitive files accessible
            'http/exposures/logs/',      # ✅ Log files exposed
            'http/exposures/backups/',   # ✅ Backup files exposed
        ],
        'scan_ssl': True  # Also scan for SSL/TLS issues on HTTPS
    },
    'database': {
        'ports': [3306, 5432, 1433, 1521, 5984, 9042, 9200, 11211, 27017, 28017, 50000],
        'services': ['mysql', 'postgresql', 'ms-sql', 'mssql', 'oracle', 'mongodb', 
                    'redis', 'cassandra', 'couchdb', 'elasticsearch', 'memcached', 'db2'],
        'templates': [
            # Detection and unauthorized access checks for exposed databases
            'network/detection/',           # ✅ Detect database services (MongoDB, Redis, MySQL, etc.)
            'network/misconfig/',          # ✅ Check for misconfigurations (unauth MongoDB, Redis, etc.)
            'network/enumeration/',        # ✅ Enumerate database information if accessible
        ],
        'network_protocol': True  # Use network protocol scanning
    },
    'network': {
        'ports': [21, 22, 23, 25, 53, 110, 143, 161, 389, 445, 548, 636, 
                 873, 1099, 2049, 3389, 5900, 5985, 5986, 6379],
        'services': ['ftp', 'ssh', 'telnet', 'smtp', 'dns', 'pop3', 'imap', 
                    'snmp', 'ldap', 'microsoft-ds', 'smb', 'afp', 'ldaps',
                    'rsync', 'rmi', 'nfs', 'ms-wbt-server', 'rdp', 'vnc', 
                    'winrm', 'wsman', 'netbios-ssn'],
        'templates': [
            # Service detection and fingerprinting only
            'network/detection/',
        ],
        'network_protocol': True
    },
    'iot': {
        'ports': [1883, 8883, 5683, 502, 20000, 47808, 1900, 5000, 8000],
        'services': ['mqtt', 'mqtts', 'coap', 'modbus', 'dnp3', 'upnp', 'iot'],
        'templates': [
            # IoT exposure detection only
            'network/detection/',
        ],
        'network_protocol': True
    },
    'devops': {
        'ports': [2375, 2376, 6443, 8443, 9418, 50000, 9000, 4040],
        'services': ['docker', 'kubernetes', 'k8s', 'git', 'jenkins', 'gitlab', 'rancher'],
        'templates': [
            # DevOps exposures - dashboards, consoles, APIs
            'http/exposed-panels/',      # ✅ Exposed DevOps panels
            'http/technologies/',        # ✅ Technology detection
            'http/exposures/apis/',      # ✅ Exposed APIs (Docker, K8s)
            'http/exposures/configs/',   # ✅ Config exposures
        ],
        'scan_ssl': True
    },
    'api': {
        'ports': [8000, 8080, 8443, 3000, 5000, 9000],
        'services': ['api', 'rest', 'graphql', 'soap'],
        'templates': [
            # API exposures - documentation, endpoints
            'http/technologies/',        # ✅ API framework detection
            'http/exposures/apis/',      # ✅ Swagger, OpenAPI, GraphQL endpoints
            'http/exposures/configs/',   # ✅ Config exposures
        ],
        'scan_ssl': True
    },
    'messaging': {
        'ports': [5672, 15672, 9092, 2181, 4369, 5671, 61616],
        'services': ['amqp', 'rabbitmq', 'kafka', 'zookeeper', 'activemq', 'mqtt'],
        'templates': [
            # Messaging service exposures - detection only
            'network/detection/',
        ],
        'network_protocol': True
    }
}

# Port-to-service mapping for direct tag-based scanning
PORT_TO_SERVICE_TAG = {
    445: 'smb',
    548: 'smb',
    22: 'ssh',
    3389: 'rdp',
    5900: 'vnc',
    3306: 'mysql',
    5432: 'postgres',
    27017: 'mongodb',
    6379: 'redis',
    2181: 'zookeeper',
    6443: 'kubernetes',
    2375: 'docker',
    2376: 'docker',
    11434: 'ollama',
    9418: 'git',
    1099: 'jmx',
    1883: 'mqtt',
    8883: 'mqtt',
    5672: 'rabbitmq',
    5671: 'rabbitmq',
    15672: 'rabbitmq',
}

# Ports that should run tech-detect first (web services and development tools)
WEB_PORTS = [80, 443, 8000, 8080, 8090, 8443, 8888, 3000, 9000, 50000, 9222, 6000, 63342, 5037, 5555, 5559]

# Technology-specific Nuclei templates and workflows
# Maps detected products/services to specific templates or workflows
TECH_SPECIFIC_TEMPLATES = {
    # According to https://github.com/projectdiscovery/nuclei-templates
    
    # Workflows for specific technologies
    'wordpress': {'type': 'workflow', 'path': 'workflows/wordpress-workflow.yaml'},
    'joomla': {'type': 'workflow', 'path': 'workflows/joomla-workflow.yaml'},
    'drupal': {'type': 'workflow', 'path': 'workflows/drupal-workflow.yaml'},
    'magento': {'type': 'workflow', 'path': 'workflows/magento-workflow.yaml'},
    'prestashop': {'type': 'workflow', 'path': 'workflows/prestashop-workflow.yaml'},
    'opencart': {'type': 'workflow', 'path': 'workflows/opencart-workflow.yaml'},
    'moodle': {'type': 'workflow', 'path': 'workflows/moodle-workflow.yaml'},
    'gitlab': {'type': 'workflow', 'path': 'workflows/gitlab-workflow.yaml'},
    'jenkins': {'type': 'workflow', 'path': 'workflows/jenkins-workflow.yaml'},
    'sharepoint': {'type': 'workflow', 'path': 'workflows/sharepoint-workflow.yaml'},
    'confluence': {'type': 'workflow', 'path': 'workflows/atlassian-confluence-workflow.yaml'},
    'jira': {'type': 'workflow', 'path': 'workflows/atlassian-jira-workflow.yaml'},
    
    # Network exposures for specific services
    'zookeeper': {'type': 'template', 'path': 'network/exposures/'},
    'apache-zookeeper': {'type': 'template', 'path': 'network/exposures/'},
    'dolibarr': {'type': 'template', 'path': 'network/exposures/'},
    'kafka': {'type': 'template', 'path': 'network/exposures/'},
    'cassandra': {'type': 'template', 'path': 'network/exposures/'},
    'memcached': {'type': 'template', 'path': 'network/exposures/'},
    'couchdb': {'type': 'template', 'path': 'network/exposures/'},
    'consul': {'type': 'template', 'path': 'network/exposures/'},
    'etcd': {'type': 'template', 'path': 'network/exposures/'},
    'influxdb': {'type': 'template', 'path': 'network/exposures/'},
    'grafana': {'type': 'template', 'path': 'network/exposures/'},
    
    # Docker/Container platforms
    'docker': {'type': 'template', 'path': 'http/exposures/', 'tags': 'docker'},
    'kubernetes': {'type': 'template', 'path': 'http/exposures/', 'tags': 'kubernetes'},
    'k8s': {'type': 'template', 'path': 'http/exposures/', 'tags': 'kubernetes'},
    
    # CMS platforms (if no workflow available, use targeted templates)
    'cms': {'type': 'template', 'path': 'http/technologies/'},
    'typo3': {'type': 'template', 'path': 'http/technologies/'},
    'phpmyadmin': {'type': 'template', 'path': 'http/exposures/', 'tags': 'phpmyadmin'},
    
    # Databases
    'mysql': {'type': 'template', 'path': 'network/exposures/', 'tags': 'mysql'},
    'postgresql': {'type': 'template', 'path': 'network/exposures/', 'tags': 'postgres'},
    'mongodb': {'type': 'template', 'path': 'network/exposures/', 'tags': 'mongodb'},
    'redis': {'type': 'template', 'path': 'network/exposures/', 'tags': 'redis'},
    'elasticsearch': {'type': 'template', 'path': 'network/exposures/', 'tags': 'elastic'},
    
    # Web servers
    'apache': {'type': 'template', 'path': 'http/misconfiguration/', 'tags': 'apache'},
    'nginx': {'type': 'template', 'path': 'http/misconfiguration/', 'tags': 'nginx'},
    'iis': {'type': 'template', 'path': 'http/misconfiguration/', 'tags': 'iis'},
    'tomcat': {'type': 'template', 'path': 'http/exposures/', 'tags': 'tomcat'},
    'jetty': {'type': 'template', 'path': 'http/exposures/', 'tags': 'jetty'},
}


class NmapNucleiScanner:
    """Scanner that processes Nmap output and runs targeted Nuclei scans"""
    
    def __init__(self, args):
        self.args = args
        self.nmap_dir = Path(args.nmap_output)
        # Use nmap output directory as base for nuclei results (seamless continuation)
        self.output_dir = self.nmap_dir
        
        # Service data structures
        self.services = defaultdict(list)  # category -> [(ip, port, service, product)]
        self.all_services = []  # all discovered services
        self.tech_specific_targets = defaultdict(list)  # technology -> list of targets
        
        # Workflow mode (set during check_requirements)
        self.use_summary = False
        
        # Create output structure by service category within same directory
        self.dirs = {
            'base': self.output_dir,
            '04_db': self.output_dir / '04_db',
            '05_network': self.output_dir / '05_network',
            '06_web': self.output_dir / '06_web',
            '07_api': self.output_dir / '07_api',
            '08_iot': self.output_dir / '08_iot',
            '09_devops': self.output_dir / '09_devops',
            '10_messaging': self.output_dir / '10_messaging',
            '11_other': self.output_dir / '11_other',
        }
        
        for dir_path in self.dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def check_requirements(self):
        """Verify required tools and files"""
        # Check nuclei
        if subprocess.run(['which', 'nuclei'], capture_output=True).returncode != 0:
            logger.error("Missing nuclei. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            sys.exit(1)
        
        # Check nmap output directory
        if not self.nmap_dir.exists():
            logger.error(f"Nmap output directory not found: {self.nmap_dir}")
            sys.exit(1)
        
        # Check for open_ports_summary.txt (preferred, from staged_nmap.py)
        summary_file = self.nmap_dir / 'open_ports_summary.txt'
        enum_dir = self.nmap_dir / '03_enum'
        
        if summary_file.exists():
            logger.info(f"Found open_ports_summary.txt - using streamlined workflow")
            self.use_summary = True
        elif enum_dir.exists() or list(self.nmap_dir.glob('*.xml')):
            logger.info(f"Using XML files for service detection")
            self.use_summary = False
        else:
            logger.error(f"No Nmap results found in: {self.nmap_dir}")
            logger.error("Expected open_ports_summary.txt or XML files")
            sys.exit(1)
        
        # Verify nuclei templates are available
        logger.info("Verifying Nuclei templates...")
        result = subprocess.run(['nuclei', '-tl', '-duc'], capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning("Unable to verify templates, but continuing...")
    
    def parse_open_ports_summary(self, summary_file: Path) -> List[Dict]:
        """
        Parse open_ports_summary.txt from staged_nmap.py
        Format: IP PORT1,PORT2,PORT3
        Example: 10.0.0.1 22,80,443
        """
        services = []
        
        try:
            with open(summary_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    
                    ip = parts[0]
                    ports = parts[1].split(',')
                    
                    for port_str in ports:
                        try:
                            port = int(port_str.strip())
                            service_dict = {
                                'ip': ip,
                                'port': port,
                                'protocol': 'tcp',
                                'service': 'unknown',
                                'product': '',
                                'version': '',
                                'tunnel': ''
                            }
                            services.append(service_dict)
                        except ValueError:
                            logger.warning(f"Invalid port number: {port_str} for {ip}")
                            continue
        
        except Exception as e:
            logger.error(f"Failed to parse {summary_file}: {e}")
            sys.exit(1)
        
        return services
    
    def parse_nmap_xml(self, xml_path: Path) -> List[Dict]:
        """Parse an Nmap XML file and extract service information"""
        services = []
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall('host'):
                # Get IP address
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host.find("address[@addrtype='ipv6']")
                if addr_elem is None:
                    continue
                
                ip = addr_elem.get('addr')
                
                # Get ports
                ports_elem = host.find('ports')
                if ports_elem is None:
                    continue
                
                for port in ports_elem.findall('port'):
                    state = port.find('state')
                    if state is None or state.get('state') not in ('open', 'open|filtered'):
                        continue
                    
                    port_id = int(port.get('portid'))
                    protocol = port.get('protocol', 'tcp')
                    
                    # Get service information
                    service_elem = port.find('service')
                    service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                    product = service_elem.get('product', '') if service_elem is not None else ''
                    version = service_elem.get('version', '') if service_elem is not None else ''
                    tunnel = service_elem.get('tunnel', '') if service_elem is not None else ''
                    
                    service_dict = {
                        'ip': ip,
                        'port': port_id,
                        'protocol': protocol,
                        'service': service_name,
                        'product': product,
                        'version': version,
                        'tunnel': tunnel
                    }
                    
                    # Note: Product detection happens in detect_technology() method
                    
                    services.append(service_dict)
        
        except ET.ParseError as e:
            logger.warning(f"Failed to parse {xml_path}: {e}")
        except Exception as e:
            logger.warning(f"Error processing {xml_path}: {e}")
        
        return services
    
    def categorize_service(self, service: Dict) -> str:
        """Determine the category for a service"""
        port = service['port']
        svc_name = service['service'].lower()
        
        # Check each category
        for category, config in SERVICE_CATEGORIES.items():
            if port in config['ports'] or any(s in svc_name for s in config['services']):
                return category
        
        return 'other'
    
    def detect_technology(self, service: Dict):
        """Detect specific technologies for targeted template selection"""
        product = service.get('product', '').lower()
        service_name = service.get('service', '').lower()
        version = service.get('version', '').lower()
        
        # Priority 1: Check Nmap product detection (most accurate)
        matched_products = []
        for product_key in ['mikrotik', 'routeros', 'aruba', 'hp', 'cisco', 'juniper', 'fortinet', 
                           'palo alto', 'apache', 'nginx', 'iis', 'tomcat', 'weblogic', 'mini_httpd',
                           'wordpress', 'joomla', 'drupal', 'jenkins', 'gitlab', 'docker', 'kubernetes',
                           'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch', 'rabbitmq', 'kafka']:
            if product_key in product or product_key in service_name:
                matched_products.append(product_key)
                logger.info(f"  🎯 Detected {product_key} on {service['ip']}:{service['port']} (from Nmap)")
        
        # Priority 2: Check legacy TECH_SPECIFIC_TEMPLATES for workflows
        for tech, config in TECH_SPECIFIC_TEMPLATES.items():
            if tech in product or tech in service_name or tech in version:
                if tech not in matched_products:
                    matched_products.append(tech)
        
        # Add matched products to tech_specific_targets for targeted scanning
        for tech in matched_products:
            ip = service['ip']
            port = service['port']
            tunnel = service.get('tunnel', '')
            
            # Format target based on service type
            if 'http' in service_name or port in [80, 443, 8000, 8080, 8443, 8888]:
                if port == 443 or tunnel == 'ssl' or 'https' in service_name:
                    target = f"https://{ip}:{port}"
                elif port == 80:
                    target = f"http://{ip}"
                else:
                    target = f"http://{ip}:{port}"
            else:
                target = f"{ip}:{port}"
            
            # Get config from TECH_SPECIFIC_TEMPLATES or create basic one
            config = TECH_SPECIFIC_TEMPLATES.get(tech, {'type': 'template', 'path': 'http/exposures/'})
            
            self.tech_specific_targets[tech].append({
                'target': target,
                'config': config,
                'service': service,
                'product': product  # Store original product string for logging
            })
    
    def load_nmap_results(self):
        """Parse all Nmap XML results and categorize services"""
        logger.info("=" * 60)
        logger.info("STAGE 0: Parsing Nmap Results")
        logger.info("=" * 60)
        
        # Check if we should use summary file or XML files
        summary_file = self.nmap_dir / 'open_ports_summary.txt'
        if hasattr(self, 'use_summary') and self.use_summary and summary_file.exists():
            logger.info(f"Parsing open_ports_summary.txt")
            services = self.parse_open_ports_summary(summary_file)
            self.all_services.extend(services)
        else:
            # Find all XML files (try 03_enum first, then root directory)
            enum_dir = self.nmap_dir / '03_enum'
            if enum_dir.exists():
                xml_files = list(enum_dir.glob('*.xml'))
            else:
                xml_files = list(self.nmap_dir.glob('*.xml'))
            
            logger.info(f"Found {len(xml_files)} Nmap XML files to parse")
            
            # Parse all XML files
            for xml_file in xml_files:
                services = self.parse_nmap_xml(xml_file)
                self.all_services.extend(services)
        
        logger.info(f"✓ Discovered {len(self.all_services)} total services")
        
        # Categorize services and detect specific technologies
        for service in self.all_services:
            category = self.categorize_service(service)
            self.services[category].append(service)
            
            # Check for technology-specific templates
            self.detect_technology(service)
        
        # Print summary
        logger.info("\nService Distribution:")
        for category in sorted(self.services.keys()):
            count = len(self.services[category])
            logger.info(f"  {category:12} : {count:4} services")
        
        # Write service summary
        summary_file = self.output_dir / 'service_summary.txt'
        with open(summary_file, 'w') as f:
            f.write("Service Discovery Summary\n")
            f.write("=" * 80 + "\n\n")
            
            for category in sorted(self.services.keys()):
                f.write(f"\n{category.upper()}\n")
                f.write("-" * 80 + "\n")
                for svc in self.services[category]:
                    f.write(f"{svc['ip']:15} {svc['port']:5} {svc['service']:20} "
                           f"{svc['product']} {svc['version']}\n")
        
        logger.info(f"✓ Service summary: {summary_file}")
        logger.info("")
        
        # Report detected technologies/products
        if self.tech_specific_targets:
            logger.info("\n" + "=" * 80)
            logger.info("🎯 DETECTED PRODUCTS & TECHNOLOGIES")
            logger.info("=" * 80)
            for tech in sorted(self.tech_specific_targets.keys()):
                count = len(self.tech_specific_targets[tech])
                tech_type = self.tech_specific_targets[tech][0]['config']['type']
                product_name = self.tech_specific_targets[tech][0].get('product', tech)
                
                # Show each target
                logger.info(f"\n📦 {tech.upper()}")
                logger.info(f"   Product: {product_name}")
                logger.info(f"   Targets: {count}")
                for target_info in self.tech_specific_targets[tech]:
                    logger.info(f"     • {target_info['target']}")
        logger.info("")
    
    def build_target_lists(self):
        """Build target lists for each service category"""
        logger.info("=" * 60)
        logger.info("STAGE 1: Building Target Lists")
        logger.info("=" * 60)
        
        target_files = {}
        
        for category, services_list in self.services.items():
            if not services_list:
                continue
            
            # Determine output directory
            if category == 'web':
                out_dir = self.dirs['06_web']
            elif category == 'database':
                out_dir = self.dirs['04_db']
            elif category == 'network':
                out_dir = self.dirs['05_network']
            elif category == 'api':
                out_dir = self.dirs['07_api']
            elif category == 'iot':
                out_dir = self.dirs['08_iot']
            elif category == 'devops':
                out_dir = self.dirs['09_devops']
            elif category == 'messaging':
                out_dir = self.dirs['10_messaging']
            else:
                out_dir = self.dirs['11_other']
            
            # Build targets
            targets = []
            for svc in services_list:
                ip = svc['ip']
                port = svc['port']
                service = svc['service']
                tunnel = svc.get('tunnel', '')
                
                # Build appropriate target format
                if category == 'web' or 'http' in service.lower():
                    # Build HTTP/HTTPS URLs
                    if port == 443 or tunnel == 'ssl' or 'https' in service.lower():
                        targets.append(f"https://{ip}:{port}")
                    elif port == 80:
                        targets.append(f"http://{ip}")
                    else:
                        targets.append(f"http://{ip}:{port}")
                        # Also try HTTPS for non-standard ports
                        if port not in [80]:
                            targets.append(f"https://{ip}:{port}")
                else:
                    # For non-web services, use host:port format
                    targets.append(f"{ip}:{port}")
            
            # Write target file
            if targets:
                target_file = out_dir / 'targets.txt'
                with open(target_file, 'w') as f:
                    f.write('\n'.join(targets))
                target_files[category] = target_file
                logger.info(f"  {category:12} : {len(targets):4} targets -> {target_file}")
        
        logger.info(f"\n✓ Built {len(target_files)} target lists\n")
        return target_files
    
    def run_tech_detect_single(self, target: str, out_dir: Path) -> List[str]:
        """
        Run tech-detect.yaml on a single target to identify technology
        Returns list of detected technology tags
        """
        results_file = out_dir / f'tech_detect_{target.replace(":", "_").replace("/", "_")}.json'
        
        cmd = [
            'nuclei',
            '-u', target,
            '-jsonl',
            '-o', str(results_file),
            '-t', 'http/technologies/tech-detect.yaml',
            '-duc',
            '-ni',
            '-silent',
            '-timeout', '5',
            '-retries', '0',
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            logger.warning(f"    ⚠ Tech detection timed out for {target}")
            return []
        
        # Parse detected technologies
        detected_tech = set()
        if results_file.exists() and results_file.stat().st_size > 0:
            with open(results_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        matcher_name = data.get('matcher-name', '').lower()
                        if matcher_name and matcher_name != 'unknown':
                            detected_tech.add(matcher_name)
                            # Also extract product names from template-id
                            template_id = data.get('template-id', '')
                            if 'tech-detect:' in template_id:
                                tech = template_id.split('tech-detect:')[1].split(']')[0]
                                detected_tech.add(tech.lower())
                    except json.JSONDecodeError:
                        continue
        
        return list(detected_tech)
    
    def run_tag_based_scan(self, target: str, tags: str, out_dir: Path) -> Path:
        """
        Run nuclei with specific tags on a target
        Returns path to results file
        """
        safe_target = target.replace(":", "_").replace("/", "_")
        safe_tags = tags.replace(",", "_")
        results_file = out_dir / f'nuclei_{safe_target}_{safe_tags}.json'
        
        cmd = [
            'nuclei',
            '-u', target,
            '-jsonl',
            '-o', str(results_file),
            '-tags', tags,
            '-duc',
            '-ni',
            '-v',
            '-timeout', str(self.args.timeout),
            '-retries', str(self.args.retries),
            '-severity', self.args.severity,
        ]
        
        logger.info(f"    Running: nuclei -tags {tags} -u {target}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.stdout:
                # Print any findings to console
                for line in result.stdout.split('\n'):
                    if line.strip():
                        print(f"      {line}")
        except subprocess.TimeoutExpired:
            logger.warning(f"    ⚠ Scan timed out for {target} with tags {tags}")
        
        return results_file
    
    def ingest_to_database(self, results_file: Path, office_id: str = None, scanner_id: str = None) -> bool:
        """
        Ingest nuclei results to database using ctem-ingester
        Returns True if successful
        """
        # Check if ingestion is disabled
        if hasattr(self.args, 'no_ingest') and self.args.no_ingest:
            return False
        
        if not results_file.exists() or results_file.stat().st_size == 0:
            return False
        
        # Find ingester script
        ingester_script = Path(__file__).parent.parent / 'ctem-ingester' / 'ingestion' / 'ingest.py'
        if not ingester_script.exists():
            logger.warning(f"    ⚠ Ingester script not found: {ingester_script}")
            return False
        
        # Use provided IDs or defaults
        if not office_id:
            office_id = self.args.office_id if hasattr(self.args, 'office_id') else 'default-office'
        if not scanner_id:
            scanner_id = self.args.scanner_id if hasattr(self.args, 'scanner_id') else 'nuclei-scanner'
        
        cmd = [
            'python3',
            str(ingester_script),
            str(results_file),
            f'--office-id={office_id}',
            f'--scanner-id={scanner_id}',
            '--scanner-type=nuclei',
            '--json'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    ingest_result = json.loads(result.stdout)
                    if ingest_result.get('status') == 'success':
                        logger.info(f"      ✓ Ingested: {ingest_result.get('events', 0)} events, "
                                  f"{ingest_result.get('exposures_new', 0)} new exposures")
                        return True
                except json.JSONDecodeError:
                    pass
            else:
                logger.warning(f"    ⚠ Ingestion failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.warning(f"    ⚠ Ingestion timed out")
        except Exception as e:
            logger.warning(f"    ⚠ Ingestion error: {e}")
        
        return False
    
    def scan_target_workflow(self, ip: str, port: int, out_dir: Path):
        """
        Two-phase scanning workflow for a single target:
        1. Tech detection (for web ports) or direct tag scan (for known services)
        2. Tag-based vulnerability scan
        3. Database ingestion
        """
        # Determine if this is a known service port
        if port in PORT_TO_SERVICE_TAG:
            # Direct tag-based scan for known services
            service_tag = PORT_TO_SERVICE_TAG[port]
            target = f"{ip}:{port}"
            
            logger.info(f"  🎯 Known service on {target} -> {service_tag}")
            results_file = self.run_tag_based_scan(target, service_tag, out_dir)
            
            # Ingest if we got results
            if results_file.exists() and results_file.stat().st_size > 0:
                self.ingest_to_database(results_file)
        
        elif port in WEB_PORTS:
            # Two-phase workflow for web services
            # Determine if HTTP or HTTPS
            if port == 443 or port == 8443:
                target = f"https://{ip}:{port}" if port != 443 else f"https://{ip}"
            elif port == 80:
                target = f"http://{ip}"
            else:
                target = f"http://{ip}:{port}"
            
            logger.info(f"  🔍 Web service on {target}")
            
            # Phase 1: Technology detection
            detected_tech = self.run_tech_detect_single(target, out_dir)
            
            if detected_tech:
                logger.info(f"    ✓ Detected: {', '.join(detected_tech[:5])}")
                
                # Phase 2: Run tag-based scan for each detected technology
                for tech in detected_tech[:3]:  # Limit to top 3 to avoid over-scanning
                    results_file = self.run_tag_based_scan(target, tech, out_dir)
                    
                    # Ingest if we got results
                    if results_file.exists() and results_file.stat().st_size > 0:
                        self.ingest_to_database(results_file)
            else:
                logger.info(f"    ℹ No specific technology detected, running general web scan")
                # Run general web exposure scan
                results_file = self.run_tag_based_scan(target, 'exposure', out_dir)
                if results_file.exists() and results_file.stat().st_size > 0:
                    self.ingest_to_database(results_file)
    
    def fingerprint_technologies(self, category: str, target_file: Path, out_dir: Path) -> List[str]:
        """Phase 1: Fingerprint technologies to identify what's running"""
        logger.info(f"  🔍 Phase 1: Technology Detection (using tech-detect.yaml)...")
        
        # Check if target file has valid targets
        if not target_file.exists() or target_file.stat().st_size == 0:
            logger.info(f"    ℹ No targets in file, skipping fingerprinting")
            return []
        
        # Run comprehensive technology detection first
        fingerprint_file = out_dir / 'tech_detect_results.json'
        fingerprint_log = out_dir / 'tech_detect.log'
        
        cmd = [
            'nuclei',
            '-l', str(target_file),
            '-jsonl',
            '-o', str(fingerprint_file),
            '-t', 'http/technologies/tech-detect.yaml',  # Comprehensive Wappalyzer-based detection
            '-duc',
            '-ni',
            '-silent',  # Silent for fingerprinting phase
            '-timeout', '5',  # Give it time to analyze responses
            '-retries', '0',  # No retries for fingerprinting
            '-rate-limit', '200',  # Moderate rate limit
            '-concurrency', '50',  # Moderate concurrency
        ]
        
        # Run fingerprinting with timeout
        try:
            with open(fingerprint_log, 'w') as log:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                
                try:
                    for line in process.stdout:
                        log.write(line)
                    
                    process.wait(timeout=60)  # 60 second timeout for fingerprinting
                except subprocess.TimeoutExpired:
                    process.kill()
                    logger.warning(f"    ⚠ Fingerprinting timed out, continuing anyway")
                    return []
        except KeyboardInterrupt:
            logger.warning(f"    ⚠ Fingerprinting interrupted by user")
            if process:
                process.kill()
            raise
        
        # Parse detected technologies from tech-detect results
        detected_technologies = set()
        detected_details = []
        
        if fingerprint_file.exists():
            with open(fingerprint_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        template_id = data.get('template-id', '').lower()
                        
                        # tech-detect.yaml uses matcher names to identify technologies
                        matcher_name = data.get('matcher-name', '').lower()
                        if matcher_name and matcher_name != 'unknown':
                            detected_technologies.add(matcher_name)
                            detected_details.append({
                                'tech': matcher_name,
                                'target': data.get('matched-at', data.get('host', 'unknown'))
                            })
                        
                        # Also check extracted results
                        extracted = data.get('extracted-results', [])
                        if extracted and isinstance(extracted, list):
                            for tech in extracted:
                                if tech:
                                    detected_technologies.add(tech.lower())
                        
                        # Fall back to tags if available
                        info = data.get('info', {})
                        tags = info.get('tags', [])
                        if isinstance(tags, list):
                            detected_technologies.update([tag.lower() for tag in tags if tag not in ['tech', 'discovery']])
                            
                    except json.JSONDecodeError:
                        continue
        
        detected_list = list(detected_technologies)
        if detected_list:
            logger.info(f"    ✅ Technologies detected: {', '.join(sorted(detected_list)[:15])}")
            if len(detected_list) > 15:
                logger.info(f"       ... and {len(detected_list) - 15} more")
            
            # Show details of what was detected on which targets
            target_summary = {}
            for detail in detected_details:
                target = detail['target']
                tech = detail['tech']
                if target not in target_summary:
                    target_summary[target] = []
                target_summary[target].append(tech)
            
            for target, techs in list(target_summary.items())[:3]:  # Show first 3 targets
                logger.info(f"       {target}: {', '.join(techs[:5])}")
        else:
            logger.info(f"    ℹ No specific technologies detected, will use general templates")
        
        return detected_list
    
    def scan_category(self, category: str, target_file: Path, out_dir: Path):
        """Run Nuclei scan for a specific service category"""
        logger.info(f"Scanning {category} services...")
        
        # Check if target file has valid targets
        if not target_file.exists() or target_file.stat().st_size == 0:
            logger.info(f"  ℹ No valid targets for {category}, skipping scan")
            return 0
        
        # Count number of targets
        with open(target_file, 'r') as f:
            target_count = len([line for line in f if line.strip()])
        
        if target_count == 0:
            logger.info(f"  ℹ No valid targets for {category}, skipping scan")
            return 0
        
        # Phase 1: Fingerprint technologies (for web-based categories)
        detected_tech = []
        if (not self.args.skip_fingerprint and 
            category in ['web', 'api', 'devops'] and 
            SERVICE_CATEGORIES.get(category, {}).get('scan_ssl')):
            try:
                detected_tech = self.fingerprint_technologies(category, target_file, out_dir)
            except KeyboardInterrupt:
                logger.warning(f"  ⚠ Scan interrupted by user")
                raise
        elif self.args.skip_fingerprint:
            logger.info(f"  ⚡ Skipping fingerprinting (fast mode)")
        
        # Skip Phase 2 label if we skipped Phase 1
        phase_label = "Phase 2: " if detected_tech or (category in ['web', 'api', 'devops'] and not self.args.skip_fingerprint) else ""
        
        # Phase 2: Run targeted scans based on detected technologies
        logger.info(f"  🎯 {phase_label}Running targeted vulnerability scans...")
        
        # Determine templates to use
        templates = SERVICE_CATEGORIES.get(category, {}).get('templates', ['exposures/'])
        
        # Build nuclei command
        output_file = out_dir / 'nuclei_results.json'
        log_file = out_dir / 'nuclei.log'
        
        cmd = [
            'nuclei',
            '-l', str(target_file),
            '-jsonl',  # Output in JSONL format (v3+ syntax)
            '-o', str(output_file),
            '-severity', self.args.severity,
            '-rate-limit', str(self.args.rate_limit),
            '-concurrency', str(self.args.concurrency),
            '-timeout', str(self.args.timeout),
            '-retries', str(self.args.retries),
            '-duc',  # Don't check for updates
            '-ni',   # No interactivity
        ]
        
        # Add template paths based on service category configuration
        category_config = SERVICE_CATEGORIES.get(category, {})
        templates = category_config.get('templates', [])
        
        if templates:
            # Use specified templates for this category (excluding technologies/ since we ran it in Phase 1)
            for template in templates:
                if 'technologies' not in template:  # Skip tech detection, we already did it
                    cmd.extend(['-t', template])
        else:
            # Fallback based on category type
            if category == 'other':
                # Use network templates for unknown services
                cmd.extend(['-t', 'network/exposures/', '-t', 'network/detection/'])
            else:
                # Default to HTTP exposures for other categories
                cmd.extend(['-t', 'http/exposures/'])
        
        # Product-specific templates are handled via tech_specific_targets in detect_technology()
        
        # Add tag-based filtering if specific technologies were detected
        if detected_tech:
            # Filter templates to only those relevant to detected technologies
            # Use tags for common technologies
            tech_tags = []
            for tech in detected_tech:
                # Map detected tech to nuclei tags
                if any(x in tech for x in ['wordpress', 'wp']):
                    tech_tags.append('wordpress')
                elif any(x in tech for x in ['joomla']):
                    tech_tags.append('joomla')
                elif any(x in tech for x in ['drupal']):
                    tech_tags.append('drupal')
                elif any(x in tech for x in ['apache', 'httpd']):
                    tech_tags.append('apache')
                elif any(x in tech for x in ['nginx']):
                    tech_tags.append('nginx')
                elif any(x in tech for x in ['iis', 'microsoft']):
                    tech_tags.append('iis')
                elif any(x in tech for x in ['php']):
                    tech_tags.append('php')
                elif any(x in tech for x in ['jenkins']):
                    tech_tags.append('jenkins')
                elif any(x in tech for x in ['docker']):
                    tech_tags.append('docker')
                elif any(x in tech for x in ['kubernetes', 'k8s']):
                    tech_tags.append('kubernetes')
                elif any(x in tech for x in ['tomcat']):
                    tech_tags.append('tomcat')
                elif any(x in tech for x in ['java']):
                    tech_tags.append('java')
                elif any(x in tech for x in ['node', 'express']):
                    tech_tags.append('node')
                elif any(x in tech for x in ['python', 'flask', 'django']):
                    tech_tags.append('python')
            
            if tech_tags:
                # Add tag filtering to focus on detected technologies
                cmd.extend(['-tags', ','.join(tech_tags)])
                logger.info(f"    🏷️  Filtering templates by tags: {', '.join(tech_tags)}")
        
        # Add SSL/TLS scanning for categories that need it
        if category_config.get('scan_ssl') and (
            'https' in str(target_file.parent / 'targets.txt') or 
            any('443' in line or 'https' in line 
                for line in open(target_file).readlines())
        ):
            cmd.extend(['-t', 'ssl/'])
        
        # Always show progress unless explicitly silenced
        if not self.args.silent:
            cmd.append('-v')  # Verbose output to see scanning progress
        else:
            cmd.append('-silent')
        
        # Run scan with real-time output
        logger.info(f"  Command: {' '.join(cmd)}")
        try:
            with open(log_file, 'w') as log:
                # Use Popen to show output in real-time while also logging
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                
                # Stream output to both console and log file
                try:
                    for line in process.stdout:
                        print(line, end='')  # Real-time output to console
                        log.write(line)  # Save to log file
                    
                    process.wait()
                    result = process
                except KeyboardInterrupt:
                    logger.warning(f"\n  ⚠ Scan interrupted by user, cleaning up...")
                    process.kill()
                    process.wait()
                    raise
        except KeyboardInterrupt:
            raise
        
        if result.returncode != 0:
            logger.warning(f"Nuclei scan for {category} exited with code {result.returncode}")
        
        # Combine fingerprint and vulnerability findings
        findings_count = 0
        all_findings = []
        
        # Include fingerprint results
        fingerprint_file = out_dir / 'fingerprint_results.json'
        if fingerprint_file.exists():
            with open(fingerprint_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        all_findings.append(data)
                        findings_count += 1
                    except json.JSONDecodeError:
                        continue
        
        # Include vulnerability scan results
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        all_findings.append(data)
                        findings_count += 1
                    except json.JSONDecodeError:
                        continue
        
        # Create human-readable output from all findings
        if all_findings:
            readable_file = out_dir / 'findings.txt'
            with open(readable_file, 'w') as out:
                out.write(f"Nuclei Scan Results - {category.upper()}\n")
                out.write("=" * 80 + "\n\n")
                out.write(f"Phase 1: Technology Fingerprinting\n")
                out.write(f"Phase 2: Targeted Vulnerability Scanning\n")
                out.write("=" * 80 + "\n\n")
                
                for idx, data in enumerate(all_findings, 1):
                    out.write(f"\n{'=' * 80}\n")
                    out.write(f"Finding #{idx}\n")
                    out.write(f"{'=' * 80}\n")
                    out.write(f"Template: {data.get('template-id', 'unknown')}\n")
                    out.write(f"Name: {data.get('info', {}).get('name', 'unknown')}\n")
                    out.write(f"Severity: {data.get('info', {}).get('severity', 'unknown').upper()}\n")
                    out.write(f"Target: {data.get('matched-at', data.get('host', 'unknown'))}\n")
                    
                    # Show tags if present
                    tags = data.get('info', {}).get('tags', [])
                    if tags:
                        out.write(f"Tags: {', '.join(tags) if isinstance(tags, list) else tags}\n")
                    
                    if 'extracted-results' in data:
                        out.write(f"Extracted: {data['extracted-results']}\n")
                    
                    if 'matcher-name' in data:
                        out.write(f"Matcher: {data['matcher-name']}\n")
                    
                    if 'description' in data.get('info', {}):
                        out.write(f"Description: {data['info']['description']}\n")
        
        logger.info(f"  ✓ {category}: {findings_count} findings")
        return findings_count
    
    def run_streamlined_workflow(self):
        """
        Run streamlined two-phase workflow on all discovered services
        This is used when parsing from open_ports_summary.txt
        """
        logger.info("=" * 60)
        logger.info("STAGE 2: Running Two-Phase Detection & Scanning Workflow")
        logger.info("=" * 60)
        logger.info("Phase 1: Technology Detection (tech-detect.yaml for web services)")
        logger.info("Phase 2: Targeted Vulnerability Scanning (tag-based)")
        logger.info("Phase 3: Database Ingestion (ctem-ingester)")
        logger.info("=" * 60)
        
        # Group services by IP for better logging
        services_by_ip = defaultdict(list)
        for svc in self.all_services:
            services_by_ip[svc['ip']].append(svc)
        
        # Determine output directory (use base or create workflow dir)
        workflow_dir = self.output_dir / '12_workflow_scans'
        workflow_dir.mkdir(parents=True, exist_ok=True)
        
        total_scans = 0
        total_ingestions = 0
        
        # Process each IP and its services
        for ip in sorted(services_by_ip.keys()):
            services = services_by_ip[ip]
            logger.info(f"\n📍 Processing {ip} ({len(services)} open ports)")
            
            # Create IP-specific directory
            ip_dir = workflow_dir / ip.replace('.', '_')
            ip_dir.mkdir(parents=True, exist_ok=True)
            
            for svc in services:
                port = svc['port']
                try:
                    self.scan_target_workflow(ip, port, ip_dir)
                    total_scans += 1
                except KeyboardInterrupt:
                    logger.warning("\n  ⚠ Scan interrupted by user")
                    raise
                except Exception as e:
                    logger.warning(f"  ⚠ Error scanning {ip}:{port} - {e}")
        
        logger.info(f"\n✓ Streamlined workflow complete")
        logger.info(f"  Total targets scanned: {total_scans}")
        logger.info(f"  Results directory: {workflow_dir}")
        
        return {'streamlined': total_scans}
    
    def run_all_scans(self, target_files: Dict[str, Path]):
        """Run Nuclei scans for all service categories"""
        logger.info("=" * 60)
        logger.info("STAGE 2: Running Targeted Vulnerability Scans")
        logger.info("=" * 60)
        
        total_findings = {}
        
        # Map categories to output directories
        category_dir_map = {
            'web': self.dirs['06_web'],
            'database': self.dirs['04_db'],
            'network': self.dirs['05_network'],
            'api': self.dirs['07_api'],
            'iot': self.dirs['08_iot'],
            'devops': self.dirs['09_devops'],
            'messaging': self.dirs['10_messaging'],
            'other': self.dirs['11_other'],
        }
        
        # First, run technology-specific scans
        if self.tech_specific_targets:
            logger.info("\n⚡ Running technology-specific scans...")
            tech_findings = self.run_technology_scans()
            total_findings.update(tech_findings)
        
        # Then run category-based scans
        logger.info("\n📊 Running category-based scans...")
        for category, target_file in target_files.items():
            out_dir = category_dir_map.get(category, self.dirs['11_other'])
            count = self.scan_category(category, target_file, out_dir)
            total_findings[category] = count
        
        logger.info("\n✓ All scans complete")
        logger.info("\nFindings Summary:")
        for category in sorted(total_findings.keys()):
            logger.info(f"  {category:12} : {total_findings[category]:4} findings")
        
        return total_findings
    
    def run_technology_scans(self) -> Dict[str, int]:
        """Run targeted scans for detected technologies"""
        tech_findings = {}
        
        for tech, targets_info in self.tech_specific_targets.items():
            config = targets_info[0]['config']
            tech_type = config['type']
            
            # Create technology-specific directory
            tech_dir = self.output_dir / f'10_tech_{tech}'
            tech_dir.mkdir(parents=True, exist_ok=True)
            
            # Build target list
            targets = [t['target'] for t in targets_info]
            target_file = tech_dir / 'targets.txt'
            with open(target_file, 'w') as f:
                f.write('\n'.join(targets))
            
            logger.info(f"  Scanning {tech} ({tech_type})...")
            
            # Build nuclei command
            output_file = tech_dir / 'nuclei_results.json'
            log_file = tech_dir / 'nuclei.log'
            
            cmd = [
                'nuclei',
                '-l', str(target_file),
                '-jsonl',
                '-o', str(output_file),
                '-severity', self.args.severity,
                '-rate-limit', str(self.args.rate_limit),
                '-concurrency', str(self.args.concurrency),
                '-timeout', str(self.args.timeout),
                '-retries', str(self.args.retries),
                '-duc',
                '-ni',
            ]
            
            # Add workflow or template path
            if tech_type == 'workflow':
                cmd.extend(['-w', config['path']])
            else:
                cmd.extend(['-t', config['path']])
                # Add tags if specified
                if 'tags' in config:
                    cmd.extend(['-tags', config['tags']])
            
            if not self.args.silent:
                cmd.append('-stats')  # Show progress statistics instead of verbose
            else:
                cmd.append('-silent')
            
            # Run scan with real-time output
            logger.info(f"  Command: {' '.join(cmd)}")
            with open(log_file, 'w') as log:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                
                for line in process.stdout:
                    print(line, end='')
                    log.write(line)
                
                process.wait()
            
            # Count findings
            findings_count = 0
            if output_file.exists():
                with open(output_file, 'r') as f:
                    findings_count = sum(1 for _ in f)
            
            tech_findings[f'tech_{tech}'] = findings_count
            logger.info(f"  ✓ {tech}: {findings_count} findings\n")
        
        return tech_findings
    
    
    def generate_summary(self, findings_by_category: Dict[str, int]):
        """Generate final summary report"""
        logger.info("=" * 60)
        logger.info("STAGE 3: Generating Summary Report")
        logger.info("=" * 60)
        
        summary_file = self.output_dir / 'NUCLEI_SUMMARY.txt'
        findings_by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        
        # Collect all findings from all category directories
        for dir_name, dir_path in self.dirs.items():
            if dir_name == 'base':
                continue
            
            results_file = dir_path / 'nuclei_results.json'
            if results_file.exists():
                with open(results_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            severity = data.get('info', {}).get('severity', 'info').lower()
                            if severity in findings_by_severity:
                                findings_by_severity[severity].append(data)
                        except json.JSONDecodeError:
                            continue
        
        # Write summary
        with open(summary_file, 'w') as f:
            f.write("NUCLEI VULNERABILITY SCAN SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Nmap Source: {self.nmap_dir}\n")
            f.write(f"Total Services Discovered: {len(self.all_services)}\n\n")
            
            f.write("SERVICES BY CATEGORY\n")
            f.write("-" * 80 + "\n")
            for category in sorted(self.services.keys()):
                count = len(self.services[category])
                f.write(f"{category:12} : {count:4} services\n")
            
            f.write("\n" + "=" * 80 + "\n\n")
            
            f.write("FINDINGS BY SEVERITY\n")
            f.write("-" * 80 + "\n")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = len(findings_by_severity[severity])
                f.write(f"{severity.upper():12} : {count:4} findings\n")
            
            f.write("\n" + "=" * 80 + "\n\n")
            
            f.write("FINDINGS BY CATEGORY\n")
            f.write("-" * 80 + "\n")
            for category in sorted(findings_by_category.keys()):
                f.write(f"{category:12} : {findings_by_category[category]:4} findings\n")
            
            f.write("\n" + "=" * 80 + "\n\n")
            
            # Detailed findings (top findings per severity)
            for severity in ['critical', 'high', 'medium', 'low']:
                findings = findings_by_severity[severity]
                if findings:
                    f.write(f"\n{severity.upper()} SEVERITY FINDINGS (Top 20)\n")
                    f.write("-" * 80 + "\n\n")
                    
                    for finding in findings[:20]:
                        f.write(f"Template: {finding.get('template-id', 'unknown')}\n")
                        f.write(f"Target: {finding.get('matched-at', finding.get('host', 'unknown'))}\n")
                        f.write(f"Name: {finding.get('info', {}).get('name', 'unknown')}\n")
                        
                        if 'extracted-results' in finding:
                            f.write(f"Details: {finding['extracted-results']}\n")
                        
                        f.write("\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("DETAILED RESULTS BY CATEGORY:\n")
            f.write(f"  Database Services:  {self.dirs['04_db']}/\n")
            f.write(f"  Network Services:   {self.dirs['05_network']}/\n")
            f.write(f"  Web Services:       {self.dirs['06_web']}/\n")
            f.write(f"  API Services:       {self.dirs['07_api']}/\n")
            f.write(f"  IoT Services:       {self.dirs['08_iot']}/\n")
            f.write(f"  DevOps Services:    {self.dirs['09_devops']}/\n")
            f.write(f"  Messaging Services: {self.dirs['10_messaging']}/\n")
            f.write(f"  Other Services:     {self.dirs['11_other']}/\n")
            
            # Add technology-specific results
            if self.tech_specific_targets:
                f.write("\nTECHNOLOGY-SPECIFIC SCANS:\n")
                for tech in sorted(self.tech_specific_targets.keys()):
                    tech_dir = self.output_dir / f'10_tech_{tech}'
                    if tech_dir.exists():
                        f.write(f"  {tech.capitalize():20}: {tech_dir}/\n")
        
        logger.info(f"✓ Summary report: {summary_file}")
        
        # Print summary to console
        print("\n" + "=" * 80)
        print("NUCLEI SCAN COMPLETE - FINDINGS SUMMARY")
        print("=" * 80)
        print("\nBy Severity:")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = len(findings_by_severity[severity])
            print(f"  {severity.upper():12} : {count:4} findings")
        
        print("\nBy Category:")
        for category in sorted(findings_by_category.keys()):
            print(f"  {category:12} : {findings_by_category[category]:4} findings")
        
        print("=" * 80)
        print(f"\nFull report: {summary_file}")
        print(f"Service summary: {self.output_dir / 'service_summary.txt'}")
    
    def run(self):
        """Execute the full Nmap -> Nuclei workflow"""
        start_time = time.time()
        
        try:
            logger.info("=" * 60)
            logger.info("Nmap-Nuclei Service Vulnerability Scanner")
            logger.info("=" * 60)
            logger.info("")
            
            # Check prerequisites
            self.check_requirements()
            
            # Stage 0: Parse Nmap results
            self.load_nmap_results()
            
            if not self.all_services:
                logger.error("No services found in Nmap results!")
                sys.exit(1)
            
            # Choose workflow based on input format
            if hasattr(self, 'use_summary') and self.use_summary:
                # Streamlined workflow for open_ports_summary.txt
                logger.info("Using streamlined two-phase workflow (open_ports_summary.txt)")
                findings = self.run_streamlined_workflow()
            else:
                # Traditional workflow for XML files
                logger.info("Using traditional category-based workflow (XML files)")
                
                # Stage 1: Build target lists
                target_files = self.build_target_lists()
                
                if not target_files:
                    logger.error("No targets to scan!")
                    sys.exit(1)
                
                # Stage 2: Run Nuclei scans
                findings = self.run_all_scans(target_files)
                
                # Stage 3: Generate summary
                self.generate_summary(findings)
            
            elapsed = time.time() - start_time
            logger.info(f"\n✓ Total scan time: {elapsed/60:.1f} minutes")
            logger.info(f"✓ Output directory: {self.output_dir}")
            
        except KeyboardInterrupt:
            logger.warning("\n\n⚠️  Scan interrupted by user (Ctrl+C)")
            logger.info("Partial results may be available in output directories")
            elapsed = time.time() - start_time
            logger.info(f"Scan duration before interruption: {elapsed/60:.1f} minutes")
            sys.exit(130)  # Standard exit code for Ctrl+C


def main():
    parser = argparse.ArgumentParser(
        description='Service-Aware Nuclei Scanner for Nmap Output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Streamlined workflow from open_ports_summary.txt
  python3 staged_nuclei.py -n nmap_staged_out --office-id office-1 --scanner-id scanner-1

  # High-severity only, fast mode
  python3 staged_nuclei.py -n nmap_staged_out -s high --fast

  # Skip database ingestion
  python3 staged_nuclei.py -n nmap_staged_out --no-ingest

Workflow (when using open_ports_summary.txt):
  1. For known services (MongoDB, MySQL, Redis, etc.):
     → Direct tag-based scan (e.g., nuclei -tags mongodb -u 10.0.0.1:27017)
  
  2. For web services (80, 443, 8080, etc.):
     → Phase 1: Technology detection (tech-detect.yaml)
     → Phase 2: Tag-based scan for detected technologies
     → Example: http://10.0.0.1:8080 → detects "mikrotik" → nuclei -tags mikrotik
  
  3. All findings are ingested to database using ctem-ingester

Expected Input:
  The script expects Nmap output from staged_nmap.py:
    - <nmap_dir>/open_ports_summary.txt (PREFERRED - enables streamlined workflow)
    - <nmap_dir>/03_enum/*.xml (Alternative - traditional category-based workflow)

Output Structure (streamlined workflow):
  <nmap_dir>/12_workflow_scans/
    ├── 10_0_0_1/           - Results for 10.0.0.1
    ├── 10_0_0_2/           - Results for 10.0.0.2
    └── ...

Output Structure (traditional workflow):
  <nmap_dir>/04_db/       - Database service vulnerabilities
  <nmap_dir>/05_network/  - Network service vulnerabilities
  <nmap_dir>/06_web/      - Web application vulnerabilities
  <nmap_dir>/07_api/      - API service vulnerabilities
  <nmap_dir>/08_iot/      - IoT service vulnerabilities
  <nmap_dir>/09_devops/   - DevOps platform vulnerabilities
  <nmap_dir>/10_messaging/ - Messaging service vulnerabilities
  <nmap_dir>/11_other/    - Other service vulnerabilities
        """
    )
    
    parser.add_argument('-n', '--nmap-output', required=True,
                       help='Nmap output directory from staged_nmap.py (Nuclei results will be added here)')
    
    # Severity and scope
    parser.add_argument('-s', '--severity', default='medium,high,critical',
                       help='Severity levels to scan (default: medium,high,critical)')
    
    # Performance tuning
    parser.add_argument('-c', '--concurrency', type=int, default=75,
                       help='Concurrent templates per scan (default: 75)')
    parser.add_argument('-rl', '--rate-limit', type=int, default=300,
                       help='Max requests per second (default: 300)')
    parser.add_argument('--timeout', type=int, default=3,
                       help='Request timeout in seconds (default: 3)')
    parser.add_argument('--retries', type=int, default=0,
                       help='Number of retries (default: 0)')
    
    # Speed optimizations
    parser.add_argument('--skip-fingerprint', action='store_true',
                       help='Skip technology fingerprinting for faster scans')
    parser.add_argument('--fast', action='store_true',
                       help='Ultra-fast mode: max speed settings (500 req/s, 100 concurrency, 2s timeout)')
    
    # Output control
    parser.add_argument('--silent', action='store_true',
                       help='Silent mode (no progress output, only results)')
    
    # Database ingestion
    parser.add_argument('--office-id', default='default-office',
                       help='Office ID for database ingestion (default: default-office)')
    parser.add_argument('--scanner-id', default='nuclei-scanner',
                       help='Scanner ID for database ingestion (default: nuclei-scanner)')
    parser.add_argument('--no-ingest', action='store_true',
                       help='Skip database ingestion step')
    
    args = parser.parse_args()
    
    # Handle 'all' severity - convert to all severity levels or omit flag
    if args.severity.lower() == 'all':
        args.severity = 'info,low,medium,high,critical'
    
    # Apply fast mode presets
    if args.fast:
        logger.info("⚡ Fast mode enabled - optimizing for speed")
        args.rate_limit = 500
        args.concurrency = 100
        args.timeout = 2
        args.retries = 0
        args.skip_fingerprint = True
    
    # Validate nmap output exists
    if not os.path.exists(args.nmap_output):
        logger.error(f"Nmap output directory not found: {args.nmap_output}")
        sys.exit(1)
    
    # Run scanner
    scanner = NmapNucleiScanner(args)
    scanner.run()


if __name__ == '__main__':
    main()
