#!/usr/bin/env python3
"""
Nuclei Vulnerability Scanner - Service-Aware Module

Combines efficiency of open_ports_summary.txt with accuracy of Nmap XML validation.

Workflow:
1. Parse open_ports_summary.txt for quick port list
2. Validate/enrich with 03_enum/*.xml for service detection
3. Run targeted scans based on detected services
4. Output simple, flat files (following Nmap's philosophy)

Output:
  04_nuclei/
  ├── scan_results.jsonl     - All findings (one JSON per line)
  ├── results_summary.txt    - Human-readable summary
  └── scan_log.txt           - Execution log
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


# ==================== Configuration ====================

# Known services for direct tag-based scanning
KNOWN_SERVICES = {
    22: {'name': 'ssh', 'tags': 'ssh'},
    445: {'name': 'smb', 'tags': 'smb'},
    548: {'name': 'afp', 'tags': 'smb,apple'},
    1883: {'name': 'mqtt', 'tags': 'mqtt,iot'},
    3306: {'name': 'mysql', 'tags': 'mysql,database'},
    3389: {'name': 'rdp', 'tags': 'rdp'},
    5432: {'name': 'postgres', 'tags': 'postgres,database'},
    5672: {'name': 'rabbitmq', 'tags': 'rabbitmq,amqp'},
    5900: {'name': 'vnc', 'tags': 'vnc'},
    6379: {'name': 'redis', 'tags': 'redis,database'},
    8883: {'name': 'mqtts', 'tags': 'mqtt,iot'},
    27017: {'name': 'mongodb', 'tags': 'mongodb,database'},
}

# Web service ports (require tech detection first)
WEB_PORTS = {80, 443, 3000, 4380, 5000, 5601, 7000, 8000, 8080, 8081, 8082, 8083, 8090, 8443, 8888, 9000, 9200, 9443, 10443}

# Technology-to-workflow/template mapping
TECH_WORKFLOWS = {
    'jenkins': 'workflows/jenkins-workflow.yaml',
    'wordpress': 'workflows/wordpress-workflow.yaml',
    'gitlab': 'workflows/gitlab-workflow.yaml',
    'drupal': 'workflows/drupal-workflow.yaml',
    'joomla': 'workflows/joomla-workflow.yaml',
}

TECH_TEMPLATES = {
    'express': 'http/misconfiguration/node-express-dev-env.yaml',
    'apache': 'http/misconfiguration/',
    'nginx': 'http/misconfiguration/',
    'tomcat': 'http/exposures/',
    'kafka': 'network/exposures/',
}


# ==================== Data Classes ====================

@dataclass
class Service:
    """Represents a discovered service"""
    ip: str
    port: int
    service_name: str = 'unknown'
    product: str = ''
    version: str = ''
    extrainfo: str = ''
    
    @property
    def target_url(self) -> str:
        """Generate appropriate target URL/format"""
        if self.port in [443, 8443]:
            return f"https://{self.ip}:{self.port}" if self.port != 443 else f"https://{self.ip}"
        elif self.port == 80:
            return f"http://{self.ip}"
        elif self.port in WEB_PORTS:
            return f"http://{self.ip}:{self.port}"
        else:
            return f"{self.ip}:{self.port}"
    
    @property
    def is_known_service(self) -> bool:
        """Check if this is a known service"""
        return self.port in KNOWN_SERVICES
    
    @property
    def is_web_service(self) -> bool:
        """Check if this is a web service"""
        return self.port in WEB_PORTS or 'http' in self.service_name.lower()


# ==================== Scanner Class ====================

class NucleiScanner:
    """Simplified, efficient Nuclei vulnerability scanner"""
    
    def __init__(self, args):
        self.args = args
        self.nmap_dir = Path(args.nmap_output)
        self.output_dir = self.nmap_dir / '04_nuclei'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Simple output files (following open_ports_summary.txt philosophy)
        self.results_file = self.output_dir / 'scan_results.jsonl'
        self.summary_file = self.output_dir / 'results_summary.txt'
        self.log_file = self.output_dir / 'scan_log.txt'
        
        # Service tracking
        self.services: List[Service] = []
        self.service_map: Dict[str, Service] = {}  # ip:port -> Service
        self.findings = []
        
        # Statistics
        self.stats = {
            'services_total': 0,
            'services_validated': 0,
            'services_scanned': 0,
            'technologies_detected': set(),
            'findings_total': 0,
            'findings_by_severity': defaultdict(int)
        }
    
    def check_requirements(self):
        """Verify nuclei is installed"""
        logger.info("[*] Checking requirements...")
        result = subprocess.run(['which', 'nuclei'], capture_output=True)
        if result.returncode != 0:
            logger.error("Nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            sys.exit(1)
        
        if not self.nmap_dir.exists():
            logger.error(f"Nmap output directory not found: {self.nmap_dir}")
            sys.exit(1)
        
        logger.info("[✓] Requirements met")
    
    def parse_open_ports_summary(self) -> List[Service]:
        """Quick parse of open_ports_summary.txt"""
        summary_file = self.nmap_dir / 'open_ports_summary.txt'
        if not summary_file.exists():
            return []
        
        services = []
        with open(summary_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                ip = parts[0]
                for port_str in parts[1].split(','):
                    try:
                        port = int(port_str.strip())
                        service = Service(ip=ip, port=port)
                        services.append(service)
                        self.service_map[f"{ip}:{port}"] = service
                    except ValueError:
                        continue
        
        return services
    
    def validate_with_xml(self, xml_path: Path):
        """Enrich services with detailed info from Nmap XML"""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall('host'):
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    continue
                
                ip = addr_elem.get('addr')
                ports_elem = host.find('ports')
                if ports_elem is None:
                    continue
                
                for port in ports_elem.findall('port'):
                    state = port.find('state')
                    if state is None or state.get('state') not in ('open', 'open|filtered'):
                        continue
                    
                    port_id = int(port.get('portid'))
                    key = f"{ip}:{port_id}"
                    
                    # If we have this service from summary, enrich it
                    if key in self.service_map:
                        service = self.service_map[key]
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service.service_name = service_elem.get('name', 'unknown')
                            service.product = service_elem.get('product', '')
                            service.version = service_elem.get('version', '')
                            service.extrainfo = service_elem.get('extrainfo', '')
                            self.stats['services_validated'] += 1
        
        except ET.ParseError as e:
            logger.warning(f"Failed to parse {xml_path}: {e}")
        except Exception as e:
            logger.warning(f"Error processing {xml_path}: {e}")
    
    def load_services(self):
        """Load and validate services"""
        logger.info("[*] Loading services...")
        
        # Step 1: Quick parse of open_ports_summary.txt
        self.services = self.parse_open_ports_summary()
        if not self.services:
            logger.error("No services found in open_ports_summary.txt")
            sys.exit(1)
        
        self.stats['services_total'] = len(self.services)
        logger.info(f"[✓] Loaded {len(self.services)} services from open_ports_summary.txt")
        
        # Step 2: Validate/enrich with XML files
        enum_dir = self.nmap_dir / '03_enum'
        if enum_dir.exists():
            xml_files = list(enum_dir.glob('*.xml'))
            logger.info(f"[*] Validating with {len(xml_files)} XML files...")
            
            for xml_file in xml_files:
                self.validate_with_xml(xml_file)
            
            logger.info(f"[✓] Validated {self.stats['services_validated']}/{len(self.services)} services")
        else:
            logger.warning("No 03_enum/ directory found, skipping validation")
        
        # Display service summary
        self._print_service_summary()
    
    def _print_service_summary(self):
        """Print summary of discovered services"""
        logger.info("\n[*] Service Summary:")
        
        by_port = defaultdict(list)
        for svc in self.services:
            by_port[svc.port].append(svc)
        
        for port in sorted(by_port.keys()):
            svcs = by_port[port]
            count = len(svcs)
            
            # Get service name
            if port in KNOWN_SERVICES:
                name = KNOWN_SERVICES[port]['name']
            elif svcs[0].service_name != 'unknown':
                name = svcs[0].service_name
            else:
                name = 'unknown'
            
            # Get product info if available
            products = set(s.product for s in svcs if s.product)
            product_str = f" ({', '.join(list(products)[:2])})" if products else ""
            
            logger.info(f"    Port {port:5d}: {count:3d} instance(s) - {name}{product_str}")
    
    def run_nuclei(self, target: str, scan_type: str, templates: str = None, 
                   tags: str = None, workflow: str = None) -> List[Dict]:
        """Execute nuclei scan and return findings"""
        cmd = ['nuclei', '-u', target, '-jsonl', '-v', '-ni', '-duc']
        
        if workflow:
            cmd.extend(['-w', workflow])
        elif templates:
            cmd.extend(['-t', templates])
        elif tags:
            cmd.extend(['-tags', tags])
        
        cmd.extend(['-severity', self.args.severity])
        cmd.extend(['-timeout', str(self.args.timeout)])
        cmd.extend(['-retries', str(self.args.retries)])
        cmd.extend(['-rate-limit', str(self.args.rate_limit)])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            findings = []
            
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        finding['scan_type'] = scan_type
                        finding['scan_target'] = target
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
            
            return findings
        
        except subprocess.TimeoutExpired:
            logger.warning(f"    ⚠ Timeout: {target}")
        except Exception as e:
            logger.warning(f"    ⚠ Error: {target} - {e}")
        
        return []
    
    def scan_service(self, service: Service):
        """Scan a single service with appropriate methodology"""
        logger.info(f"  [{service.ip}:{service.port}] Scanning...")
        
        all_findings = []
        
        # Strategy 1: Known service (MySQL, MongoDB, Redis, etc.)
        if service.is_known_service:
            known = KNOWN_SERVICES[service.port]
            logger.info(f"    → Known service: {known['name']}")
            self.stats['technologies_detected'].add(known['name'])
            
            # Network detection
            findings = self.run_nuclei(
                service.target_url,
                'network_detection',
                templates='network/detection/'
            )
            all_findings.extend(findings)
            
            # Tag-based scan
            findings = self.run_nuclei(
                service.target_url,
                'tag_scan',
                tags=known['tags']
            )
            all_findings.extend(findings)
        
        # Strategy 2: Web service (requires tech detection first)
        elif service.is_web_service:
            logger.info(f"    → Web service: {service.target_url}")
            
            # Phase 1: Technology detection
            tech_findings = self.run_nuclei(
                service.target_url,
                'tech_detection',
                templates='http/technologies/tech-detect.yaml'
            )
            all_findings.extend(tech_findings)
            
            # Extract detected technologies
            detected_techs = set()
            for finding in tech_findings:
                tech = finding.get('matcher-name', '').lower()
                if tech and tech != 'unknown':
                    detected_techs.add(tech)
                    self.stats['technologies_detected'].add(tech)
            
            if detected_techs:
                logger.info(f"    → Detected: {', '.join(sorted(detected_techs)[:3])}")
                
                # Phase 2: Targeted scans based on detected technologies
                for tech in detected_techs:
                    # Workflow scan
                    if tech in TECH_WORKFLOWS:
                        logger.info(f"    → Running {tech} workflow")
                        findings = self.run_nuclei(
                            service.target_url,
                            'workflow',
                            workflow=TECH_WORKFLOWS[tech]
                        )
                        all_findings.extend(findings)
                    
                    # Template scan
                    elif tech in TECH_TEMPLATES:
                        logger.info(f"    → Running {tech} templates")
                        findings = self.run_nuclei(
                            service.target_url,
                            'template',
                            templates=TECH_TEMPLATES[tech]
                        )
                        all_findings.extend(findings)
                    
                    # Tag scan
                    else:
                        findings = self.run_nuclei(
                            service.target_url,
                            'tag_scan',
                            tags=tech
                        )
                        all_findings.extend(findings)
            else:
                logger.info(f"    → No technologies detected, skipping")
        
        else:
            logger.info(f"    → Unknown service type, skipping")
        
        # Record findings
        if all_findings:
            self.stats['services_scanned'] += 1
            self.stats['findings_total'] += len(all_findings)
            
            for finding in all_findings:
                severity = finding.get('info', {}).get('severity', 'info').lower()
                self.stats['findings_by_severity'][severity] += 1
            
            logger.info(f"    ✓ Found {len(all_findings)} issue(s)")
        
        return all_findings
    
    def write_results(self):
        """Write all results to simple, flat files"""
        logger.info("\n[*] Writing results...")
        
        # 1. JSONL file (one JSON object per line, easy to parse)
        with open(self.results_file, 'w') as f:
            for finding in self.findings:
                f.write(json.dumps(finding) + '\n')
        
        logger.info(f"[✓] Results: {self.results_file}")
        
        # 2. Human-readable summary (following open_ports_summary.txt style)
        with open(self.summary_file, 'w') as f:
            f.write("NUCLEI VULNERABILITY SCAN SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            
            # Statistics
            f.write("SCAN STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Services Total:      {self.stats['services_total']}\n")
            f.write(f"Services Validated:  {self.stats['services_validated']}\n")
            f.write(f"Services Scanned:    {self.stats['services_scanned']}\n")
            f.write(f"Technologies Found:  {len(self.stats['technologies_detected'])}\n")
            f.write(f"Total Findings:      {self.stats['findings_total']}\n\n")
            
            # Findings by severity
            f.write("FINDINGS BY SEVERITY\n")
            f.write("-" * 80 + "\n")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = self.stats['findings_by_severity'].get(severity, 0)
                f.write(f"{severity.upper():12}: {count:5d}\n")
            f.write("\n")
            
            # Detected technologies
            if self.stats['technologies_detected']:
                f.write("DETECTED TECHNOLOGIES\n")
                f.write("-" * 80 + "\n")
                for tech in sorted(self.stats['technologies_detected']):
                    f.write(f"  • {tech}\n")
                f.write("\n")
            
            # Findings by host (summary format like open_ports_summary.txt)
            if self.findings:
                f.write("FINDINGS BY HOST\n")
                f.write("-" * 80 + "\n")
                
                by_ip = defaultdict(list)
                for finding in self.findings:
                    target = finding.get('scan_target', '')
                    ip = target.split(':')[0].replace('http://', '').replace('https://', '')
                    by_ip[ip].append(finding)
                
                for ip in sorted(by_ip.keys()):
                    findings = by_ip[ip]
                    f.write(f"\n{ip}: {len(findings)} finding(s)\n")
                    
                    # Show top 10 per host
                    for finding in findings[:10]:
                        severity = finding.get('info', {}).get('severity', 'unknown').upper()
                        name = finding.get('info', {}).get('name', 'unknown')
                        template = finding.get('template-id', 'unknown')
                        f.write(f"  [{severity:8}] {name}\n")
                        f.write(f"               Template: {template}\n")
                    
                    if len(findings) > 10:
                        f.write(f"  ... and {len(findings) - 10} more (see scan_results.jsonl)\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"Full results: {self.results_file}\n")
        
        logger.info(f"[✓] Summary: {self.summary_file}")
    
    def run(self):
        """Execute full scanning workflow"""
        start_time = time.time()
        
        try:
            logger.info("=" * 80)
            logger.info("NUCLEI VULNERABILITY SCANNER")
            logger.info("Service-Aware, Simplified Output")
            logger.info("=" * 80)
            
            self.check_requirements()
            self.load_services()
            
            logger.info(f"\n[*] Starting scans on {len(self.services)} services...")
            logger.info("-" * 80)
            
            for service in self.services:
                findings = self.scan_service(service)
                self.findings.extend(findings)
            
            logger.info("-" * 80)
            self.write_results()
            
            elapsed = time.time() - start_time
            logger.info(f"\n[✓] Scan complete in {elapsed/60:.1f} minutes")
            logger.info(f"[✓] Findings: {self.stats['findings_total']}")
            logger.info(f"[✓] Output: {self.output_dir}/")
        
        except KeyboardInterrupt:
            logger.warning("\n[!] Scan interrupted by user")
            sys.exit(130)
        except Exception as e:
            logger.error(f"\n[!] Error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


# ==================== Main ====================

def main():
    parser = argparse.ArgumentParser(
        description='Nuclei Vulnerability Scanner - Service-Aware, Simplified',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 staged_nuclei.py -n out_bigscan

  # High severity only
  python3 staged_nuclei.py -n out_bigscan -s high,critical

  # Faster scan
  python3 staged_nuclei.py -n out_bigscan -rl 300 --timeout 3

Output Structure (Simple & Flat):
  04_nuclei/
  ├── scan_results.jsonl     - All findings (one JSON per line)
  ├── results_summary.txt    - Human-readable summary
  └── scan_log.txt           - Execution log

Workflow:
  1. Parse open_ports_summary.txt (fast port list)
  2. Validate with 03_enum/*.xml (accurate service detection)
  3. Known services → Direct tag scans
  4. Web services → Tech detection → Targeted scans
  5. Unknown → Skip (no blind scanning)
"""
    )
    
    parser.add_argument('-n', '--nmap-output', required=True,
                       help='Nmap output directory')
    
    # Severity
    parser.add_argument('-s', '--severity', default='medium,high,critical',
                       help='Severity levels (default: medium,high,critical)')
    
    # Performance
    parser.add_argument('-rl', '--rate-limit', type=int, default=150,
                       help='Max requests per second (default: 150)')
    parser.add_argument('--timeout', type=int, default=5,
                       help='Request timeout in seconds (default: 5)')
    parser.add_argument('--retries', type=int, default=1,
                       help='Number of retries (default: 1)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.nmap_output):
        logger.error(f"Directory not found: {args.nmap_output}")
        sys.exit(1)
    
    scanner = NucleiScanner(args)
    scanner.run()


if __name__ == '__main__':
    main()
