#!/usr/bin/env python3
"""
Staged Nuclei Scanner for Nmap Output

A service-aware vulnerability scanner that seamlessly continues from staged_nmap.py:
1. Parses Nmap scan results (XML from 03_enum/)
2. Categorizes services (web, database, network, iot, devops)
3. Builds appropriate targets per service type
4. Runs targeted Nuclei scans based on detected services
5. Segregates results by service category within the same output directory

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
SERVICE_CATEGORIES = {
    'web': {
        'ports': [80, 81, 443, 8000, 8002, 8080, 8081, 8443, 8888, 3000, 5000, 9000, 9090],
        'services': ['http', 'https', 'http-proxy', 'ssl/http', 'http-alt'],
        'templates': ['http/exposures/', 'http/cves/', 'http/vulnerabilities/', 
                     'http/misconfiguration/', 'http/default-logins/', 'http/token-spray/']
    },
    'database': {
        'ports': [3306, 5432, 1433, 1521, 27017, 6379, 9042, 5984, 9200],
        'services': ['mysql', 'postgresql', 'ms-sql', 'oracle', 'mongodb', 
                    'redis', 'cassandra', 'couchdb', 'elasticsearch'],
        'templates': ['network/exposures/', 'network/cves/', 'network/vulnerabilities/']
    },
    'network': {
        'ports': [21, 22, 23, 25, 53, 110, 143, 161, 389, 445, 548, 636, 
                 873, 1099, 2049, 3389, 5900, 5985, 5986],
        'services': ['ftp', 'ssh', 'telnet', 'smtp', 'dns', 'pop3', 'imap', 
                    'snmp', 'ldap', 'microsoft-ds', 'smb', 'afp', 'ldaps',
                    'rsync', 'rmi', 'nfs', 'ms-wbt-server', 'rdp', 'vnc', 
                    'winrm', 'wsman'],
        'templates': ['network/exposures/', 'network/cves/', 'network/detection/']
    },
    'iot': {
        'ports': [1883, 8883, 5683, 502, 20000],
        'services': ['mqtt', 'mqtts', 'coap', 'modbus', 'dnp3'],
        'templates': ['iot/']
    },
    'devops': {
        'ports': [2375, 2376, 6443, 9418, 50000],
        'services': ['docker', 'kubernetes', 'k8s', 'git', 'jenkins'],
        'templates': ['exposures/', 'misconfiguration/', 'cves/']
    }
}

# Port-specific Nuclei templates
PORT_TEMPLATE_MAP = {
    # Web servers
    80: 'http',
    443: 'ssl',
    8080: 'http',
    8443: 'ssl',
    8000: 'http',
    8888: 'http',
    
    # Databases
    3306: 'mysql',
    5432: 'postgresql',
    27017: 'mongodb',
    6379: 'redis',
    9200: 'elasticsearch',
    
    # Network services
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    445: 'smb',
    3389: 'rdp',
    5900: 'vnc',
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
        
        # Create output structure by service category within same directory
        self.dirs = {
            'base': self.output_dir,
            '04_db': self.output_dir / '04_db',
            '05_network': self.output_dir / '05_network',
            '06_web': self.output_dir / '06_web',
            '07_iot': self.output_dir / '07_iot',
            '08_devops': self.output_dir / '08_devops',
            '09_other': self.output_dir / '09_other',
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
        
        # Check for expected nmap output files
        enum_dir = self.nmap_dir / '03_enum'
        if not enum_dir.exists():
            logger.error(f"Nmap enumeration directory not found: {enum_dir}")
            logger.error("Expected directory structure from staged_nmap.py output")
            sys.exit(1)
        
        # Verify nuclei templates are available
        logger.info("Verifying Nuclei templates...")
        result = subprocess.run(['nuclei', '-tl', '-duc'], capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning("Unable to verify templates, but continuing...")
    
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
                    
                    services.append({
                        'ip': ip,
                        'port': port_id,
                        'protocol': protocol,
                        'service': service_name,
                        'product': product,
                        'version': version,
                        'tunnel': tunnel
                    })
        
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
    
    def load_nmap_results(self):
        """Parse all Nmap XML results and categorize services"""
        logger.info("=" * 60)
        logger.info("STAGE 0: Parsing Nmap Results")
        logger.info("=" * 60)
        
        enum_dir = self.nmap_dir / '03_enum'
        xml_files = list(enum_dir.glob('*.xml'))
        
        logger.info(f"Found {len(xml_files)} Nmap XML files to parse")
        
        # Parse all XML files
        for xml_file in xml_files:
            services = self.parse_nmap_xml(xml_file)
            self.all_services.extend(services)
        
        logger.info(f"✓ Discovered {len(self.all_services)} total services")
        
        # Categorize services
        for service in self.all_services:
            category = self.categorize_service(service)
            self.services[category].append(service)
        
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
        
        logger.info(f"✓ Service summary: {summary_file}\n")
    
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
            elif category == 'iot':
                out_dir = self.dirs['07_iot']
            elif category == 'devops':
                out_dir = self.dirs['08_devops']
            else:
                out_dir = self.dirs['09_other']
            
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
    
    def scan_category(self, category: str, target_file: Path, out_dir: Path):
        """Run Nuclei scan for a specific service category"""
        logger.info(f"Scanning {category} services...")
        
        # Determine templates to use
        templates = SERVICE_CATEGORIES.get(category, {}).get('templates', ['exposures/'])
        
        # Build nuclei command
        output_file = out_dir / 'nuclei_results.json'
        log_file = out_dir / 'nuclei.log'
        
        cmd = [
            'nuclei',
            '-l', str(target_file),
            '-json',
            '-o', str(output_file),
            '-severity', self.args.severity,
            '-rate-limit', str(self.args.rate_limit),
            '-concurrency', str(self.args.concurrency),
            '-timeout', str(self.args.timeout),
            '-retries', str(self.args.retries),
            '-duc',  # Don't check for updates
            '-ni',   # No interactivity
        ]
        
        # Add template paths
        if category == 'web':
            # Web services get http templates
            cmd.extend(['-t', 'http/exposures/', '-t', 'http/cves/', 
                       '-t', 'http/vulnerabilities/', '-t', 'http/misconfiguration/'])
        elif category in ['database', 'network', 'iot']:
            # Network-based services
            cmd.extend(['-t', 'network/'])
        else:
            # Default templates
            cmd.extend(['-t', 'exposures/'])
        
        if self.args.verbose:
            cmd.append('-v')
        else:
            cmd.append('-silent')
        
        # Run scan
        with open(log_file, 'w') as log:
            result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
        
        if result.returncode != 0:
            logger.warning(f"Nuclei scan for {category} exited with code {result.returncode}")
        
        # Parse results and create human-readable output
        findings_count = 0
        if output_file.exists():
            readable_file = out_dir / 'findings.txt'
            with open(readable_file, 'w') as out:
                out.write(f"Nuclei Scan Results - {category.upper()}\n")
                out.write("=" * 80 + "\n\n")
                
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            findings_count += 1
                            
                            out.write(f"\n{'=' * 80}\n")
                            out.write(f"Finding #{findings_count}\n")
                            out.write(f"{'=' * 80}\n")
                            out.write(f"Template: {data.get('template-id', 'unknown')}\n")
                            out.write(f"Name: {data.get('info', {}).get('name', 'unknown')}\n")
                            out.write(f"Severity: {data.get('info', {}).get('severity', 'unknown').upper()}\n")
                            out.write(f"Target: {data.get('matched-at', data.get('host', 'unknown'))}\n")
                            
                            if 'extracted-results' in data:
                                out.write(f"Extracted: {data['extracted-results']}\n")
                            
                            if 'matcher-name' in data:
                                out.write(f"Matcher: {data['matcher-name']}\n")
                            
                            if 'description' in data.get('info', {}):
                                out.write(f"Description: {data['info']['description']}\n")
                            
                        except json.JSONDecodeError:
                            continue
        
        logger.info(f"  ✓ {category}: {findings_count} findings")
        return findings_count
    
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
            'iot': self.dirs['07_iot'],
            'devops': self.dirs['08_devops'],
            'other': self.dirs['09_other'],
        }
        
        for category, target_file in target_files.items():
            out_dir = category_dir_map.get(category, self.dirs['09_other'])
            count = self.scan_category(category, target_file, out_dir)
            total_findings[category] = count
        
        logger.info("\n✓ All scans complete")
        logger.info("\nFindings Summary:")
        for category in sorted(total_findings.keys()):
            logger.info(f"  {category:12} : {total_findings[category]:4} findings")
        
        return total_findings
    
    
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
            f.write(f"  Web Services:     {self.dirs['06_web']}/\n")
            f.write(f"  Database Services: {self.dirs['04_db']}/\n")
            f.write(f"  Network Services:  {self.dirs['05_network']}/\n")
            f.write(f"  IoT Services:      {self.dirs['07_iot']}/\n")
            f.write(f"  DevOps Services:   {self.dirs['08_devops']}/\n")
            f.write(f"  Other Services:    {self.dirs['09_other']}/\n")
        
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


def main():
    parser = argparse.ArgumentParser(
        description='Service-Aware Nuclei Scanner for Nmap Output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan services from nmap output (results go in same directory)
  python3 staged_nuclei.py -n out_bigscan

  # High-severity only
  python3 staged_nuclei.py -n out_bigscan -s high

  # Verbose mode
  python3 staged_nuclei.py -n out_bigscan -v

Expected Input:
  The script expects Nmap output from staged_nmap.py:
    - <nmap_dir>/03_enum/*.xml (Nmap XML files with service details)
    - <nmap_dir>/open_ports_summary.txt (optional, for quick reference)

Output Structure (within nmap directory):
  <nmap_dir>/04_db/       - Database service vulnerabilities
  <nmap_dir>/05_network/  - Network service vulnerabilities
  <nmap_dir>/06_web/      - Web application vulnerabilities
  <nmap_dir>/07_iot/      - IoT service vulnerabilities
  <nmap_dir>/08_devops/   - DevOps platform vulnerabilities
  <nmap_dir>/09_other/    - Other service vulnerabilities
        """
    )
    
    parser.add_argument('-n', '--nmap-output', required=True,
                       help='Nmap output directory from staged_nmap.py (Nuclei results will be added here)')
    
    # Severity and scope
    parser.add_argument('-s', '--severity', default='medium,high,critical',
                       help='Severity levels to scan (default: medium,high,critical)')
    
    # Performance tuning
    parser.add_argument('-c', '--concurrency', type=int, default=25,
                       help='Concurrent templates per scan (default: 25)')
    parser.add_argument('-rl', '--rate-limit', type=int, default=150,
                       help='Max requests per second (default: 150)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--retries', type=int, default=1,
                       help='Number of retries (default: 1)')
    
    # Output control
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate nmap output exists
    if not os.path.exists(args.nmap_output):
        logger.error(f"Nmap output directory not found: {args.nmap_output}")
        sys.exit(1)
    
    # Run scanner
    scanner = NmapNucleiScanner(args)
    scanner.run()


if __name__ == '__main__':
    main()
