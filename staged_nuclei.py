#!/usr/bin/env python3
"""
Staged Nuclei Scanner with Technology Detection

A smart, multi-stage vulnerability scanner that:
1. Discovers live HTTP/HTTPS services
2. Takes screenshots for visual reconnaissance
3. Detects technologies (CMS, frameworks, servers)
4. Runs targeted scans based on detected tech
5. Performs deep vulnerability enumeration

Designed for efficient large-scale web application reconnaissance.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set, Tuple
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


# Technology to template tag mapping
TECH_TEMPLATE_MAP = {
    # CMS
    'wordpress': ['wordpress'],
    'drupal': ['drupal'],
    'joomla': ['joomla'],
    'magento': ['magento'],
    'shopify': ['shopify'],
    'prestashop': ['prestashop'],
    'opencart': ['opencart'],
    
    # Frameworks
    'django': ['django'],
    'laravel': ['laravel', 'php'],
    'spring': ['spring', 'java'],
    'express': ['express', 'nodejs'],
    'flask': ['flask', 'python'],
    'rails': ['rails', 'ruby'],
    'asp.net': ['asp', 'microsoft'],
    
    # Servers
    'apache': ['apache'],
    'nginx': ['nginx'],
    'iis': ['iis', 'microsoft'],
    'tomcat': ['tomcat', 'java'],
    'jetty': ['jetty', 'java'],
    'websphere': ['websphere', 'ibm'],
    'weblogic': ['weblogic', 'oracle'],
    
    # Platforms
    'jenkins': ['jenkins', 'ci'],
    'gitlab': ['gitlab'],
    'github': ['github'],
    'bitbucket': ['bitbucket'],
    'docker': ['docker'],
    'kubernetes': ['kubernetes', 'k8s'],
    'grafana': ['grafana'],
    'kibana': ['kibana', 'elastic'],
    'sonarqube': ['sonarqube'],
    
    # Databases/Admin
    'phpmyadmin': ['phpmyadmin', 'php'],
    'adminer': ['adminer', 'php'],
    'mongodb': ['mongodb'],
    'elasticsearch': ['elasticsearch', 'elastic'],
    
    # Other
    'coldfusion': ['coldfusion', 'adobe'],
    'sharepoint': ['sharepoint', 'microsoft'],
    'confluence': ['confluence', 'atlassian'],
    'jira': ['jira', 'atlassian'],
}

# Default important templates to always run
DEFAULT_TEMPLATES = [
    'http/cves/',
    'http/exposures/',
    'http/misconfiguration/',
    'http/vulnerabilities/',
    'http/default-logins/',
]

# Severity-based template groups
SEVERITY_TEMPLATES = {
    'critical': ['http/cves/', 'http/vulnerabilities/'],
    'high': ['http/cves/', 'http/vulnerabilities/', 'http/exposures/'],
    'medium': ['http/cves/', 'http/vulnerabilities/', 'http/exposures/', 'http/misconfiguration/'],
    'all': DEFAULT_TEMPLATES + ['http/fuzzing/', 'http/token-spray/']
}


class StagedNucleiScanner:
    def __init__(self, args):
        self.args = args
        self.output_dir = Path(args.output)
        self.targets = []
        self.live_targets = []
        self.tech_detected = {}  # target -> [technologies]
        self.scan_queue = {}  # target -> [template_tags]
        
        # Create output structure
        self.dirs = {
            'base': self.output_dir,
            'stage0': self.output_dir / '00_httpx',
            'stage1': self.output_dir / '01_gowitness',
            'stage2': self.output_dir / '02_tech_detect',
            'stage3': self.output_dir / '03_targeted_scan',
            'stage4': self.output_dir / '04_deep_enum',
        }
        
        for dir_path in self.dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def check_requirements(self):
        """Verify required tools are installed"""
        required = ['httpx', 'gowitness', 'nuclei']
        missing = []
        
        for tool in required:
            if subprocess.run(['which', tool], capture_output=True).returncode != 0:
                missing.append(tool)
        
        if missing:
            logger.error(f"Missing required tools: {', '.join(missing)}")
            logger.error("Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            logger.error("             go install -v github.com/sensepost/gowitness@latest")
            logger.error("             go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            sys.exit(1)
        
        # Update nuclei templates
        logger.info("Updating Nuclei templates...")
        subprocess.run(['nuclei', '-ut'], capture_output=True)
    
    def load_targets(self):
        """Load targets from input file"""
        logger.info(f"Loading targets from {self.args.input}")
        
        with open(self.args.input, 'r') as f:
            for line in f:
                target = line.strip()
                if target and not target.startswith('#'):
                    # Normalize targets
                    if not target.startswith(('http://', 'https://')):
                        # Add both http and https
                        self.targets.append(f'http://{target}')
                        self.targets.append(f'https://{target}')
                    else:
                        self.targets.append(target)
        
        logger.info(f"Loaded {len(self.targets)} targets (including http/https variants)")
        
        # Write targets file for tools
        targets_file = self.output_dir / 'input_targets.txt'
        with open(targets_file, 'w') as f:
            f.write('\n'.join(self.targets))
        
        return targets_file
    
    def stage0_discovery(self, targets_file):
        """Stage 0: Discover live HTTP/HTTPS services using httpx"""
        logger.info("=" * 60)
        logger.info("STAGE 0: HTTP/HTTPS Service Discovery")
        logger.info("=" * 60)
        
        output_file = self.dirs['stage0'] / 'live_services.json'
        log_file = self.dirs['stage0'] / 'httpx.log'
        
        cmd = [
            'httpx',
            '-l', str(targets_file),
            '-o', str(self.dirs['stage0'] / 'live_services.txt'),
            '-json',
            '-o', str(output_file),
            '-status-code',
            '-title',
            '-tech-detect',
            '-server',
            '-follow-redirects',
            '-random-agent',
            '-timeout', str(self.args.timeout),
            '-threads', str(self.args.threads),
            '-retries', str(self.args.retries),
        ]
        
        if self.args.verbose:
            cmd.append('-verbose')
        
        logger.info(f"Running: {' '.join(cmd)}")
        
        with open(log_file, 'w') as log:
            result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
        
        if result.returncode != 0:
            logger.warning(f"httpx exited with code {result.returncode}")
        
        # Parse results
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        url = data.get('url', '')
                        if url:
                            self.live_targets.append(url)
                            
                            # Extract initial tech detection from httpx
                            techs = data.get('tech', [])
                            if techs:
                                self.tech_detected[url] = [t.lower() for t in techs]
                    except json.JSONDecodeError:
                        continue
        
        logger.info(f"✓ Discovered {len(self.live_targets)} live services")
        
        # Write live targets
        live_file = self.output_dir / 'live_targets.txt'
        with open(live_file, 'w') as f:
            f.write('\n'.join(self.live_targets))
        
        if not self.live_targets:
            logger.error("No live targets found! Check your input and network connectivity.")
            sys.exit(1)
        
        return live_file
    
    def stage1_screenshots(self, live_file):
        """Stage 1: Take screenshots of all live services using gowitness"""
        logger.info("=" * 60)
        logger.info("STAGE 1: Visual Reconnaissance (Screenshots)")
        logger.info("=" * 60)
        
        # Create gowitness database and screenshots directory
        db_file = self.dirs['stage1'] / 'gowitness.sqlite3'
        screenshots_dir = self.dirs['stage1'] / 'screenshots'
        screenshots_dir.mkdir(exist_ok=True)
        
        log_file = self.dirs['stage1'] / 'gowitness.log'
        
        # Run gowitness
        cmd = [
            'gowitness',
            'file',
            '-f', str(live_file),
            '--db-path', str(db_file),
            '--screenshot-path', str(screenshots_dir),
            '--threads', str(self.args.threads),
            '--timeout', str(self.args.timeout),
            '--delay', '0',
            '--disable-logging',
        ]
        
        logger.info(f"Taking screenshots of {len(self.live_targets)} services...")
        logger.info(f"Screenshots will be saved to: {screenshots_dir}")
        
        with open(log_file, 'w') as log:
            result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
        
        if result.returncode != 0:
            logger.warning(f"gowitness exited with code {result.returncode}")
        
        # Count screenshots taken
        screenshot_count = len(list(screenshots_dir.glob('*.png')))
        logger.info(f"✓ Captured {screenshot_count} screenshots")
        
        # Generate HTML report
        logger.info("Generating screenshot gallery...")
        report_file = self.dirs['stage1'] / 'report.html'
        
        report_cmd = [
            'gowitness',
            'report',
            'generate',
            '--db-path', str(db_file),
            '--output', str(report_file),
        ]
        
        subprocess.run(report_cmd, capture_output=True)
        
        if report_file.exists():
            logger.info(f"✓ Screenshot gallery: {report_file}")
            logger.info(f"   Open in browser: file://{report_file.absolute()}")
        
        # Create screenshot summary
        summary_file = self.dirs['stage1'] / 'screenshot_summary.txt'
        with open(summary_file, 'w') as f:
            f.write("Screenshot Summary\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Total Screenshots: {screenshot_count}\n")
            f.write(f"Gallery Report: {report_file}\n\n")
            
            # List all screenshots
            f.write("Screenshots by Target:\n")
            f.write("-" * 60 + "\n")
            for screenshot in sorted(screenshots_dir.glob('*.png')):
                f.write(f"{screenshot.name}\n")
        
        logger.info(f"✓ Screenshot summary: {summary_file}")
    
    def stage2_tech_detection(self, live_file):
        """Stage 2: Deep technology detection using Nuclei"""
        logger.info("=" * 60)
        logger.info("STAGE 2: Technology Detection & Fingerprinting")
        logger.info("=" * 60)
        
        output_file = self.dirs['stage2'] / 'tech_detect.json'
        log_file = self.dirs['stage2'] / 'nuclei_tech.log'
        
        cmd = [
            'nuclei',
            '-l', str(live_file),
            '-tags', 'tech,detect,exposure',
            '-severity', 'info,low,medium,high,critical',
            '-json',
            '-o', str(output_file),
            '-stats',
            '-silent',
            '-rate-limit', str(self.args.rate_limit),
            '-concurrency', str(self.args.concurrency),
            '-timeout', str(self.args.timeout),
            '-retries', str(self.args.retries),
        ]
        
        if self.args.verbose:
            cmd.remove('-silent')
            cmd.append('-v')
        
        logger.info(f"Running technology detection with {self.args.concurrency} concurrent requests...")
        
        with open(log_file, 'w') as log:
            result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
        
        if result.returncode != 0:
            logger.warning(f"Nuclei tech detection exited with code {result.returncode}")
        
        # Parse detected technologies
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        host = data.get('host', '')
                        template_id = data.get('template-id', '').lower()
                        info = data.get('info', {})
                        
                        if host:
                            if host not in self.tech_detected:
                                self.tech_detected[host] = []
                            
                            # Extract tech from template ID and tags
                            for tech, tags in TECH_TEMPLATE_MAP.items():
                                if any(tag in template_id for tag in tags):
                                    if tech not in self.tech_detected[host]:
                                        self.tech_detected[host].append(tech)
                            
                            # Also check template tags
                            template_tags = info.get('tags', [])
                            for tag in template_tags:
                                tag_lower = tag.lower()
                                if tag_lower in TECH_TEMPLATE_MAP:
                                    if tag_lower not in self.tech_detected[host]:
                                        self.tech_detected[host].append(tag_lower)
                    
                    except json.JSONDecodeError:
                        continue
        
        # Generate tech summary
        tech_summary_file = self.dirs['stage2'] / 'tech_summary.txt'
        with open(tech_summary_file, 'w') as f:
            f.write("Technology Detection Summary\n")
            f.write("=" * 60 + "\n\n")
            
            for target, techs in sorted(self.tech_detected.items()):
                f.write(f"{target}\n")
                if techs:
                    for tech in sorted(techs):
                        f.write(f"  - {tech}\n")
                else:
                    f.write("  - No specific technologies detected\n")
                f.write("\n")
        
        logger.info(f"✓ Technology detection complete for {len(self.tech_detected)} targets")
        logger.info(f"✓ Summary written to {tech_summary_file}")
    
    def stage3_build_scan_queue(self):
        """Stage 3: Build targeted scan queue based on detected technologies"""
        logger.info("=" * 60)
        logger.info("STAGE 3: Building Targeted Scan Queue")
        logger.info("=" * 60)
        
        for target in self.live_targets:
            self.scan_queue[target] = set()
            
            # Add default templates based on severity level
            for template in SEVERITY_TEMPLATES.get(self.args.severity, DEFAULT_TEMPLATES):
                self.scan_queue[target].add(template)
            
            # Add technology-specific templates
            techs = self.tech_detected.get(target, [])
            for tech in techs:
                tags = TECH_TEMPLATE_MAP.get(tech, [])
                for tag in tags:
                    self.scan_queue[target].add(tag)
        
        # Write scan queue summary
        queue_file = self.dirs['stage3'] / 'scan_queue.txt'
        with open(queue_file, 'w') as f:
            f.write("Targeted Scan Queue\n")
            f.write("=" * 60 + "\n\n")
            
            for target, tags in sorted(self.scan_queue.items()):
                f.write(f"{target}\n")
                f.write(f"  Templates: {', '.join(sorted(tags))}\n\n")
        
        total_scans = sum(len(tags) for tags in self.scan_queue.values())
        logger.info(f"✓ Built scan queue: {total_scans} template groups across {len(self.scan_queue)} targets")
    
    def stage4_targeted_scan(self):
        """Stage 4: Run targeted Nuclei scans per target"""
        logger.info("=" * 60)
        logger.info("STAGE 4: Targeted Vulnerability Scanning")
        logger.info("=" * 60)
        
        # Prepare per-target scan jobs
        scan_jobs = []
        for target, tags in self.scan_queue.items():
            if tags:
                scan_jobs.append((target, tags))
        
        logger.info(f"Scanning {len(scan_jobs)} targets with {self.args.parallel} parallel jobs...")
        
        # Execute scans in parallel
        completed = 0
        with ThreadPoolExecutor(max_workers=self.args.parallel) as executor:
            futures = {
                executor.submit(self._scan_target, target, tags): target 
                for target, tags in scan_jobs
            }
            
            for future in as_completed(futures):
                target = futures[future]
                try:
                    future.result()
                    completed += 1
                    logger.info(f"Progress: {completed}/{len(scan_jobs)} targets completed")
                except Exception as e:
                    logger.error(f"Error scanning {target}: {e}")
        
        logger.info("✓ Targeted scanning complete")
    
    def _scan_target(self, target: str, tags: Set[str]):
        """Scan a single target with specified template tags"""
        # Sanitize target for filename
        safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
        target_dir = self.dirs['stage4'] / safe_target
        target_dir.mkdir(exist_ok=True)
        
        output_file = target_dir / 'results.json'
        log_file = target_dir / 'scan.log'
        
        # Create temporary target file
        target_file = target_dir / 'target.txt'
        with open(target_file, 'w') as f:
            f.write(target)
        
        # Build command with all tags
        cmd = [
            'nuclei',
            '-l', str(target_file),
            '-tags', ','.join(tags),
            '-severity', self.args.severity if self.args.severity != 'all' else 'info,low,medium,high,critical',
            '-json',
            '-o', str(output_file),
            '-silent',
            '-rate-limit', str(self.args.rate_limit),
            '-timeout', str(self.args.timeout),
            '-retries', str(self.args.retries),
        ]
        
        # Run scan
        with open(log_file, 'w') as log:
            subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
        
        # Also save human-readable output
        if output_file.exists():
            readable_file = target_dir / 'results.txt'
            with open(readable_file, 'w') as out:
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            out.write(f"\n{'=' * 60}\n")
                            out.write(f"Template: {data.get('template-id', 'unknown')}\n")
                            out.write(f"Severity: {data.get('info', {}).get('severity', 'unknown').upper()}\n")
                            out.write(f"URL: {data.get('matched-at', target)}\n")
                            
                            if 'extracted-results' in data:
                                out.write(f"Extracted: {data['extracted-results']}\n")
                            
                            if 'matcher-name' in data:
                                out.write(f"Matcher: {data['matcher-name']}\n")
                            
                            out.write(f"{'=' * 60}\n")
                        except json.JSONDecodeError:
                            continue
    
    def generate_summary(self):
        """Generate final summary report"""
        logger.info("=" * 60)
        logger.info("Generating Summary Report")
        logger.info("=" * 60)
        
        summary_file = self.output_dir / 'SUMMARY.txt'
        findings_by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        
        # Collect all findings
        for target_dir in self.dirs['stage4'].iterdir():
            if target_dir.is_dir():
                results_file = target_dir / 'results.json'
                if results_file.exists():
                    with open(results_file, 'r') as f:
                        for line in f:
                            try:
                                data = json.loads(line.strip())
                                severity = data.get('info', {}).get('severity', 'info').lower()
                                findings_by_severity[severity].append(data)
                            except json.JSONDecodeError:
                                continue
        
        # Write summary
        with open(summary_file, 'w') as f:
            f.write("NUCLEI SCAN SUMMARY REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Targets: {len(self.targets)}\n")
            f.write(f"Live Services: {len(self.live_targets)}\n")
            f.write(f"Technologies Detected: {sum(len(t) for t in self.tech_detected.values())}\n\n")
            
            f.write("FINDINGS BY SEVERITY\n")
            f.write("-" * 80 + "\n")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = len(findings_by_severity[severity])
                f.write(f"{severity.upper():12} : {count:4} findings\n")
            
            f.write("\n" + "=" * 80 + "\n\n")
            
            # Detailed findings
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                findings = findings_by_severity[severity]
                if findings:
                    f.write(f"\n{severity.upper()} SEVERITY FINDINGS ({len(findings)})\n")
                    f.write("-" * 80 + "\n\n")
                    
                    for finding in findings[:50]:  # Limit to 50 per severity
                        f.write(f"Template: {finding.get('template-id', 'unknown')}\n")
                        f.write(f"Target: {finding.get('matched-at', 'unknown')}\n")
                        f.write(f"Name: {finding.get('info', {}).get('name', 'unknown')}\n")
                        
                        if 'extracted-results' in finding:
                            f.write(f"Details: {finding['extracted-results']}\n")
                        
                        f.write("\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Detailed results available in: " + str(self.dirs['stage4']) + "\n")
        
        logger.info(f"✓ Summary report: {summary_file}")
        
        # Print summary to console
        print("\n" + "=" * 80)
        print("SCAN COMPLETE - FINDINGS SUMMARY")
        print("=" * 80)
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = len(findings_by_severity[severity])
            print(f"{severity.upper():12} : {count:4} findings")
        print("=" * 80)
        print(f"\nFull report: {summary_file}")
        print(f"Detailed scans: {self.dirs['stage4']}/")
        print(f"Screenshot gallery: {self.dirs['stage1']}/report.html")
    
    def run(self):
        """Execute the full staged scan"""
        start_time = time.time()
        
        logger.info("Starting Staged Nuclei Scanner")
        self.check_requirements()
        
        # Load and prepare targets
        targets_file = self.load_targets()
        
        # Stage 0: Service discovery
        live_file = self.stage0_discovery(targets_file)
        
        # Stage 1: Screenshots
        self.stage1_screenshots(live_file)
        
        # Stage 2: Technology detection
        self.stage2_tech_detection(live_file)
        
        # Stage 3: Build scan queue
        self.stage3_build_scan_queue()
        
        # Stage 4: Targeted scanning
        self.stage4_targeted_scan()
        
        # Generate summary
        self.generate_summary()
        
        elapsed = time.time() - start_time
        logger.info(f"\n✓ Total scan time: {elapsed/60:.1f} minutes")


def main():
    parser = argparse.ArgumentParser(
        description='Staged Nuclei Scanner with Technology Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with auto-detection
  python3 staged_nuclei.py -i targets.txt -o out_scan

  # High-severity only with more parallelism
  python3 staged_nuclei.py -i targets.txt -o out_scan -s high -j 10

  # Verbose mode for debugging
  python3 staged_nuclei.py -i targets.txt -o out_scan -v
        """
    )
    
    parser.add_argument('-i', '--input', required=True,
                       help='Input file with targets (URLs, IPs, domains)')
    parser.add_argument('-o', '--output', required=True,
                       help='Output directory for results')
    
    # Severity and scope
    parser.add_argument('-s', '--severity', default='medium',
                       choices=['critical', 'high', 'medium', 'all'],
                       help='Minimum severity level (default: medium)')
    
    # Performance tuning
    parser.add_argument('-j', '--parallel', type=int, default=5,
                       help='Parallel target scans in Stage 3 (default: 5)')
    parser.add_argument('-c', '--concurrency', type=int, default=25,
                       help='Concurrent templates per scan (default: 25)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Threads for httpx discovery (default: 50)')
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
    
    # Validate
    if not os.path.exists(args.input):
        logger.error(f"Input file not found: {args.input}")
        sys.exit(1)
    
    # Run scanner
    scanner = StagedNucleiScanner(args)
    scanner.run()


if __name__ == '__main__':
    main()
