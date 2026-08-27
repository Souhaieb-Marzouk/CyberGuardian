#!/usr/bin/env python3
"""
CyberGuardian - Windows Malware & Anomaly Detection Tool
=========================================================

A comprehensive security scanner for detecting malware, suspicious processes,
registry persistence, and network threats.

Usage:
    python main.py                    # Launch GUI
    python main.py --cli --scan-all   # CLI full scan
    python main.py --cli --process    # CLI process scan only
    python main.py --help             # Show help
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Initialize logging first (uses config setting, not hardcoded)
from utils.logging_utils import setup_logging, get_logger
setup_logging()  # Will use log_level from config

logger = get_logger('main')


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='CyberGuardian - Windows Malware & Anomaly Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    python main.py                      # Launch GUI (default)
    python main.py --cli --scan-all     # Run all scans in CLI mode
    python main.py --cli --process      # Process scan only
    python main.py --cli --file /path   # Scan specific file/folder
    python main.py --cli --network      # Network scan
    python main.py --cli --registry     # Registry scan
    python main.py --realtime           # Start real-time monitoring
    python main.py --export report.html # Export last results
        '''
    )
    
    # Mode selection
    parser.add_argument(
        '--cli', '-c',
        action='store_true',
        help='Run in CLI mode (no GUI)'
    )
    
    # Scan types
    scan_group = parser.add_argument_group('Scan Options')
    
    scan_group.add_argument(
        '--scan-all', '-a',
        action='store_true',
        help='Run all available scans'
    )
    
    scan_group.add_argument(
        '--process', '-p',
        action='store_true',
        help='Scan running processes'
    )
    
    scan_group.add_argument(
        '--file', '-f',
        type=str,
        metavar='PATH',
        help='Scan file or folder'
    )
    
    scan_group.add_argument(
        '--registry', '-r',
        action='store_true',
        help='Scan Windows registry'
    )
    
    scan_group.add_argument(
        '--network', '-n',
        action='store_true',
        help='Scan network connections'
    )
    
    # Real-time monitoring
    parser.add_argument(
        '--realtime',
        action='store_true',
        help='Start real-time monitoring mode'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    
    output_group.add_argument(
        '--export', '-e',
        type=str,
        metavar='FILE',
        help='Export report to file (HTML, PDF, or JSON)'
    )
    
    output_group.add_argument(
        '--format',
        choices=['html', 'pdf', 'json', 'text'],
        default='html',
        help='Report format (default: html)'
    )
    
    output_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    output_group.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Minimal output (errors only)'
    )
    
    # Configuration
    config_group = parser.add_argument_group('Configuration')
    
    config_group.add_argument(
        '--config',
        type=str,
        metavar='FILE',
        help='Path to configuration file'
    )
    
    config_group.add_argument(
        '--update-rules',
        action='store_true',
        help='Update Yara rules from remote'
    )
    
    config_group.add_argument(
        '--list-whitelist',
        action='store_true',
        help='List all whitelist entries'
    )
    
    return parser.parse_args()


def run_cli_scan(args):
    """Run scans in CLI mode."""
    from scanners.process_scanner import ProcessScanner
    from scanners.file_scanner import FileScanner
    from scanners.registry_scanner import RegistryScanner
    from scanners.network_scanner import NetworkScanner
    from reporting.generator import ReportGenerator
    from utils.config import get_config
    from utils.logging_utils import log_scan_complete
    
    config = get_config()
    results = []
    
    # Set log level based on args
    if args.verbose:
        logging.getLogger('cyberguardian').setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger('cyberguardian').setLevel(logging.ERROR)
    
    print("\n" + "=" * 60)
    print("  CYBERGUARDIAN - Security Scanner")
    print("  Version: " + config.config.version)
    print("=" * 60 + "\n")
    
    # Process scan
    if args.scan_all or args.process:
        print("[*] Starting process scan...")
        scanner = ProcessScanner()
        result = scanner.scan()
        results.append(result)
        print(f"    Completed: {result.total_items} processes, {len(result.detections)} detections")
    
    # File scan
    if args.scan_all or args.file:
        target = args.file or os.getcwd()
        print(f"[*] Starting file scan: {target}")
        scanner = FileScanner()
        result = scanner.scan(target)
        results.append(result)
        print(f"    Completed: {result.total_items} files, {len(result.detections)} detections")
    
    # Registry scan
    if args.scan_all or args.registry:
        print("[*] Starting registry scan...")
        scanner = RegistryScanner()
        result = scanner.scan()
        results.append(result)
        print(f"    Completed: {result.total_items} entries, {len(result.detections)} detections")
    
    # Network scan
    if args.scan_all or args.network:
        print("[*] Starting network scan...")
        scanner = NetworkScanner()
        result = scanner.scan()
        results.append(result)
        print(f"    Completed: {result.total_items} connections, {len(result.detections)} detections")
    
    # Print summary
    if results:
        print("\n" + "-" * 60)
        print("  SCAN SUMMARY")
        print("-" * 60)
        
        total_items = sum(r.total_items for r in results)
        total_detections = sum(len(r.detections) for r in results)
        critical = sum(1 for r in results for d in r.detections if d.risk_level.value == 'critical')
        high = sum(1 for r in results for d in r.detections if d.risk_level.value == 'high')
        medium = sum(1 for r in results for d in r.detections if d.risk_level.value == 'medium')
        
        print(f"  Total items scanned:  {total_items}")
        print(f"  Total detections:     {total_detections}")
        print(f"    - Critical:         {critical}")
        print(f"    - High:             {high}")
        print(f"    - Medium:           {medium}")
        print("-" * 60 + "\n")
        
        # Print detections
        if total_detections > 0:
            print("  DETECTIONS:")
            print("-" * 60)
            
            for result in results:
                for detection in result.detections:
                    risk_str = f"[{detection.risk_level.value.upper()}]"
                    print(f"  {risk_str:12} {detection.detection_type}: {detection.indicator[:50]}")
                    
                    if args.verbose:
                        print(f"               {detection.description[:80]}")
                        print(f"               Remediation: {detection.remediation[0] if detection.remediation else 'N/A'}")
            
            print("-" * 60 + "\n")
        
        # Export report
        if args.export:
            print(f"[*] Exporting report to: {args.export}")
            generator = ReportGenerator()
            
            if args.format == 'json':
                filepath = generator.export_json(results)
            elif args.format == 'pdf':
                filepath = generator.generate_pdf_report(results)
            else:
                filepath = generator.generate_html_report(results)
            
            print(f"    Report saved to: {filepath}")
    
    else:
        print("[!] No scans specified. Use --scan-all or specific scan options.")
    
    return results


def run_realtime_monitor():
    """Run real-time monitoring in CLI mode."""
    from scanners.realtime_monitor import get_monitor
    import time
    
    print("\n" + "=" * 60)
    print("  CYBERGUARDIAN - Real-Time Monitor")
    print("  Press Ctrl+C to stop")
    print("=" * 60 + "\n")
    
    monitor = get_monitor()
    
    def on_detection(detection):
        print(f"\n[!] DETECTION: {detection.risk_level.value.upper()}")
        print(f"    Type: {detection.detection_type}")
        print(f"    Indicator: {detection.indicator}")
        print(f"    Description: {detection.description}")
        print(f"    Remediation: {detection.remediation[0] if detection.remediation else 'N/A'}")
    
    monitor.set_detection_callback(on_detection)
    monitor.start()
    
    try:
        while monitor.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping monitor...")
        monitor.stop()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Handle special commands
    if args.update_rules:
        from scanners.yara_manager import get_yara_manager
        print("[*] Updating Yara rules...")
        yara_manager = get_yara_manager()
        yara_manager.update_rules_from_remote()
        return
    
    if args.list_whitelist:
        from utils.whitelist import get_whitelist
        whitelist = get_whitelist()
        
        print("\n" + "=" * 60)
        print("  WHITELIST ENTRIES")
        print("=" * 60)
        
        for entry in whitelist.get_all_entries():
            print(f"  {entry.entry_type:10} | {entry.identifier[:40]} | {entry.source}")
        
        print("=" * 60 + "\n")
        return
    
    # CLI mode
    if args.cli or args.realtime:
        if args.realtime:
            run_realtime_monitor()
        else:
            run_cli_scan(args)
    
    # GUI mode (default)
    else:
        from ui.main_window import run_application
        run_application()


if __name__ == '__main__':
    main()
