#!/usr/bin/env python3
"""
SharpEye - Linux Intrusion Detection System
Main entry point for the application.
"""

import os
import sys
import argparse
import logging
import yaml
from datetime import datetime

# Import modules
from modules.system_resources import SystemResourceAnalyzer
from modules.user_accounts import UserAccountAnalyzer
from modules.processes import ProcessAnalyzer
from modules.network import NetworkAnalyzer
from modules.file_integrity import FileIntegrityAnalyzer
from modules.log_analysis import LogAnalyzer
from modules.kernel_modules import KernelModuleAnalyzer
from modules.library_inspection import LibraryInspectionAnalyzer
from modules.privilege_escalation import PrivilegeEscalationAnalyzer
from modules.ssh_analyzer import SSHAnalyzer
from modules.cryptominer import CryptominerDetector
from modules.rootkit_detector import RootkitDetector
from modules.scheduled_tasks import ScheduledTasksAnalyzer
from utils.reporter import Reporter

# Setup logging
def setup_logging(log_level):
    """Configure logging settings"""
    log_levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    
    level = log_levels.get(log_level.lower(), logging.INFO)
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Set up logging to file and console
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = f"logs/sharpeye_{timestamp}.log"
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger('sharpeye')

def load_config(config_path):
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as config_file:
            return yaml.safe_load(config_file)
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        return {}

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='SharpEye - Linux Intrusion Detection System'
    )
    
    parser.add_argument(
        '--config', 
        default='/etc/sharpeye/config.yaml',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['debug', 'info', 'warning', 'error', 'critical'],
        default='info',
        help='Set logging level'
    )
    
    parser.add_argument(
        '--output-dir',
        default='./reports',
        help='Directory to store reports'
    )
    
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '--full-scan',
        action='store_true',
        help='Run all detection modules'
    )
    
    scan_group.add_argument(
        '--module',
        choices=[
            'system', 'users', 'processes', 'network', 'file_integrity',
            'log_analysis', 'kernel_modules', 'library_inspection', 'privilege_escalation',
            'ssh', 'cryptominer', 'rootkit', 'scheduled_tasks'
        ],
        help='Run a specific detection module'
    )
    
    baseline_group = parser.add_argument_group('Baseline Options')
    baseline_group.add_argument(
        '--establish-baseline',
        action='store_true',
        help='Establish baseline for future comparison'
    )
    
    baseline_group.add_argument(
        '--compare-baseline',
        action='store_true',
        help='Compare against previously established baseline'
    )
    
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--format',
        choices=['text', 'json', 'html', 'pdf'],
        default='text',
        help='Report output format'
    )
    
    output_group.add_argument(
        '--email',
        help='Email address to send reports to'
    )
    
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(args.log_level)
    logger.info("Starting SharpEye Intrusion Detection System")
    
    # Load configuration
    config = load_config(args.config)
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    # Initialize reporter
    reporter = Reporter(args.output_dir, args.format)
    
    # Initialize analyzers
    analyzers = {
        'system': SystemResourceAnalyzer(config.get('system_resources', {})),
        'users': UserAccountAnalyzer(config.get('user_accounts', {})),
        'processes': ProcessAnalyzer(config.get('processes', {})),
        'network': NetworkAnalyzer(config.get('network', {})),
        'file_integrity': FileIntegrityAnalyzer(config.get('file_integrity', {})),
        'log_analysis': LogAnalyzer(config.get('log_analysis', {})),
        'kernel_modules': KernelModuleAnalyzer(config.get('kernel_modules', {})),
        'library_inspection': LibraryInspectionAnalyzer(config.get('library_inspection', {})),
        'privilege_escalation': PrivilegeEscalationAnalyzer(config.get('privilege_escalation', {})),
        'ssh': SSHAnalyzer(config.get('ssh', {})),
        'cryptominer': CryptominerDetector(config.get('cryptominer', {})),
        'rootkit': RootkitDetector(config.get('rootkit', {})),
        'scheduled_tasks': ScheduledTasksAnalyzer(config.get('scheduled_tasks', {}))
    }
    
    # Run in baseline mode
    if args.establish_baseline:
        logger.info("Establishing system baseline")
        # Run each analyzer in baseline mode
        for name, analyzer in analyzers.items():
            if hasattr(analyzer, 'establish_baseline'):
                logger.info(f"Establishing baseline for {name} module")
                analyzer.establish_baseline()
        logger.info("Baseline establishment complete")
        return
    
    # Run in comparison mode
    if args.compare_baseline:
        logger.info("Comparing against baseline")
        for name, analyzer in analyzers.items():
            if hasattr(analyzer, 'compare_baseline'):
                logger.info(f"Comparing baseline for {name} module")
                results = analyzer.compare_baseline()
                reporter.add_section(name, results)
        reporter.generate_report()
        return
    
    # Run specific module
    if args.module:
        logger.info(f"Running {args.module} module")
        analyzer = analyzers.get(args.module)
        if analyzer:
            results = analyzer.analyze()
            reporter.add_section(args.module, results)
            reporter.generate_report()
        else:
            logger.error(f"Module {args.module} not found")
        return
    
    # Run full scan
    if args.full_scan or not (args.establish_baseline or args.compare_baseline or args.module):
        logger.info("Running full system scan")
        for name, analyzer in analyzers.items():
            logger.info(f"Running {name} module")
            results = analyzer.analyze()
            reporter.add_section(name, results)
        
        # Generate and possibly email the report
        report_path = reporter.generate_report()
        
        if args.email and report_path:
            # TODO: Add email functionality
            logger.info(f"Report would be emailed to {args.email}")
    
    logger.info("SharpEye scan completed")

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: SharpEye requires root privileges to function properly.")
        print("Please run with sudo or as root.")
        sys.exit(1)
    
    main()