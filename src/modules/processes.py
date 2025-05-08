#!/usr/bin/env python3
"""
ProcessAnalyzer Module
Detects malicious processes, hidden processes, and suspicious process behavior.
Features advanced process relationship mapping to identify lateral movement and malicious process chains.
"""

import os
import logging
import subprocess
import json
import re
import time
import hashlib
import networkx as nx
import matplotlib.pyplot as plt
from io import BytesIO
import base64
from collections import defaultdict
from datetime import datetime

class ProcessRelationshipMapper:
    """Maps process relationships and analyzes process chains for anomalies"""
    
    def __init__(self, config=None):
        """Initialize the process relationship mapper"""
        self.logger = logging.getLogger('sharpeye.processes.mapper')
        self.config = config or {}
        
        # Configure options
        self.max_chain_depth = self.config.get('max_chain_depth', 10)
        self.enable_visualization = self.config.get('enable_visualization', True)
        self.visualization_path = self.config.get('visualization_path', '/var/lib/sharpeye/visualizations')
        
        # Process Chain Detection
        self.suspicious_chain_patterns = self.config.get('suspicious_chain_patterns', [
            # Web server -> shell -> network tool (web shell)
            {'chain': ['httpd|apache|nginx', 'sh|bash|dash', 'nc|wget|curl'], 'description': 'Web shell with network activity'},
            # User shell -> sudo/su -> network tool (privilege escalation with exfiltration)
            {'chain': ['bash|sh|zsh', 'sudo|su', 'nc|curl|wget'], 'description': 'Privilege escalation with network activity'},
            # Shell -> compilers -> execution (compilation of malicious code)
            {'chain': ['bash|sh|zsh', 'gcc|g++|make', '.*'], 'description': 'Compilation and execution of code'},
            # Cron -> shell -> network tool (scheduled backdoor)
            {'chain': ['cron|crond', 'bash|sh|python', 'nc|curl|wget'], 'description': 'Scheduled task with network activity'},
            # SSH -> shell -> file modification in system directories (compromise via SSH)
            {'chain': ['sshd', 'bash|sh', 'vi|vim|nano|echo'], 'description': 'SSH session with sensitive file modifications'}
        ])
        
        # Process tree graph
        self.process_graph = nx.DiGraph()
        
        # Create visualization directory if enabled
        if self.enable_visualization:
            os.makedirs(self.visualization_path, exist_ok=True)
    
    def build_process_tree(self, processes):
        """
        Build a process tree from process information
        
        Args:
            processes: List of process dictionaries with pid and ppid
            
        Returns:
            nx.DiGraph: Directed graph of process relationships
        """
        # Create a new graph
        self.process_graph = nx.DiGraph()
        
        # Add all processes as nodes
        for process in processes:
            pid = process.get('pid')
            if pid:
                # Add node with all process attributes
                self.process_graph.add_node(pid, **process)
        
        # Add edges based on parent-child relationships
        for process in processes:
            pid = process.get('pid')
            ppid = process.get('ppid')
            
            if pid and ppid and pid != ppid:  # Avoid self-loops
                # Don't add edge if parent doesn't exist (like for init)
                if ppid in self.process_graph:
                    self.process_graph.add_edge(ppid, pid)
        
        return self.process_graph
    
    def find_suspicious_chains(self):
        """
        Find suspicious process chains in the process tree
        
        Returns:
            list: Suspicious process chains with descriptions
        """
        suspicious_chains = []
        
        if not self.process_graph:
            self.logger.warning("Process graph not built yet, cannot find suspicious chains")
            return suspicious_chains
        
        # Get all root processes (no parents in our graph)
        root_pids = [pid for pid, degree in self.process_graph.in_degree() if degree == 0]
        
        # For each root, find all paths up to max_chain_depth
        for root_pid in root_pids:
            # Use BFS to find all paths
            for node in self.process_graph.nodes():
                if node != root_pid:
                    for path in nx.all_simple_paths(self.process_graph, root_pid, node, cutoff=self.max_chain_depth):
                        # Convert path of PIDs to commands
                        commands = [self.process_graph.nodes[pid].get('command', '') for pid in path]
                        
                        # Check against suspicious chain patterns
                        for pattern in self.suspicious_chain_patterns:
                            pattern_chain = pattern['chain']
                            
                            # Skip if path is shorter than pattern
                            if len(commands) < len(pattern_chain):
                                continue
                            
                            # Check for matches in sequential segments
                            for i in range(len(commands) - len(pattern_chain) + 1):
                                segment = commands[i:i+len(pattern_chain)]
                                
                                # Check if segment matches pattern
                                if self._match_command_chain(segment, pattern_chain):
                                    # Create a chain entry with process details
                                    chain_processes = [self.process_graph.nodes[path[i+j]] for j in range(len(pattern_chain))]
                                    
                                    suspicious_chains.append({
                                        'pattern': pattern['description'],
                                        'processes': chain_processes,
                                        'path': path[i:i+len(pattern_chain)],
                                        'commands': segment
                                    })
        
        return suspicious_chains
    
    def _match_command_chain(self, commands, patterns):
        """
        Check if a command chain matches a pattern chain
        
        Args:
            commands: List of command strings
            patterns: List of regex patterns to match against
            
        Returns:
            bool: True if commands match patterns
        """
        if len(commands) != len(patterns):
            return False
        
        for cmd, pattern in zip(commands, patterns):
            if not re.search(pattern, cmd):
                return False
        
        return True
    
    def find_process_anomalies(self):
        """
        Find anomalies in the process tree structure
        
        Returns:
            dict: Anomalies found in the process tree
        """
        anomalies = {
            'unusual_parent_child': [],
            'long_process_chains': [],
            'suspicious_process_hierarchies': [],
            'is_anomalous': False
        }
        
        if not self.process_graph:
            self.logger.warning("Process graph not built yet, cannot find process anomalies")
            return anomalies
        
        # Find unusual parent-child relationships
        unusual_relationships = self._find_unusual_parent_child()
        if unusual_relationships:
            anomalies['unusual_parent_child'] = unusual_relationships
            anomalies['is_anomalous'] = True
        
        # Find unusually long process chains
        long_chains = self._find_long_process_chains()
        if long_chains:
            anomalies['long_process_chains'] = long_chains
            anomalies['is_anomalous'] = True
        
        # Find suspicious process hierarchies
        suspicious_hierarchies = self._find_suspicious_hierarchies()
        if suspicious_hierarchies:
            anomalies['suspicious_process_hierarchies'] = suspicious_hierarchies
            anomalies['is_anomalous'] = True
        
        return anomalies
    
    def _find_unusual_parent_child(self):
        """Find unusual parent-child relationships"""
        unusual_relationships = []
        
        # Define normal parent-child relationships
        normal_relationships = {
            'sshd': ['sshd', 'bash', 'sh', 'zsh', 'sftp-server'],
            'systemd': ['systemd', 'systemd-journal', 'systemd-udevd', 'systemd-resolved', 'dbus-daemon'],
            'init': ['systemd', 'upstart', 'sysvinit'],
            'apache2': ['apache2', 'php-fpm', 'php', 'perl'],
            'httpd': ['httpd', 'php-fpm', 'php', 'perl'],
            'nginx': ['nginx', 'php-fpm', 'php', 'perl'],
            'cron': ['cron', 'crond', 'bash', 'sh', 'python', 'perl', 'php'],
            'containerd': ['containerd-shim', 'docker', 'dockerd'],
            'bash': ['bash', 'sh', 'python', 'perl', 'ruby', 'php', 'node', 'java', 'grep', 'awk', 'sed']
        }
        
        # Check all edges in the graph
        for parent_pid, child_pid in self.process_graph.edges():
            parent = self.process_graph.nodes[parent_pid]
            child = self.process_graph.nodes[child_pid]
            
            parent_cmd = parent.get('command', '')
            child_cmd = child.get('command', '')
            
            # Extract base command names
            parent_base = parent_cmd.split()[0].split('/')[-1] if parent_cmd else ''
            child_base = child_cmd.split()[0].split('/')[-1] if child_cmd else ''
            
            # Check if this is an unusual relationship
            if parent_base in normal_relationships:
                expected_children = normal_relationships[parent_base]
                
                # If child isn't in the expected list for this parent
                if not any(re.match(f'^{pattern}', child_base) for pattern in expected_children):
                    unusual_relationships.append({
                        'parent_pid': parent_pid,
                        'parent_command': parent_cmd,
                        'child_pid': child_pid,
                        'child_command': child_cmd,
                        'reason': f"Unusual child process {child_base} for parent {parent_base}"
                    })
        
        return unusual_relationships
    
    def _find_long_process_chains(self):
        """Find unusually long process chains"""
        long_chains = []
        
        # Consider chains longer than 5 processes to be potentially suspicious
        threshold = 5
        
        # Find all simple paths in the graph
        for source in self.process_graph.nodes():
            for target in self.process_graph.nodes():
                if source != target:
                    # Find paths from source to target
                    for path in nx.all_simple_paths(self.process_graph, source, target, cutoff=self.max_chain_depth):
                        if len(path) > threshold:
                            # Extract process details for this chain
                            processes = [self.process_graph.nodes[pid] for pid in path]
                            
                            # Create a chain entry
                            long_chains.append({
                                'length': len(path),
                                'path': path,
                                'processes': processes,
                                'commands': [p.get('command', '') for p in processes]
                            })
        
        return long_chains
    
    def _find_suspicious_hierarchies(self):
        """Find suspicious process hierarchies based on ancestry patterns"""
        suspicious_hierarchies = []
        
        # Find processes with suspicious ancestors
        for pid in self.process_graph.nodes():
            process = self.process_graph.nodes[pid]
            command = process.get('command', '')
            
            # Skip system processes
            if self._is_system_process(command):
                continue
            
            # Check if this process has suspicious commands
            is_suspicious_command = any(pattern in command.lower() for pattern in [
                'nc ', 'ncat', 'netcat', 'wget', 'curl', 'bash -i', 'sh -i', 
                'awk ', 'python -c', 'perl -e', 'ruby -e', '/dev/tcp/'
            ])
            
            if is_suspicious_command:
                # Find all ancestors
                ancestors = []
                current = pid
                
                while True:
                    # Get all predecessors (parents)
                    predecessors = list(self.process_graph.predecessors(current))
                    
                    if not predecessors:
                        break
                    
                    # Add the first parent to ancestors
                    parent = predecessors[0]
                    parent_process = self.process_graph.nodes[parent]
                    ancestors.append({
                        'pid': parent,
                        'command': parent_process.get('command', '')
                    })
                    
                    # Move up to the parent
                    current = parent
                
                if ancestors:
                    suspicious_hierarchies.append({
                        'pid': pid,
                        'command': command,
                        'ancestors': ancestors,
                        'reason': "Suspicious command with unusual ancestry"
                    })
        
        return suspicious_hierarchies
    
    def _is_system_process(self, command):
        """Check if this is a common system process"""
        system_processes = [
            'systemd', 'init', 'kthreadd', 'kworker', 'ksoftirqd', 'migration', 
            'rcu_', 'bio', 'devfreq', 'watchdog', 'irq', 'scsi_', 'mmcqd', 
            'jbd2', 'ext4-'
        ]
        
        if not command:
            return False
            
        cmd_base = command.split()[0].split('/')[-1]
        return any(cmd_base.startswith(sys_proc) for sys_proc in system_processes)
    
    def visualize_process_tree(self):
        """
        Create visualization of the process tree with suspicious processes highlighted
        
        Returns:
            str: Base64 encoded PNG image or path to saved file
        """
        if not self.enable_visualization:
            return None
            
        if not self.process_graph or len(self.process_graph) == 0:
            self.logger.warning("Process graph not built or empty, cannot visualize")
            return None
        
        try:
            # Create a copy of the graph for visualization
            viz_graph = self.process_graph.copy()
            
            # Create position layout
            pos = nx.spring_layout(viz_graph)
            
            # Setup colors based on process attributes
            node_colors = []
            labels = {}
            
            for pid in viz_graph.nodes():
                process = viz_graph.nodes[pid]
                cmd = process.get('command', '')
                cmd_short = cmd.split()[0].split('/')[-1] if cmd else 'unknown'
                
                # Create shorter labels for readability
                labels[pid] = f"{pid}:{cmd_short}"
                
                # Check if this is a suspicious process
                if process.get('is_suspicious', False):
                    node_colors.append('red')
                elif self._is_system_process(cmd):
                    node_colors.append('lightblue')
                else:
                    node_colors.append('lightgreen')
            
            # Create figure with dynamic size based on node count
            node_count = len(viz_graph)
            plt.figure(figsize=(max(8, node_count/5), max(6, node_count/5)))
            
            # Draw the graph
            nx.draw(viz_graph, pos, 
                   node_color=node_colors, 
                   labels=labels, 
                   font_size=8, 
                   node_size=500, 
                   edge_color='gray', 
                   with_labels=True)
            
            # Add timestamp to filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"process_tree_{timestamp}.png"
            filepath = os.path.join(self.visualization_path, filename)
            
            # Save to file
            plt.savefig(filepath, bbox_inches='tight', dpi=100)
            plt.close()
            
            # Return both file path and base64 encoded image
            with open(filepath, 'rb') as f:
                image_data = f.read()
                base64_image = base64.b64encode(image_data).decode('utf-8')
                
            return {
                'filepath': filepath,
                'base64': base64_image
            }
            
        except Exception as e:
            self.logger.error(f"Error visualizing process tree: {e}")
            return None
    
    def calculate_risk_score(self, pid):
        """
        Calculate a risk score for a process based on its attributes and relationships
        
        Args:
            pid: The process ID to calculate risk for
            
        Returns:
            float: Risk score between 0 and 100
        """
        if not pid in self.process_graph:
            return 0
        
        process = self.process_graph.nodes[pid]
        score = 0
        
        # Base scoring
        command = process.get('command', '')
        user = process.get('user', '')
        
        # Running as root
        if user == 'root':
            score += 10
        
        # Suspicious command patterns
        suspicious_patterns = [
            'nc ', 'ncat', 'netcat', 'wget', 'curl', 'bash -i', 'sh -i', 
            'python -c', 'perl -e', 'ruby -e', '/dev/tcp/'
        ]
        for pattern in suspicious_patterns:
            if pattern in command.lower():
                score += 15
                break
        
        # Suspicious paths
        suspicious_paths = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/']
        for path in suspicious_paths:
            if path in command:
                score += 15
                break
        
        # Process ancestry
        ancestors = list(nx.ancestors(self.process_graph, pid))
        if len(ancestors) > 5:  # Deep process chains
            score += 5
        
        # Web server ancestry
        web_servers = ['httpd', 'apache2', 'nginx']
        for ancestor in ancestors:
            ancestor_cmd = self.process_graph.nodes[ancestor].get('command', '')
            if any(server in ancestor_cmd.lower() for server in web_servers):
                score += 20
                break
        
        # Shell ancestry
        shells = ['bash', 'sh', 'dash', 'zsh', 'csh']
        shell_ancestors = 0
        for ancestor in ancestors:
            ancestor_cmd = self.process_graph.nodes[ancestor].get('command', '')
            ancestor_base = ancestor_cmd.split()[0].split('/')[-1]
            if ancestor_base in shells:
                shell_ancestors += 1
        
        if shell_ancestors > 2:  # Multiple shell invocations in ancestry
            score += 10
        
        # Child processes check
        children = list(self.process_graph.successors(pid))
        network_children = 0
        for child in children:
            child_cmd = self.process_graph.nodes[child].get('command', '')
            if any(net_tool in child_cmd.lower() for net_tool in ['nc', 'curl', 'wget', 'ncat', 'ssh']):
                network_children += 1
        
        if network_children > 0:
            score += 15
            
        # Cap the score at a maximum of 100
        return min(score, 100)


class ProcessAnalyzer:
    """Analyzes processes for suspicious behavior"""
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.processes')
        self.config = config or {}
        
        # Configure options
        self.baseline_file = self.config.get('baseline_file', '/var/lib/sharpeye/baselines/processes.json')
        self.check_hidden = self.config.get('check_hidden', True)
        self.check_relationships = self.config.get('check_relationships', True)
        self.check_execution_path = self.config.get('check_execution_path', True)
        self.check_file_handles = self.config.get('check_file_handles', True)
        self.check_network_connections = self.config.get('check_network_connections', True)
        self.new_process_threshold = self.config.get('new_process_threshold', 3600)  # 1 hour
        
        # Suspicious paths configuration
        self.suspicious_paths = self.config.get('suspicious_paths', [
            "/tmp", "/dev/shm", "/var/tmp", "/run/user"
        ])
        
        # Suspicious command patterns
        self.suspicious_commands = self.config.get('suspicious_commands', [
            "miner", "xmr", "crypto", "kworker", "./", "/tmp/",
            "curl", "wget", "nc ", "netcat", "ncat",
            "bash -i", "perl -e", "python -c", "ruby -e"
        ])
        
        # Initialize the process relationship mapper
        self.process_mapper = ProcessRelationshipMapper(config)
    
    def analyze(self):
        """Analyze processes for anomalies"""
        self.logger.info("Analyzing processes")
        
        # Get basic process information
        running_processes = self._get_running_processes()
        
        # Get detailed analysis results
        results = {
            'running_processes': running_processes,
            'suspicious_processes': self._find_suspicious_processes(),
            'hidden_processes': self._find_hidden_processes() if self.check_hidden else {'skipped': True},
            'unusual_relationships': self._check_process_relationships() if self.check_relationships else {'skipped': True},
            'unusual_execution_paths': self._check_execution_paths() if self.check_execution_path else {'skipped': True},
            'suspicious_file_handles': self._check_file_handles() if self.check_file_handles else {'skipped': True},
            'network_connections': self._check_network_connections() if self.check_network_connections else {'skipped': True}
        }
        
        # Add advanced process relationship mapping
        self._add_process_relationship_mapping(results, running_processes.get('processes', []))
        
        # Determine if any anomalies were found
        is_anomalous = (
            results['suspicious_processes'].get('is_anomalous', False) or
            results['hidden_processes'].get('is_anomalous', False) or
            results['unusual_relationships'].get('is_anomalous', False) or
            results['unusual_execution_paths'].get('is_anomalous', False) or
            results['suspicious_file_handles'].get('is_anomalous', False) or
            results['network_connections'].get('is_anomalous', False) or
            results.get('process_relationships', {}).get('is_anomalous', False)
        )
        
        results['is_anomalous'] = is_anomalous
        results['timestamp'] = datetime.now().isoformat()
        
        return results
        
    def _add_process_relationship_mapping(self, results, processes):
        """
        Add advanced process relationship mapping data to results
        
        Args:
            results: Results dictionary to update
            processes: List of process dictionaries
        """
        self.logger.debug("Analyzing process relationships using the relationship mapper")
        
        try:
            # Build the process graph from the process list
            self.process_mapper.build_process_tree(processes)
            
            # Find suspicious process chains
            suspicious_chains = self.process_mapper.find_suspicious_chains()
            
            # Find other process tree anomalies
            process_anomalies = self.process_mapper.find_process_anomalies()
            
            # Calculate risk scores for all processes
            high_risk_processes = []
            for process in processes:
                pid = process.get('pid')
                if pid:
                    risk_score = self.process_mapper.calculate_risk_score(pid)
                    if risk_score > 70:  # Processes with high risk score
                        process_with_score = process.copy()
                        process_with_score['risk_score'] = risk_score
                        high_risk_processes.append(process_with_score)
            
            # Generate visualization
            visualization = self.process_mapper.visualize_process_tree()
            
            # Add to results
            results['process_relationships'] = {
                'suspicious_chains': suspicious_chains,
                'unusual_parent_child': process_anomalies.get('unusual_parent_child', []),
                'long_process_chains': process_anomalies.get('long_process_chains', []),
                'suspicious_hierarchies': process_anomalies.get('suspicious_process_hierarchies', []),
                'high_risk_processes': high_risk_processes,
                'visualization': visualization,
                'is_anomalous': (
                    len(suspicious_chains) > 0 or
                    process_anomalies.get('is_anomalous', False) or
                    len(high_risk_processes) > 0
                )
            }
            
        except Exception as e:
            self.logger.error(f"Error performing process relationship mapping: {e}")
            results['process_relationships'] = {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _get_running_processes(self):
        """Get information about all running processes"""
        self.logger.debug("Getting running processes")
        
        try:
            # Get all processes
            cmd = ["ps", "-eo", "pid,ppid,user,lstart,command"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            processes = []
            # Skip header line
            lines = output.strip().split('\n')[1:]
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Parse the line
                # Format: PID PPID USER START_DATE START_TIME TZ COMMAND
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    pid = parts[0]
                    ppid = parts[1]
                    user = parts[2]
                    # Combine the rest as the command
                    start_and_cmd = parts[3:]
                    
                    # Try to extract the start time
                    start_info = ' '.join(start_and_cmd[:-1]) if len(start_and_cmd) > 1 else ''
                    command = start_and_cmd[-1]
                    
                    # Add process information
                    processes.append({
                        'pid': pid,
                        'ppid': ppid,
                        'user': user,
                        'start_time': start_info,
                        'command': command
                    })
            
            return {
                'count': len(processes),
                'processes': processes
            }
            
        except Exception as e:
            self.logger.error(f"Error getting running processes: {e}")
            return {
                'error': str(e),
                'count': 0,
                'processes': []
            }
    
    def _find_suspicious_processes(self):
        """Find processes with suspicious characteristics"""
        self.logger.debug("Finding suspicious processes")
        
        suspicious_processes = []
        
        try:
            # Get all processes
            processes = self._get_running_processes().get('processes', [])
            
            for process in processes:
                pid = process.get('pid')
                command = process.get('command', '')
                user = process.get('user', '')
                
                is_suspicious = False
                reasons = []
                
                # Check for suspicious command patterns
                for pattern in self.suspicious_commands:
                    if pattern in command.lower():
                        is_suspicious = True
                        reasons.append(f"Suspicious command pattern: '{pattern}'")
                
                # Check executable path
                exe_path = ""
                try:
                    exe_path = os.path.realpath(f"/proc/{pid}/exe")
                    
                    # Check if running from suspicious location
                    for path in self.suspicious_paths:
                        if exe_path.startswith(path):
                            is_suspicious = True
                            reasons.append(f"Running from suspicious location: {exe_path}")
                except (FileNotFoundError, PermissionError):
                    # Process might have terminated or we don't have permission
                    pass
                
                # Check for unusual users
                system_users = ['root', 'nobody', 'www-data', 'apache', 'nginx']
                if user not in system_users and int(pid) < 1000:  # Low PID but not a system user
                    is_suspicious = True
                    reasons.append(f"Unusual user for system process: {user}")
                
                # Check process age
                start_time_str = process.get('start_time', '')
                if start_time_str:
                    try:
                        # Try to parse the start time
                        process_time = time.strptime(start_time_str)
                        process_timestamp = time.mktime(process_time)
                        current_timestamp = time.time()
                        
                        # Check if process is new
                        if current_timestamp - process_timestamp < self.new_process_threshold:
                            # New process with suspicious characteristics is more concerning
                            if is_suspicious:
                                reasons.append(f"Recently started process ({start_time_str})")
                    except ValueError:
                        # Could not parse time
                        pass
                
                # Check for hidden files in process directory
                try:
                    proc_dir = f"/proc/{pid}"
                    if os.path.exists(proc_dir):
                        files = os.listdir(proc_dir)
                        hidden_files = [f for f in files if f.startswith('.') and f not in ['.', '..']]
                        
                        if hidden_files:
                            is_suspicious = True
                            reasons.append(f"Hidden files in process directory: {', '.join(hidden_files)}")
                except (PermissionError, FileNotFoundError):
                    # Process might have terminated or we don't have permission
                    pass
                
                # Add to suspicious processes if criteria met
                if is_suspicious:
                    suspicious_processes.append({
                        'pid': pid,
                        'ppid': process.get('ppid'),
                        'user': user,
                        'command': command,
                        'exe_path': exe_path,
                        'reasons': reasons
                    })
            
            return {
                'count': len(suspicious_processes),
                'suspicious_processes': suspicious_processes,
                'is_anomalous': len(suspicious_processes) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error finding suspicious processes: {e}")
            return {
                'error': str(e),
                'count': 0,
                'suspicious_processes': [],
                'is_anomalous': False
            }
    
    def _find_hidden_processes(self):
        """Find hidden processes by comparing ps output with /proc directory"""
        self.logger.debug("Finding hidden processes")
        
        hidden_processes = []
        
        try:
            # Get PIDs from ps command
            cmd = ["ps", "-eo", "pid", "--no-headers"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            ps_pids = set()
            
            for line in output.strip().split('\n'):
                if line.strip():
                    ps_pids.add(line.strip())
            
            # Get PIDs from /proc directory
            proc_pids = set()
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    proc_pids.add(entry)
            
            # Find PIDs in /proc but not in ps output
            for pid in proc_pids:
                if pid not in ps_pids:
                    # This is a potentially hidden process
                    process_info = {
                        'pid': pid,
                        'command': '(unknown)',
                        'user': '(unknown)'
                    }
                    
                    # Try to get more information
                    try:
                        # Check command line
                        cmdline_path = f"/proc/{pid}/cmdline"
                        if os.path.exists(cmdline_path):
                            with open(cmdline_path, 'r') as f:
                                cmdline = f.read().replace('\0', ' ').strip()
                                if cmdline:
                                    process_info['command'] = cmdline
                        
                        # Check status for user information
                        status_path = f"/proc/{pid}/status"
                        if os.path.exists(status_path):
                            with open(status_path, 'r') as f:
                                for line in f:
                                    if line.startswith('Uid:'):
                                        uid = line.split()[1]
                                        process_info['uid'] = uid
                                        
                                        # Try to get username from uid
                                        try:
                                            uid_int = int(uid)
                                            import pwd
                                            process_info['user'] = pwd.getpwuid(uid_int).pw_name
                                        except (ValueError, KeyError):
                                            pass
                                            
                                    elif line.startswith('PPid:'):
                                        process_info['ppid'] = line.split()[1]
                    except (PermissionError, FileNotFoundError):
                        # Process might have terminated or we don't have permission
                        pass
                    
                    hidden_processes.append(process_info)
            
            return {
                'count': len(hidden_processes),
                'hidden_processes': hidden_processes,
                'is_anomalous': len(hidden_processes) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error finding hidden processes: {e}")
            return {
                'error': str(e),
                'count': 0,
                'hidden_processes': [],
                'is_anomalous': False
            }
    
    def _check_process_relationships(self):
        """Check for unusual parent-child process relationships"""
        self.logger.debug("Checking process relationships")
        
        unusual_relationships = []
        
        try:
            # Get all processes
            processes = self._get_running_processes().get('processes', [])
            
            # Create PID to process mapping
            pid_map = {proc.get('pid'): proc for proc in processes}
            
            # Define suspicious parent-child combinations
            suspicious_combinations = [
                ('sshd', 'bash'),  # SSH to bash (potential remote shell)
                ('apache', 'bash'),  # Web server to bash (potential web shell)
                ('nginx', 'bash'),  # Web server to bash
                ('httpd', 'bash'),  # Web server to bash
                ('cron', 'curl'),   # Cron to network tools
                ('cron', 'wget'),
                ('cron', 'ncat'),
                ('cron', 'nc'),
                ('init', 'nc'),     # Init to network tools
                ('init', 'ncat')
            ]
            
            # Check each process for unusual parent
            for proc in processes:
                pid = proc.get('pid')
                ppid = proc.get('ppid')
                command = proc.get('command', '')
                
                # Skip processes with no parent (init processes)
                if ppid == '0' or ppid == '1':
                    continue
                
                # Get parent process
                parent = pid_map.get(ppid)
                if not parent:
                    continue
                
                parent_command = parent.get('command', '')
                
                # Extract the base command (without args)
                current_base = command.split()[0].split('/')[-1] if command else ''
                parent_base = parent_command.split()[0].split('/')[-1] if parent_command else ''
                
                # Check for suspicious combinations
                for parent_pattern, child_pattern in suspicious_combinations:
                    if (parent_base == parent_pattern or parent_pattern in parent_command) and \
                       (current_base == child_pattern or child_pattern in command):
                        unusual_relationships.append({
                            'pid': pid,
                            'command': command,
                            'ppid': ppid,
                            'parent_command': parent_command,
                            'reason': f"Suspicious parent-child relationship: {parent_pattern} → {child_pattern}"
                        })
                
                # Check for shells spawned by server processes
                server_processes = ['httpd', 'apache', 'apache2', 'nginx', 'www-data', 'tomcat', 'jetty']
                shell_processes = ['bash', 'sh', 'ksh', 'zsh', 'dash', 'csh', 'tcsh']
                
                if any(server in parent_base or server in parent_command for server in server_processes) and \
                   any(shell == current_base or shell in command for shell in shell_processes):
                    unusual_relationships.append({
                        'pid': pid,
                        'command': command,
                        'ppid': ppid,
                        'parent_command': parent_command,
                        'reason': f"Web server spawning shell: {parent_base} → {current_base}"
                    })
                
                # Check for network tools spawned by suspicious processes
                network_tools = ['nc', 'ncat', 'netcat', 'curl', 'wget', 'ftp', 'ssh', 'scp', 'sftp']
                
                if current_base in network_tools or any(tool in command for tool in network_tools):
                    # Network tool detected - check if parent is suspicious
                    
                    # Cron running network tools is suspicious
                    if 'cron' in parent_base or 'cron' in parent_command:
                        unusual_relationships.append({
                            'pid': pid,
                            'command': command,
                            'ppid': ppid,
                            'parent_command': parent_command,
                            'reason': f"Cron job running network tool: {parent_base} → {current_base}"
                        })
                    
                    # Init running network tools directly is suspicious
                    if parent_base in ['init', 'systemd'] and ppid in ['1', '0']:
                        unusual_relationships.append({
                            'pid': pid,
                            'command': command,
                            'ppid': ppid,
                            'parent_command': parent_command,
                            'reason': f"Init process running network tool: {parent_base} → {current_base}"
                        })
            
            return {
                'count': len(unusual_relationships),
                'unusual_relationships': unusual_relationships,
                'is_anomalous': len(unusual_relationships) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking process relationships: {e}")
            return {
                'error': str(e),
                'count': 0,
                'unusual_relationships': [],
                'is_anomalous': False
            }
    
    def _check_execution_paths(self):
        """Check for processes running from unusual or suspicious paths"""
        self.logger.debug("Checking execution paths")
        
        unusual_execution_paths = []
        
        try:
            # Get all processes
            processes = self._get_running_processes().get('processes', [])
            
            for process in processes:
                pid = process.get('pid')
                command = process.get('command', '')
                
                # Skip kernel processes
                if "[" in command and "]" in command and not os.path.exists(f"/proc/{pid}/exe"):
                    continue
                
                try:
                    # Get executable path
                    exe_path = os.path.realpath(f"/proc/{pid}/exe")
                    
                    # Skip common paths
                    common_paths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin']
                    if any(exe_path.startswith(path) for path in common_paths):
                        continue
                    
                    # Check for suspicious paths
                    suspicious = False
                    reason = ""
                    
                    # Check if running from suspicious location
                    for path in self.suspicious_paths:
                        if exe_path.startswith(path):
                            suspicious = True
                            reason = f"Running from suspicious location: {exe_path}"
                            break
                    
                    # Check if running from home directory
                    if exe_path.startswith('/home/') and '/.' in exe_path:
                        suspicious = True
                        reason = f"Running from hidden location in home directory: {exe_path}"
                    
                    # Check if running from world-writable directory
                    if os.path.exists(os.path.dirname(exe_path)):
                        dir_mode = os.stat(os.path.dirname(exe_path)).st_mode
                        if dir_mode & 0o002:  # World-writable
                            suspicious = True
                            reason = f"Running from world-writable directory: {os.path.dirname(exe_path)}"
                    
                    if suspicious:
                        unusual_execution_paths.append({
                            'pid': pid,
                            'command': command,
                            'exe_path': exe_path,
                            'reason': reason
                        })
                
                except (FileNotFoundError, PermissionError):
                    # Process might have terminated or we don't have permission
                    pass
            
            return {
                'count': len(unusual_execution_paths),
                'unusual_execution_paths': unusual_execution_paths,
                'is_anomalous': len(unusual_execution_paths) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking execution paths: {e}")
            return {
                'error': str(e),
                'count': 0,
                'unusual_execution_paths': [],
                'is_anomalous': False
            }
    
    def _check_file_handles(self):
        """Check for processes with suspicious file handles"""
        self.logger.debug("Checking file handles")
        
        suspicious_file_handles = []
        
        try:
            # Get all processes
            processes = self._get_running_processes().get('processes', [])
            
            for process in processes:
                pid = process.get('pid')
                command = process.get('command', '')
                
                # Skip kernel processes
                if "[" in command and "]" in command:
                    continue
                
                try:
                    # Use lsof to get file handles
                    cmd = ["lsof", "-p", pid]
                    output = subprocess.check_output(cmd, universal_newlines=True)
                    
                    suspicious_files = []
                    
                    # Skip header line
                    lines = output.strip().split('\n')[1:]
                    
                    for line in lines:
                        if not line.strip():
                            continue
                        
                        parts = line.split()
                        if len(parts) >= 9:
                            file_path = ' '.join(parts[8:])
                            
                            # Check for suspicious files
                            if any(file_path.startswith(path) for path in self.suspicious_paths):
                                suspicious_files.append({
                                    'file': file_path,
                                    'reason': "Suspicious location"
                                })
                            
                            # Check for hidden files in home directories
                            if file_path.startswith('/home/') and '/.' in file_path:
                                suspicious_files.append({
                                    'file': file_path,
                                    'reason': "Hidden file in home directory"
                                })
                            
                            # Check for suspicious named pipes
                            if parts[4] == 'FIFO' and (file_path.startswith('/tmp') or '/.' in file_path):
                                suspicious_files.append({
                                    'file': file_path,
                                    'reason': "Suspicious named pipe"
                                })
                            
                            # Check for memory-mapped files in suspicious locations
                            if parts[4] == 'REG' and parts[5] == 'mem' and any(file_path.startswith(path) for path in self.suspicious_paths):
                                suspicious_files.append({
                                    'file': file_path,
                                    'reason': "Memory-mapped file in suspicious location"
                                })
                    
                    if suspicious_files:
                        suspicious_file_handles.append({
                            'pid': pid,
                            'command': command,
                            'suspicious_files': suspicious_files
                        })
                
                except (subprocess.CalledProcessError, FileNotFoundError):
                    # lsof might not be installed or we don't have permission
                    pass
                except Exception as e:
                    self.logger.debug(f"Error checking file handles for process {pid}: {e}")
            
            return {
                'count': len(suspicious_file_handles),
                'suspicious_file_handles': suspicious_file_handles,
                'is_anomalous': len(suspicious_file_handles) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking file handles: {e}")
            return {
                'error': str(e),
                'count': 0,
                'suspicious_file_handles': [],
                'is_anomalous': False
            }
    
    def _check_network_connections(self):
        """Check for processes with suspicious network connections"""
        self.logger.debug("Checking network connections")
        
        suspicious_connections = []
        
        try:
            # Get all processes with network connections
            cmd = ["netstat", "-tunp"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Define suspicious ports
            suspicious_ports = self.config.get('suspicious_ports', [
                31337,  # Back Orifice
                12345,  # NetBus
                6667    # IRC (often used by botnets)
            ])
            
            # Extract connections
            # Skip header lines
            lines = output.strip().split('\n')[2:]
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 7:
                    proto = parts[0]
                    local_addr = parts[3]
                    remote_addr = parts[4]
                    state = parts[5] if len(parts) > 5 else ""
                    pid_info = parts[6] if len(parts) > 6 else ""
                    
                    # Extract PID and program name
                    pid = ""
                    program = ""
                    
                    pid_match = re.search(r'(\d+)/(.*)', pid_info)
                    if pid_match:
                        pid = pid_match.group(1)
                        program = pid_match.group(2)
                    
                    # Check for suspicious connections
                    suspicious = False
                    reason = []
                    
                    # Check for suspicious local ports
                    local_port = int(local_addr.split(':')[-1]) if ':' in local_addr else 0
                    if local_port in suspicious_ports:
                        suspicious = True
                        reason.append(f"Suspicious local port: {local_port}")
                    
                    # Check for suspicious remote ports
                    remote_port = int(remote_addr.split(':')[-1]) if ':' in remote_addr else 0
                    if remote_port in suspicious_ports:
                        suspicious = True
                        reason.append(f"Suspicious remote port: {remote_port}")
                    
                    # Check for unusual programs with network connections
                    unusual_programs = ['bash', 'sh', 'ksh', 'zsh', 'perl', 'python', 'ruby', 'nc', 'ncat', 'netcat']
                    if any(prog == program for prog in unusual_programs):
                        suspicious = True
                        reason.append(f"Unusual program with network connection: {program}")
                    
                    # Check for established connections to unusual ports
                    if state == "ESTABLISHED" and remote_port not in [80, 443, 22, 21, 25, 465, 587, 110, 995, 143, 993]:
                        # Not one of the common service ports
                        if remote_port > 1024:
                            # High port - more likely to be suspicious
                            suspicious = True
                            reason.append(f"Established connection to unusual high port: {remote_port}")
                    
                    if suspicious and pid:
                        # Get more information about the process
                        process_info = {}
                        
                        try:
                            # Get command line
                            with open(f"/proc/{pid}/cmdline", 'r') as f:
                                cmdline = f.read().replace('\0', ' ').strip()
                                process_info['command'] = cmdline if cmdline else program
                            
                            # Get executable path
                            process_info['exe_path'] = os.path.realpath(f"/proc/{pid}/exe")
                            
                            # Get user
                            with open(f"/proc/{pid}/status", 'r') as f:
                                for status_line in f:
                                    if status_line.startswith('Uid:'):
                                        uid = status_line.split()[1]
                                        try:
                                            import pwd
                                            process_info['user'] = pwd.getpwuid(int(uid)).pw_name
                                        except (ValueError, KeyError):
                                            process_info['uid'] = uid
                                        break
                        except (FileNotFoundError, PermissionError):
                            # Process might have terminated or we don't have permission
                            pass
                        
                        suspicious_connections.append({
                            'pid': pid,
                            'program': program,
                            'proto': proto,
                            'local_addr': local_addr,
                            'remote_addr': remote_addr,
                            'state': state,
                            'reasons': reason,
                            'process_info': process_info
                        })
            
            return {
                'count': len(suspicious_connections),
                'suspicious_connections': suspicious_connections,
                'is_anomalous': len(suspicious_connections) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking network connections: {e}")
            return {
                'error': str(e),
                'count': 0,
                'suspicious_connections': [],
                'is_anomalous': False
            }
    
    def establish_baseline(self):
        """Establish baseline for processes"""
        self.logger.info("Establishing baseline for processes")
        
        # Get basic process information
        processes = self._get_process_baseline()
        
        # Build process relationship graph
        self.process_mapper.build_process_tree(processes)
        
        # Calculate process relationship hashes and baseline characteristics
        relationship_data = self._calculate_relationship_baseline()
        
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'processes': processes,
            'process_relationships': relationship_data
        }
        
        # Generate and store visualization if enabled
        visualization = self.process_mapper.visualize_process_tree()
        if visualization:
            baseline['visualization_path'] = visualization.get('filepath')
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
        
        # Write baseline to file
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        self.logger.info(f"Baseline saved to {self.baseline_file}")
        
        return baseline
        
    def _calculate_relationship_baseline(self):
        """Calculate baseline characteristics for process relationships"""
        relationship_data = {
            'process_chain_hashes': [],
            'parent_child_patterns': {},
            'common_process_chains': []
        }
        
        # Generate hashes for process chains to allow future comparison
        process_graph = self.process_mapper.process_graph
        
        # For all leaf nodes (processes with no children)
        leaf_nodes = [n for n in process_graph.nodes() if process_graph.out_degree(n) == 0]
        
        for leaf in leaf_nodes:
            # Find all ancestors
            for root in [n for n in process_graph.nodes() if process_graph.in_degree(n) == 0]:
                for path in nx.all_simple_paths(process_graph, root, leaf):
                    if len(path) > 1:  # Paths with at least 2 processes
                        # Create a chain signature
                        chain_cmds = []
                        for pid in path:
                            cmd = process_graph.nodes[pid].get('command', '')
                            cmd_base = cmd.split()[0].split('/')[-1] if cmd else 'unknown'
                            chain_cmds.append(cmd_base)
                            
                        # Create a hash of the chain
                        chain_str = '->'.join(chain_cmds)
                        chain_hash = hashlib.md5(chain_str.encode()).hexdigest()
                        
                        relationship_data['process_chain_hashes'].append({
                            'hash': chain_hash,
                            'chain': chain_cmds,
                            'path': path
                        })
                        
                        # Record common parent-child relationships
                        for i in range(len(chain_cmds) - 1):
                            parent = chain_cmds[i]
                            child = chain_cmds[i+1]
                            parent_child = f"{parent}->{child}"
                            
                            if parent_child in relationship_data['parent_child_patterns']:
                                relationship_data['parent_child_patterns'][parent_child] += 1
                            else:
                                relationship_data['parent_child_patterns'][parent_child] = 1
        
        # Find common process chains
        if relationship_data['process_chain_hashes']:
            # Group by chain patterns
            chain_patterns = defaultdict(list)
            for chain_data in relationship_data['process_chain_hashes']:
                chain_str = '->'.join(chain_data['chain'])
                chain_patterns[chain_str].append(chain_data)
            
            # Find most common chains (more than 1 occurrence)
            for pattern, instances in chain_patterns.items():
                if len(instances) > 1:
                    relationship_data['common_process_chains'].append({
                        'pattern': pattern,
                        'count': len(instances),
                        'examples': instances[:3]  # Just include a few examples
                    })
        
        return relationship_data
    
    def _get_process_baseline(self):
        """Get baseline information for processes"""
        process_baseline = []
        
        try:
            # Get all processes
            cmd = ["ps", "-eo", "pid,ppid,user,args"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Skip header line
            lines = output.strip().split('\n')[1:]
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split(None, 3)
                if len(parts) >= 4:
                    pid = parts[0]
                    ppid = parts[1]
                    user = parts[2]
                    args = parts[3]
                    
                    process_info = {
                        'pid': pid,
                        'ppid': ppid,
                        'user': user,
                        'command': args
                    }
                    
                    # Try to get executable path
                    try:
                        process_info['exe_path'] = os.path.realpath(f"/proc/{pid}/exe")
                    except (FileNotFoundError, PermissionError):
                        # Process might have terminated or we don't have permission
                        pass
                    
                    # Get network connections
                    try:
                        cmd = ["lsof", "-i", "-a", "-p", pid]
                        net_output = subprocess.check_output(cmd, universal_newlines=True)
                        
                        connections = []
                        # Skip header line
                        net_lines = net_output.strip().split('\n')[1:]
                        
                        for net_line in net_lines:
                            if not net_line.strip():
                                continue
                            
                            parts = net_line.split()
                            if len(parts) >= 9:
                                proto = parts[4]
                                local_addr = parts[8].split('->')[0] if '->' in parts[8] else parts[8]
                                
                                connections.append({
                                    'proto': proto,
                                    'local_addr': local_addr
                                })
                        
                        if connections:
                            process_info['connections'] = connections
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        # lsof might not be installed or no network connections
                        pass
                    
                    process_baseline.append(process_info)
            
            return process_baseline
            
        except Exception as e:
            self.logger.error(f"Error getting process baseline: {e}")
            return []
    
    def compare_baseline(self):
        """Compare current processes with baseline"""
        self.logger.info("Comparing processes with baseline")
        
        # Check if baseline exists
        if not os.path.exists(self.baseline_file):
            self.logger.warning("No baseline found. Run with --establish-baseline first.")
            return {
                'error': "No baseline found",
                'is_anomalous': False
            }
        
        # Load baseline
        with open(self.baseline_file, 'r') as f:
            baseline = json.load(f)
        
        # Get current processes
        current_processes = self._get_process_baseline()
        
        # Compare processes based on command line and user
        baseline_processes = {
            self._get_process_key(proc): proc for proc in baseline.get('processes', [])
        }
        
        current_processes_dict = {
            self._get_process_key(proc): proc for proc in current_processes
        }
        
        # Find new processes
        new_processes = []
        for key, proc in current_processes_dict.items():
            if key not in baseline_processes:
                new_processes.append(proc)
        
        # Find missing processes
        missing_processes = []
        for key, proc in baseline_processes.items():
            if key not in current_processes_dict:
                missing_processes.append(proc)
        
        # Find modified processes
        modified_processes = []
        for key, current_proc in current_processes_dict.items():
            if key in baseline_processes:
                baseline_proc = baseline_processes[key]
                
                # Check for changes
                if current_proc.get('exe_path') != baseline_proc.get('exe_path'):
                    modified_processes.append({
                        'current': current_proc,
                        'baseline': baseline_proc,
                        'change': 'Executable path changed'
                    })
                
                # Check connections
                baseline_connections = baseline_proc.get('connections', [])
                current_connections = current_proc.get('connections', [])
                
                if len(current_connections) != len(baseline_connections):
                    modified_processes.append({
                        'current': current_proc,
                        'baseline': baseline_proc,
                        'change': 'Network connections changed'
                    })
        
        # Determine if there are any suspicious new processes
        suspicious_new_processes = self._find_suspicious_in_list(new_processes)
        
        # Build the process graph for relationship comparison
        self.process_mapper.build_process_tree(current_processes)
        
        # Get relationship comparison
        relationship_comparison = self._compare_process_relationships(baseline)
        
        # Determine if there are any anomalies
        is_anomalous = (
            len(suspicious_new_processes) > 0 or 
            len(modified_processes) > 0 or 
            relationship_comparison.get('is_anomalous', False)
        )
        
        return {
            'timestamp': datetime.now().isoformat(),
            'baseline_timestamp': baseline.get('timestamp'),
            'new_processes': new_processes,
            'suspicious_new_processes': suspicious_new_processes,
            'missing_processes': missing_processes,
            'modified_processes': modified_processes,
            'new_count': len(new_processes),
            'suspicious_new_count': len(suspicious_new_processes),
            'missing_count': len(missing_processes),
            'modified_count': len(modified_processes),
            'process_relationships': relationship_comparison,
            'is_anomalous': is_anomalous
        }
    
    def _compare_process_relationships(self, baseline):
        """
        Compare current process relationships with baseline
        
        Args:
            baseline: Baseline data with process relationship information
            
        Returns:
            dict: Comparison results for process relationships
        """
        comparison = {
            'new_process_chains': [],
            'new_parent_child_relationships': [],
            'missing_common_chains': [],
            'is_anomalous': False
        }
        
        # Skip if no relationship data in baseline
        if 'process_relationships' not in baseline:
            return comparison
            
        baseline_relationships = baseline.get('process_relationships', {})
        
        # Calculate current relationship data
        current_relationships = self._calculate_relationship_baseline()
        
        # Compare process chain hashes
        baseline_chain_hashes = {chain['hash']: chain for chain in baseline_relationships.get('process_chain_hashes', [])}
        current_chain_hashes = {chain['hash']: chain for chain in current_relationships.get('process_chain_hashes', [])}
        
        # Find new process chains
        for hash_key, chain_data in current_chain_hashes.items():
            if hash_key not in baseline_chain_hashes:
                comparison['new_process_chains'].append(chain_data)
        
        # Compare parent-child relationships
        baseline_parent_child = baseline_relationships.get('parent_child_patterns', {})
        current_parent_child = current_relationships.get('parent_child_patterns', {})
        
        # Find new parent-child relationships
        for pattern, count in current_parent_child.items():
            if pattern not in baseline_parent_child:
                # Extract parent and child from pattern
                parent, child = pattern.split('->')
                
                comparison['new_parent_child_relationships'].append({
                    'pattern': pattern,
                    'parent': parent,
                    'child': child,
                    'count': count
                })
        
        # Check for missing common process chains
        baseline_common_chains = {chain['pattern']: chain for chain in baseline_relationships.get('common_process_chains', [])}
        current_common_patterns = {chain['pattern']: chain for chain in current_relationships.get('common_process_chains', [])}
        
        for pattern, chain_data in baseline_common_chains.items():
            if pattern not in current_common_patterns:
                comparison['missing_common_chains'].append(chain_data)
        
        # Generate visualization of current process tree
        visualization = self.process_mapper.visualize_process_tree()
        if visualization:
            comparison['visualization'] = visualization
        
        # Determine if there are anomalies
        is_anomalous = (
            len(comparison['new_process_chains']) > 0 or
            len(comparison['new_parent_child_relationships']) > 0 or
            len(comparison['missing_common_chains']) > 0
        )
        
        # Add anomaly flag
        comparison['is_anomalous'] = is_anomalous
        
        return comparison
    
    def _get_process_key(self, process):
        """Generate a key for process comparison"""
        # Use a combination of command (without PID) and user
        command = process.get('command', '')
        user = process.get('user', '')
        
        # Remove PIDs from command if present
        # This is a simplistic approach - in a real implementation, you'd want to be more sophisticated
        command = re.sub(r'\b\d{1,6}\b', 'PID', command)
        
        return f"{user}:{command}"
    
    def _find_suspicious_in_list(self, process_list):
        """Find suspicious processes in a list"""
        suspicious_processes = []
        
        for process in process_list:
            command = process.get('command', '')
            
            is_suspicious = False
            reasons = []
            
            # Check for suspicious command patterns
            for pattern in self.suspicious_commands:
                if pattern in command.lower():
                    is_suspicious = True
                    reasons.append(f"Suspicious command pattern: '{pattern}'")
            
            # Check executable path
            exe_path = process.get('exe_path', '')
            if exe_path:
                # Check if running from suspicious location
                for path in self.suspicious_paths:
                    if exe_path.startswith(path):
                        is_suspicious = True
                        reasons.append(f"Running from suspicious location: {exe_path}")
            
            if is_suspicious:
                process['reasons'] = reasons
                suspicious_processes.append(process)
        
        return suspicious_processes