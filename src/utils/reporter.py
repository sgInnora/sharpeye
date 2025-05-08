#!/usr/bin/env python3
"""
Reporter Module
Generates reports from detection module results.
"""

import os
import logging
import json
import datetime
import time
import textwrap
from jinja2 import Environment, FileSystemLoader, select_autoescape

class Reporter:
    """Handles report generation for scan results"""
    
    def __init__(self, output_dir, format='text'):
        """Initialize with output directory and format"""
        self.logger = logging.getLogger('sharpeye.reporter')
        self.output_dir = output_dir
        self.format = format.lower()
        self.results = {}
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def add_section(self, section_name, section_data):
        """Add a section to the report"""
        self.results[section_name] = section_data
    
    def generate_report(self):
        """Generate the report based on format"""
        if not self.results:
            self.logger.warning("No results to generate report from")
            return None
        
        # Create timestamp for filename
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"sharpeye_report_{timestamp}"
        
        # Generate report based on format
        if self.format == 'json':
            return self._generate_json_report(filename)
        elif self.format == 'html':
            return self._generate_html_report(filename)
        elif self.format == 'pdf':
            return self._generate_pdf_report(filename)
        else:
            # Default to text format
            return self._generate_text_report(filename)
    
    def _generate_json_report(self, filename):
        """Generate JSON report"""
        self.logger.info("Generating JSON report")
        
        # Add summary information
        report_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'hostname': os.uname().nodename,
            'sections': self.results,
            'summary': self._generate_summary()
        }
        
        # Write to file
        filepath = os.path.join(self.output_dir, f"{filename}.json")
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"JSON report saved to {filepath}")
        
        return filepath
    
    def _generate_text_report(self, filename):
        """Generate text report"""
        self.logger.info("Generating text report")
        
        # Create report content
        content = []
        
        # Add header
        content.append("=" * 80)
        content.append(f"SharpEye Intrusion Detection Report")
        content.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append(f"Hostname: {os.uname().nodename}")
        content.append("=" * 80)
        content.append("")
        
        # Add summary
        content.append("SUMMARY")
        content.append("-" * 80)
        
        summary = self._generate_summary()
        
        if summary['total_anomalies'] > 0:
            content.append(f"WARNING: {summary['total_anomalies']} anomalies detected!")
            content.append("")
            
            for section_name, anomaly_count in summary['anomalies_by_section'].items():
                if anomaly_count > 0:
                    content.append(f"- {section_name}: {anomaly_count} anomalies detected")
        else:
            content.append("No anomalies detected.")
        
        content.append("")
        
        # Add detailed results for each section
        for section_name, section_data in self.results.items():
            content.append(f"{section_name.upper()}")
            content.append("-" * 80)
            
            # Check if section has anomalies
            is_anomalous = section_data.get('is_anomalous', False)
            if is_anomalous:
                content.append("STATUS: ANOMALIES DETECTED")
            else:
                content.append("STATUS: No anomalies detected")
            
            content.append("")
            
            # Add section details
            self._add_section_text(content, section_name, section_data)
            
            content.append("")
        
        # Write to file
        filepath = os.path.join(self.output_dir, f"{filename}.txt")
        with open(filepath, 'w') as f:
            f.write('\n'.join(content))
        
        self.logger.info(f"Text report saved to {filepath}")
        
        return filepath
    
    def _add_section_text(self, content, section_name, section_data, indent=0):
        """Add section data to text report"""
        indent_str = ' ' * indent
        
        # Skip some keys
        skip_keys = ['is_anomalous', 'timestamp', 'error']
        
        for key, value in section_data.items():
            if key in skip_keys:
                continue
            
            if isinstance(value, dict):
                content.append(f"{indent_str}{key.replace('_', ' ').title()}:")
                self._add_section_text(content, f"{section_name}.{key}", value, indent + 2)
            elif isinstance(value, list):
                content.append(f"{indent_str}{key.replace('_', ' ').title()}: {len(value)} items")
                
                if len(value) > 0:
                    if isinstance(value[0], dict):
                        for i, item in enumerate(value[:10]):  # Limit to 10 items
                            content.append(f"{indent_str}  {i+1}.")
                            for item_key, item_value in item.items():
                                content.append(f"{indent_str}    {item_key}: {item_value}")
                        
                        if len(value) > 10:
                            content.append(f"{indent_str}  ... and {len(value) - 10} more items")
                    else:
                        # Simple list of values
                        for i, item in enumerate(value[:10]):  # Limit to 10 items
                            content.append(f"{indent_str}  - {item}")
                        
                        if len(value) > 10:
                            content.append(f"{indent_str}  ... and {len(value) - 10} more items")
            else:
                content.append(f"{indent_str}{key.replace('_', ' ').title()}: {value}")
    
    def _generate_html_report(self, filename):
        """Generate HTML report"""
        self.logger.info("Generating HTML report")
        
        # Load templates
        templates_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'templates')
        
        # If templates directory doesn't exist, create it with a simple template
        if not os.path.exists(templates_dir):
            os.makedirs(templates_dir)
            
            # Create a basic template if it doesn't exist
            template_file = os.path.join(templates_dir, 'report.html')
            if not os.path.exists(template_file):
                with open(template_file, 'w') as f:
                    f.write("""<!DOCTYPE html>
<html>
<head>
    <title>SharpEye Intrusion Detection Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #3498db; margin-top: 30px; }
        h3 { color: #2980b9; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
        .anomaly { color: #e74c3c; font-weight: bold; }
        .normal { color: #27ae60; }
        .section { margin-bottom: 30px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .details { margin-left: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        th { background-color: #3498db; color: white; }
    </style>
</head>
<body>
    <h1>SharpEye Intrusion Detection Report</h1>
    <div class="summary">
        <p><strong>Generated:</strong> {{ timestamp }}</p>
        <p><strong>Hostname:</strong> {{ hostname }}</p>
        
        {% if summary.total_anomalies > 0 %}
            <p class="anomaly">WARNING: {{ summary.total_anomalies }} anomalies detected!</p>
            <ul>
                {% for section, count in summary.anomalies_by_section.items() %}
                    {% if count > 0 %}
                        <li class="anomaly">{{ section }}: {{ count }} anomalies detected</li>
                    {% endif %}
                {% endfor %}
            </ul>
        {% else %}
            <p class="normal">No anomalies detected.</p>
        {% endif %}
    </div>
    
    {% for section_name, section_data in results.items() %}
        <div class="section">
            <h2>{{ section_name|title }}</h2>
            
            {% if section_data.is_anomalous %}
                <p class="anomaly">STATUS: ANOMALIES DETECTED</p>
            {% else %}
                <p class="normal">STATUS: No anomalies detected</p>
            {% endif %}
            
            <div class="details">
                {% for key, value in section_data.items() %}
                    {% if key not in ['is_anomalous', 'timestamp', 'error'] %}
                        {% if value is mapping %}
                            <h3>{{ key|replace('_', ' ')|title }}</h3>
                            <table>
                                <tr>
                                    <th>Property</th>
                                    <th>Value</th>
                                </tr>
                                {% for subkey, subvalue in value.items() %}
                                    <tr>
                                        <td>{{ subkey|replace('_', ' ')|title }}</td>
                                        <td>{{ subvalue }}</td>
                                    </tr>
                                {% endfor %}
                            </table>
                        {% elif value is sequence and value is not string %}
                            <h3>{{ key|replace('_', ' ')|title }}</h3>
                            {% if value|length > 0 %}
                                {% if value[0] is mapping %}
                                    <table>
                                        <tr>
                                            {% for subkey in value[0].keys() %}
                                                <th>{{ subkey|replace('_', ' ')|title }}</th>
                                            {% endfor %}
                                        </tr>
                                        {% for item in value %}
                                            <tr>
                                                {% for subvalue in item.values() %}
                                                    <td>{{ subvalue }}</td>
                                                {% endfor %}
                                            </tr>
                                        {% endfor %}
                                    </table>
                                {% else %}
                                    <ul>
                                        {% for item in value %}
                                            <li>{{ item }}</li>
                                        {% endfor %}
                                    </ul>
                                {% endif %}
                            {% else %}
                                <p>No items found.</p>
                            {% endif %}
                        {% else %}
                            <p><strong>{{ key|replace('_', ' ')|title }}:</strong> {{ value }}</p>
                        {% endif %}
                    {% endif %}
                {% endfor %}
            </div>
        </div>
    {% endfor %}
</body>
</html>
""")
        
        try:
            env = Environment(
                loader=FileSystemLoader(templates_dir),
                autoescape=select_autoescape(['html', 'xml'])
            )
            
            template = env.get_template('report.html')
            
            # Add summary information
            report_data = {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hostname': os.uname().nodename,
                'results': self.results,
                'summary': self._generate_summary()
            }
            
            # Render template
            html_content = template.render(**report_data)
            
            # Write to file
            filepath = os.path.join(self.output_dir, f"{filename}.html")
            with open(filepath, 'w') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report saved to {filepath}")
            
            return filepath
        
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            # Fall back to text report
            return self._generate_text_report(filename)
    
    def _generate_pdf_report(self, filename):
        """Generate PDF report"""
        self.logger.info("Generating PDF report")
        
        try:
            # Try to import pdfkit
            import pdfkit
            
            # First generate HTML report
            html_path = self._generate_html_report(filename)
            
            # Convert HTML to PDF
            pdf_path = os.path.join(self.output_dir, f"{filename}.pdf")
            
            # Check if pdfkit is installed
            pdfkit.from_file(html_path, pdf_path)
            
            self.logger.info(f"PDF report saved to {pdf_path}")
            
            return pdf_path
        
        except ImportError:
            self.logger.warning("pdfkit not installed, falling back to HTML report")
            return self._generate_html_report(filename)
        
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")
            # Fall back to text report
            return self._generate_text_report(filename)
    
    def _generate_summary(self):
        """Generate summary of results"""
        total_anomalies = 0
        anomalies_by_section = {}
        
        for section_name, section_data in self.results.items():
            is_anomalous = section_data.get('is_anomalous', False)
            
            if is_anomalous:
                anomaly_count = 0
                
                # Try to count specific anomalies
                if section_name == 'system':
                    # Count suspicious processes
                    suspicious_processes = section_data.get('suspicious_processes', {}).get('suspicious_processes', [])
                    anomaly_count += len(suspicious_processes)
                
                elif section_name == 'users':
                    # Count suspicious accounts
                    suspicious_accounts = section_data.get('suspicious_accounts', {}).get('suspicious_accounts', [])
                    anomaly_count += len(suspicious_accounts)
                
                elif section_name == 'network':
                    # Count suspicious connections
                    suspicious_connections = section_data.get('suspicious_connections', [])
                    anomaly_count += len(suspicious_connections)
                
                # Default to 1 if we can't count specific anomalies
                if anomaly_count == 0:
                    anomaly_count = 1
                
                total_anomalies += anomaly_count
                anomalies_by_section[section_name] = anomaly_count
            else:
                anomalies_by_section[section_name] = 0
        
        return {
            'total_anomalies': total_anomalies,
            'anomalies_by_section': anomalies_by_section
        }