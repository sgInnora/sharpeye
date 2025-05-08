#!/usr/bin/env python3
"""
Threat Intelligence Module
Provides integration with various threat intelligence feeds to enhance detection capabilities.
"""

import os
import logging
import json
import hashlib
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Union

class ThreatIntelligence:
    """Threat intelligence feed integration"""
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.threat_intel')
        self.config = config or {}
        
        # Configure options
        self.cache_dir = self.config.get('cache_dir', '/var/lib/sharpeye/cache/threat_intel')
        self.cache_ttl = self.config.get('cache_ttl', 86400)  # 24 hours by default
        self.enabled_feeds = self.config.get('enabled_feeds', ['alienvault', 'abuse_ch', 'emerging_threats'])
        self.api_keys = self.config.get('api_keys', {})
        
        # Ensure cache directory exists
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Initialize feed caches
        self.ip_blacklist: Set[str] = set()
        self.domain_blacklist: Set[str] = set()
        self.url_blacklist: Set[str] = set()
        self.indicator_details: Dict[str, Dict] = {}
        
        # Load cached data
        self._load_cached_data()
    
    def _load_cached_data(self):
        """Load cached threat intelligence data if available and not expired"""
        cache_file = os.path.join(self.cache_dir, 'threat_intel_cache.json')
        
        if os.path.exists(cache_file):
            try:
                file_mtime = os.path.getmtime(cache_file)
                if time.time() - file_mtime < self.cache_ttl:
                    with open(cache_file, 'r') as f:
                        cached_data = json.load(f)
                        
                        self.ip_blacklist = set(cached_data.get('ip_blacklist', []))
                        self.domain_blacklist = set(cached_data.get('domain_blacklist', []))
                        self.url_blacklist = set(cached_data.get('url_blacklist', []))
                        self.indicator_details = cached_data.get('indicator_details', {})
                        
                        self.logger.info(f"Loaded {len(self.ip_blacklist)} IPs, {len(self.domain_blacklist)} domains, and {len(self.url_blacklist)} URLs from cache")
                        return
            except Exception as e:
                self.logger.error(f"Error loading cached threat intelligence data: {e}")
        
        # If we get here, we need to refresh the data
        self.refresh_all()
    
    def _save_cached_data(self):
        """Save current threat intelligence data to cache"""
        cache_file = os.path.join(self.cache_dir, 'threat_intel_cache.json')
        
        try:
            cached_data = {
                'ip_blacklist': list(self.ip_blacklist),
                'domain_blacklist': list(self.domain_blacklist),
                'url_blacklist': list(self.url_blacklist),
                'indicator_details': self.indicator_details,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(cache_file, 'w') as f:
                json.dump(cached_data, f)
                
            self.logger.info(f"Saved threat intelligence data to cache: {cache_file}")
        except Exception as e:
            self.logger.error(f"Error saving threat intelligence data to cache: {e}")
    
    def refresh_all(self):
        """Refresh all threat intelligence feeds"""
        self.logger.info("Refreshing all threat intelligence feeds")
        
        for feed in self.enabled_feeds:
            try:
                if feed == 'alienvault':
                    self._refresh_alienvault()
                elif feed == 'abuse_ch':
                    self._refresh_abuse_ch()
                elif feed == 'emerging_threats':
                    self._refresh_emerging_threats()
                elif feed == 'custom':
                    self._refresh_custom_feeds()
            except Exception as e:
                self.logger.error(f"Error refreshing {feed} feed: {e}")
        
        # Save to cache
        self._save_cached_data()
    
    def _refresh_alienvault(self):
        """Refresh AlienVault OTX feed"""
        self.logger.info("Refreshing AlienVault OTX feed")
        
        api_key = self.api_keys.get('alienvault')
        if not api_key:
            self.logger.warning("AlienVault OTX API key not configured, using public reputation database")
            
            # Fallback to public reputation database
            try:
                # IP reputation database
                response = requests.get(
                    'https://reputation.alienvault.com/reputation.data',
                    timeout=10
                )
                
                if response.status_code == 200:
                    for line in response.text.splitlines():
                        if line and not line.startswith('#'):
                            parts = line.split('#')
                            if len(parts) >= 1:
                                ip = parts[0].strip()
                                if ip:
                                    self.ip_blacklist.add(ip)
                                    self.indicator_details[ip] = {
                                        'source': 'alienvault',
                                        'type': 'ip',
                                        'reputation': 'malicious'
                                    }
                    
                    self.logger.info(f"Added {len(self.ip_blacklist)} IPs from AlienVault public reputation database")
            except Exception as e:
                self.logger.error(f"Error fetching AlienVault public reputation database: {e}")
            
            return
        
        # If we have an API key, use the OTX API
        try:
            from OTXv2 import OTXv2
            import IndicatorTypes
            
            otx = OTXv2(api_key)
            
            # Get pulse subscriptions
            pulses = otx.getall()
            self.logger.info(f"Retrieved {len(pulses)} pulses from AlienVault OTX")
            
            # Process pulses
            for pulse in pulses:
                if 'indicators' in pulse:
                    for indicator in pulse['indicators']:
                        indicator_type = indicator.get('type')
                        indicator_value = indicator.get('indicator')
                        
                        if not indicator_value:
                            continue
                        
                        # Store in appropriate blacklist
                        if indicator_type == 'IPv4' or indicator_type == 'IPv6':
                            self.ip_blacklist.add(indicator_value)
                            self.indicator_details[indicator_value] = {
                                'source': 'alienvault',
                                'type': 'ip',
                                'pulse_name': pulse.get('name'),
                                'description': pulse.get('description'),
                                'tags': pulse.get('tags', [])
                            }
                        elif indicator_type == 'domain' or indicator_type == 'hostname':
                            self.domain_blacklist.add(indicator_value)
                            self.indicator_details[indicator_value] = {
                                'source': 'alienvault',
                                'type': 'domain',
                                'pulse_name': pulse.get('name'),
                                'description': pulse.get('description'),
                                'tags': pulse.get('tags', [])
                            }
                        elif indicator_type == 'URL' or indicator_type == 'URI':
                            self.url_blacklist.add(indicator_value)
                            self.indicator_details[indicator_value] = {
                                'source': 'alienvault',
                                'type': 'url',
                                'pulse_name': pulse.get('name'),
                                'description': pulse.get('description'),
                                'tags': pulse.get('tags', [])
                            }
            
            self.logger.info(f"Added indicators from AlienVault OTX: {len(self.ip_blacklist)} IPs, {len(self.domain_blacklist)} domains, {len(self.url_blacklist)} URLs")
        except ImportError:
            self.logger.warning("OTXv2 library not installed, cannot use AlienVault OTX API")
        except Exception as e:
            self.logger.error(f"Error retrieving AlienVault OTX indicators: {e}")
    
    def _refresh_abuse_ch(self):
        """Refresh Abuse.ch feeds"""
        self.logger.info("Refreshing Abuse.ch feeds")
        
        try:
            # Feodo Tracker - Botnet C&C IPs
            response = requests.get(
                'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                timeout=10
            )
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line and not line.startswith('#'):
                        ip = line.strip()
                        if ip:
                            self.ip_blacklist.add(ip)
                            self.indicator_details[ip] = {
                                'source': 'abuse.ch',
                                'type': 'ip',
                                'feed': 'feodotracker',
                                'description': 'Botnet C&C IP'
                            }
                
                self.logger.info(f"Added IPs from Abuse.ch Feodo Tracker")
        except Exception as e:
            self.logger.error(f"Error fetching Abuse.ch Feodo Tracker feed: {e}")
        
        try:
            # URLhaus - Malicious URLs
            response = requests.get(
                'https://urlhaus.abuse.ch/downloads/text/',
                timeout=10
            )
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line and not line.startswith('#'):
                        url = line.strip()
                        if url:
                            self.url_blacklist.add(url)
                            self.indicator_details[url] = {
                                'source': 'abuse.ch',
                                'type': 'url',
                                'feed': 'urlhaus',
                                'description': 'Malware distribution URL'
                            }
                
                self.logger.info(f"Added URLs from Abuse.ch URLhaus")
        except Exception as e:
            self.logger.error(f"Error fetching Abuse.ch URLhaus feed: {e}")
        
        try:
            # SSL Blacklist - Malicious SSL certificates
            response = requests.get(
                'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
                timeout=10
            )
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line and not line.startswith('#'):
                        ip = line.strip()
                        if ip:
                            self.ip_blacklist.add(ip)
                            self.indicator_details[ip] = {
                                'source': 'abuse.ch',
                                'type': 'ip',
                                'feed': 'sslbl',
                                'description': 'Malicious SSL certificate'
                            }
                
                self.logger.info(f"Added IPs from Abuse.ch SSL Blacklist")
        except Exception as e:
            self.logger.error(f"Error fetching Abuse.ch SSL Blacklist feed: {e}")
    
    def _refresh_emerging_threats(self):
        """Refresh Emerging Threats feeds"""
        self.logger.info("Refreshing Emerging Threats feeds")
        
        try:
            # Emerging Threats - Known compromised hosts
            response = requests.get(
                'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                timeout=10
            )
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line and not line.startswith('#'):
                        ip = line.strip()
                        if ip:
                            self.ip_blacklist.add(ip)
                            self.indicator_details[ip] = {
                                'source': 'emerging_threats',
                                'type': 'ip',
                                'feed': 'compromised',
                                'description': 'Known compromised host'
                            }
                
                self.logger.info(f"Added IPs from Emerging Threats compromised hosts")
        except Exception as e:
            self.logger.error(f"Error fetching Emerging Threats compromised hosts feed: {e}")
        
        try:
            # Emerging Threats - Command and Control servers
            response = requests.get(
                'https://rules.emergingthreats.net/blockrules/emerging-botcc.rules',
                timeout=10
            )
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if 'IP:' in line:
                        parts = line.split('IP:')
                        if len(parts) >= 2:
                            ip_part = parts[1].strip()
                            ip = ip_part.split(' ')[0]
                            if ip:
                                self.ip_blacklist.add(ip)
                                self.indicator_details[ip] = {
                                    'source': 'emerging_threats',
                                    'type': 'ip',
                                    'feed': 'botcc',
                                    'description': 'Command and Control server'
                                }
                
                self.logger.info(f"Added IPs from Emerging Threats C&C servers")
        except Exception as e:
            self.logger.error(f"Error fetching Emerging Threats C&C servers feed: {e}")
    
    def _refresh_custom_feeds(self):
        """Refresh custom feeds defined in configuration"""
        self.logger.info("Refreshing custom feeds")
        
        custom_feeds = self.config.get('custom_feeds', [])
        for feed in custom_feeds:
            feed_name = feed.get('name', 'unknown')
            feed_url = feed.get('url')
            feed_type = feed.get('type', 'ip')
            feed_format = feed.get('format', 'text')
            
            if not feed_url:
                self.logger.warning(f"Custom feed {feed_name} missing URL, skipping")
                continue
            
            try:
                self.logger.info(f"Fetching custom feed: {feed_name}")
                response = requests.get(feed_url, timeout=10)
                
                if response.status_code == 200:
                    if feed_format == 'text':
                        for line in response.text.splitlines():
                            if line and not line.startswith('#'):
                                indicator = line.strip()
                                if indicator:
                                    if feed_type == 'ip':
                                        self.ip_blacklist.add(indicator)
                                    elif feed_type == 'domain':
                                        self.domain_blacklist.add(indicator)
                                    elif feed_type == 'url':
                                        self.url_blacklist.add(indicator)
                                    
                                    self.indicator_details[indicator] = {
                                        'source': 'custom',
                                        'feed_name': feed_name,
                                        'type': feed_type,
                                        'description': feed.get('description', 'Custom feed')
                                    }
                    elif feed_format == 'json':
                        data = response.json()
                        indicators = feed.get('json_path', [])
                        
                        if isinstance(indicators, str):
                            # Simple JSON path like 'data.indicators'
                            parts = indicators.split('.')
                            current = data
                            for part in parts:
                                if isinstance(current, dict) and part in current:
                                    current = current[part]
                                else:
                                    current = []
                                    break
                            
                            indicators = current
                        
                        if isinstance(indicators, list):
                            for indicator in indicators:
                                if isinstance(indicator, str):
                                    value = indicator
                                elif isinstance(indicator, dict):
                                    value = indicator.get(feed.get('value_field', 'indicator'), '')
                                else:
                                    continue
                                
                                if value:
                                    if feed_type == 'ip':
                                        self.ip_blacklist.add(value)
                                    elif feed_type == 'domain':
                                        self.domain_blacklist.add(value)
                                    elif feed_type == 'url':
                                        self.url_blacklist.add(value)
                                    
                                    self.indicator_details[value] = {
                                        'source': 'custom',
                                        'feed_name': feed_name,
                                        'type': feed_type,
                                        'description': feed.get('description', 'Custom feed')
                                    }
                    
                    self.logger.info(f"Added indicators from custom feed {feed_name}")
            except Exception as e:
                self.logger.error(f"Error fetching custom feed {feed_name}: {e}")
    
    def check_ip(self, ip: str) -> dict:
        """Check if an IP is in a blacklist
        
        Args:
            ip (str): IP address to check
            
        Returns:
            dict: Information about the indicator if found, empty dict if not
        """
        if ip in self.ip_blacklist:
            return self.indicator_details.get(ip, {'source': 'unknown', 'type': 'ip'})
        return {}
    
    def check_domain(self, domain: str) -> dict:
        """Check if a domain is in a blacklist
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: Information about the indicator if found, empty dict if not
        """
        # Direct match
        if domain in self.domain_blacklist:
            return self.indicator_details.get(domain, {'source': 'unknown', 'type': 'domain'})
        
        # Check for subdomain matches
        parts = domain.split('.')
        for i in range(1, len(parts) - 1):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.domain_blacklist:
                result = self.indicator_details.get(parent_domain, {'source': 'unknown', 'type': 'domain'})
                result['matched_parent'] = parent_domain
                return result
        
        return {}
    
    def check_url(self, url: str) -> dict:
        """Check if a URL is in a blacklist
        
        Args:
            url (str): URL to check
            
        Returns:
            dict: Information about the indicator if found, empty dict if not
        """
        if url in self.url_blacklist:
            return self.indicator_details.get(url, {'source': 'unknown', 'type': 'url'})
        return {}
    
    def get_stats(self) -> dict:
        """Get statistics about the loaded threat intelligence data
        
        Returns:
            dict: Statistics
        """
        return {
            'ip_count': len(self.ip_blacklist),
            'domain_count': len(self.domain_blacklist),
            'url_count': len(self.url_blacklist),
            'total_indicators': len(self.indicator_details),
            'feeds': list(set(item.get('source', 'unknown') for item in self.indicator_details.values()))
        }