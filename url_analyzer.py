#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URL Analysis and Reputation System
"""
import re
import socket
import urllib.parse
from typing import Dict, List, Optional, Tuple
import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta

class URLAnalyzer:
    """Analyze URLs for phishing indicators and reputation."""
    
    def __init__(self, cache_dir: str = "cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
        # Local blacklist/whitelist
        self.blacklist_file = self.cache_dir / "url_blacklist.json"
        self.whitelist_file = self.cache_dir / "url_whitelist.json"
        
        self.blacklist = self._load_list(self.blacklist_file)
        self.whitelist = self._load_list(self.whitelist_file)
        
        # Known phishing patterns
        self.phishing_keywords = {
            'secure', 'account', 'update', 'verify', 'suspend', 'confirm',
            'banking', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
            'refund', 'locked', 'expired', 'billing', 'payment'
        }
        
        # Suspicious TLDs often used in phishing
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review',
            '.top', '.win', '.bid', '.trade', '.date', '.stream', '.press'
        }
        
        # URL shorteners that hide the real destination
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 't.co',
            'buff.ly', 'short.link', 'tiny.cc', 'shorturl.at', 'cutt.ly',
            'rebrand.ly', 'short.io', 'bl.ink', 'zapier.com', 'qr.net'
        }
        
        # Legitimate domains for similarity checking
        self.legitimate_domains = {
            'google.com': ['accounts.google.com', 'mail.google.com', 'drive.google.com'],
            'apple.com': ['appleid.apple.com', 'icloud.com', 'support.apple.com'],
            'microsoft.com': ['login.microsoftonline.com', 'outlook.com', 'office.com'],
            'amazon.com': ['smile.amazon.com', 'aws.amazon.com', 'prime.amazon.com'],
            'paypal.com': ['checkout.paypal.com', 'paypalobjects.com'],
            'facebook.com': ['m.facebook.com', 'business.facebook.com'],
            'linkedin.com': ['www.linkedin.com', 'lnkd.in'],
            'twitter.com': ['mobile.twitter.com', 'api.twitter.com'],
            'ebay.com': ['signin.ebay.com', 'pages.ebay.com'],
            'netflix.com': ['www.netflix.com', 'help.netflix.com']
        }
    
    def analyze_url(self, url: str) -> Dict[str, any]:
        """Comprehensive URL analysis."""
        if not url:
            return {'error': 'No URL provided'}
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            parsed = urllib.parse.urlparse(url)
        except:
            return {'error': 'Invalid URL format'}
        
        analysis = {
            'url': url,
            'domain': parsed.netloc,
            'path': parsed.path,
            'risk_score': 0.0,
            'risk_factors': [],
            'is_blacklisted': False,
            'is_whitelisted': False,
            'indicators': {}
        }
        
        # Check blacklist/whitelist
        domain_hash = self._hash_domain(parsed.netloc)
        if domain_hash in self.blacklist:
            analysis['is_blacklisted'] = True
            analysis['risk_score'] = 1.0
            analysis['risk_factors'].append('Previously identified as phishing')
            return analysis
        
        if domain_hash in self.whitelist:
            analysis['is_whitelisted'] = True
            analysis['risk_score'] = 0.0
            return analysis
        
        # Perform various checks
        risk_score = 0.0
        
        # Check URL shortener
        if self._is_shortener(parsed.netloc):
            risk_score += 0.3
            analysis['risk_factors'].append('URL shortener detected')
            analysis['indicators']['is_shortener'] = True
        
        # Check for IP address
        if self._is_ip_address(parsed.netloc):
            risk_score += 0.4
            analysis['risk_factors'].append('IP address instead of domain')
            analysis['indicators']['has_ip'] = True
        
        # Check suspicious TLD
        tld_risk = self._check_suspicious_tld(url)
        if tld_risk > 0:
            risk_score += tld_risk
            analysis['risk_factors'].append(f'Suspicious TLD detected')
            analysis['indicators']['suspicious_tld'] = True
        
        # Check for homograph attack
        homograph_risk = self._check_homograph_attack(parsed.netloc)
        if homograph_risk > 0:
            risk_score += homograph_risk
            analysis['risk_factors'].append('Possible homograph attack')
            analysis['indicators']['homograph_attack'] = True
        
        # Check for typosquatting
        typo_result = self._check_typosquatting(parsed.netloc)
        if typo_result:
            risk_score += 0.5
            analysis['risk_factors'].append(f'Possible typosquatting of {typo_result}')
            analysis['indicators']['typosquatting'] = typo_result
        
        # Check URL length and complexity
        if len(url) > 100:
            risk_score += 0.1
            analysis['risk_factors'].append('Unusually long URL')
            analysis['indicators']['long_url'] = True
        
        # Check for multiple subdomains
        subdomain_count = parsed.netloc.count('.')
        if subdomain_count > 3:
            risk_score += 0.2
            analysis['risk_factors'].append('Multiple subdomains')
            analysis['indicators']['many_subdomains'] = subdomain_count
        
        # Check for suspicious keywords in URL
        keyword_risk = self._check_phishing_keywords(url.lower())
        if keyword_risk > 0:
            risk_score += keyword_risk
            analysis['risk_factors'].append('Phishing keywords in URL')
            analysis['indicators']['has_keywords'] = True
        
        # Check for redirects
        if parsed.query and ('url=' in parsed.query or 'redirect=' in parsed.query):
            risk_score += 0.2
            analysis['risk_factors'].append('Contains redirect parameter')
            analysis['indicators']['has_redirect'] = True
        
        # Check for @ symbol (can hide real domain)
        if '@' in url:
            risk_score += 0.3
            analysis['risk_factors'].append('Contains @ symbol (may hide real destination)')
            analysis['indicators']['has_at_symbol'] = True
        
        # Normalize risk score
        analysis['risk_score'] = min(risk_score, 1.0)
        
        # Classify risk level
        if analysis['risk_score'] >= 0.7:
            analysis['risk_level'] = 'high'
        elif analysis['risk_score'] >= 0.4:
            analysis['risk_level'] = 'medium'
        else:
            analysis['risk_level'] = 'low'
        
        return analysis
    
    def _is_shortener(self, domain: str) -> bool:
        """Check if domain is a URL shortener."""
        return any(shortener in domain.lower() for shortener in self.url_shorteners)
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address."""
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Check for IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, domain):
            return True
        
        # Check for IPv6
        try:
            socket.inet_pton(socket.AF_INET6, domain)
            return True
        except:
            pass
        
        return False
    
    def _check_suspicious_tld(self, url: str) -> float:
        """Check for suspicious TLDs."""
        url_lower = url.lower()
        for tld in self.suspicious_tlds:
            if tld in url_lower:
                return 0.3
        return 0.0
    
    def _check_homograph_attack(self, domain: str) -> float:
        """Check for homograph attacks using similar-looking characters."""
        # Common homograph substitutions
        homographs = {
            'o': ['0', 'ο'],  # Latin o vs zero vs Greek omicron
            'i': ['1', 'l', 'ı', 'í'],  # Various i-like characters
            'a': ['α', '@', '4'],  # Latin a vs Greek alpha
            'e': ['ε', '3'],  # Latin e vs Greek epsilon
            'c': ['с'],  # Latin c vs Cyrillic s
            'p': ['ρ'],  # Latin p vs Greek rho
            'n': ['η'],  # Latin n vs Greek eta
            'v': ['ν'],  # Latin v vs Greek nu
            'x': ['х'],  # Latin x vs Cyrillic kh
        }
        
        # Check if domain contains mix of scripts
        has_latin = bool(re.search(r'[a-z]', domain.lower()))
        has_cyrillic = bool(re.search(r'[а-я]', domain.lower()))
        has_greek = bool(re.search(r'[α-ω]', domain.lower()))
        
        script_count = sum([has_latin, has_cyrillic, has_greek])
        
        if script_count > 1:
            return 0.5  # Mixed scripts detected
        
        # Check for suspicious substitutions
        for char, substitutes in homographs.items():
            for sub in substitutes:
                if sub in domain:
                    # Check if this looks like a known domain
                    for legit in self.legitimate_domains:
                        if char in legit and domain.replace(sub, char) == legit:
                            return 0.6
        
        return 0.0
    
    def _check_typosquatting(self, domain: str) -> Optional[str]:
        """Check if domain is typosquatting a legitimate domain."""
        domain_clean = domain.lower().replace('www.', '')
        
        for legit_domain, variations in self.legitimate_domains.items():
            # Check exact variations
            if domain_clean in variations:
                continue  # It's a legitimate subdomain
            
            # Check common typos
            typo_patterns = [
                legit_domain.replace('.com', '-com'),
                legit_domain.replace('.', ''),
                legit_domain.replace('a', '4'),
                legit_domain.replace('e', '3'),
                legit_domain.replace('i', '1'),
                legit_domain.replace('o', '0'),
                legit_domain.replace('s', '5'),
            ]
            
            # Check character swaps
            for i in range(len(legit_domain) - 1):
                swapped = list(legit_domain)
                swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
                typo_patterns.append(''.join(swapped))
            
            # Check if current domain matches any typo pattern
            for pattern in typo_patterns:
                if domain_clean == pattern or pattern in domain_clean:
                    return legit_domain
            
            # Check Levenshtein distance
            if self._levenshtein_distance(domain_clean, legit_domain) <= 2:
                return legit_domain
        
        return None
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _check_phishing_keywords(self, url: str) -> float:
        """Check for phishing keywords in URL."""
        keyword_count = sum(1 for keyword in self.phishing_keywords if keyword in url)
        if keyword_count >= 3:
            return 0.4
        elif keyword_count >= 2:
            return 0.2
        elif keyword_count >= 1:
            return 0.1
        return 0.0
    
    def add_to_blacklist(self, url: str):
        """Add URL to blacklist."""
        parsed = urllib.parse.urlparse(url)
        domain_hash = self._hash_domain(parsed.netloc)
        
        if domain_hash not in self.blacklist:
            self.blacklist[domain_hash] = {
                'domain': parsed.netloc,
                'added': datetime.now().isoformat(),
                'count': 1
            }
        else:
            self.blacklist[domain_hash]['count'] += 1
        
        self._save_list(self.blacklist, self.blacklist_file)
    
    def add_to_whitelist(self, url: str):
        """Add URL to whitelist."""
        parsed = urllib.parse.urlparse(url)
        domain_hash = self._hash_domain(parsed.netloc)
        
        if domain_hash not in self.whitelist:
            self.whitelist[domain_hash] = {
                'domain': parsed.netloc,
                'added': datetime.now().isoformat()
            }
        
        self._save_list(self.whitelist, self.whitelist_file)
    
    def _hash_domain(self, domain: str) -> str:
        """Hash domain for storage."""
        return hashlib.sha256(domain.lower().encode()).hexdigest()[:16]
    
    def _load_list(self, file_path: Path) -> Dict:
        """Load blacklist or whitelist from file."""
        if file_path.exists():
            try:
                with open(file_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def _save_list(self, data: Dict, file_path: Path):
        """Save blacklist or whitelist to file."""
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)


def check_url_safety(url: str) -> Dict[str, any]:
    """Convenience function to check URL safety."""
    analyzer = URLAnalyzer()
    return analyzer.analyze_url(url)