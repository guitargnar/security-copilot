#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Feature Extraction for Enhanced Phishing Detection
"""
import re
import urllib.parse
from typing import Dict, List, Tuple
from collections import Counter
import string
import math

class AdvancedFeatureExtractor:
    """Extract sophisticated features from email/text content for better detection."""
    
    def __init__(self):
        # Common phishing keywords by category
        self.urgency_words = {
            'urgent', 'immediate', 'expires', 'suspended', 'locked',
            'verify', 'confirm', 'update', 'act now', 'limited time',
            'final notice', 'warning', 'alert', 'attention required'
        }
        
        self.financial_words = {
            'payment', 'invoice', 'refund', 'tax', 'irs', 'bank',
            'account', 'billing', 'credit', 'debit', 'transaction',
            'transfer', 'wire', 'deposit', 'withdrawal'
        }
        
        self.prize_words = {
            'congratulations', 'winner', 'won', 'prize', 'lottery',
            'jackpot', 'million', 'claim', 'selected', 'lucky'
        }
        
        self.action_words = {
            'click', 'download', 'install', 'open', 'view',
            'access', 'login', 'sign', 'enter', 'submit'
        }
        
        # Suspicious URL patterns
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd',
            'buff.ly', 'short.link', 'tiny.cc', 'shorturl.at'
        }
        
        # Common legitimate domains for comparison
        self.legitimate_domains = {
            'google.com', 'gmail.com', 'apple.com', 'microsoft.com',
            'amazon.com', 'paypal.com', 'ebay.com', 'facebook.com',
            'twitter.com', 'linkedin.com', 'youtube.com', 'instagram.com'
        }
        
    def extract_all_features(self, text: str) -> Dict[str, float]:
        """Extract all advanced features from text."""
        text_lower = text.lower()
        
        features = {}
        
        # Basic statistics
        features.update(self._extract_basic_stats(text))
        
        # Keyword features
        features.update(self._extract_keyword_features(text_lower))
        
        # URL features
        features.update(self._extract_url_features(text))
        
        # Pattern features
        features.update(self._extract_pattern_features(text))
        
        # Entropy and complexity
        features.update(self._extract_entropy_features(text))
        
        # Grammatical features
        features.update(self._extract_grammar_features(text))
        
        return features
    
    def _extract_basic_stats(self, text: str) -> Dict[str, float]:
        """Extract basic statistical features."""
        return {
            'length': len(text),
            'num_words': len(text.split()),
            'num_sentences': text.count('.') + text.count('!') + text.count('?'),
            'num_capitals': sum(1 for c in text if c.isupper()),
            'capital_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
            'num_digits': sum(1 for c in text if c.isdigit()),
            'digit_ratio': sum(1 for c in text if c.isdigit()) / max(len(text), 1),
            'num_special': sum(1 for c in text if c in '!@#$%^&*()'),
            'special_ratio': sum(1 for c in text if c in '!@#$%^&*()') / max(len(text), 1),
        }
    
    def _extract_keyword_features(self, text: str) -> Dict[str, float]:
        """Extract keyword-based features."""
        features = {
            'urgency_score': sum(1 for word in self.urgency_words if word in text),
            'financial_score': sum(1 for word in self.financial_words if word in text),
            'prize_score': sum(1 for word in self.prize_words if word in text),
            'action_score': sum(1 for word in self.action_words if word in text),
        }
        
        # Check for ALL CAPS urgency
        features['has_caps_urgency'] = 1.0 if any(
            word.upper() in text for word in self.urgency_words
        ) else 0.0
        
        # Multiple exclamation marks
        features['multiple_exclamation'] = 1.0 if '!!' in text else 0.0
        features['exclamation_count'] = text.count('!')
        
        return features
    
    def _extract_url_features(self, text: str) -> Dict[str, float]:
        """Extract URL-related features."""
        # Find all URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text.lower())
        
        features = {
            'num_urls': len(urls),
            'has_url': 1.0 if urls else 0.0,
            'has_shortener': 0.0,
            'has_ip_address': 0.0,
            'suspicious_tld': 0.0,
            'typosquatting_risk': 0.0,
            'url_entropy_avg': 0.0,
        }
        
        if not urls:
            return features
        
        entropy_scores = []
        
        for url in urls:
            # Check for URL shorteners
            if any(shortener in url for shortener in self.url_shorteners):
                features['has_shortener'] = 1.0
            
            # Check for IP addresses
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.search(ip_pattern, url):
                features['has_ip_address'] = 1.0
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            if any(tld in url for tld in suspicious_tlds):
                features['suspicious_tld'] = 1.0
            
            # Check for typosquatting
            for legit in self.legitimate_domains:
                if self._is_typosquatting(url, legit):
                    features['typosquatting_risk'] = 1.0
            
            # Calculate URL entropy
            entropy_scores.append(self._calculate_entropy(url))
        
        features['url_entropy_avg'] = sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0.0
        
        return features
    
    def _is_typosquatting(self, url: str, legitimate: str) -> bool:
        """Check if URL might be typosquatting a legitimate domain."""
        # Common typosquatting patterns
        typo_patterns = [
            legitimate.replace('a', '4'),
            legitimate.replace('e', '3'),
            legitimate.replace('i', '1'),
            legitimate.replace('o', '0'),
            legitimate.replace('s', '5'),
            legitimate.replace('m', 'rn'),
            legitimate.replace('l', 'I'),
        ]
        
        for pattern in typo_patterns:
            if pattern in url and legitimate not in url:
                return True
        
        # Check for extra characters
        if legitimate[:-4] in url and legitimate not in url:  # Remove .com
            return True
            
        return False
    
    def _extract_pattern_features(self, text: str) -> Dict[str, float]:
        """Extract pattern-based features."""
        features = {}
        
        # Check for currency amounts
        currency_pattern = r'\$[\d,]+\.?\d*|\d+\s*(USD|dollars?|euros?|pounds?|GBP|EUR)'
        features['has_currency'] = 1.0 if re.search(currency_pattern, text, re.IGNORECASE) else 0.0
        features['currency_count'] = len(re.findall(currency_pattern, text, re.IGNORECASE))
        
        # Check for phone numbers
        phone_pattern = r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b|\b\d{10}\b'
        features['has_phone'] = 1.0 if re.search(phone_pattern, text) else 0.0
        
        # Check for email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        features['num_emails'] = len(re.findall(email_pattern, text))
        
        # Check for suspicious phrases
        suspicious_phrases = [
            'verify your account',
            'suspended account',
            'click here immediately',
            'confirm your identity',
            'update your information',
            'claim your prize',
            'act now',
            'limited time offer',
            'this is not a scam',
            'dear customer',
            'valued customer'
        ]
        
        features['suspicious_phrase_count'] = sum(
            1 for phrase in suspicious_phrases if phrase in text.lower()
        )
        
        return features
    
    def _extract_entropy_features(self, text: str) -> Dict[str, float]:
        """Extract entropy and complexity features."""
        features = {}
        
        # Character entropy
        features['char_entropy'] = self._calculate_entropy(text)
        
        # Word entropy
        words = text.lower().split()
        features['word_entropy'] = self._calculate_entropy(' '.join(words))
        
        # Punctuation density
        punct_count = sum(1 for c in text if c in string.punctuation)
        features['punctuation_density'] = punct_count / max(len(text), 1)
        
        # Whitespace irregularity
        features['multiple_spaces'] = 1.0 if '  ' in text else 0.0
        features['space_ratio'] = text.count(' ') / max(len(text), 1)
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _extract_grammar_features(self, text: str) -> Dict[str, float]:
        """Extract grammatical and stylistic features."""
        features = {}
        
        # Average word length
        words = text.split()
        if words:
            features['avg_word_length'] = sum(len(word) for word in words) / len(words)
        else:
            features['avg_word_length'] = 0.0
        
        # Sentence length variance
        sentences = re.split(r'[.!?]+', text)
        sentence_lengths = [len(s.split()) for s in sentences if s.strip()]
        
        if sentence_lengths:
            features['avg_sentence_length'] = sum(sentence_lengths) / len(sentence_lengths)
            if len(sentence_lengths) > 1:
                mean = sum(sentence_lengths) / len(sentence_lengths)
                variance = sum((x - mean) ** 2 for x in sentence_lengths) / len(sentence_lengths)
                features['sentence_length_variance'] = variance
            else:
                features['sentence_length_variance'] = 0.0
        else:
            features['avg_sentence_length'] = 0.0
            features['sentence_length_variance'] = 0.0
        
        # Question marks (fishing for information)
        features['num_questions'] = text.count('?')
        features['question_ratio'] = text.count('?') / max(len(sentences), 1)
        
        # Repeated punctuation
        features['repeated_punctuation'] = 1.0 if any(
            p * 2 in text for p in '!?.'
        ) else 0.0
        
        return features
    
    def get_feature_importance_scores(self, features: Dict[str, float]) -> List[Tuple[str, float]]:
        """Return features sorted by their importance for phishing detection."""
        # Weight different feature categories
        weights = {
            'urgency_score': 3.0,
            'has_shortener': 2.5,
            'has_ip_address': 3.0,
            'typosquatting_risk': 3.5,
            'suspicious_phrase_count': 2.0,
            'currency_count': 1.5,
            'multiple_exclamation': 1.2,
            'suspicious_tld': 2.8,
            'financial_score': 2.0,
            'prize_score': 2.5,
        }
        
        scored_features = []
        for feature, value in features.items():
            weight = weights.get(feature, 1.0)
            scored_features.append((feature, value * weight))
        
        return sorted(scored_features, key=lambda x: x[1], reverse=True)


def extract_features_for_model(text: str) -> Dict[str, float]:
    """Convenience function to extract features for model training/prediction."""
    extractor = AdvancedFeatureExtractor()
    return extractor.extract_all_features(text)