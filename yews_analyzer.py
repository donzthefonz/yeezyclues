#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple, Set
import requests
from bs4 import BeautifulSoup
import base64
import re
from dataclasses import dataclass
from datetime import datetime
import logging
from pathlib import Path
import json
from urllib.parse import urljoin, urlparse
from tqdm import tqdm
from collections import Counter
import math
from enum import Enum, auto

class SuspiciousType(Enum):
    """Types of suspicious patterns that can be detected."""
    UNUSUAL_BASE64 = auto()
    HIDDEN_CONTENT = auto()
    ANOMALOUS_LENGTH = auto()
    STEGANOGRAPHY_MARKER = auto()
    UNUSUAL_DISTRIBUTION = auto()
    KNOWN_PATTERN = auto()

@dataclass
class SuspiciousPattern:
    """Details about a suspicious pattern found."""
    type: SuspiciousType
    description: str
    severity: int  # 1-10
    evidence: str

@dataclass
class AnalysisResult:
    """Contains results from analyzing a single piece of content."""
    url: str
    timestamp: datetime
    pattern_count: int
    content_length: int
    encoded_segments: List[str]
    content_type: str
    suspicious_patterns: List[SuspiciousPattern]

class YewsAnalyzer:
    """Analyzes content from yews.news for specific encoded patterns."""
    
    # Known suspicious patterns
    SUSPICIOUS_MARKERS = {
        r'PK\x03\x04': 'ZIP header',
        r'\xFF\xD8\xFF\xE0': 'JPEG header',
        r'JFIF': 'JPEG marker',
        r'IHDR': 'PNG header',
        'BEGIN:VCARD': 'vCard data',
        'data:image': 'Data URI',
    }
    
    # Common steganography tool markers
    STEGO_MARKERS = {
        'outguess': 'OutGuess tool marker',
        'steghide': 'StegHide marker',
        'jsteg': 'JSteG marker',
        'f5': 'F5 algorithm marker',
    }
    
    def __init__(self, target_pattern: str = "4NBT", output_dir: Path = Path("scan_results")):
        """
        Initialize the analyzer.
        
        Args:
            target_pattern: The pattern to search for in encoded content
            output_dir: Directory to store scan results
        """
        self.target_pattern = target_pattern
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.visited_urls: Set[str] = set()
        self.base_domain = "yews.news"
        
        # Track content statistics for anomaly detection
        self.content_lengths: List[int] = []
        self.base64_lengths: List[int] = []
        
        # Configure session for requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(output_dir / "analysis.log")
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string data."""
        counter = Counter(data)
        entropy = 0
        for count in counter.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
        return entropy

    def _is_suspicious_base64(self, content: str) -> Optional[SuspiciousPattern]:
        """Check if Base64 content looks suspicious."""
        try:
            # Try to decode and check entropy
            decoded = base64.b64decode(content)
            entropy = self._calculate_entropy(decoded.decode('utf-8', errors='ignore'))
            
            if entropy > 7.5:  # High entropy often indicates encryption/compression
                return SuspiciousPattern(
                    type=SuspiciousType.UNUSUAL_BASE64,
                    description="Unusually high entropy in Base64 content",
                    severity=7,
                    evidence=f"Entropy: {entropy:.2f}"
                )
                
            # Check for known file signatures in decoded content
            for marker, desc in self.SUSPICIOUS_MARKERS.items():
                if marker in str(decoded):
                    return SuspiciousPattern(
                        type=SuspiciousType.HIDDEN_CONTENT,
                        description=f"Found hidden {desc} in Base64 content",
                        severity=8,
                        evidence=f"Marker: {marker}"
                    )
                    
        except Exception:
            pass
        return None

    def _check_for_steganography(self, content: str) -> List[SuspiciousPattern]:
        """Check for common steganography markers."""
        suspicious = []
        
        # Check for steganography tool markers
        for marker, desc in self.STEGO_MARKERS.items():
            if marker.lower() in content.lower():
                suspicious.append(SuspiciousPattern(
                    type=SuspiciousType.STEGANOGRAPHY_MARKER,
                    description=f"Found potential steganography marker: {desc}",
                    severity=9,
                    evidence=f"Marker: {marker}"
                ))
        
        # Check for unusual patterns in content
        if ''.join(sorted(set(content))) in content:
            suspicious.append(SuspiciousPattern(
                type=SuspiciousType.UNUSUAL_DISTRIBUTION,
                description="Found sorted character sequence (possible encoding)",
                severity=6,
                evidence="Sorted sequence found"
            ))
            
        return suspicious

    def _detect_anomalies(self, content_length: int, encoded_segments: List[str]) -> List[SuspiciousPattern]:
        """Detect anomalies in content and encoding patterns."""
        suspicious = []
        
        # Check for anomalous content length
        if self.content_lengths:
            mean_length = sum(self.content_lengths) / len(self.content_lengths)
            if content_length > mean_length * 3:
                suspicious.append(SuspiciousPattern(
                    type=SuspiciousType.ANOMALOUS_LENGTH,
                    description="Content length significantly above average",
                    severity=5,
                    evidence=f"Length: {content_length}, Mean: {mean_length:.0f}"
                ))
        
        # Check encoded segment patterns
        if encoded_segments:
            # Look for patterns in segment lengths
            lengths = [len(s) for s in encoded_segments]
            if len(set(lengths)) == 1 and len(lengths) > 3:
                suspicious.append(SuspiciousPattern(
                    type=SuspiciousType.UNUSUAL_DISTRIBUTION,
                    description="Multiple encoded segments with identical length",
                    severity=7,
                    evidence=f"Found {len(lengths)} segments of length {lengths[0]}"
                ))
        
        return suspicious

    def _extract_base64_content(self, text: str) -> List[str]:
        """
        Extract potential Base64 encoded segments from text.
        
        Args:
            text: Raw text to analyze
            
        Returns:
            List of potential Base64 encoded segments
        """
        # Look for Base64-like patterns (continuous alphanumeric + /+ with = padding)
        pattern = r'[A-Za-z0-9+/]{4,}(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        return re.findall(pattern, text)

    def analyze_content(self, content: str, url: str, content_type: str) -> AnalysisResult:
        """Analyze any type of content for patterns."""
        encoded_segments = self._extract_base64_content(content)
        pattern_count = sum(
            1 for segment in encoded_segments 
            if self.target_pattern.lower() in segment.lower()
        )
        
        # Collect all suspicious patterns
        suspicious_patterns = []
        
        # Check each encoded segment
        for segment in encoded_segments:
            if suspicious := self._is_suspicious_base64(segment):
                suspicious_patterns.append(suspicious)
        
        # Check for steganography markers
        suspicious_patterns.extend(self._check_for_steganography(content))
        
        # Update statistics and check for anomalies
        self.content_lengths.append(len(content))
        suspicious_patterns.extend(self._detect_anomalies(len(content), encoded_segments))
        
        # Alert on high-severity findings
        for pattern in suspicious_patterns:
            if pattern.severity >= 7:
                self.logger.warning(
                    f"HIGH SEVERITY finding at {url}: {pattern.description}\n"
                    f"Evidence: {pattern.evidence}"
                )
        
        return AnalysisResult(
            url=url,
            timestamp=datetime.now(),
            pattern_count=pattern_count,
            content_length=len(content),
            encoded_segments=[s for s in encoded_segments if self.target_pattern.lower() in s.lower()],
            content_type=content_type,
            suspicious_patterns=suspicious_patterns
        )

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain."""
        return self.base_domain in urlparse(url).netloc

    def _extract_urls(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all URLs from a page that belong to the same domain."""
        urls = []
        
        # Get all links
        for a in soup.find_all('a', href=True):
            url = urljoin(base_url, a['href'])
            if self._is_same_domain(url) and url not in self.visited_urls:
                urls.append(url)
        
        # Get JavaScript files
        for script in soup.find_all('script', src=True):
            url = urljoin(base_url, script['src'])
            if self._is_same_domain(url) and url not in self.visited_urls:
                urls.append(url)
                
        return list(set(urls))

    def analyze_url(self, url: str) -> Optional[AnalysisResult]:
        """
        Analyze a single URL for encoded patterns.
        
        Args:
            url: The URL to analyze
            
        Returns:
            AnalysisResult if successful, None if failed
        """
        if url in self.visited_urls:
            return None
            
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '').lower()
            
            # Analyze raw source first
            source_result = self.analyze_content(response.text, url, 'source')
            
            # If it's HTML, also parse and analyze the text content
            if 'html' in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Return the result with more matches
                text_result = self.analyze_content(soup.get_text(), url, 'text')
                return source_result if source_result.pattern_count > text_result.pattern_count else text_result
            
            return source_result
            
        except Exception as e:
            self.logger.error(f"Error analyzing {url}: {str(e)}")
            return None

    def crawl_site(self, start_url: str) -> List[AnalysisResult]:
        """Crawl entire site starting from given URL."""
        to_visit = [start_url]
        results = []
        
        with tqdm(desc="Analyzing pages", unit="page") as pbar:
            while to_visit:
                url = to_visit.pop(0)
                
                try:
                    response = self.session.get(url, timeout=30)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Add new URLs to visit
                    new_urls = self._extract_urls(soup, url)
                    to_visit.extend(new_urls)
                    
                    # Analyze current page
                    result = self.analyze_url(url)
                    if result and result.pattern_count > 0:
                        results.append(result)
                        self.logger.info(
                            f"Found {result.pattern_count} instances of {self.target_pattern} "
                            f"in {result.content_length} characters at {url}"
                        )
                    
                    pbar.update(1)
                    
                except Exception as e:
                    self.logger.error(f"Error crawling {url}: {str(e)}")
                    continue
        
        return results

    def save_results(self, results: List[AnalysisResult]) -> None:
        """
        Save analysis results to a JSON file.
        
        Args:
            results: List of analysis results to save
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"yews_analysis_{timestamp}.json"
        
        serialized_results = [
            {
                "url": r.url,
                "timestamp": r.timestamp.isoformat(),
                "pattern_count": r.pattern_count,
                "content_length": r.content_length,
                "encoded_segments": r.encoded_segments,
                "content_type": r.content_type,
                "suspicious_patterns": [
                    {
                        "type": p.type.name,
                        "description": p.description,
                        "severity": p.severity,
                        "evidence": p.evidence
                    }
                    for p in r.suspicious_patterns
                ]
            }
            for r in results
        ]
        
        with open(output_file, 'w') as f:
            json.dump(serialized_results, f, indent=2)
        
        self.logger.info(f"Results saved to {output_file}")
        
        # Save summary with suspicious patterns highlighted
        summary_file = self.output_dir / f"yews_analysis_{timestamp}_summary.txt"
        with open(summary_file, 'w') as f:
            f.write(f"Analysis completed at: {datetime.now().isoformat()}\n")
            f.write(f"Total pages analyzed: {len(self.visited_urls)}\n")
            f.write(f"Pages with matches: {len(results)}\n")
            f.write(f"Total pattern instances: {sum(r.pattern_count for r in results)}\n")
            
            # Count suspicious patterns by severity
            severity_counts = Counter()
            for r in results:
                for p in r.suspicious_patterns:
                    severity_counts[p.severity] += 1
            
            f.write("\nSUSPICIOUS PATTERN SUMMARY:\n")
            for severity in sorted(severity_counts.keys(), reverse=True):
                f.write(f"Severity {severity}: {severity_counts[severity]} findings\n")
            
            for r in results:
                f.write(f"\nURL: {r.url}\n")
                f.write(f"Pattern count: {r.pattern_count}\n")
                f.write(f"Content type: {r.content_type}\n")
                
                if r.suspicious_patterns:
                    f.write("!!! SUSPICIOUS PATTERNS FOUND !!!\n")
                    for p in sorted(r.suspicious_patterns, key=lambda x: x.severity, reverse=True):
                        f.write(f"  - [{p.severity}/10] {p.description}\n")
                        f.write(f"    Evidence: {p.evidence}\n")
                
                f.write("Encoded segments:\n")
                for segment in r.encoded_segments:
                    f.write(f"  - {segment[:100]}...\n")

def main() -> None:
    """Main entry point for the yews.news analyzer."""
    analyzer = YewsAnalyzer()
    
    # Start with the main URL
    base_url = "https://yews.news"
    
    # Crawl entire site
    results = analyzer.crawl_site(base_url)
    
    # Save results
    analyzer.save_results(results)

if __name__ == "__main__":
    main() 