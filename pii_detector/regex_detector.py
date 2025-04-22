import re
from typing import Dict, List, Tuple, Pattern, Any
import logging

logger = logging.getLogger(__name__)

class RegexDetector:
    """Detects PII using regular expressions.
    
    This class contains regex patterns for various types of PII and methods to detect
    them in text content.
    """
    
    def __init__(self):
        # Dictionary of regex patterns for different PII types
        self.patterns: Dict[str, Pattern] = {
            # Email addresses
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            
            # Phone numbers (various formats)
            'phone': re.compile(r'\b(\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'),
            
            # Credit card numbers
            'credit_card': re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
            
            # Indian Aadhaar numbers (12 digits, may be space/dash separated)
            'aadhaar': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
            
            # Indian PAN numbers (10 character alphanumeric)
            'pan': re.compile(r'\b[A-Z]{5}\d{4}[A-Z]{1}\b'),
            
            # Dates in various formats
            'date': re.compile(r'\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b'),
            
            # Social Security Numbers (US)
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            
            # IP Addresses
            'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            
            # URLs
            'url': re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'),
            
            # Passport numbers (generic pattern)
            'passport': re.compile(r'\b[A-Z]{1,2}\d{6,9}\b')
        }
    
    def detect(self, text: str) -> List[Dict[str, Any]]:
        """Detect PII in the given text using regex patterns.
        
        Args:
            text: The text to analyze for PII
            
        Returns:
            A list of dictionaries containing PII type, value, and position
        """
        if not text or not isinstance(text, str):
            logger.warning("Empty or non-string input provided to regex detector")
            return []
        
        results = []
        
        for pii_type, pattern in self.patterns.items():
            matches = pattern.finditer(text)
            for match in matches:
                results.append({
                    'type': pii_type,
                    'value': match.group(),
                    'start': match.start(),
                    'end': match.end(),
                    'detection_method': 'regex'
                })
        
        # Sort results by position in text
        results.sort(key=lambda x: x['start'])
        
        return results
    
    def add_pattern(self, pii_type: str, pattern: str) -> None:
        """Add a custom regex pattern for PII detection.
        
        Args:
            pii_type: Name/type of the PII to detect
            pattern: Regex pattern as string
        """
        try:
            self.patterns[pii_type] = re.compile(pattern)
            logger.info(f"Added custom pattern for {pii_type}")
        except re.error as e:
            logger.error(f"Invalid regex pattern for {pii_type}: {e}")
            raise ValueError(f"Invalid regex pattern: {e}")
    
    def remove_pattern(self, pii_type: str) -> bool:
        """Remove a pattern from the detector.
        
        Args:
            pii_type: The type of PII pattern to remove
            
        Returns:
            True if pattern was removed, False if it didn't exist
        """
        if pii_type in self.patterns:
            del self.patterns[pii_type]
            logger.info(f"Removed pattern for {pii_type}")
            return True
        return False
    
    def get_available_patterns(self) -> List[str]:
        """Get a list of all available PII pattern types.
        
        Returns:
            List of pattern type names
        """
        return list(self.patterns.keys())