import re
from typing import Dict, List, Any, Optional, Union, Tuple
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class TextRedactor:
    """Redacts PII from text content.
    
    This class handles the redaction of PII from plain text content by replacing
    detected PII with customizable redaction markers.
    """
    
    def __init__(self, redaction_marker: str = "[REDACTED]"):
        """Initialize the text redactor.
        
        Args:
            redaction_marker: The text to replace PII with
        """
        self.redaction_marker = redaction_marker
    
    def redact(self, text: str, pii_list: List[Dict[str, Any]]) -> str:
        """Redact PII from the given text.
        
        Args:
            text: The original text content
            pii_list: List of PII items with 'start' and 'end' positions
            
        Returns:
            Redacted text with PII replaced by redaction markers
        """
        if not text or not isinstance(text, str):
            logger.warning("Empty or non-string input provided to text redactor")
            return ""
        
        if not pii_list:
            logger.info("No PII to redact")
            return text
        
        # Sort PII items by position (end position in reverse order)
        # This allows us to replace from end to start to avoid changing positions
        sorted_pii = sorted(pii_list, key=lambda x: x['end'], reverse=True)
        
        # Create a mutable list of characters from the text
        chars = list(text)
        
        # Replace each PII instance with the redaction marker
        for pii in sorted_pii:
            start = pii['start']
            end = pii['end']
            
            # Validate positions
            if not (0 <= start < len(chars) and 0 < end <= len(chars) and start < end):
                logger.warning(f"Invalid PII positions: start={start}, end={end}, text length={len(chars)}")
                continue
            
            # Replace the characters with the redaction marker
            chars[start:end] = list(self.redaction_marker)
        
        # Join the characters back into a string
        redacted_text = ''.join(chars)
        
        return redacted_text
    
    def redact_with_context(self, text: str, pii_list: List[Dict[str, Any]], context_chars: int = 10) -> List[Dict[str, Any]]:
        """Redact PII and provide context around each redaction.
        
        Args:
            text: The original text content
            pii_list: List of PII items with 'start' and 'end' positions
            context_chars: Number of characters to include as context before and after
            
        Returns:
            List of dictionaries with redacted text and context information
        """
        if not text or not isinstance(text, str):
            logger.warning("Empty or non-string input provided to text redactor")
            return []
        
        if not pii_list:
            logger.info("No PII to redact")
            return []
        
        # Sort PII items by position
        sorted_pii = sorted(pii_list, key=lambda x: x['start'])
        
        results = []
        
        for pii in sorted_pii:
            start = pii['start']
            end = pii['end']
            
            # Validate positions
            if not (0 <= start < len(text) and 0 < end <= len(text) and start < end):
                logger.warning(f"Invalid PII positions: start={start}, end={end}, text length={len(text)}")
                continue
            
            # Get context before and after the PII
            context_start = max(0, start - context_chars)
            context_end = min(len(text), end + context_chars)
            
            # Extract the context with the PII
            context_with_pii = text[context_start:context_end]
            
            # Replace the PII with the redaction marker in the context
            redacted_context = (
                context_with_pii[:start - context_start] +
                self.redaction_marker +
                context_with_pii[end - context_start:]
            )
            
            results.append({
                'original_pii': pii,
                'context_before': text[context_start:start],
                'context_after': text[end:context_end],
                'redacted_context': redacted_context
            })
        
        return results
    
    def redact_file(self, input_file: Union[str, Path], output_file: Union[str, Path], pii_list: List[Dict[str, Any]]) -> bool:
        """Redact PII from a text file and save to a new file.
        
        Args:
            input_file: Path to the input text file
            output_file: Path to save the redacted text file
            pii_list: List of PII items with 'start' and 'end' positions
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Read the input file
            with open(input_file, 'r', encoding='utf-8') as f:
                text = f.read()
            
            # Redact the text
            redacted_text = self.redact(text, pii_list)
            
            # Write the redacted text to the output file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(redacted_text)
            
            logger.info(f"Redacted text saved to {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error redacting file {input_file}: {e}")
            return False
    
    def set_redaction_marker(self, marker: str) -> None:
        """Set the redaction marker text.
        
        Args:
            marker: The text to replace PII with
        """
        self.redaction_marker = marker
        logger.info(f"Redaction marker set to: {marker}")
    
    def get_redaction_marker(self) -> str:
        """Get the current redaction marker text.
        
        Returns:
            The current redaction marker
        """
        return self.redaction_marker