import cv2
import numpy as np
from PIL import Image
from typing import Dict, List, Any, Optional, Union, Tuple
import logging
from pathlib import Path
import os

logger = logging.getLogger(__name__)

class ImageRedactor:
    """Redacts PII from image content.
    
    This class handles the redaction of PII from images by applying visual
    redaction methods such as blurring or black boxes over detected PII regions.
    """
    
    def __init__(self, redaction_method: str = "box", box_color: Tuple[int, int, int] = (0, 0, 0)):
        """Initialize the image redactor.
        
        Args:
            redaction_method: Method to use for redaction ('box', 'blur', or 'pixelate')
            box_color: RGB color tuple for box redaction (default: black)
        """
        self.redaction_method = redaction_method.lower()
        self.box_color = box_color
        
        # Validate redaction method
        valid_methods = ["box", "blur", "pixelate"]
        if self.redaction_method not in valid_methods:
            logger.warning(f"Invalid redaction method: {redaction_method}. Using 'box' instead.")
            self.redaction_method = "box"
    
    def redact(self, image: Union[str, Path, np.ndarray, Image.Image], 
               regions: List[Tuple[int, int, int, int]]) -> np.ndarray:
        """Redact regions in the given image.
        
        Args:
            image: Image file path, numpy array, or PIL Image object
            regions: List of regions to redact as (x, y, width, height) tuples
            
        Returns:
            Redacted image as numpy array
        """
        # Handle different input types
        if isinstance(image, (str, Path)):
            img = cv2.imread(str(image))
        elif isinstance(image, np.ndarray):
            img = image.copy()
        elif isinstance(image, Image.Image):
            img = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        else:
            raise TypeError(f"Unsupported image type: {type(image)}")
        
        if img is None or img.size == 0:
            logger.error("Failed to load image or empty image provided")
            return np.zeros((100, 100, 3), dtype=np.uint8)
        
        # Apply redaction to each region
        for region in regions:
            x, y, width, height = region
            
            # Ensure coordinates are within image bounds
            x = max(0, min(x, img.shape[1] - 1))
            y = max(0, min(y, img.shape[0] - 1))
            width = min(width, img.shape[1] - x)
            height = min(height, img.shape[0] - y)
            
            if width <= 0 or height <= 0:
                continue
            
            # Apply the selected redaction method
            if self.redaction_method == "box":
                # Draw a filled rectangle
                cv2.rectangle(img, (x, y), (x + width, y + height), self.box_color, -1)
            
            elif self.redaction_method == "blur":
                # Apply Gaussian blur
                roi = img[y:y+height, x:x+width]
                blurred = cv2.GaussianBlur(roi, (51, 51), 0)
                img[y:y+height, x:x+width] = blurred
            
            elif self.redaction_method == "pixelate":
                # Apply pixelation effect
                roi = img[y:y+height, x:x+width]
                
                # Determine pixelation block size (larger of 10% of width/height or 5 pixels)
                block_size = max(5, int(min(width, height) * 0.1))
                
                # Resize down and back up to create pixelation
                small = cv2.resize(roi, (width // block_size, height // block_size),
                                  interpolation=cv2.INTER_LINEAR)
                pixelated = cv2.resize(small, (width, height),
                                      interpolation=cv2.INTER_NEAREST)
                
                img[y:y+height, x:x+width] = pixelated
        
        return img
    
    def redact_from_text_positions(self, image: Union[str, Path, np.ndarray, Image.Image],
                                  pii_list: List[Dict[str, Any]], 
                                  text_positions: List[Dict[str, Any]],
                                  padding: int = 5) -> np.ndarray:
        """Redact PII in an image based on text positions from OCR.
        
        Args:
            image: Image file path, numpy array, or PIL Image object
            pii_list: List of PII items with 'value' field
            text_positions: List of text position data from OCR with 'text' and 'bbox' fields
            padding: Additional padding around detected regions (pixels)
            
        Returns:
            Redacted image as numpy array
        """
        # Handle different input types
        if isinstance(image, (str, Path)):
            img = cv2.imread(str(image))
        elif isinstance(image, np.ndarray):
            img = image.copy()
        elif isinstance(image, Image.Image):
            img = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        else:
            raise TypeError(f"Unsupported image type: {type(image)}")
        
        if img is None or img.size == 0:
            logger.error("Failed to load image or empty image provided")
            return np.zeros((100, 100, 3), dtype=np.uint8)
        
        # Extract PII values
        pii_values = [pii['value'] for pii in pii_list]
        
        # Find regions to redact
        regions_to_redact = []
        
        for pos in text_positions:
            text = pos.get('text', '')
            
            # Check if this text contains any PII
            for pii_value in pii_values:
                if pii_value in text:
                    # Get bounding box
                    bbox = pos.get('bbox')
                    if bbox:
                        x, y, w, h = bbox
                        
                        # Add padding
                        x = max(0, x - padding)
                        y = max(0, y - padding)
                        w = w + 2 * padding
                        h = h + 2 * padding
                        
                        regions_to_redact.append((x, y, w, h))
                    break
        
        # Apply redaction to the identified regions
        return self.redact(img, regions_to_redact)
    
    def redact_file(self, input_file: Union[str, Path], 
                    output_file: Union[str, Path],
                    regions: List[Tuple[int, int, int, int]]) -> bool:
        """Redact regions in an image file and save to a new file.
        
        Args:
            input_file: Path to the input image file
            output_file: Path to save the redacted image file
            regions: List of regions to redact as (x, y, width, height) tuples
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Redact the image
            redacted_img = self.redact(input_file, regions)
            
            # Ensure output directory exists
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save the redacted image
            cv2.imwrite(str(output_file), redacted_img)
            
            logger.info(f"Redacted image saved to {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error redacting image file {input_file}: {e}")
            return False
    
    def set_redaction_method(self, method: str) -> None:
        """Set the redaction method.
        
        Args:
            method: Method to use for redaction ('box', 'blur', or 'pixelate')
        """
        valid_methods = ["box", "blur", "pixelate"]
        method = method.lower()
        
        if method in valid_methods:
            self.redaction_method = method
            logger.info(f"Redaction method set to: {method}")
        else:
            logger.warning(f"Invalid redaction method: {method}. Using current method.")
    
    def set_box_color(self, color: Tuple[int, int, int]) -> None:
        """Set the color for box redaction.
        
        Args:
            color: RGB color tuple (e.g., (0, 0, 0) for black)
        """
        self.box_color = color
        logger.info(f"Box color set to: {color}")
    
    def get_redaction_method(self) -> str:
        """Get the current redaction method.
        
        Returns:
            The current redaction method
        """
        return self.redaction_method