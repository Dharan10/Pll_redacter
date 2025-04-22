import pytesseract
import cv2
import numpy as np
from PIL import Image
from typing import Dict, List, Any, Optional, Union, Tuple
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

class OCREngine:
    """Extracts text from images using OCR for PII detection.
    
    This class uses pytesseract (Tesseract OCR) to extract text from images,
    which can then be processed by the PII detectors.
    """
    
    def __init__(self, tesseract_cmd: Optional[str] = None, lang: str = 'eng'):
        """Initialize the OCR engine.
        
        Args:
            tesseract_cmd: Path to the Tesseract executable (optional)
            lang: Language for OCR (default: 'eng')
        """
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
        self.lang = lang
        
        # Test if Tesseract is available
        try:
            pytesseract.get_tesseract_version()
            logger.info("Tesseract OCR is available")
        except Exception as e:
            logger.warning(f"Tesseract OCR may not be properly installed: {e}")
            logger.warning("Please install Tesseract OCR and ensure it's in your PATH")
    
    def extract_text(self, image: Union[str, Path, np.ndarray, Image.Image]) -> str:
        """Extract text from an image using OCR.
        
        Args:
            image: Image file path, numpy array, or PIL Image object
            
        Returns:
            Extracted text as string
        """
        try:
            # Handle different input types
            if isinstance(image, (str, Path)):
                img = Image.open(image)
            elif isinstance(image, np.ndarray):
                img = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
            elif isinstance(image, Image.Image):
                img = image
            else:
                raise TypeError(f"Unsupported image type: {type(image)}")
            
            # Extract text using pytesseract
            text = pytesseract.image_to_string(img, lang=self.lang)
            return text
        except Exception as e:
            logger.error(f"Error extracting text from image: {e}")
            return ""
    
    def extract_text_with_positions(self, image: Union[str, Path, np.ndarray, Image.Image]) -> List[Dict[str, Any]]:
        """Extract text with position information from an image.
        
        Args:
            image: Image file path, numpy array, or PIL Image object
            
        Returns:
            List of dictionaries containing text, position, and confidence
        """
        try:
            # Handle different input types
            if isinstance(image, (str, Path)):
                img_path = str(image)
                img = cv2.imread(img_path)
            elif isinstance(image, np.ndarray):
                img = image
            elif isinstance(image, Image.Image):
                img = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            else:
                raise TypeError(f"Unsupported image type: {type(image)}")
            
            # Get image dimensions
            height, width = img.shape[:2]
            
            # Extract text data using pytesseract
            data = pytesseract.image_to_data(img, lang=self.lang, output_type=pytesseract.Output.DICT)
            
            results = []
            n_boxes = len(data['text'])
            
            for i in range(n_boxes):
                # Skip empty text
                if not data['text'][i].strip():
                    continue
                
                # Calculate confidence (if available)
                confidence = data.get('conf', [0] * n_boxes)[i]
                if confidence == '-1':
                    confidence = 0
                
                # Get bounding box coordinates
                x, y, w, h = (
                    data['left'][i],
                    data['top'][i],
                    data['width'][i],
                    data['height'][i]
                )
                
                # Normalize coordinates as percentages of image dimensions
                norm_x = x / width
                norm_y = y / height
                norm_w = w / width
                norm_h = h / height
                
                results.append({
                    'text': data['text'][i],
                    'confidence': float(confidence),
                    'bbox': (x, y, w, h),  # Original pixel coordinates
                    'norm_bbox': (norm_x, norm_y, norm_w, norm_h),  # Normalized coordinates
                    'page_num': data.get('page_num', [1] * n_boxes)[i],
                    'block_num': data.get('block_num', [0] * n_boxes)[i],
                    'line_num': data.get('line_num', [0] * n_boxes)[i]
                })
            
            return results
        except Exception as e:
            logger.error(f"Error extracting text with positions from image: {e}")
            return []
    
    def get_text_regions(self, image: Union[str, Path, np.ndarray, Image.Image]) -> Tuple[np.ndarray, List[Tuple[int, int, int, int]]]:
        """Identify text regions in an image for targeted processing.
        
        Args:
            image: Image file path, numpy array, or PIL Image object
            
        Returns:
            Tuple of (processed image, list of bounding boxes)
        """
        try:
            # Handle different input types
            if isinstance(image, (str, Path)):
                img = cv2.imread(str(image))
            elif isinstance(image, np.ndarray):
                img = image.copy()
            elif isinstance(image, Image.Image):
                img = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            else:
                raise TypeError(f"Unsupported image type: {type(image)}")
            
            # Convert to grayscale
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # Apply thresholding
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
            
            # Find contours
            contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            # Filter contours by size
            min_area = 100  # Minimum area to consider as text
            text_regions = []
            
            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                area = w * h
                aspect_ratio = w / float(h) if h > 0 else 0
                
                # Filter by area and aspect ratio
                if area > min_area and 0.1 < aspect_ratio < 15:
                    text_regions.append((x, y, w, h))
                    # Draw rectangle around text region (for visualization)
                    cv2.rectangle(img, (x, y), (x + w, y + h), (0, 255, 0), 2)
            
            return img, text_regions
        except Exception as e:
            logger.error(f"Error identifying text regions in image: {e}")
            if isinstance(image, np.ndarray):
                return image, []
            else:
                # Return empty image and empty regions list
                return np.zeros((100, 100, 3), dtype=np.uint8), []
    
    def set_language(self, lang: str) -> None:
        """Set the OCR language.
        
        Args:
            lang: Language code (e.g., 'eng', 'fra', etc.)
        """
        self.lang = lang
        logger.info(f"OCR language set to: {lang}")