import fitz  # PyMuPDF
import cv2
import numpy as np
from typing import Dict, List, Any, Optional, Union, Tuple
import logging
from pathlib import Path
import os
import tempfile

logger = logging.getLogger(__name__)

class PDFRedactor:
    """Redacts PII from PDF documents.
    
    This class handles the redaction of PII from PDF files using PyMuPDF (fitz),
    with options for text replacement or visual redaction methods.
    """
    
    def __init__(self, redaction_marker: str = "[REDACTED]", visual_mode: bool = True,
                 box_color: Tuple[float, float, float] = (0, 0, 0)):
        """Initialize the PDF redactor.
        
        Args:
            redaction_marker: The text to replace PII with in text mode
            visual_mode: If True, use visual redaction (black boxes), else use text replacement
            box_color: RGB color tuple for visual redaction (values from 0 to 1)
        """
        self.redaction_marker = redaction_marker
        self.visual_mode = visual_mode
        self.box_color = box_color
    
    def redact(self, pdf_path: Union[str, Path], pii_list: List[Dict[str, Any]],
               output_path: Union[str, Path]) -> bool:
        """Redact PII from a PDF document.
        
        Args:
            pdf_path: Path to the input PDF file
            pii_list: List of PII items with 'value', 'page_num' (optional), and other fields
            output_path: Path to save the redacted PDF file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Open the PDF document
            doc = fitz.open(pdf_path)
            
            # Group PII by page number if available
            pii_by_page = {}
            
            for pii in pii_list:
                # Default to page 0 if page_num not specified
                page_num = pii.get('page_num', 0)
                
                if page_num not in pii_by_page:
                    pii_by_page[page_num] = []
                
                pii_by_page[page_num].append(pii)
            
            # Process each page
            for page_num in range(doc.page_count):
                page = doc[page_num]
                
                # Skip pages with no PII to redact
                if page_num not in pii_by_page:
                    continue
                
                # Get PII for this page
                page_pii = pii_by_page[page_num]
                
                if self.visual_mode:
                    # Visual redaction (black boxes)
                    self._apply_visual_redaction(page, page_pii)
                else:
                    # Text replacement redaction
                    self._apply_text_redaction(page, page_pii)
            
            # Save the redacted PDF
            doc.save(output_path)
            doc.close()
            
            logger.info(f"Redacted PDF saved to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error redacting PDF {pdf_path}: {e}")
            return False
    
    def _apply_visual_redaction(self, page: fitz.Page, pii_list: List[Dict[str, Any]]) -> None:
        """Apply visual redaction (black boxes) to a PDF page.
        
        Args:
            page: The PDF page object
            pii_list: List of PII items to redact on this page
        """
        for pii in pii_list:
            pii_value = pii['value']
            
            # Search for the PII text on the page
            text_instances = page.search_for(pii_value)
            
            # Draw black rectangles over each instance
            for inst in text_instances:
                # Add a small padding around the text
                rect = inst.irect  # integer rectangle
                padding = 2
                rect = fitz.Rect(rect.x0 - padding, rect.y0 - padding,
                                rect.x1 + padding, rect.y1 + padding)
                
                # Add redaction annotation
                annot = page.add_redact_annot(rect, fill=self.box_color)
                
                # Apply the redaction
                page.apply_redactions()
    
    def _apply_text_redaction(self, page: fitz.Page, pii_list: List[Dict[str, Any]]) -> None:
        """Apply text replacement redaction to a PDF page.
        
        Args:
            page: The PDF page object
            pii_list: List of PII items to redact on this page
        """
        # Get the page text
        text = page.get_text("text")
        
        # Create a dictionary to store text replacements
        replacements = {}
        
        for pii in pii_list:
            pii_value = pii['value']
            replacements[pii_value] = self.redaction_marker
        
        # Apply text replacements using page methods
        for old_text, new_text in replacements.items():
            # Find all instances of the text
            text_instances = page.search_for(old_text)
            
            # Replace each instance
            for inst in text_instances:
                page.add_redact_annot(
                    inst,
                    text=new_text,
                    fill=(1, 1, 1)  # White background
                )
        
        # Apply the redactions
        page.apply_redactions()
    
    def extract_text_with_positions(self, pdf_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Extract text with position information from a PDF.
        
        Args:
            pdf_path: Path to the PDF file
            
        Returns:
            List of dictionaries containing text, position, and page number
        """
        try:
            # Open the PDF document
            doc = fitz.open(pdf_path)
            
            results = []
            
            # Process each page
            for page_num in range(doc.page_count):
                page = doc[page_num]
                
                # Extract text blocks
                blocks = page.get_text("dict")["blocks"]
                
                for block in blocks:
                    if "lines" in block:
                        for line in block["lines"]:
                            for span in line["spans"]:
                                text = span["text"]
                                if text.strip():
                                    # Get the bounding box
                                    bbox = fitz.Rect(span["bbox"])
                                    
                                    results.append({
                                        'text': text,
                                        'page_num': page_num,
                                        'bbox': (bbox.x0, bbox.y0, bbox.width, bbox.height),
                                        'font': span["font"],
                                        'font_size': span["size"]
                                    })
            
            doc.close()
            return results
        except Exception as e:
            logger.error(f"Error extracting text from PDF {pdf_path}: {e}")
            return []
    
    def convert_to_images(self, pdf_path: Union[str, Path], dpi: int = 300) -> List[np.ndarray]:
        """Convert PDF pages to images for processing with image-based methods.
        
        Args:
            pdf_path: Path to the PDF file
            dpi: Resolution for rendering (dots per inch)
            
        Returns:
            List of page images as numpy arrays
        """
        try:
            # Open the PDF document
            doc = fitz.open(pdf_path)
            
            images = []
            
            # Convert each page to an image
            for page_num in range(doc.page_count):
                page = doc[page_num]
                
                # Render page to a pixmap
                pix = page.get_pixmap(matrix=fitz.Matrix(dpi/72, dpi/72))
                
                # Convert pixmap to numpy array
                img = np.frombuffer(pix.samples, dtype=np.uint8).reshape(
                    pix.height, pix.width, pix.n
                )
                
                # Convert RGBA to RGB if needed
                if pix.n == 4:
                    img = cv2.cvtColor(img, cv2.COLOR_RGBA2RGB)
                
                images.append(img)
            
            doc.close()
            return images
        except Exception as e:
            logger.error(f"Error converting PDF to images {pdf_path}: {e}")
            return []
    
    def create_from_images(self, images: List[np.ndarray], output_path: Union[str, Path]) -> bool:
        """Create a PDF from a list of images (for image-based redaction workflow).
        
        Args:
            images: List of images as numpy arrays
            output_path: Path to save the created PDF file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create a new PDF document
            doc = fitz.open()
            
            # Add each image as a page
            for img in images:
                # Convert BGR to RGB if needed
                if img.shape[2] == 3:
                    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                
                # Create a temporary image file
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                    tmp_path = tmp.name
                    cv2.imwrite(tmp_path, img)
                
                # Create a new page with the image dimensions
                page = doc.new_page(width=img.shape[1], height=img.shape[0])
                
                # Insert the image into the page
                page.insert_image(fitz.Rect(0, 0, img.shape[1], img.shape[0]), filename=tmp_path)
                
                # Remove the temporary file
                os.unlink(tmp_path)
            
            # Save the PDF
            doc.save(output_path)
            doc.close()
            
            logger.info(f"Created PDF from images at {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error creating PDF from images: {e}")
            return False
    
    def set_redaction_marker(self, marker: str) -> None:
        """Set the redaction marker text.
        
        Args:
            marker: The text to replace PII with in text mode
        """
        self.redaction_marker = marker
        logger.info(f"Redaction marker set to: {marker}")
    
    def set_visual_mode(self, visual_mode: bool) -> None:
        """Set the redaction mode.
        
        Args:
            visual_mode: If True, use visual redaction, else use text replacement
        """
        self.visual_mode = visual_mode
        mode_str = "visual" if visual_mode else "text replacement"
        logger.info(f"Redaction mode set to: {mode_str}")
    
    def set_box_color(self, color: Tuple[float, float, float]) -> None:
        """Set the color for visual redaction boxes.
        
        Args:
            color: RGB color tuple with values from 0 to 1
        """
        self.box_color = color
        logger.info(f"Box color set to: {color}")