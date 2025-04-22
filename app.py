import streamlit as st
import os
import tempfile
import logging
from pathlib import Path
import numpy as np
import cv2
from PIL import Image
import io
import time

# Import PII detector modules
from pii_detector.regex_detector import RegexDetector
from pii_detector.ner_detector import NERDetector, TransformerNERDetector
from pii_detector.ocr_engine import OCREngine

# Import redactor modules
from redactors.text_redactor import TextRedactor
from redactors.image_redactor import ImageRedactor
from redactors.pdf_redactor import PDFRedactor
from redactors.docx_redactor import DocxRedactor

# Import utility modules
from utils.file_handler import FileHandler
from utils.audit_logger import AuditLogger
from utils.visualization import Visualization

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize session state
def init_session_state():
    """Initialize Streamlit session state variables."""
    if 'settings' not in st.session_state:
        st.session_state.settings = {
            'text_redaction_marker': '[REDACTED]',
            'image_redaction_method': 'box',
            'pdf_visual_mode': True,
            'use_regex': True,
            'use_ner': True,
            'use_transformers': False,
            'max_display_items': 100,
            'show_details': True
        }
    
    if 'file_handler' not in st.session_state:
        st.session_state.file_handler = FileHandler()
    
    if 'audit_logger' not in st.session_state:
        st.session_state.audit_logger = AuditLogger()
    
    if 'visualization' not in st.session_state:
        st.session_state.visualization = Visualization()
    
    if 'uploaded_file_path' not in st.session_state:
        st.session_state.uploaded_file_path = None
    
    if 'redacted_file_path' not in st.session_state:
        st.session_state.redacted_file_path = None
    
    if 'pii_results' not in st.session_state:
        st.session_state.pii_results = []
    
    if 'audit_record' not in st.session_state:
        st.session_state.audit_record = None

# Initialize detectors and redactors
def init_components():
    """Initialize PII detectors and redactors based on current settings."""
    settings = st.session_state.settings
    
    # Initialize detectors
    regex_detector = RegexDetector()
    ner_detector = NERDetector()
    transformer_detector = None
    if settings['use_transformers']:
        try:
            transformer_detector = TransformerNERDetector()
        except Exception as e:
            st.warning(f"Failed to initialize transformer model: {e}")
    
    ocr_engine = OCREngine()
    
    # Initialize redactors
    text_redactor = TextRedactor(redaction_marker=settings['text_redaction_marker'])
    image_redactor = ImageRedactor(redaction_method=settings['image_redaction_method'])
    pdf_redactor = PDFRedactor(
        redaction_marker=settings['text_redaction_marker'],
        visual_mode=settings['pdf_visual_mode']
    )
    docx_redactor = DocxRedactor(redaction_marker=settings['text_redaction_marker'])
    
    return {
        'regex_detector': regex_detector,
        'ner_detector': ner_detector,
        'transformer_detector': transformer_detector,
        'ocr_engine': ocr_engine,
        'text_redactor': text_redactor,
        'image_redactor': image_redactor,
        'pdf_redactor': pdf_redactor,
        'docx_redactor': docx_redactor
    }

# PII detection functions
def detect_pii_in_text(text, components):
    """Detect PII in text content using available detectors.
    
    Args:
        text: Text content to analyze
        components: Dictionary of detector components
        
    Returns:
        List of detected PII items
    """
    settings = st.session_state.settings
    results = []
    
    # Use regex detector if enabled
    if settings['use_regex']:
        regex_results = components['regex_detector'].detect(text)
        results.extend(regex_results)
    
    # Use NER detector if enabled
    if settings['use_ner']:
        ner_results = components['ner_detector'].detect(text)
        results.extend(ner_results)
    
    # Use transformer detector if enabled and available
    if settings['use_transformers'] and components['transformer_detector']:
        transformer_results = components['transformer_detector'].detect(text)
        results.extend(transformer_results)
    
    # Sort results by position
    results.sort(key=lambda x: x['start'])
    
    return results

def detect_pii_in_image(image_path, components):
    """Detect PII in an image using OCR and text-based detectors.
    
    Args:
        image_path: Path to the image file
        components: Dictionary of detector components
        
    Returns:
        Tuple of (list of detected PII items, list of text positions)
    """
    # Extract text from image using OCR
    text = components['ocr_engine'].extract_text(image_path)
    text_positions = components['ocr_engine'].extract_text_with_positions(image_path)
    
    # Detect PII in the extracted text
    pii_results = detect_pii_in_text(text, components)
    
    return pii_results, text_positions

def detect_pii_in_pdf(pdf_path, components):
    """Detect PII in a PDF document.
    
    Args:
        pdf_path: Path to the PDF file
        components: Dictionary of detector components
        
    Returns:
        List of detected PII items with page information
    """
    # Extract text with positions from PDF
    text_blocks = components['pdf_redactor'].extract_text_with_positions(pdf_path)
    
    all_pii = []
    
    # Process each text block
    for block in text_blocks:
        text = block['text']
        page_num = block['page_num']
        
        # Detect PII in the text
        pii_results = detect_pii_in_text(text, components)
        
        # Add page information to PII results
        for pii in pii_results:
            pii['page_num'] = page_num
            all_pii.append(pii)
    
    return all_pii

def detect_pii_in_docx(docx_path, components):
    """Detect PII in a DOCX document.
    
    Args:
        docx_path: Path to the DOCX file
        components: Dictionary of detector components
        
    Returns:
        List of detected PII items with structural information
    """
    # Extract text with structural information from DOCX
    text_blocks = components['docx_redactor'].extract_text_with_positions(docx_path)
    
    all_pii = []
    
    # Process each text block
    for block in text_blocks:
        text = block['text']
        
        # Detect PII in the text
        pii_results = detect_pii_in_text(text, components)
        
        # Add structural information to PII results
        for pii in pii_results:
            pii['block_type'] = block['type']
            pii['block_index'] = block.get('index')
            all_pii.append(pii)
    
    return all_pii

# Redaction functions
def redact_text_file(file_path, pii_results, components):
    """Redact PII from a text file.
    
    Args:
        file_path: Path to the text file
        pii_results: List of detected PII items
        components: Dictionary of redactor components
        
    Returns:
        Path to the redacted file
    """
    # Create output path
    output_path = st.session_state.file_handler.create_output_path(file_path)
    
    # Redact the file
    success = components['text_redactor'].redact_file(file_path, output_path, pii_results)
    
    if success:
        return output_path
    else:
        return None

def redact_image_file(file_path, pii_results, text_positions, components):
    """Redact PII from an image file.
    
    Args:
        file_path: Path to the image file
        pii_results: List of detected PII items
        text_positions: List of text positions from OCR
        components: Dictionary of redactor components
        
    Returns:
        Path to the redacted file
    """
    # Create output path
    output_path = st.session_state.file_handler.create_output_path(file_path)
    
    # Redact the image based on text positions
    redacted_image = components['image_redactor'].redact_from_text_positions(
        file_path, pii_results, text_positions
    )
    
    # Save the redacted image
    cv2.imwrite(str(output_path), redacted_image)
    
    return output_path

def redact_pdf_file(file_path, pii_results, components):
    """Redact PII from a PDF file.
    
    Args:
        file_path: Path to the PDF file
        pii_results: List of detected PII items
        components: Dictionary of redactor components
        
    Returns:
        Path to the redacted file
    """
    # Create output path
    output_path = st.session_state.file_handler.create_output_path(file_path)
    
    # Redact the PDF
    success = components['pdf_redactor'].redact(file_path, pii_results, output_path)
    
    if success:
        return output_path
    else:
        return None

def redact_docx_file(file_path, pii_results, components):
    """Redact PII from a DOCX file.
    
    Args:
        file_path: Path to the DOCX file
        pii_results: List of detected PII items
        components: Dictionary of redactor components
        
    Returns:
        Path to the redacted file
    """
    # Create output path
    output_path = st.session_state.file_handler.create_output_path(file_path)
    
    # Redact the DOCX
    success = components['docx_redactor'].redact(file_path, pii_results, output_path)
    
    if success:
        return output_path
    else:
        return None

# Process file function
def process_file(file_path, components):
    """Process a file for PII detection and redaction.
    
    Args:
        file_path: Path to the file
        components: Dictionary of detector and redactor components
        
    Returns:
        Tuple of (pii_results, redacted_file_path, audit_record)
    """
    # Get file information
    file_info = st.session_state.file_handler.get_file_info(file_path)
    file_type = file_info['type']
    
    pii_results = []
    redacted_file_path = None
    
    # Process based on file type
    if file_type == 'text':
        # Read the text file
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
        
        # Detect PII in text
        pii_results = detect_pii_in_text(text, components)
        
        # Redact the text file
        if pii_results:
            redacted_file_path = redact_text_file(file_path, pii_results, components)
    
    elif file_type == 'image':
        # Detect PII in image
        pii_results, text_positions = detect_pii_in_image(file_path, components)
        
        # Redact the image file
        if pii_results:
            redacted_file_path = redact_image_file(file_path, pii_results, text_positions, components)
    
    elif file_type == 'pdf':
        # Detect PII in PDF
        pii_results = detect_pii_in_pdf(file_path, components)
        
        # Redact the PDF file
        if pii_results:
            redacted_file_path = redact_pdf_file(file_path, pii_results, components)
    
    elif file_type == 'docx':
        # Detect PII in DOCX
        pii_results = detect_pii_in_docx(file_path, components)
        
        # Redact the DOCX file
        if pii_results:
            redacted_file_path = redact_docx_file(file_path, pii_results, components)
    
    # Create audit record
    audit_record = None
    if pii_results:
        audit_record = st.session_state.audit_logger.log_detection(file_info, pii_results)
    
    return pii_results, redacted_file_path, audit_record

# Main application
def main():
    """Main application function."""
    # Initialize session state
    init_session_state()
    
    # Set page config
    st.set_page_config(
        page_title="Auto PII Redactor",
        page_icon="🔒",
        layout="wide"
    )
    
    # Display header
    st.title("Auto PII Redactor")
    st.markdown(
        """Automatically detect and redact Personally Identifiable Information (PII) from various file formats.
        Upload a file to get started."""
    )
    
    # Initialize components
    components = init_components()
    
    # Sidebar
    with st.sidebar:
        st.header("Controls")
        
        # File upload
        uploaded_file = st.file_uploader(
            "Upload a file",
            type=["txt", "csv", "jpg", "jpeg", "png", "pdf", "docx"]
        )
        
        # Process button
        process_button = st.button("Process File", disabled=uploaded_file is None)
        
        # Settings
        st.session_state.settings = st.session_state.visualization.display_settings(
            st.session_state.settings,
            lambda settings: st.session_state.update(settings=settings)
        )
        
        # Audit log button
        if st.button("View Audit Log"):
            st.session_state.show_audit = True
        else:
            st.session_state.show_audit = False
    
    # Main content area
    if uploaded_file is not None:
        # Save the uploaded file
        file_path = st.session_state.file_handler.save_uploaded_file(
            uploaded_file, uploaded_file.name
        )
        st.session_state.uploaded_file_path = file_path
        
        # Display file information
        file_info = st.session_state.file_handler.get_file_info(file_path)
        st.info(f"File: {file_info['name']} ({file_info['type']})")
        
        # Process the file when button is clicked
        if process_button:
            with st.spinner("Processing file..."):
                # Process the file
                pii_results, redacted_file_path, audit_record = process_file(file_path, components)
                
                # Update session state
                st.session_state.pii_results = pii_results
                st.session_state.redacted_file_path = redacted_file_path
                st.session_state.audit_record = audit_record
            
            st.success("File processed successfully!")
        
        # Display results if available
        if st.session_state.pii_results:
            # Display PII summary
            st.session_state.visualization.display_pii_summary(st.session_state.pii_results)
            
            # Display PII details if enabled
            if st.session_state.settings['show_details']:
                st.session_state.visualization.display_pii_details(
                    st.session_state.pii_results,
                    max_items=st.session_state.settings['max_display_items']
                )
            
            # Display risk assessment
            if st.session_state.audit_record:
                risk_data = st.session_state.audit_record['risk_assessment']
                st.session_state.visualization.display_risk_assessment(risk_data)
            
            # Display comparison based on file type
            if st.session_state.redacted_file_path:
                file_type = file_info['type']
                
                if file_type == 'text':
                    # Read original and redacted text
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        original_text = f.read()
                    
                    with open(st.session_state.redacted_file_path, 'r', encoding='utf-8', errors='replace') as f:
                        redacted_text = f.read()
                    
                    # Display text comparison
                    st.session_state.visualization.display_text_comparison(original_text, redacted_text)
                
                elif file_type == 'image':
                    # Display image comparison
                    st.session_state.visualization.display_image_comparison(
                        file_path, st.session_state.redacted_file_path
                    )
                
                # Download button for redacted file
                st.markdown("### Download Redacted File")
                download_link = st.session_state.visualization.create_download_link(
                    st.session_state.redacted_file_path,
                    "Download Redacted File"
                )
                st.markdown(download_link, unsafe_allow_html=True)
    
    # Display audit log if requested
    if getattr(st.session_state, 'show_audit', False):
        audit_records = st.session_state.audit_logger.get_audit_records()
        st.session_state.visualization.display_audit_log(audit_records)

# Run the application
if __name__ == "__main__":
    main()