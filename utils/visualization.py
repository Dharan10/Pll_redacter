import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import cv2
from PIL import Image
from typing import Dict, List, Any, Optional, Union, Tuple
import logging
from pathlib import Path
import base64
import io

logger = logging.getLogger(__name__)

class Visualization:
    """Handles visualization components for the PII redactor application.
    
    This class provides methods for displaying PII detection results,
    side-by-side comparisons, and other visual elements in the Streamlit UI.
    """
    
    def __init__(self):
        """Initialize the visualization utilities."""
        pass
    
    def display_pii_summary(self, pii_list: List[Dict[str, Any]]) -> None:
        """Display a summary of detected PII.
        
        Args:
            pii_list: List of detected PII items
        """
        if not pii_list:
            st.info("No PII detected in the document.")
            return
        
        # Count PII by type
        pii_counts = {}
        for pii in pii_list:
            pii_type = pii['type']
            pii_counts[pii_type] = pii_counts.get(pii_type, 0) + 1
        
        # Create a DataFrame for display
        df = pd.DataFrame({
            'PII Type': list(pii_counts.keys()),
            'Count': list(pii_counts.values())
        })
        
        # Sort by count (descending)
        df = df.sort_values('Count', ascending=False).reset_index(drop=True)
        
        # Display the summary
        st.subheader("PII Detection Summary")
        st.write(f"Total PII instances detected: {len(pii_list)}")
        st.dataframe(df)
        
        # Create a bar chart
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.bar(df['PII Type'], df['Count'], color='#ff6b6b')
        ax.set_xlabel('PII Type')
        ax.set_ylabel('Count')
        ax.set_title('PII Detection by Type')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        st.pyplot(fig)
    
    def display_pii_details(self, pii_list: List[Dict[str, Any]], max_items: int = 100) -> None:
        """Display detailed information about detected PII.
        
        Args:
            pii_list: List of detected PII items
            max_items: Maximum number of items to display
        """
        if not pii_list:
            return
        
        # Limit the number of items to display
        display_list = pii_list[:max_items]
        
        # Create a DataFrame for display
        data = []
        for pii in display_list:
            data.append({
                'Type': pii['type'],
                'Value': pii['value'],
                'Detection Method': pii.get('detection_method', 'unknown')
            })
        
        df = pd.DataFrame(data)
        
        # Display the details
        st.subheader("PII Detection Details")
        if len(pii_list) > max_items:
            st.write(f"Showing {max_items} of {len(pii_list)} detected PII instances")
        st.dataframe(df)
    
    def display_risk_assessment(self, risk_data: Dict[str, Any]) -> None:
        """Display risk assessment information.
        
        Args:
            risk_data: Risk assessment data
        """
        st.subheader("Risk Assessment")
        
        # Get risk score and level
        risk_score = risk_data.get('score', 0)
        risk_level = risk_data.get('level', 'Unknown')
        risk_factors = risk_data.get('factors', [])
        
        # Create columns for score and level
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Risk Score", f"{risk_score:.1f}/100")
        
        with col2:
            # Display risk level with appropriate color
            if risk_level == "Low":
                st.success(f"Risk Level: {risk_level}")
            elif risk_level == "Medium":
                st.warning(f"Risk Level: {risk_level}")
            elif risk_level == "High":
                st.error(f"Risk Level: {risk_level}")
            elif risk_level == "Critical":
                st.error(f"Risk Level: {risk_level}")
            else:
                st.info(f"Risk Level: {risk_level}")
        
        # Display risk factors
        if risk_factors:
            st.subheader("Risk Factors")
            for factor in risk_factors:
                st.write(f"• {factor}")
    
    def display_text_comparison(self, original_text: str, redacted_text: str) -> None:
        """Display a side-by-side comparison of original and redacted text.
        
        Args:
            original_text: Original text content
            redacted_text: Redacted text content
        """
        st.subheader("Text Comparison")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Original Text**")
            st.text_area("Original", original_text, height=300, disabled=True, key="original_text")
        
        with col2:
            st.markdown("**Redacted Text**")
            st.text_area("Redacted", redacted_text, height=300, disabled=True, key="redacted_text")
    
    def display_image_comparison(self, original_image: Union[np.ndarray, Image.Image, str, Path],
                               redacted_image: Union[np.ndarray, Image.Image, str, Path]) -> None:
        """Display a side-by-side comparison of original and redacted images.
        
        Args:
            original_image: Original image
            redacted_image: Redacted image
        """
        st.subheader("Image Comparison")
        
        # Convert to PIL Image if needed
        if isinstance(original_image, np.ndarray):
            original_image = Image.fromarray(cv2.cvtColor(original_image, cv2.COLOR_BGR2RGB))
        elif isinstance(original_image, (str, Path)):
            original_image = Image.open(original_image)
        
        if isinstance(redacted_image, np.ndarray):
            redacted_image = Image.fromarray(cv2.cvtColor(redacted_image, cv2.COLOR_BGR2RGB))
        elif isinstance(redacted_image, (str, Path)):
            redacted_image = Image.open(redacted_image)
        
        # Display side by side
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Original Image**")
            st.image(original_image, use_column_width=True)
        
        with col2:
            st.markdown("**Redacted Image**")
            st.image(redacted_image, use_column_width=True)
    
    def create_download_link(self, file_path: Union[str, Path], link_text: str = "Download") -> str:
        """Create a download link for a file.
        
        Args:
            file_path: Path to the file to download
            link_text: Text to display for the download link
            
        Returns:
            HTML for a download link
        """
        try:
            file_path = Path(file_path)
            
            # Read the file as bytes
            with open(file_path, 'rb') as f:
                file_bytes = f.read()
            
            # Encode as base64
            b64 = base64.b64encode(file_bytes).decode()
            
            # Get the file size
            file_size = file_path.stat().st_size
            size_str = self._format_file_size(file_size)
            
            # Create the download link
            href = f'<a href="data:application/octet-stream;base64,{b64}" download="{file_path.name}">{link_text} ({size_str})</a>'
            
            return href
        except Exception as e:
            logger.error(f"Error creating download link for {file_path}: {e}")
            return ""
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in a human-readable format.
        
        Args:
            size_bytes: File size in bytes
            
        Returns:
            Formatted file size string
        """
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    def display_audit_log(self, audit_records: List[Dict[str, Any]], max_records: int = 10) -> None:
        """Display the audit log.
        
        Args:
            audit_records: List of audit records
            max_records: Maximum number of records to display
        """
        if not audit_records:
            st.info("No audit records available.")
            return
        
        st.subheader("Audit Log")
        
        # Limit the number of records to display
        display_records = audit_records[:max_records]
        
        # Create a DataFrame for display
        data = []
        for record in display_records:
            timestamp = record.get('timestamp', '')
            file_info = record.get('file_info', {})
            pii_detected = record.get('pii_detected', {})
            risk_assessment = record.get('risk_assessment', {})
            
            data.append({
                'Timestamp': timestamp,
                'File Name': file_info.get('name', 'unknown'),
                'File Type': file_info.get('type', 'unknown'),
                'PII Count': pii_detected.get('total_count', 0),
                'Risk Score': risk_assessment.get('score', 0),
                'Risk Level': risk_assessment.get('level', 'Unknown')
            })
        
        df = pd.DataFrame(data)
        
        # Display the audit log
        if len(audit_records) > max_records:
            st.write(f"Showing {max_records} of {len(audit_records)} audit records")
        st.dataframe(df)
    
    def display_settings(self, settings: Dict[str, Any], on_change_callback: callable) -> Dict[str, Any]:
        """Display and update application settings.
        
        Args:
            settings: Current settings
            on_change_callback: Callback function when settings change
            
        Returns:
            Updated settings
        """
        st.subheader("Settings")
        
        updated_settings = settings.copy()
        
        # Create tabs for different settings categories
        tab1, tab2, tab3 = st.tabs(["Redaction", "Detection", "Display"])
        
        with tab1:
            st.markdown("**Redaction Settings**")
            
            # Text redaction marker
            text_marker = st.text_input(
                "Text Redaction Marker",
                value=settings.get('text_redaction_marker', '[REDACTED]')
            )
            updated_settings['text_redaction_marker'] = text_marker
            
            # Image redaction method
            image_method = st.selectbox(
                "Image Redaction Method",
                options=["box", "blur", "pixelate"],
                index=["box", "blur", "pixelate"].index(settings.get('image_redaction_method', 'box'))
            )
            updated_settings['image_redaction_method'] = image_method
            
            # PDF redaction mode
            pdf_visual = st.checkbox(
                "Use visual redaction for PDFs",
                value=settings.get('pdf_visual_mode', True)
            )
            updated_settings['pdf_visual_mode'] = pdf_visual
        
        with tab2:
            st.markdown("**Detection Settings**")
            
            # Enable/disable detection methods
            use_regex = st.checkbox(
                "Use regex patterns",
                value=settings.get('use_regex', True)
            )
            updated_settings['use_regex'] = use_regex
            
            use_ner = st.checkbox(
                "Use Named Entity Recognition",
                value=settings.get('use_ner', True)
            )
            updated_settings['use_ner'] = use_ner
            
            use_transformers = st.checkbox(
                "Use transformer models (more accurate but slower)",
                value=settings.get('use_transformers', False)
            )
            updated_settings['use_transformers'] = use_transformers
        
        with tab3:
            st.markdown("**Display Settings**")
            
            # Maximum PII items to display
            max_items = st.slider(
                "Maximum PII items to display",
                min_value=10,
                max_value=500,
                value=settings.get('max_display_items', 100),
                step=10
            )
            updated_settings['max_display_items'] = max_items
            
            # Show detailed PII information
            show_details = st.checkbox(
                "Show detailed PII information",
                value=settings.get('show_details', True)
            )
            updated_settings['show_details'] = show_details
        
        # Apply button
        if st.button("Apply Settings"):
            on_change_callback(updated_settings)
            st.success("Settings updated successfully!")
        
        return updated_settings