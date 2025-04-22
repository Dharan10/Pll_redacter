import os
import tempfile
import mimetypes
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple, BinaryIO
import logging
import uuid

logger = logging.getLogger(__name__)

class FileHandler:
    """Handles file operations for the PII redactor application.
    
    This class manages file uploads, downloads, format detection, and temporary
    file storage for the application.
    """
    
    # Supported file formats and their MIME types
    SUPPORTED_FORMATS = {
        'text': ['text/plain', 'text/csv', 'text/html', 'application/json'],
        'image': ['image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/tiff'],
        'pdf': ['application/pdf'],
        'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document']
    }
    
    # File extensions for each category
    FILE_EXTENSIONS = {
        'text': ['.txt', '.csv', '.html', '.htm', '.json', '.xml'],
        'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif'],
        'pdf': ['.pdf'],
        'docx': ['.docx']
    }
    
    def __init__(self, temp_dir: Optional[str] = None):
        """Initialize the file handler.
        
        Args:
            temp_dir: Directory to store temporary files (optional)
        """
        # Create a temporary directory if not provided
        if temp_dir:
            self.temp_dir = Path(temp_dir)
            self.temp_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.temp_dir = Path(tempfile.mkdtemp())
        
        logger.info(f"File handler initialized with temp directory: {self.temp_dir}")
        
        # Initialize mimetypes
        mimetypes.init()
    
    def save_uploaded_file(self, file_obj: BinaryIO, filename: str) -> Path:
        """Save an uploaded file to the temporary directory.
        
        Args:
            file_obj: File-like object containing the uploaded file data
            filename: Original filename of the uploaded file
            
        Returns:
            Path to the saved temporary file
        """
        # Generate a unique filename to avoid collisions
        unique_id = str(uuid.uuid4())[:8]
        safe_filename = f"{unique_id}_{os.path.basename(filename)}"
        file_path = self.temp_dir / safe_filename
        
        # Save the file
        with open(file_path, 'wb') as f:
            file_obj.seek(0)  # Ensure we're at the start of the file
            shutil.copyfileobj(file_obj, f)
        
        logger.info(f"Saved uploaded file '{filename}' to {file_path}")
        return file_path
    
    def get_file_type(self, file_path: Union[str, Path]) -> str:
        """Determine the type of a file based on its extension and content.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File type category ('text', 'image', 'pdf', 'docx', or 'unknown')
        """
        file_path = Path(file_path)
        extension = file_path.suffix.lower()
        
        # Check by extension first
        for file_type, extensions in self.FILE_EXTENSIONS.items():
            if extension in extensions:
                return file_type
        
        # If extension check fails, try MIME type detection
        mime_type, _ = mimetypes.guess_type(str(file_path))
        
        if mime_type:
            for file_type, mime_types in self.SUPPORTED_FORMATS.items():
                if mime_type in mime_types:
                    return file_type
        
        # If all else fails, try to determine by content
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)  # Read first 8 bytes
                
                # Check for PDF signature
                if header.startswith(b'%PDF'):
                    return 'pdf'
                
                # Check for DOCX (ZIP) signature
                if header.startswith(b'PK\x03\x04'):
                    return 'docx'
                
                # Check for common image signatures
                if header.startswith(b'\xff\xd8'):
                    return 'image'  # JPEG
                if header.startswith(b'\x89PNG'):
                    return 'image'  # PNG
                if header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
                    return 'image'  # GIF
                
                # Try to read as text
                f.seek(0)
                try:
                    f.read(1024).decode('utf-8')
                    return 'text'  # If decoding succeeds, it's probably text
                except UnicodeDecodeError:
                    pass
        except Exception as e:
            logger.warning(f"Error determining file type by content: {e}")
        
        return 'unknown'
    
    def is_supported_format(self, file_path: Union[str, Path]) -> bool:
        """Check if a file is in a supported format.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if the file format is supported, False otherwise
        """
        file_type = self.get_file_type(file_path)
        return file_type != 'unknown'
    
    def create_output_path(self, original_path: Union[str, Path], suffix: str = "_redacted") -> Path:
        """Create a path for the redacted output file.
        
        Args:
            original_path: Path to the original file
            suffix: Suffix to add to the filename
            
        Returns:
            Path for the redacted output file
        """
        original_path = Path(original_path)
        stem = original_path.stem
        extension = original_path.suffix
        
        output_filename = f"{stem}{suffix}{extension}"
        output_path = self.temp_dir / output_filename
        
        return output_path
    
    def cleanup(self) -> None:
        """Clean up temporary files."""
        try:
            shutil.rmtree(self.temp_dir)
            logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.error(f"Error cleaning up temporary directory: {e}")
    
    def get_file_size(self, file_path: Union[str, Path]) -> int:
        """Get the size of a file in bytes.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File size in bytes
        """
        return os.path.getsize(file_path)
    
    def get_file_info(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Get information about a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with file information
        """
        file_path = Path(file_path)
        file_type = self.get_file_type(file_path)
        file_size = self.get_file_size(file_path)
        
        return {
            'name': file_path.name,
            'path': str(file_path),
            'type': file_type,
            'size': file_size,
            'extension': file_path.suffix.lower(),
            'is_supported': file_type != 'unknown'
        }