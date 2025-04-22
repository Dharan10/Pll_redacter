import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
import os

logger = logging.getLogger(__name__)

class AuditLogger:
    """Handles audit logging and risk scoring for PII detection.
    
    This class manages the logging of PII detections, calculates risk scores,
    and maintains an audit trail for compliance purposes.
    """
    
    # Risk weights for different PII types (higher = more sensitive)
    DEFAULT_RISK_WEIGHTS = {
        'email': 3,
        'phone': 3,
        'credit_card': 5,
        'aadhaar': 5,
        'pan': 5,
        'date': 2,
        'ssn': 5,
        'passport': 5,
        'ip_address': 2,
        'url': 1,
        'person_name': 3,
        'organization': 2,
        'location': 2,
        'financial_info': 4,
        'demographic': 3
    }
    
    def __init__(self, log_dir: Optional[str] = None, risk_weights: Optional[Dict[str, int]] = None):
        """Initialize the audit logger.
        
        Args:
            log_dir: Directory to store audit logs (optional)
            risk_weights: Custom risk weights for PII types (optional)
        """
        # Set up log directory
        if log_dir:
            self.log_dir = Path(log_dir)
            self.log_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.log_dir = Path(os.getcwd()) / 'audit_logs'
            self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up risk weights
        self.risk_weights = risk_weights or self.DEFAULT_RISK_WEIGHTS.copy()
        
        logger.info(f"Audit logger initialized with log directory: {self.log_dir}")
    
    def log_detection(self, file_info: Dict[str, Any], pii_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Log a PII detection event and calculate risk score.
        
        Args:
            file_info: Information about the processed file
            pii_list: List of detected PII items
            
        Returns:
            Audit record with detection details and risk score
        """
        # Create timestamp
        timestamp = datetime.now().isoformat()
        
        # Count PII by type
        pii_counts = {}
        for pii in pii_list:
            pii_type = pii['type']
            pii_counts[pii_type] = pii_counts.get(pii_type, 0) + 1
        
        # Calculate risk score
        risk_score, risk_factors = self.calculate_risk_score(pii_list, file_info)
        
        # Create audit record
        audit_record = {
            'timestamp': timestamp,
            'file_info': {
                'name': file_info.get('name', 'unknown'),
                'type': file_info.get('type', 'unknown'),
                'size': file_info.get('size', 0)
            },
            'pii_detected': {
                'total_count': len(pii_list),
                'by_type': pii_counts
            },
            'risk_assessment': {
                'score': risk_score,
                'level': self.get_risk_level(risk_score),
                'factors': risk_factors
            }
        }
        
        # Save the audit record
        self._save_audit_record(audit_record)
        
        return audit_record
    
    def calculate_risk_score(self, pii_list: List[Dict[str, Any]], 
                             file_info: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Calculate a risk score based on detected PII.
        
        Args:
            pii_list: List of detected PII items
            file_info: Information about the processed file
            
        Returns:
            Tuple of (risk score, list of risk factors)
        """
        if not pii_list:
            return 0.0, ["No PII detected"]
        
        # Base score starts at 0
        score = 0.0
        risk_factors = []
        
        # Count PII by type
        pii_counts = {}
        for pii in pii_list:
            pii_type = pii['type']
            pii_counts[pii_type] = pii_counts.get(pii_type, 0) + 1
        
        # Calculate weighted score based on PII types and counts
        for pii_type, count in pii_counts.items():
            weight = self.risk_weights.get(pii_type, 1)  # Default weight of 1 if not specified
            type_score = weight * count
            score += type_score
            
            if count > 0:
                risk_factors.append(f"{count} instances of {pii_type} (weight: {weight})")
        
        # Adjust score based on file type (some formats may be riskier)
        file_type = file_info.get('type', 'unknown')
        if file_type == 'pdf':
            score *= 1.2  # PDFs might contain hidden text layers
            risk_factors.append("PDF format (may contain hidden text layers)")
        elif file_type == 'docx':
            score *= 1.1  # DOCX might contain metadata
            risk_factors.append("DOCX format (may contain metadata)")
        
        # Normalize score to a 0-100 scale
        # This is a simple normalization; adjust as needed for your use case
        normalized_score = min(100, score * 5)  # Cap at 100
        
        return normalized_score, risk_factors
    
    def get_risk_level(self, risk_score: float) -> str:
        """Convert a numerical risk score to a categorical risk level.
        
        Args:
            risk_score: Numerical risk score (0-100)
            
        Returns:
            Risk level category (Low, Medium, High, Critical)
        """
        if risk_score < 20:
            return "Low"
        elif risk_score < 50:
            return "Medium"
        elif risk_score < 80:
            return "High"
        else:
            return "Critical"
    
    def _save_audit_record(self, audit_record: Dict[str, Any]) -> None:
        """Save an audit record to the log directory.
        
        Args:
            audit_record: The audit record to save
        """
        try:
            # Create a filename based on timestamp
            timestamp = datetime.fromisoformat(audit_record['timestamp'])
            filename = f"audit_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
            file_path = self.log_dir / filename
            
            # Write the audit record to a JSON file
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(audit_record, f, indent=2)
            
            logger.info(f"Saved audit record to {file_path}")
        except Exception as e:
            logger.error(f"Error saving audit record: {e}")
    
    def get_audit_records(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit records.
        
        Args:
            limit: Maximum number of records to return
            
        Returns:
            List of audit records, sorted by timestamp (newest first)
        """
        try:
            # Get all JSON files in the log directory
            json_files = list(self.log_dir.glob('audit_*.json'))
            
            # Sort by modification time (newest first)
            json_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Limit the number of files
            json_files = json_files[:limit]
            
            # Read and parse each file
            records = []
            for file_path in json_files:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        record = json.load(f)
                        records.append(record)
                except Exception as e:
                    logger.warning(f"Error reading audit record {file_path}: {e}")
            
            return records
        except Exception as e:
            logger.error(f"Error getting audit records: {e}")
            return []
    
    def set_risk_weights(self, risk_weights: Dict[str, int]) -> None:
        """Set custom risk weights for PII types.
        
        Args:
            risk_weights: Dictionary mapping PII types to risk weights
        """
        self.risk_weights = risk_weights
        logger.info(f"Updated risk weights: {risk_weights}")
    
    def get_risk_weights(self) -> Dict[str, int]:
        """Get the current risk weights for PII types.
        
        Returns:
            Dictionary mapping PII types to risk weights
        """
        return self.risk_weights.copy()