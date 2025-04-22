import spacy
from typing import Dict, List, Any, Optional, Union
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class NERDetector:
    """Detects PII using Named Entity Recognition.
    
    This class uses spaCy models to identify named entities that might be
    considered PII, such as person names, organizations, locations, etc.
    """
    
    def __init__(self, model_name: str = "en_core_web_md"):
        """Initialize the NER detector with a spaCy model.
        
        Args:
            model_name: Name of the spaCy model to use
        """
        try:
            self.nlp = spacy.load(model_name)
            logger.info(f"Loaded spaCy model: {model_name}")
        except OSError:
            logger.warning(f"Model {model_name} not found. Attempting to download...")
            try:
                # Try to download the model
                spacy.cli.download(model_name)
                self.nlp = spacy.load(model_name)
                logger.info(f"Downloaded and loaded spaCy model: {model_name}")
            except Exception as e:
                logger.error(f"Failed to download model {model_name}: {e}")
                raise
        
        # Default entity types to consider as PII
        self.pii_entity_types = {
            'PERSON': 'person_name',
            'ORG': 'organization',
            'GPE': 'location',  # Geopolitical entity
            'LOC': 'location',
            'DATE': 'date',
            'MONEY': 'financial_info',
            'NORP': 'demographic',  # Nationalities, religious or political groups
        }
    
    def detect(self, text: str) -> List[Dict[str, Any]]:
        """Detect PII entities in the given text using NER.
        
        Args:
            text: The text to analyze for PII entities
            
        Returns:
            A list of dictionaries containing PII type, value, and position
        """
        if not text or not isinstance(text, str):
            logger.warning("Empty or non-string input provided to NER detector")
            return []
        
        results = []
        doc = self.nlp(text)
        
        for ent in doc.ents:
            if ent.label_ in self.pii_entity_types:
                results.append({
                    'type': self.pii_entity_types[ent.label_],
                    'value': ent.text,
                    'start': ent.start_char,
                    'end': ent.end_char,
                    'detection_method': 'ner',
                    'entity_type': ent.label_
                })
        
        # Sort results by position in text
        results.sort(key=lambda x: x['start'])
        
        return results
    
    def set_pii_entity_types(self, entity_mapping: Dict[str, str]) -> None:
        """Set custom entity types to consider as PII.
        
        Args:
            entity_mapping: Dictionary mapping spaCy entity labels to PII types
        """
        self.pii_entity_types = entity_mapping
        logger.info(f"Updated PII entity types: {entity_mapping}")
    
    def add_pii_entity_type(self, spacy_label: str, pii_type: str) -> None:
        """Add a single entity type to consider as PII.
        
        Args:
            spacy_label: The spaCy entity label
            pii_type: The PII type to map it to
        """
        self.pii_entity_types[spacy_label] = pii_type
        logger.info(f"Added PII entity type: {spacy_label} -> {pii_type}")
    
    def remove_pii_entity_type(self, spacy_label: str) -> bool:
        """Remove an entity type from PII consideration.
        
        Args:
            spacy_label: The spaCy entity label to remove
            
        Returns:
            True if entity type was removed, False if it didn't exist
        """
        if spacy_label in self.pii_entity_types:
            del self.pii_entity_types[spacy_label]
            logger.info(f"Removed PII entity type: {spacy_label}")
            return True
        return False
    
    def get_available_entity_types(self) -> Dict[str, str]:
        """Get all available entity types considered as PII.
        
        Returns:
            Dictionary mapping spaCy entity labels to PII types
        """
        return self.pii_entity_types.copy()


class TransformerNERDetector:
    """Detects PII using transformer-based NER models.
    
    This class uses Hugging Face transformer models for more advanced
    named entity recognition.
    """
    
    def __init__(self, model_name: str = "dslim/bert-base-NER"):
        """Initialize the transformer-based NER detector.
        
        Args:
            model_name: Name of the Hugging Face model to use
        """
        try:
            from transformers import AutoTokenizer, AutoModelForTokenClassification
            from transformers import pipeline
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForTokenClassification.from_pretrained(model_name)
            self.ner_pipeline = pipeline("ner", model=self.model, tokenizer=self.tokenizer, aggregation_strategy="simple")
            logger.info(f"Loaded transformer model: {model_name}")
        except Exception as e:
            logger.error(f"Failed to load transformer model {model_name}: {e}")
            raise
        
        # Default entity types to consider as PII
        self.pii_entity_types = {
            'PER': 'person_name',
            'ORG': 'organization',
            'LOC': 'location',
            'MISC': 'miscellaneous'
        }
    
    def detect(self, text: str) -> List[Dict[str, Any]]:
        """Detect PII entities in the given text using transformer-based NER.
        
        Args:
            text: The text to analyze for PII entities
            
        Returns:
            A list of dictionaries containing PII type, value, and position
        """
        if not text or not isinstance(text, str):
            logger.warning("Empty or non-string input provided to transformer NER detector")
            return []
        
        results = []
        
        try:
            entities = self.ner_pipeline(text)
            
            for entity in entities:
                entity_type = entity['entity_group']
                if entity_type in self.pii_entity_types:
                    results.append({
                        'type': self.pii_entity_types[entity_type],
                        'value': entity['word'],
                        'start': entity['start'],
                        'end': entity['end'],
                        'detection_method': 'transformer_ner',
                        'entity_type': entity_type,
                        'score': entity['score']
                    })
            
            # Sort results by position in text
            results.sort(key=lambda x: x['start'])
        except Exception as e:
            logger.error(f"Error in transformer NER detection: {e}")
        
        return results
    
    def set_pii_entity_types(self, entity_mapping: Dict[str, str]) -> None:
        """Set custom entity types to consider as PII.
        
        Args:
            entity_mapping: Dictionary mapping model entity labels to PII types
        """
        self.pii_entity_types = entity_mapping
        logger.info(f"Updated transformer PII entity types: {entity_mapping}")
    
    def get_available_entity_types(self) -> Dict[str, str]:
        """Get all available entity types considered as PII.
        
        Returns:
            Dictionary mapping model entity labels to PII types
        """
        return self.pii_entity_types.copy()