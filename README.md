# Auto PII Redactor

An advanced application for detecting and redacting Personally Identifiable Information (PII) from various file formats including text, images, PDFs, and DOCX files.

## Features

- **Multi-format Support**: Process text files, images (JPG/PNG), PDFs, and DOCX documents
- **Advanced PII Detection**: Identify sensitive information using regex patterns and Named Entity Recognition (NER)
- **Customizable Redaction**: Replace text with [REDACTED] tags or apply visual redaction to images
- **Interactive UI**: User-friendly Streamlit interface for file uploads, previews, and downloads
- **Audit Logging**: Track detected PII types and calculate risk scores
- **Side-by-side Comparison**: View original and redacted content for verification

## PII Types Detected

- Email addresses
- Phone numbers
- Aadhaar numbers (Indian national ID)
- PAN numbers (Indian tax ID)
- Dates of birth
- Credit card details
- Names and addresses (via NER)
- And more...

## Setup and Installation

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Download required NLP models:
   ```
   python -m spacy download en_core_web_md
   ```
4. Run the application:
   ```
   streamlit run app.py
   ```

## Project Structure

```
├── app.py                  # Main Streamlit application
├── requirements.txt        # Project dependencies
├── README.md               # Project documentation
├── pii_detector/
│   ├── __init__.py
│   ├── regex_detector.py   # Regex-based PII detection
│   ├── ner_detector.py     # NER-based PII detection
│   └── ocr_engine.py       # OCR for image-based text extraction
├── redactors/
│   ├── __init__.py
│   ├── text_redactor.py    # Text file redaction
│   ├── image_redactor.py   # Image redaction
│   ├── pdf_redactor.py     # PDF redaction
│   └── docx_redactor.py    # DOCX redaction
└── utils/
    ├── __init__.py
    ├── file_handler.py     # File upload/download utilities
    ├── audit_logger.py     # Logging and risk scoring
    └── visualization.py    # UI components for visualization
```

## Usage

1. Launch the application
2. Upload a file (text, image, PDF, or DOCX)
3. View detected PII information
4. Adjust redaction settings if needed
5. Download the redacted file

## License

MIT
