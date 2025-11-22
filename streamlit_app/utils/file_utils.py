"""
File utility functions for handling uploaded files and temporary storage.
"""

import os
import tempfile
from pathlib import Path
from typing import Optional


def save_uploaded_file(uploaded_file, temp_dir: Optional[str] = None) -> str:
    """
    Save an uploaded Streamlit file to a temporary location.
    
    Args:
        uploaded_file: Streamlit UploadedFile object
        temp_dir: Optional temporary directory path
        
    Returns:
        Path to the saved file
    """
    if temp_dir is None:
        temp_dir = tempfile.gettempdir()
    
    # Create a subdirectory for our app
    app_temp_dir = Path(temp_dir) / "incident_responder"
    app_temp_dir.mkdir(parents=True, exist_ok=True)
    
    # Save the file
    file_path = app_temp_dir / uploaded_file.name
    
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    return str(file_path)


def cleanup_temp_file(file_path: str) -> None:
    """
    Clean up a temporary file.
    
    Args:
        file_path: Path to the file to delete
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass  # Ignore cleanup errors

