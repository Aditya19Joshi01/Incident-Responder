"""
Script to build MITRE ATT&CK technique embeddings.
Run this once to generate embeddings for the knowledge base.
"""

import sys
import os

# Add parent directory to path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from utils.embedding import MITREEmbeddingStore
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """Build embeddings for MITRE techniques."""
    logger.info("Building MITRE ATT&CK embeddings...")
    
    # Check for OpenAI key
    use_openai = os.getenv("OPENAI_API_KEY") is not None
    openai_key = os.getenv("OPENAI_API_KEY")
    
    if use_openai:
        logger.info("Using OpenAI embeddings (text-embedding-3-small)")
    else:
        logger.info("Using fallback embeddings (no API key required)")
    
    # Initialize embedding store
    store = MITREEmbeddingStore(use_openai=use_openai, api_key=openai_key)
    
    # Build embeddings
    store.build_embeddings()
    
    logger.info("Embedding build complete!")
    logger.info(f"Techniques loaded: {len(store.techniques)}")
    logger.info(f"Embeddings shape: {store.embeddings.shape if store.embeddings is not None else 'None'}")


if __name__ == "__main__":
    main()

