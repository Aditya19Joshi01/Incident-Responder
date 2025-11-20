"""
Embedding utilities for MITRE ATT&CK technique search.
"""

import json
import numpy as np
from typing import List, Dict, Any, Tuple
import logging
import os

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logging.warning("OpenAI not available. Using fallback embeddings.")

logger = logging.getLogger(__name__)


class MITREEmbeddingStore:
    """Manages MITRE ATT&CK technique embeddings for similarity search."""
    
    def __init__(self, techniques_path: str = "data/mitre_techniques.json", 
                 embeddings_path: str = "data/mitre_embeddings.npy",
                 use_openai: bool = True,
                 api_key: str = None):
        """
        Initialize the MITRE embedding store.
        
        Args:
            techniques_path: Path to MITRE techniques JSON file
            embeddings_path: Path to stored embeddings numpy file
            use_openai: Whether to use OpenAI embeddings (requires API key)
            api_key: OpenAI API key (if None, uses OPENAI_API_KEY env var)
        """
        self.techniques_path = techniques_path
        self.embeddings_path = embeddings_path
        self.use_openai = use_openai and OPENAI_AVAILABLE
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        
        self.techniques = []
        self.embeddings = None
        self.client = None
        
        if self.use_openai and self.api_key:
            self.client = OpenAI(api_key=self.api_key)
        else:
            logger.warning("Using fallback embedding method (simple keyword matching)")
        
        self._load_data()
    
    def _load_data(self):
        """Load techniques and embeddings from disk."""
        if os.path.exists(self.techniques_path):
            with open(self.techniques_path, 'r') as f:
                self.techniques = json.load(f)
            logger.info(f"Loaded {len(self.techniques)} MITRE techniques")
        else:
            logger.warning(f"MITRE techniques file not found at {self.techniques_path}")
        
        if os.path.exists(self.embeddings_path):
            self.embeddings = np.load(self.embeddings_path)
            logger.info(f"Loaded embeddings with shape {self.embeddings.shape}")
        else:
            logger.info("No embeddings file found. Will use fallback search or generate on first use.")
    
    def _get_openai_embedding(self, text: str) -> np.ndarray:
        """Get embedding from OpenAI API."""
        if not self.client:
            raise ValueError("OpenAI client not initialized")
        
        try:
            response = self.client.embeddings.create(
                model="text-embedding-3-small",
                input=text
            )
            return np.array(response.data[0].embedding)
        except Exception as e:
            logger.error(f"Error getting OpenAI embedding: {e}")
            return self._fallback_embedding(text)
    
    def _fallback_embedding(self, text: str) -> np.ndarray:
        """Simple fallback embedding using keyword frequency."""
        # Simple bag-of-words style embedding (normalized)
        words = text.lower().split()
        # Create a simple hash-based embedding
        vec = np.zeros(384)  # Standard small embedding size
        for i, word in enumerate(words[:384]):
            vec[i % 384] += hash(word) % 100 / 100.0
        return vec / (np.linalg.norm(vec) + 1e-8)
    
    def _get_embedding(self, text: str) -> np.ndarray:
        """Get embedding for text using available method."""
        if self.use_openai and self.client:
            return self._get_openai_embedding(text)
        else:
            return self._fallback_embedding(text)
    
    def build_embeddings(self):
        """Build embeddings for all techniques and save to disk."""
        if not self.techniques:
            logger.error("No techniques loaded. Cannot build embeddings.")
            return
        
        logger.info("Building embeddings for MITRE techniques...")
        embeddings_list = []
        
        for technique in self.techniques:
            # Combine technique fields for embedding
            text = f"{technique.get('name', '')} {technique.get('description', '')} {technique.get('tactic', '')}"
            embedding = self._get_embedding(text)
            embeddings_list.append(embedding)
        
        self.embeddings = np.array(embeddings_list)
        
        # Save to disk
        os.makedirs(os.path.dirname(self.embeddings_path) or '.', exist_ok=True)
        np.save(self.embeddings_path, self.embeddings)
        logger.info(f"Saved embeddings to {self.embeddings_path}")
    
    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Search for similar MITRE techniques.
        
        Args:
            query: Search query text
            top_k: Number of results to return
            
        Returns:
            List of technique dictionaries with similarity scores
        """
        if len(self.techniques) == 0:
            logger.warning("No techniques available. Returning empty results.")
            return []
        
        # If embeddings don't exist, build them on the fly
        if self.embeddings is None:
            logger.info("Embeddings not found. Building embeddings on the fly...")
            self.build_embeddings()
        
        if self.embeddings is None:
            logger.warning("Failed to build embeddings. Using fallback search.")
            return self._fallback_search(query, top_k)
        
        # Get query embedding
        query_embedding = self._get_embedding(query)
        
        # Compute cosine similarity
        if self.use_openai and self.client:
            # Normalize for cosine similarity
            query_embedding = query_embedding / (np.linalg.norm(query_embedding) + 1e-8)
            similarities = np.dot(self.embeddings, query_embedding)
        else:
            # For fallback, use simple dot product
            similarities = np.dot(self.embeddings, query_embedding)
        
        # Get top-k indices
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        results = []
        for idx in top_indices:
            technique = self.techniques[idx].copy()
            technique['similarity_score'] = float(similarities[idx])
            results.append(technique)
        
        return results
    
    def _fallback_search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Fallback search using simple keyword matching when embeddings unavailable."""
        query_lower = query.lower()
        results = []
        
        for technique in self.techniques:
            score = 0.0
            name = technique.get("name", "").lower()
            description = technique.get("description", "").lower()
            tactic = technique.get("tactic", "").lower()
            technique_id = technique.get("technique_id", "").lower()
            
            # Simple keyword matching
            if query_lower in technique_id:
                score += 2.0
            if query_lower in name:
                score += 1.5
            if query_lower in description:
                score += 1.0
            if query_lower in tactic:
                score += 0.5
            
            if score > 0:
                result = technique.copy()
                result['similarity_score'] = score
                results.append((score, result))
        
        # Sort by score and return top_k
        results.sort(key=lambda x: x[0], reverse=True)
        return [result[1] for result in results[:top_k]]

