"""
Knowledge Retrieval Agent - Searches MITRE ATT&CK knowledge base.
"""

import logging
from typing import Dict, Any, List
import sys
import os

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from utils.embedding import MITREEmbeddingStore

logger = logging.getLogger(__name__)


class KnowledgeRetrievalAgent:
    """Agent responsible for retrieving MITRE ATT&CK technique details."""
    
    def __init__(self, embedding_store: MITREEmbeddingStore = None):
        """
        Initialize the Knowledge Retrieval Agent.
        
        Args:
            embedding_store: Pre-initialized MITREEmbeddingStore instance
        """
        if embedding_store:
            self.embedding_store = embedding_store
        else:
            self.embedding_store = MITREEmbeddingStore()
    
    def retrieve(self, technique_guess: str, threat_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Retrieve detailed MITRE technique information.
        
        Args:
            technique_guess: MITRE technique ID (e.g., "T1595")
            threat_context: Context from Threat Attribution Agent
            
        Returns:
            Dictionary containing detailed MITRE technique information
        """
        logger.info(f"Retrieving MITRE knowledge for technique: {technique_guess}")
        
        # Build search query from context
        query = self._build_query(technique_guess, threat_context)
        
        # Perform vector search
        search_results = self.embedding_store.search(query, top_k=3)
        
        # Find exact match if available
        exact_match = self._find_exact_match(technique_guess)
        
        # Combine results
        result = {
            "requested_technique": technique_guess,
            "exact_match": exact_match,
            "similar_techniques": search_results,
            "recommended_technique": exact_match if exact_match else (search_results[0] if search_results else None)
        }
        
        logger.info(f"Knowledge retrieval complete. Found {len(search_results)} similar techniques")
        return result
    
    def _build_query(self, technique_id: str, context: Dict[str, Any]) -> str:
        """Build search query from technique ID and context."""
        classification = context.get("threat_classification", {})
        reasoning = context.get("reasoning", "")
        
        query_parts = [technique_id]
        query_parts.append(classification.get("category", ""))
        query_parts.append(classification.get("subcategory", ""))
        query_parts.append(reasoning[:200])  # First 200 chars of reasoning
        
        return " ".join(query_parts)
    
    def _find_exact_match(self, technique_id: str) -> Dict[str, Any]:
        """Find exact technique match by ID."""
        for technique in self.embedding_store.techniques:
            if technique.get("technique_id") == technique_id:
                return technique
        return None

