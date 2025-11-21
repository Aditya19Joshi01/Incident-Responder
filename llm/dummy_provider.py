"""
Dummy provider used when no external LLM is configured.
"""

from __future__ import annotations

import json
import logging

from .base import AIModelInterface

logger = logging.getLogger(__name__)


class DummyProvider(AIModelInterface):
    """
    Fallback provider that returns deterministic, rule-based responses.
    """

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """
        Return a simple JSON encoded fallback response.

        Args:
            system_prompt: Ignored.
            user_prompt: Ignored.

        Returns:
            JSON string describing fallback behavior.
        """
        logger.debug("DummyProvider invoked. Returning fallback response.")
        payload = {
            "mode": "fallback",
            "system_prompt": system_prompt[:120],
            "user_prompt_sample": user_prompt[:120],
            "result": "AI provider not configured. Using deterministic logic.",
        }
        return json.dumps(payload)

