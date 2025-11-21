"""
OpenAI provider implementation.
"""

from __future__ import annotations

import logging
from typing import Optional

try:
    from openai import OpenAI
    from openai._exceptions import OpenAIError
except ImportError:  # pragma: no cover - optional dependency
    OpenAI = None  # type: ignore
    OpenAIError = Exception  # type: ignore

from .base import AIModelInterface

logger = logging.getLogger(__name__)


class OpenAIProvider(AIModelInterface):
    """Adapter for OpenAI Chat Completions API."""

    def __init__(self, api_key: str, model_name: str = "gpt-4o-mini", endpoint: Optional[str] = None):
        if OpenAI is None:
            raise ImportError("openai package is required for OpenAIProvider.")
        if not api_key:
            raise ValueError("OpenAI API key is required for OpenAIProvider.")

        self.client = OpenAI(api_key=api_key, base_url=endpoint) if endpoint else OpenAI(api_key=api_key)
        self.model_name = model_name

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """
        Generate a completion using OpenAI chat completions API.
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return response.choices[0].message.content
        except OpenAIError as exc:
            logger.error("OpenAI API error: %s", exc)
            raise RuntimeError("OpenAI provider failed") from exc

