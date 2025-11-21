"""
LM Studio provider (OpenAI compatible HTTP API).
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

from .base import AIModelInterface

logger = logging.getLogger(__name__)


class LMStudioProvider(AIModelInterface):
    """Provider for LM Studio OpenAI-compatible endpoint."""

    def __init__(self, endpoint: str, model_name: str = "local-model"):
        if not endpoint:
            raise ValueError("LM Studio endpoint is required.")
        self.endpoint = endpoint.rstrip("/")
        self.model_name = model_name

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
        }

        url = f"{self.endpoint}/v1/chat/completions"
        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except requests.RequestException as exc:
            logger.error("LM Studio request failed: %s", exc)
            raise RuntimeError("LM Studio provider failed") from exc

