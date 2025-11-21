"""
Ollama provider implementation.
"""

from __future__ import annotations

import logging

import requests

from .base import AIModelInterface

logger = logging.getLogger(__name__)


class OllamaProvider(AIModelInterface):
    """Provider for interacting with local Ollama HTTP API."""

    def __init__(self, endpoint: str = "http://localhost:11434", model_name: str = "llama3"):
        if not endpoint:
            raise ValueError("Ollama endpoint is required.")
        self.endpoint = endpoint.rstrip("/")
        self.model_name = model_name

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model_name,
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        url = f"{self.endpoint}/api/chat"
        try:
            response = requests.post(url, json=payload, timeout=120)
            response.raise_for_status()
            data = response.json()
            message = data.get("message", {})
            return message.get("content", "")
        except requests.RequestException as exc:
            logger.error("Ollama request failed: %s", exc)
            raise RuntimeError("Ollama provider failed") from exc

