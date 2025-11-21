"""
Anthropic Claude provider implementation.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

from .base import AIModelInterface

logger = logging.getLogger(__name__)


class AnthropicProvider(AIModelInterface):
    """Provider for Anthropic Claude Messages API."""

    API_URL = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"

    def __init__(self, api_key: str, model_name: str = "claude-3-sonnet-20240229"):
        if not api_key:
            raise ValueError("Anthropic API key is required.")
        self.api_key = api_key
        self.model_name = model_name

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model_name,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "max_tokens": 1024,
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.API_VERSION,
            "content-type": "application/json",
        }
        try:
            response = requests.post(self.API_URL, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            content = data.get("content", [])
            if content and isinstance(content[0], dict):
                return content[0].get("text", "")
            return ""
        except requests.RequestException as exc:
            logger.error("Anthropic request failed: %s", exc)
            raise RuntimeError("Anthropic provider failed") from exc

