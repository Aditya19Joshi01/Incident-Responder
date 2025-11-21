"""
Google Gemini provider implementation.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

from .base import AIModelInterface

logger = logging.getLogger(__name__)


class GeminiProvider(AIModelInterface):
    """Provider for Google Gemini Generative Language API."""

    BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self, api_key: str, model_name: str = "gemini-1.5-flash"):
        if not api_key:
            raise ValueError("Gemini API key is required.")
        self.api_key = api_key
        self.model_name = model_name

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": f"{system_prompt}\n\n{user_prompt}"},
                    ],
                }
            ]
        }
        url = f"{self.BASE_URL}/models/{self.model_name}:generateContent?key={self.api_key}"
        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
            return ""
        except requests.RequestException as exc:
            logger.error("Gemini request failed: %s", exc)
            raise RuntimeError("Gemini provider failed") from exc

