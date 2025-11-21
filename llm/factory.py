"""
Factory responsible for instantiating the configured LLM provider.
"""

from __future__ import annotations

import logging
from typing import Optional

from utils.config import load_ai_config

from .anthropic_provider import AnthropicProvider
from .dummy_provider import DummyProvider
from .gemini_provider import GeminiProvider
from .lmstudio_provider import LMStudioProvider
from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider
from .base import AIModelInterface

logger = logging.getLogger(__name__)

_LLM_INSTANCE: Optional[AIModelInterface] = None


def get_llm() -> AIModelInterface:
    """
    Return a singleton LLM provider based on configuration/environment.
    """
    global _LLM_INSTANCE
    if _LLM_INSTANCE is not None:
        return _LLM_INSTANCE

    config = load_ai_config()
    provider = (config.get("ai_provider") or "dummy").lower()
    api_key = config.get("ai_api_key")
    endpoint = config.get("ai_endpoint")
    model_name = config.get("model_name") or "local-model"

    try:
        if provider == "openai":
            _LLM_INSTANCE = OpenAIProvider(api_key=api_key, model_name=model_name, endpoint=endpoint)
        elif provider == "lmstudio":
            _LLM_INSTANCE = LMStudioProvider(endpoint=endpoint or "http://localhost:1234", model_name=model_name)
        elif provider == "ollama":
            _LLM_INSTANCE = OllamaProvider(endpoint=endpoint or "http://localhost:11434", model_name=model_name)
        elif provider == "anthropic":
            _LLM_INSTANCE = AnthropicProvider(api_key=api_key, model_name=model_name)
        elif provider == "gemini":
            _LLM_INSTANCE = GeminiProvider(api_key=api_key, model_name=model_name)
        else:
            raise ValueError("Unsupported or missing AI provider configuration.")
        logger.info("LLM provider initialized: %s", provider)
    except Exception as exc:
        logger.warning("Falling back to DummyProvider due to error: %s", exc)
        _LLM_INSTANCE = DummyProvider()

    return _LLM_INSTANCE

