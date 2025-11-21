"""
Configuration helpers for loading AI provider settings.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"


def _load_yaml_config(config_path: Path = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """
    Load configuration from YAML file if it exists.

    Args:
        config_path: Optional custom path to config file.

    Returns:
        Dictionary containing configuration values.
    """
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    return {}


def load_ai_config() -> Dict[str, Any]:
    """
    Load AI configuration combining YAML defaults with environment overrides.

    Environment variables take precedence over YAML values.

    Returns:
        Dictionary containing ai_provider, ai_endpoint, ai_api_key, model_name.
    """
    config = _load_yaml_config()

    provider = os.getenv("AI_PROVIDER", config.get("ai_provider", "dummy"))
    endpoint = os.getenv("AI_ENDPOINT", config.get("ai_endpoint"))
    api_key = os.getenv("AI_API_KEY", config.get("ai_api_key"))
    model_name = os.getenv("AI_MODEL_NAME", config.get("model_name", "local-model"))

    return {
        "ai_provider": (provider or "dummy").lower(),
        "ai_endpoint": endpoint,
        "ai_api_key": api_key,
        "model_name": model_name,
    }

