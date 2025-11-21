"""
Unit tests for LLM factory configuration.
"""

import unittest
from unittest import mock

from llm.factory import get_llm
from llm.dummy_provider import DummyProvider


class TestLLMFactory(unittest.TestCase):
    """Ensure factory returns DummyProvider when configuration is missing."""

    def setUp(self):
        # Reset cached instance
        import llm.factory as factory
        factory._LLM_INSTANCE = None  # type: ignore[attr-defined]

    @mock.patch("llm.factory.load_ai_config", return_value={"ai_provider": "dummy"})
    def test_dummy_provider_fallback(self, mock_config):
        provider = get_llm()
        self.assertIsInstance(provider, DummyProvider)


if __name__ == "__main__":
    unittest.main()

