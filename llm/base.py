"""
Base interface for Large Language Model providers.
"""

from abc import ABC, abstractmethod


class AIModelInterface(ABC):
    """Abstract base class for all AI model providers."""

    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """
        Return a model-generated completion as a string.

        Args:
            system_prompt: Instructions describing assistant behavior.
            user_prompt: User content or payload for the model.

        Returns:
            Model generated string response.
        """
        raise NotImplementedError

