"""
LLM-based proposer using real AI providers (Anthropic Claude, OpenAI).

This module implements proposers that use actual LLM APIs to generate proposals.
It includes safety measures to prevent prompt injection and ensure structured output.
"""

import json
import asyncio
from typing import Dict, Any, Optional, Union
import logging
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.proposer.base import BaseProposer, ProposalError, ProposalValidationError
from app.policy.models import PaymentEvent, AIProposal
from app.config import settings

logger = logging.getLogger(__name__)


class LLMProposer(BaseProposer):
    """Base class for LLM-based proposers."""

    def __init__(self, name: str, model: str):
        super().__init__(name)
        self.model = model
        self.max_retries = 3
        self.timeout_seconds = 30

    async def _call_llm(self, messages: list) -> Dict[str, Any]:
        """Call the LLM API (to be implemented by subclasses)."""
        raise NotImplementedError

    async def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response into structured proposal."""
        try:
            # Try to extract JSON from response
            json_str = self._extract_json(response)
            proposal_dict = json.loads(json_str)
            return proposal_dict
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            logger.debug(f"Raw response: {response}")
            raise ProposalValidationError(f"Invalid JSON response: {e}")
        except Exception as e:
            logger.error(f"Failed to parse LLM response: {e}")
            raise ProposalValidationError(f"Response parsing failed: {e}")

    def _extract_json(self, text: str) -> str:
        """Extract JSON from text response."""
        # Find JSON-like content
        start = text.find('{')
        end = text.rfind('}') + 1

        if start == -1 or end == 0:
            raise ValueError("No JSON found in response")

        json_str = text[start:end]

        # Clean up common issues
        json_str = json_str.strip()
        json_str = json_str.replace('\n', ' ').replace('\r', ' ')

        return json_str

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((ProposalError, asyncio.TimeoutError)),
        reraise=True
    )
    async def propose(self, event: PaymentEvent) -> AIProposal:
        """Generate proposal using LLM."""
        try:
            logger.info(f"{self.name} generating proposal for {event.transaction_id}")

            # Build messages
            messages = [
                {"role": "system", "content": self._system_prompt},
                {"role": "user", "content": self._build_user_prompt(event)}
            ]

            # Call LLM with timeout
            try:
                response = await asyncio.wait_for(
                    self._call_llm(messages),
                    timeout=self.timeout_seconds
                )
            except asyncio.TimeoutError:
                logger.error(f"{self.name} timeout after {self.timeout_seconds}s")
                raise ProposalError("LLM request timeout")

            # Parse response
            proposal_dict = await self._parse_response(response)

            # Validate and return
            proposal = self._validate_proposal(proposal_dict)
            logger.info(f"{self.name} generated proposal: {proposal.action} "
                       f"(confidence: {proposal.confidence})")
            return proposal

        except ProposalError:
            raise  # Re-raise our own errors
        except Exception as e:
            logger.error(f"{self.name} failed: {e}")
            raise ProposalError(f"LLM proposal generation failed: {e}", e)


class AnthropicProposer(LLMProposer):
    """Proposer using Anthropic Claude API."""

    def __init__(self, model: str = "claude-3-5-sonnet-20241022"):
        super().__init__("AnthropicProposer", model)
        self.api_key = settings.llm.anthropic_api_key

        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is required for AnthropicProposer")

        # Import here to avoid dependency if not using Anthropic
        try:
            import anthropic
            self.client = anthropic.AsyncAnthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "anthropic package not installed. "
                "Install with: pip install anthropic"
            )

    async def _call_llm(self, messages: list) -> Dict[str, Any]:
        """Call Anthropic Claude API."""
        try:
            # Convert messages to Anthropic format
            system_message = None
            user_messages = []

            for msg in messages:
                if msg["role"] == "system":
                    system_message = msg["content"]
                else:
                    user_messages.append(msg["content"])

            # Combine user messages
            user_content = "\n\n".join(user_messages)

            # Make API call
            response = await self.client.messages.create(
                model=self.model,
                system=system_message,
                messages=[{"role": "user", "content": user_content}],
                max_tokens=1000,
                temperature=0.1,  # Low temperature for deterministic output
            )

            return response.content[0].text

        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise ProposalError(f"Anthropic API error: {e}", e)


class OpenAIProposer(LLMProposer):
    """Proposer using OpenAI API."""

    def __init__(self, model: str = "gpt-4-turbo-preview"):
        super().__init__("OpenAIProposer", model)
        self.api_key = settings.llm.openai_api_key

        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is required for OpenAIProposer")

        # Import here to avoid dependency if not using OpenAI
        try:
            from openai import AsyncOpenAI
            self.client = AsyncOpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "openai package not installed. "
                "Install with: pip install openai"
            )

    async def _call_llm(self, messages: list) -> Dict[str, Any]:
        """Call OpenAI API."""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=1000,
                temperature=0.1,  # Low temperature for deterministic output
                response_format={"type": "json_object"}  # Force JSON output
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise ProposalError(f"OpenAI API error: {e}", e)


class ProposerFactory:
    """Factory for creating proposer instances based on configuration."""

    @staticmethod
    def create_proposer() -> BaseProposer:
        """Create proposer instance based on configuration."""
        provider = settings.llm.provider

        if provider == "mock":
            from app.proposer.mock_proposer import MockProposer
            return MockProposer()

        elif provider == "anthropic":
            if not settings.llm.anthropic_api_key:
                raise ValueError(
                    "ANTHROPIC_API_KEY is required when LLM_PROVIDER=anthropic. "
                    "Set it in .env or use mock provider."
                )
            return AnthropicProposer()

        elif provider == "openai":
            if not settings.llm.openai_api_key:
                raise ValueError(
                    "OPENAI_API_KEY is required when LLM_PROVIDER=openai. "
                    "Set it in .env or use mock provider."
                )
            return OpenAIProposer()

        else:
            raise ValueError(f"Unknown LLM provider: {provider}")

    @staticmethod
    def get_available_providers() -> Dict[str, str]:
        """Get list of available providers and their status."""
        providers = {
            "mock": {
                "available": True,
                "requires_key": False,
                "description": "Mock proposer for testing (no API key needed)"
            },
            "anthropic": {
                "available": bool(settings.llm.anthropic_api_key),
                "requires_key": True,
                "description": "Anthropic Claude API"
            },
            "openai": {
                "available": bool(settings.llm.openai_api_key),
                "requires_key": True,
                "description": "OpenAI GPT API"
            }
        }
        return providers

    @staticmethod
    def validate_provider_config(provider: str) -> bool:
        """Validate configuration for a provider."""
        if provider == "mock":
            return True
        elif provider == "anthropic":
            return bool(settings.llm.anthropic_api_key)
        elif provider == "openai":
            return bool(settings.llm.openai_api_key)
        else:
            return False


# Global proposer factory
proposer_factory = ProposerFactory()