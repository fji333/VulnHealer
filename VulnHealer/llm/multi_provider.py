"""
Multi-LLM Provider
Supports OpenAI, DeepSeek, Anthropic, Ollama (local) with fallback chain.
"""

import os
import json
import asyncio
from typing import List, Dict, Any, Optional, AsyncGenerator
from dataclasses import dataclass
import logging
import time

import openai
from openai import AsyncOpenAI
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Standardized LLM response."""
    content: str
    provider: str
    model: str
    tokens_used: int = 0
    tokens_prompt: int = 0
    tokens_completion: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    raw_response: Any = None


class MultiLLMProvider:
    """
    Multi-provider LLM client with automatic fallback.

    Priority:
    1. DeepSeek (best for code, cheapest)
    2. OpenAI GPT-4o (most capable)
    3. Anthropic Claude (long context)
    4. Ollama (local, free, no API key)
    """

    # Pricing per 1M tokens (as of 2024)
    PRICING = {
        'deepseek-chat': {'input': 0.14, 'output': 0.28},
        'deepseek-coder': {'input': 0.14, 'output': 0.28},
        'gpt-4o': {'input': 5.0, 'output': 15.0},
        'gpt-4o-mini': {'input': 0.15, 'output': 0.6},
        'claude-3-opus-20240229': {'input': 15.0, 'output': 75.0},
        'claude-3-sonnet-20240229': {'input': 3.0, 'output': 15.0},
        'codellama:13b': {'input': 0.0, 'output': 0.0},  # Local
    }

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.llm_config = config.get('llm', {})

        # Provider configs
        self.openai_key = os.getenv('OPENAI_API_KEY') or self.llm_config.get('openai_api_key')
        self.deepseek_key = os.getenv('DEEPSEEK_API_KEY') or self.llm_config.get('deepseek_api_key')
        self.anthropic_key = os.getenv('ANTHROPIC_API_KEY') or self.llm_config.get('anthropic_api_key')
        self.ollama_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')

        # Default provider and model
        self.default_provider = os.getenv('DEFAULT_LLM_PROVIDER', 'deepseek')
        self.openai_model = os.getenv('OPENAI_MODEL', 'gpt-4o')
        self.deepseek_model = os.getenv('DEEPSEEK_MODEL', 'deepseek-coder')
        self.anthropic_model = os.getenv('ANTHROPIC_MODEL', 'claude-3-sonnet-20240229')
        self.ollama_model = os.getenv('OLLAMA_MODEL', 'codellama:13b')

        # Initialize clients
        self._init_clients()

        # Fallback chain
        self.fallback_chain = self._build_fallback_chain()

    def _init_clients(self):
        """Initialize API clients."""
        self.clients = {}

        if self.openai_key:
            self.clients['openai'] = AsyncOpenAI(api_key=self.openai_key)
            logger.info("OpenAI client initialized")

        if self.deepseek_key:
            self.clients['deepseek'] = AsyncOpenAI(
                api_key=self.deepseek_key,
                base_url="https://api.deepseek.com/v1"
            )
            logger.info("DeepSeek client initialized")

        if self.anthropic_key:
            try:
                import anthropic
                self.clients['anthropic'] = anthropic.AsyncAnthropic(api_key=self.anthropic_key)
                logger.info("Anthropic client initialized")
            except ImportError:
                logger.warning("anthropic package not installed, skipping")

        # Ollama doesn't need key
        self.clients['ollama'] = None  # Uses direct HTTP

    def _build_fallback_chain(self) -> List[str]:
        """Build provider fallback chain based on availability."""
        chain = []

        # Prefer configured default
        preferred = self.llm_config.get('default_provider', self.default_provider)

        if preferred == 'deepseek' and 'deepseek' in self.clients:
            chain.append('deepseek')
        elif preferred == 'openai' and 'openai' in self.clients:
            chain.append('openai')
        elif preferred == 'anthropic' and 'anthropic' in self.clients:
            chain.append('anthropic')
        elif preferred == 'ollama':
            chain.append('ollama')

        # Add remaining providers
        for provider in ['deepseek', 'openai', 'anthropic', 'ollama']:
            if provider not in chain:
                if provider == 'ollama' or provider in self.clients:
                    chain.append(provider)

        logger.info(f"LLM fallback chain: {chain}")
        return chain

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def complete(self, prompt: str, system_prompt: str = None, temperature: float = 0.2,
                       max_tokens: int = 4096, provider: str = None) -> LLMResponse:
        """
        Send completion request with automatic fallback.

        Args:
            prompt: User prompt
            system_prompt: System prompt
            temperature: Sampling temperature
            max_tokens: Max tokens to generate
            provider: Specific provider to use (None for default chain)

        Returns:
            LLMResponse with standardized output
        """
        providers_to_try = [provider] if provider else self.fallback_chain

        last_error = None
        for prov in providers_to_try:
            if not prov:
                continue

            start_time = time.time()
            try:
                if prov == 'openai':
                    response = await self._call_openai(prompt, system_prompt, temperature, max_tokens)
                elif prov == 'deepseek':
                    response = await self._call_deepseek(prompt, system_prompt, temperature, max_tokens)
                elif prov == 'anthropic':
                    response = await self._call_anthropic(prompt, system_prompt, temperature, max_tokens)
                elif prov == 'ollama':
                    response = await self._call_ollama(prompt, system_prompt, temperature, max_tokens)
                else:
                    continue

                response.latency_ms = (time.time() - start_time) * 1000
                logger.info(f"LLM call succeeded with {prov} in {response.latency_ms:.0f}ms")
                return response

            except Exception as e:
                last_error = e
                logger.warning(f"LLM call failed for {prov}: {e}")
                continue

        raise last_error or Exception("All LLM providers failed")

    async def _call_openai(self, prompt: str, system_prompt: str, temperature: float,
                           max_tokens: int) -> LLMResponse:
        """Call OpenAI API."""
        client = self.clients['openai']
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = await client.chat.completions.create(
            model=self.openai_model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )

        content = response.choices[0].message.content
        tokens_prompt = response.usage.prompt_tokens
        tokens_completion = response.usage.completion_tokens
        tokens_total = response.usage.total_tokens

        cost = self._calculate_cost(self.openai_model, tokens_prompt, tokens_completion)

        return LLMResponse(
            content=content,
            provider='openai',
            model=self.openai_model,
            tokens_used=tokens_total,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            cost_usd=cost,
            raw_response=response
        )

    async def _call_deepseek(self, prompt: str, system_prompt: str, temperature: float,
                             max_tokens: int) -> LLMResponse:
        """Call DeepSeek API."""
        client = self.clients['deepseek']
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = await client.chat.completions.create(
            model=self.deepseek_model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )

        content = response.choices[0].message.content
        tokens_prompt = response.usage.prompt_tokens
        tokens_completion = response.usage.completion_tokens
        tokens_total = response.usage.total_tokens

        cost = self._calculate_cost(self.deepseek_model, tokens_prompt, tokens_completion)

        return LLMResponse(
            content=content,
            provider='deepseek',
            model=self.deepseek_model,
            tokens_used=tokens_total,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            cost_usd=cost,
            raw_response=response
        )

    async def _call_anthropic(self, prompt: str, system_prompt: str, temperature: float,
                              max_tokens: int) -> LLMResponse:
        """Call Anthropic Claude API."""
        client = self.clients['anthropic']

        response = await client.messages.create(
            model=self.anthropic_model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt or "You are a helpful assistant.",
            messages=[{"role": "user", "content": prompt}]
        )

        content = response.content[0].text
        tokens_prompt = response.usage.input_tokens
        tokens_completion = response.usage.output_tokens
        tokens_total = tokens_prompt + tokens_completion

        cost = self._calculate_cost(self.anthropic_model, tokens_prompt, tokens_completion)

        return LLMResponse(
            content=content,
            provider='anthropic',
            model=self.anthropic_model,
            tokens_used=tokens_total,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            cost_usd=cost,
            raw_response=response
        )

    async def _call_ollama(self, prompt: str, system_prompt: str, temperature: float,
                          max_tokens: int) -> LLMResponse:
        """Call local Ollama instance."""
        url = f"{self.ollama_url}/api/generate"

        payload = {
            "model": self.ollama_model,
            "prompt": prompt,
            "system": system_prompt or "",
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                result = await resp.json()

        content = result.get('response', '')
        tokens_prompt = result.get('prompt_eval_count', 0)
        tokens_completion = result.get('eval_count', 0)

        return LLMResponse(
            content=content,
            provider='ollama',
            model=self.ollama_model,
            tokens_used=tokens_prompt + tokens_completion,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            cost_usd=0.0,
            raw_response=result
        )

    def _calculate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate API call cost in USD."""
        pricing = self.PRICING.get(model, {'input': 0, 'output': 0})
        input_cost = (input_tokens / 1_000_000) * pricing['input']
        output_cost = (output_tokens / 1_000_000) * pricing['output']
        return input_cost + output_cost

    def estimate_cost(self, prompt: str, expected_output_tokens: int = 1000) -> Dict[str, float]:
        """Estimate cost for a prompt across all providers."""
        # Rough token estimation: ~4 chars per token
        input_tokens = len(prompt) // 4

        estimates = {}
        for provider in self.fallback_chain:
            model = getattr(self, f'{provider}_model', 'unknown')
            pricing = self.PRICING.get(model, {'input': 0, 'output': 0})
            cost = (input_tokens / 1_000_000) * pricing['input'] + \
                   (expected_output_tokens / 1_000_000) * pricing['output']
            estimates[provider] = round(cost, 4)

        return estimates
