"""AI provider catalog and adapters.

Four wire protocols cover the supported providers:
* ``openai``    — OpenAI-compatible Chat Completions (most vendors, aggregators and self-hosted servers)
* ``azure``     — Azure OpenAI (deployment URL + api-version + ``api-key`` header)
* ``anthropic`` — Anthropic Messages API
* ``bedrock``   — Amazon Bedrock Converse (boto3; IAM task role in AWS — no stored keys)
plus token-exchange auth for ``watsonx`` (IBM IAM API key → bearer) and ``vertex`` (Google service-account
JWT → bearer) on top of OpenAI-compatible endpoints.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from exposurecatalyst.config import Settings
from exposurecatalyst.ingestion.http import SourceClient
from exposurecatalyst.security.ssrf import validate_outbound_url


class AiError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderSpec:
    kind: str
    label: str
    group: str  # commercial | cloud | aggregator | self-hosted
    protocol: str  # openai | azure | anthropic | bedrock | watsonx | vertex
    base_url: str
    hosts: tuple[str, ...]
    example_models: tuple[str, ...]
    secrets: tuple[str, ...] = ("api_key",)
    config_keys: tuple[str, ...] = ()
    self_hosted: bool = False
    notes: str = ""

    def public(self) -> dict[str, Any]:
        return asdict(self)


def _p(kind, label, group, protocol, base_url, hosts, models, **kw) -> ProviderSpec:
    return ProviderSpec(kind, label, group, protocol, base_url, tuple(hosts), tuple(models), **kw)


CATALOG: dict[str, ProviderSpec] = {
    s.kind: s
    for s in [
        # Commercial
        _p(
            "openai",
            "OpenAI",
            "commercial",
            "openai",
            "https://api.openai.com/v1",
            ["api.openai.com"],
            ["gpt-4.1", "gpt-4.1-mini"],
        ),
        _p(
            "anthropic",
            "Anthropic Claude",
            "commercial",
            "anthropic",
            "https://api.anthropic.com",
            ["api.anthropic.com"],
            ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"],
        ),
        _p(
            "gemini",
            "Google Gemini",
            "commercial",
            "openai",
            "https://generativelanguage.googleapis.com/v1beta/openai",
            ["generativelanguage.googleapis.com"],
            ["gemini-2.5-pro", "gemini-2.5-flash"],
        ),
        _p("xai", "xAI Grok", "commercial", "openai", "https://api.x.ai/v1", ["api.x.ai"], ["grok-4"]),
        _p(
            "mistral",
            "Mistral",
            "commercial",
            "openai",
            "https://api.mistral.ai/v1",
            ["api.mistral.ai"],
            ["mistral-large-latest"],
        ),
        _p(
            "cohere",
            "Cohere",
            "commercial",
            "openai",
            "https://api.cohere.ai/compatibility/v1",
            ["api.cohere.ai", "api.cohere.com"],
            ["command-a-03-2025"],
        ),
        _p(
            "deepseek",
            "DeepSeek",
            "commercial",
            "openai",
            "https://api.deepseek.com/v1",
            ["api.deepseek.com"],
            ["deepseek-chat"],
        ),
        _p(
            "qwen",
            "Alibaba Qwen (DashScope)",
            "commercial",
            "openai",
            "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            ["*.aliyuncs.com"],
            ["qwen-max", "qwen-plus"],
        ),
        _p(
            "moonshot",
            "Moonshot Kimi",
            "commercial",
            "openai",
            "https://api.moonshot.ai/v1",
            ["api.moonshot.ai", "api.moonshot.cn"],
            ["kimi-k2-0905-preview"],
        ),
        _p(
            "zhipu",
            "Zhipu GLM",
            "commercial",
            "openai",
            "https://open.bigmodel.cn/api/paas/v4",
            ["open.bigmodel.cn", "api.z.ai"],
            ["glm-4.6"],
        ),
        _p(
            "ai21",
            "AI21 Labs",
            "commercial",
            "openai",
            "https://api.ai21.com/studio/v1",
            ["api.ai21.com"],
            ["jamba-large"],
        ),
        _p(
            "perplexity",
            "Perplexity",
            "commercial",
            "openai",
            "https://api.perplexity.ai",
            ["api.perplexity.ai"],
            ["sonar-pro"],
            notes="Perplexity models search the web; prompts leave your boundary even with redaction.",
        ),
        # Cloud platforms
        _p(
            "azure_openai",
            "Azure OpenAI",
            "cloud",
            "azure",
            "https://<resource>.openai.azure.com",
            ["*.openai.azure.com"],
            ["<deployment-name>"],
            config_keys=("api_version",),
        ),
        _p(
            "bedrock",
            "Amazon Bedrock",
            "cloud",
            "bedrock",
            "https://bedrock-runtime.us-east-1.amazonaws.com",
            ["bedrock-runtime.*.amazonaws.com"],
            ["anthropic.claude-sonnet-4-5-20250929-v1:0", "amazon.nova-pro-v1:0"],
            secrets=(),
            config_keys=("region",),
            notes="Uses the ECS task role (IAM) — no keys stored. Requires `pip install exposurecatalyst[aws]`.",
        ),
        _p(
            "vertex",
            "Google Vertex AI",
            "cloud",
            "vertex",
            "https://us-central1-aiplatform.googleapis.com/v1/projects/<project>/locations/us-central1/endpoints/openapi",
            ["*-aiplatform.googleapis.com", "aiplatform.googleapis.com"],
            ["google/gemini-2.5-pro"],
            secrets=("service_account_json",),
            notes="Service-account JSON with roles/aiplatform.user.",
        ),
        _p(
            "watsonx",
            "IBM watsonx.ai",
            "cloud",
            "watsonx",
            "https://us-south.ml.cloud.ibm.com",
            ["*.ml.cloud.ibm.com"],
            ["ibm/granite-3-8b-instruct"],
            config_keys=("project_id",),
            notes="IBM Cloud API key exchanged for an IAM token.",
        ),
        _p(
            "nvidia_nim",
            "NVIDIA NIM",
            "cloud",
            "openai",
            "https://integrate.api.nvidia.com/v1",
            ["integrate.api.nvidia.com"],
            ["meta/llama-3.3-70b-instruct"],
        ),
        # Inference hosts / aggregators
        _p(
            "groq",
            "Groq",
            "aggregator",
            "openai",
            "https://api.groq.com/openai/v1",
            ["api.groq.com"],
            ["llama-3.3-70b-versatile"],
        ),
        _p(
            "together",
            "Together AI",
            "aggregator",
            "openai",
            "https://api.together.xyz/v1",
            ["api.together.xyz"],
            ["meta-llama/Llama-3.3-70B-Instruct-Turbo"],
        ),
        _p(
            "fireworks",
            "Fireworks AI",
            "aggregator",
            "openai",
            "https://api.fireworks.ai/inference/v1",
            ["api.fireworks.ai"],
            ["accounts/fireworks/models/llama-v3p3-70b-instruct"],
        ),
        _p(
            "cerebras",
            "Cerebras",
            "aggregator",
            "openai",
            "https://api.cerebras.ai/v1",
            ["api.cerebras.ai"],
            ["llama-3.3-70b"],
        ),
        _p(
            "openrouter",
            "OpenRouter",
            "aggregator",
            "openai",
            "https://openrouter.ai/api/v1",
            ["openrouter.ai"],
            ["anthropic/claude-sonnet-4.5"],
            notes="Routes to third-party providers; check OpenRouter's data policy.",
        ),
        _p(
            "huggingface",
            "Hugging Face Inference",
            "aggregator",
            "openai",
            "https://router.huggingface.co/v1",
            ["router.huggingface.co"],
            ["meta-llama/Llama-3.3-70B-Instruct"],
        ),
        # Self-hosted
        _p(
            "ollama",
            "Ollama",
            "self-hosted",
            "openai",
            "http://localhost:11434/v1",
            [],
            ["llama3.1:8b"],
            secrets=(),
            self_hosted=True,
        ),
        _p(
            "vllm",
            "vLLM",
            "self-hosted",
            "openai",
            "http://vllm.internal:8000/v1",
            [],
            ["meta-llama/Llama-3.1-8B-Instruct"],
            self_hosted=True,
        ),
        _p(
            "lmstudio",
            "LM Studio",
            "self-hosted",
            "openai",
            "http://localhost:1234/v1",
            [],
            ["local-model"],
            secrets=(),
            self_hosted=True,
        ),
        _p(
            "openai_compatible",
            "Any OpenAI-compatible endpoint",
            "self-hosted",
            "openai",
            "https://llm.example.internal/v1",
            [],
            ["<model>"],
            self_hosted=True,
        ),
    ]
}


@dataclass
class Completion:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def endpoint_allowlist(spec: ProviderSpec, base_url: str) -> list[str]:
    """Commercial/cloud providers: their own hosts only. Self-hosted: exactly the configured host."""
    return list(spec.hosts) if spec.hosts else [(urlsplit(base_url).hostname or "").lower()]


def validate_endpoint(spec: ProviderSpec, base_url: str, settings: Settings) -> str:
    schemes = ("https", "http") if spec.self_hosted else ("https",)
    validate_outbound_url(
        base_url,
        allowlist=endpoint_allowlist(spec, base_url),
        allow_private=spec.self_hosted and settings.ai_allow_private_endpoints,
        resolve_dns=settings.ssrf_resolve_dns,
        allowed_schemes=schemes,
    )
    return base_url.rstrip("/")


TRANSPORTS: dict[str, httpx.BaseTransport] = {}  # test hook, keyed by protocol


class Adapter:
    def __init__(
        self, spec: ProviderSpec, base_url: str, secrets: dict[str, str], config: dict[str, Any], settings: Settings
    ):
        self.spec, self.base_url, self.secrets, self.config, self.settings = (
            spec,
            base_url.rstrip("/"),
            secrets,
            config,
            settings,
        )
        self.client = SourceClient(
            f"ai:{spec.kind}",
            settings,
            rate=10,
            per=1.0,
            allowlist=[*endpoint_allowlist(spec, base_url), "iam.cloud.ibm.com", "oauth2.googleapis.com"],
            transport=TRANSPORTS.get(spec.protocol),
            timeout=settings.ai_timeout_seconds,
        )
        if spec.self_hosted and settings.ai_allow_private_endpoints:
            self.client.settings = settings.model_copy(update={"ssrf_allow_private_networks": True})

    def close(self) -> None:
        self.client.close()

    def _post(self, url: str, body: dict, headers: dict[str, str]) -> dict[str, Any]:
        try:
            resp = self.client.request("POST", url, json=body, headers=headers)
        except Exception as exc:
            raise AiError(f"{self.spec.label}: {type(exc).__name__}: {str(exc)[:300]}") from exc
        return resp.json()

    # ---- protocols ------------------------------------------------------------------------------
    def complete(
        self,
        system: str,
        messages: list[dict[str, str]],
        *,
        model: str,
        temperature: float,
        max_tokens: int,
        json_mode: bool = False,
    ) -> Completion:
        proto = self.spec.protocol
        if proto == "anthropic":
            return self._anthropic(system, messages, model, temperature, max_tokens)
        if proto == "bedrock":
            return self._bedrock(system, messages, model, temperature, max_tokens)
        return self._openai(system, messages, model, temperature, max_tokens, json_mode)

    def _openai(self, system, messages, model, temperature, max_tokens, json_mode) -> Completion:
        proto = self.spec.protocol
        headers: dict[str, str] = {}
        url = f"{self.base_url}/chat/completions"
        if proto == "azure":
            url = f"{self.base_url}/openai/deployments/{model}/chat/completions?api-version=" + str(
                self.config.get("api_version") or "2024-10-21"
            )
            headers["api-key"] = self.secrets.get("api_key", "")
        elif proto == "watsonx":
            url = f"{self.base_url}/ml/v1/text/chat?version=2024-10-08"
            headers["Authorization"] = f"Bearer {self._watsonx_token()}"
        elif proto == "vertex":
            headers["Authorization"] = f"Bearer {self._vertex_token()}"
        elif self.secrets.get("api_key"):
            headers["Authorization"] = f"Bearer {self.secrets['api_key']}"
        body: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "system", "content": system}, *messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if proto == "watsonx":
            body = {
                "model_id": model,
                "project_id": self.config.get("project_id"),
                "messages": body["messages"],
                "parameters": {"temperature": temperature, "max_tokens": max_tokens},
            }
        if json_mode and proto in ("openai", "azure"):
            body["response_format"] = {"type": "json_object"}
        data = self._post(url, body, headers)
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise AiError(f"{self.spec.label}: unexpected response shape") from exc
        usage = data.get("usage") or {}
        return Completion(
            text=text,
            input_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
            model=data.get("model", model),
        )

    def _anthropic(self, system, messages, model, temperature, max_tokens) -> Completion:
        data = self._post(
            f"{self.base_url}/v1/messages",
            {
                "model": model,
                "system": system,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
            {"x-api-key": self.secrets.get("api_key", ""), "anthropic-version": "2023-06-01"},
        )
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        usage = data.get("usage") or {}
        return Completion(
            text=text,
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            model=data.get("model", model),
        )

    def _bedrock(self, system, messages, model, temperature, max_tokens) -> Completion:
        try:
            import boto3  # optional dependency: exposurecatalyst[aws]
        except ImportError as exc:
            raise AiError("Amazon Bedrock requires boto3 (pip install 'exposurecatalyst[aws]')") from exc
        region = self.config.get("region") or "us-east-1"
        client = boto3.client("bedrock-runtime", region_name=region)
        try:
            resp = client.converse(
                modelId=model,
                system=[{"text": system}],
                messages=[{"role": m["role"], "content": [{"text": m["content"]}]} for m in messages],
                inferenceConfig={"temperature": temperature, "maxTokens": max_tokens},
            )
        except Exception as exc:
            raise AiError(f"Bedrock: {type(exc).__name__}: {str(exc)[:300]}") from exc
        text = "".join(c.get("text", "") for c in resp["output"]["message"]["content"])
        usage = resp.get("usage") or {}
        return Completion(
            text=text,
            input_tokens=int(usage.get("inputTokens", 0)),
            output_tokens=int(usage.get("outputTokens", 0)),
            model=model,
        )

    # ---- token exchanges --------------------------------------------------------------------------
    _cache: dict[str, tuple[str, float]] = {}

    def _watsonx_token(self) -> str:
        key = "watsonx:" + self.secrets.get("api_key", "")[-6:]
        tok = self._cache.get(key)
        if tok and tok[1] > time.time() + 60:
            return tok[0]
        resp = self.client.request(
            "POST",
            "https://iam.cloud.ibm.com/identity/token",
            data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": self.secrets.get("api_key", "")},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        body = resp.json()
        self._cache[key] = (body["access_token"], time.time() + int(body.get("expires_in", 3600)))
        return body["access_token"]

    def _vertex_token(self) -> str:
        import base64

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        try:
            sa = json.loads(self.secrets.get("service_account_json", ""))
            email, pem = sa["client_email"], sa["private_key"]
        except (ValueError, KeyError) as exc:
            raise AiError("Vertex AI: invalid service account JSON") from exc
        key = "vertex:" + email
        tok = self._cache.get(key)
        if tok and tok[1] > time.time() + 60:
            return tok[0]

        def b64(d: bytes) -> str:
            return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

        now = int(time.time())
        header = b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        claims = b64(
            json.dumps(
                {
                    "iss": email,
                    "scope": "https://www.googleapis.com/auth/cloud-platform",
                    "aud": "https://oauth2.googleapis.com/token",
                    "iat": now,
                    "exp": now + 3600,
                }
            ).encode()
        )
        pk = serialization.load_pem_private_key(pem.encode(), password=None)
        sig = pk.sign(f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())  # type: ignore[call-arg]
        resp = self.client.request(
            "POST",
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": f"{header}.{claims}.{b64(sig)}",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        body = resp.json()
        self._cache[key] = (body["access_token"], time.time() + int(body.get("expires_in", 3600)))
        return body["access_token"]
