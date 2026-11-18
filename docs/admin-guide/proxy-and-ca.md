# Corporate proxy and custom CA

## Outbound proxy

```yaml
# config/exposurecatalyst.yaml (applied by ./run.sh)
outbound_proxy: "http://proxy.corp.example:3128"
```

or in `.env`: `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` (defaults keep internal services direct:
`localhost,127.0.0.1,postgres,redis,api,proxy,ollama`). The API, scheduler and worker containers use it for CVE
sources, integrations, AI providers and subscriptions. The application's egress allowlist and SSRF checks
still apply to every destination.

## Trusted CA bundle (TLS inspection, internal PKI)

Upload your internal root/issuing CAs (or the TLS-inspection proxy's CA) in **Settings → Certificates &
Domain → Trusted CA bundle**. While a bundle exists, outbound connections trust it in addition to the public
roots (the app exports a combined bundle as `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`, honoured by its HTTP
clients, AI SDKs and SMTP); remove it to return to the public roots only. Without the UI flag, mount a PEM file
and set `EXCAT_CA_BUNDLE=/path/in/container.pem`.

Image builds behind a proxy or mirror: set `EXCAT_DOCKERHUB_MIRROR` (e.g. a pull-through cache); images stay
pinned by digest.
