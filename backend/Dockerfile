# Gradril Backend — Guardrails AI Server
# Multi-stage build for smaller image

FROM python:3.11-slim AS base

WORKDIR /app

# Install system dependencies for ML models
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Guardrails AI with API server support
RUN pip install --no-cache-dir "guardrails-ai[api]>=0.5.0" certifi pip-system-certs

# Set SSL certs for Python/httpx/HuggingFace model downloads
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV HF_HUB_DISABLE_TELEMETRY=1

# Configure Guardrails Hub token (required to download validators)
ARG GUARDRAILS_TOKEN
RUN printf 'n\nn\n' | guardrails configure --token "${GUARDRAILS_TOKEN}"

# Install Hub validators (each separate for better caching)
# || true allows build to continue if post-install model download fails (models download lazily at runtime)
RUN guardrails hub install hub://guardrails/detect_pii || true
RUN guardrails hub install hub://guardrails/toxic_language || true
RUN guardrails hub install hub://guardrails/detect_jailbreak || true
RUN guardrails hub install hub://guardrails/secrets_present || true
RUN guardrails hub install hub://guardrails/unusual_prompt || true
RUN guardrails hub install hub://groundedai/grounded_ai_hallucination || true
RUN guardrails hub install hub://guardrails/bias_check || true

# Copy guard config + startup wrapper (spec-driven workflow)
COPY config.py .
COPY start.py .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start server (spec-driven: guards defined in config.py, start.py binds to 0.0.0.0)
CMD ["python", "start.py"]
