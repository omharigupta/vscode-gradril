# Gradril — Guardrails AI Backend Setup

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

## Quick Start

```bash
# 1. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# 2. Install Guardrails AI with API server support
pip install "guardrails-ai[api]"

# 3. Configure your API key
#    Get a free key from https://guardrailsai.com/hub/keys
guardrails configure

# 4. Install Hub validators
guardrails hub install hub://guardrails/detect_pii
guardrails hub install hub://guardrails/toxic_language
guardrails hub install hub://guardrails/detect_jailbreak
guardrails hub install hub://guardrails/secrets_present
guardrails hub install hub://guardrails/unusual_prompt

# 5. Start the server
guardrails start --config config.py

# 6. Verify the server is running
#    Open http://localhost:8000/docs in your browser
```

## Server Details

- **Default URL**: `http://localhost:8000`
- **API Docs**: `http://localhost:8000/docs` (Swagger UI)
- **Health Check**: `GET http://localhost:8000/health`
- **Validate Endpoint**: `POST /guards/gradril_input_guard/validate`

## Guard Configuration

The `config.py` file defines a single input guard (`gradril_input_guard`) with:

| Validator | Hub ID | On Failure | Purpose |
|---|---|---|---|
| DetectPII | `guardrails/detect_pii` | `fix` (auto-redact) | ML-based PII detection via Microsoft Presidio |
| ToxicLanguage | `guardrails/toxic_language` | `exception` (block) | ML toxicity classification |
| DetectJailbreak | `guardrails/detect_jailbreak` | `exception` (block) | ML jailbreak pattern recognition |
| SecretsPresent | `guardrails/secrets_present` | `fix` (auto-redact) | Rule + ML secret detection |
| UnusualPrompt | `guardrails/unusual_prompt` | `noop` (log only) | LLM-based trickery detection |

## VS Code Extension Integration

The Gradril extension connects to this server via:
- Setting: `gradril.backendUrl` (default: `http://localhost:8000`)
- Setting: `gradril.backendEnabled` (default: `true`)
- Setting: `gradril.backendTimeout` (default: `2000` ms)

If the backend is unreachable, the extension falls back to local-only validation.

## Troubleshooting

### Server won't start
- Ensure Python 3.9+ is installed: `python --version`
- Ensure all hub validators are installed (step 4)
- Check for port conflicts: `netstat -an | grep 8000`

### Validators not loading
- Re-run `guardrails configure` with a valid API key
- Re-install hub validators: `guardrails hub install hub://guardrails/<name>`

### Slow responses
- First request may be slow due to model loading
- Consider running with more workers for production:
  ```bash
  gunicorn --bind 0.0.0.0:8000 --timeout=90 --workers=4 \
    'guardrails_api.app:create_app(None, "config.py")'
  ```
