# Gradril — Server Startup Wrapper (Spec-Driven)
#
# Wraps guardrails_api.app.create_app to bind to 0.0.0.0
# (guardrails start CLI hardcodes 127.0.0.1 via uvicorn.run defaults)
#
# Guards are defined in config.py (spec-driven workflow).
# This file only handles startup — no guard logic here.

import uvicorn
from guardrails_api.app import create_app

# Create app from config.py spec (same as `guardrails start --config config.py`)
app = create_app(env="", config="config.py", port=8000)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
