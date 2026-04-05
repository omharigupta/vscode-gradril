# Gradril — FastAPI Backend Server (Guardrails with Pydantic)
#
# Custom FastAPI server using Guardrails AI validators with Pydantic models.
# Replaces `guardrails start` CLI with full control over endpoints & behavior.
#
# Endpoints:
#   GET  /health                            → Health check
#   POST /guards/{guard_name}/validate      → Validate prompt or LLM output
#   POST /semantic-check                    → Semantic injection detection (ML)
#   GET  /docs                              → Swagger UI (auto-generated)
#
# Run:
#   uvicorn server:app --host 0.0.0.0 --port 8000

import uuid
import traceback
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ─── Import Guards from config ───────────────────────────────────────────────

from config import gradril_input_guard, gradril_output_guard


# ─── Pydantic Models ────────────────────────────────────────────────────────

class ValidateRequest(BaseModel):
    """Request body for POST /guards/{guard_name}/validate"""
    llmOutput: Optional[str] = Field(None, description="Text to validate")
    numReasks: int = Field(0, description="Number of reask attempts (0 = none)")
    metadata: Optional[dict] = Field(None, description="Extra metadata for validators")


class ValidationOutcome(BaseModel):
    """Response from POST /guards/{guard_name}/validate"""
    callId: str = Field(..., description="Unique call identifier")
    rawLlmOutput: Optional[str] = Field(None, description="Original input text")
    validatedOutput: Optional[str] = Field(None, description="Sanitized/validated output")
    validationPassed: bool = Field(..., description="Whether all validations passed")
    error: Optional[str] = Field(None, description="Error message if validation failed")


class HealthResponse(BaseModel):
    """Response from GET /health"""
    status: str = "healthy"
    guards: list[str] = []


# ─── Semantic Detection Models ──────────────────────────────────────────────

class SemanticCheckRequest(BaseModel):
    """Request body for POST /semantic-check"""
    text: str = Field(..., description="Text to check for injection")
    threshold: Optional[float] = Field(0.72, description="Similarity threshold (0-1)")


class SemanticMatch(BaseModel):
    """A matched injection prototype"""
    prototype: str
    category: str
    similarity: float


class SemanticCheckResponse(BaseModel):
    """Response from POST /semantic-check"""
    is_injection: bool = Field(..., description="Whether injection was detected")
    confidence: float = Field(..., description="Detection confidence (0-1)")
    top_matches: List[SemanticMatch] = Field(default_factory=list)
    normalized_input: str = Field(..., description="Preprocessed input text")


# ─── Guard Registry ─────────────────────────────────────────────────────────

GUARDS = {
    "gradril_input_guard": gradril_input_guard,
    "gradril_output_guard": gradril_output_guard,
}


# ─── App Setup ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    print(f"Gradril backend starting — {len(GUARDS)} guards loaded")
    for name in GUARDS:
        print(f"  ✓ {name}")
    yield
    print("Gradril backend shutting down")


app = FastAPI(
    title="Gradril Backend",
    description="Guardrails AI validation server for the Gradril VS Code extension",
    version="1.0.0",
    lifespan=lifespan,
)


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        guards=list(GUARDS.keys()),
    )


# ─── Semantic Detection Endpoint ────────────────────────────────────────────

@app.post("/semantic-check", response_model=SemanticCheckResponse)
async def semantic_check(request: SemanticCheckRequest):
    """
    Check text for prompt injection using semantic similarity.
    
    This endpoint uses ML-based detection with sentence embeddings to catch
    paraphrased injections that regex patterns might miss. It compares the
    input against known injection prototypes using cosine similarity.
    
    - Returns is_injection=True if similarity exceeds threshold
    - confidence indicates how certain the detection is (0-1)
    - top_matches shows the most similar injection prototypes
    """
    try:
        from semantic_detector import SemanticDetector
        
        detector = SemanticDetector(threshold=request.threshold)
        result = detector.detect(request.text)
        
        return SemanticCheckResponse(
            is_injection=result.is_injection,
            confidence=result.confidence,
            top_matches=[
                SemanticMatch(
                    prototype=m.prototype,
                    category=m.category,
                    similarity=m.similarity,
                )
                for m in result.top_matches
            ],
            normalized_input=result.normalized_input,
        )
        
    except ImportError as e:
        # sentence-transformers not installed
        raise HTTPException(
            status_code=503,
            detail=f"Semantic detection unavailable: {str(e)}. "
                   f"Install with: pip install sentence-transformers",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Semantic check error: {str(e)}",
        )


@app.post("/guards/{guard_name}/validate", response_model=ValidationOutcome)
async def validate(guard_name: str, request: ValidateRequest):
    """
    Validate text against a named guard.

    - **gradril_input_guard**: Validates user prompts (PII, toxicity, jailbreak, secrets)
    - **gradril_output_guard**: Validates LLM responses (hallucination, bias, toxicity, PII)
    """
    guard = GUARDS.get(guard_name)
    if not guard:
        raise HTTPException(
            status_code=404,
            detail=f"Guard '{guard_name}' not found. Available: {list(GUARDS.keys())}",
        )

    call_id = str(uuid.uuid4())
    text = request.llmOutput or ""

    try:
        # Run Guardrails validation with Pydantic
        result = guard.validate(text)

        # Extract the outcome
        validated_output = None
        validation_passed = True

        if hasattr(result, "validated_output"):
            validated_output = result.validated_output
        if hasattr(result, "validation_passed"):
            validation_passed = result.validation_passed

        # If validated_output is the same Pydantic/dict structure, convert to string
        if validated_output is not None and not isinstance(validated_output, str):
            validated_output = str(validated_output)

        return ValidationOutcome(
            callId=call_id,
            rawLlmOutput=text,
            validatedOutput=validated_output,
            validationPassed=validation_passed,
        )

    except Exception as e:
        # Validation raised an exception (e.g., toxic content detected)
        # Return as a structured error — NOT an HTTP error
        error_msg = str(e)
        tb = traceback.format_exc()
        print(f"Validation error for guard '{guard_name}': {error_msg}\n{tb}")

        return ValidationOutcome(
            callId=call_id,
            rawLlmOutput=text,
            validatedOutput=None,
            validationPassed=False,
            error=error_msg,
        )
