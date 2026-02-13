"""FastAPI demo with PromptShieldMiddleware scanning incoming requests."""

from fastapi import FastAPI
from pydantic import BaseModel

from prompt_shield.integrations.fastapi_middleware import PromptShieldMiddleware

app = FastAPI(title="prompt-shield FastAPI Demo")

# Add middleware — every POST/PUT/PATCH body is scanned automatically.
# The middleware extracts text from "body.prompt" and "body.messages.*.content"
# by default. Requests containing prompt injection are rejected with HTTP 400.
app.add_middleware(
    PromptShieldMiddleware,
    mode="block",  # "block" (reject), "monitor" (log only), or "flag"
)


class ChatRequest(BaseModel):
    prompt: str


class ChatResponse(BaseModel):
    reply: str


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Process a chat message.

    If the middleware detects an injection, this handler is never reached;
    the client receives a 400 response with scan details instead.
    """
    # In a real app you would forward request.prompt to your LLM here.
    return ChatResponse(reply=f"Echo: {request.prompt}")


@app.get("/health")
async def health():
    return {"status": "ok"}
