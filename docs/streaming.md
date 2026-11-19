# Streaming coverage

`prompt_shield>=0.10.0` guards streamed, async, and Responses-API /
`messages.stream` responses on both `PromptShieldOpenAI` and
`PromptShieldAnthropic`. Mode semantics and scan-engine coverage are defined
in the `StreamGuard` module docstring
(`src/prompt_shield/streaming/stream_guard.py`) and the wrapper docstrings; this page covers call
shapes and operational gotchas. Do not rely on this page for authoritative
semantics — the docstring is the source of truth.

## OpenAI

### Sync stream

Streaming guards apply when `scan_responses=True`.

```python
from openai import OpenAI
from prompt_shield.integrations.openai_wrapper import PromptShieldOpenAI
from prompt_shield.streaming import PromptShieldStreamBlocked

shield = PromptShieldOpenAI(client=OpenAI(), mode="block", scan_responses=True)

try:
    stream = shield.create(
        model="YOUR_MODEL_ID",
        messages=[{"role": "user", "content": "Tell me a short story."}],
        stream=True,
    )
    for chunk in stream:
        print(chunk.choices[0].delta.content or "", end="")
except PromptShieldStreamBlocked as exc:
    # Raised on the first finding. Chunks already printed were released
    # before the finding and cannot be recalled.
    print("\nstream stopped:", exc)
```

### Async stream

```python
from openai import AsyncOpenAI
from prompt_shield.integrations.openai_wrapper import PromptShieldOpenAI

shield = PromptShieldOpenAI(client=AsyncOpenAI(), mode="flag", scan_responses=True)

async def main() -> None:
    stream = await shield.acreate(
        model="YOUR_MODEL_ID",
        messages=[{"role": "user", "content": "Tell me a short story."}],
        stream=True,
    )
    async for chunk in stream:
        print(chunk.choices[0].delta.content or "", end="")
```

### Responses API

```python
# Buffered
response = shield.responses.create(model="YOUR_MODEL_ID", input="Hello")

# Streamed
for event in shield.responses.create(model="YOUR_MODEL_ID", input="Hello", stream=True):
    ...  # guarded Responses-API events
```

The async variants are `await shield.responses.acreate(...)` (buffered) and
`await shield.responses.acreate(..., stream=True)` with `async for`.

## Anthropic

### Sync stream

```python
from anthropic import Anthropic
from prompt_shield.integrations.anthropic_wrapper import PromptShieldAnthropic

shield = PromptShieldAnthropic(client=Anthropic(), mode="block", scan_responses=True)

for event in shield.create(
    model="YOUR_MODEL_ID",
    max_tokens=512,
    messages=[{"role": "user", "content": "Hello"}],
    stream=True,
):
    ...  # raw stream events, same shape as the SDK, guarded
```

### Async stream

```python
from anthropic import AsyncAnthropic
from prompt_shield.integrations.anthropic_wrapper import PromptShieldAnthropic

shield = PromptShieldAnthropic(client=AsyncAnthropic(), mode="block", scan_responses=True)

async def main() -> None:
    stream = await shield.acreate(
        model="YOUR_MODEL_ID",
        max_tokens=512,
        messages=[{"role": "user", "content": "Hello"}],
        stream=True,
    )
    async for event in stream:
        ...
```

### `messages.stream` context manager

```python
with shield.stream_messages(
    model="YOUR_MODEL_ID",
    max_tokens=512,
    messages=[{"role": "user", "content": "Hello"}],
) as s:
    for text in s.text_stream:
        print(text, end="")
    final = s.get_final_message()  # also guarded
```

The async equivalent is `async with shield.astream_messages(...) as s:` with
`async for text in s.text_stream`.

## Configuration

Both wrappers accept these kwargs (forwarded to `StreamGuard`):

- `stream_scanners` — override the stream-safe default scanner set.
  By default, `sentiment`, `relevance`, `hallucination`, and
  `schema_validation` are excluded because they are not meaningful on
  sub-complete fragments.
- `stream_canary_tokens` — list of canary tokens routed through
  `LeakDetector` on the hold-back window.
- `stream_hold_back` — buffered-tail length in characters.
- `stream_overlap` — re-scan overlap in characters.

Defaults live in `StreamGuard.__init__`; see its docstring for ranges
and the rationale behind each default.

## Gotchas

- **Released text cannot be recalled.** `block` stops **future** chunks on
  the first finding. Anything already yielded by `feed()` has been seen
  by the caller. If you need a retract-all contract, buffer until
  `finish()` and gate emission on `StreamReport.findings`.
- **Two engines, two detector sets.** Stream **text** scanning runs through
  `StreamGuard`'s own `OutputScanEngine` with the stream-safe default
  scanner set (configurable via `stream_scanners=`). Streamed **tool-call
  arguments** flow through the wrapper's existing engine with the full
  input detector set, so `d034` honeypot-tool detection and the rest of
  the input taxonomy still apply. This split is documented in the
  wrapper docstrings (*Scan engine coverage* in `PromptShieldAnthropic`,
  *Stream scan coverage* in the OpenAI wrapper).
- **Positionless dedup under coarse chunking (`flag` / `log`).** Two
  identical positionless findings of the same scanner in the same
  hold-back window collapse to one finding. `block` mode is unaffected.
  Pinned by test; refinement queued for a follow-up release.
- **`d022` residual FPs on plain-JSON tool-call arguments.** Roughly two
  in five benign JSON tool calls flag on `d022` in `block` mode. This
  is pre-existing semantic-classifier behaviour, not introduced by
  streaming. Switch to `flag` / `log` or disable `d022` on the engine
  if noisy on your traffic.
- **`sanitize` mode is not supported on streams.** There is no
  stream-time sanitizer because released text cannot be recalled; one
  would misrepresent what the caller has already seen. Both wrappers
  raise `ValueError` at stream entry when `mode="sanitize"` is
  combined with `stream=True` (chat, async, Responses on OpenAI;
  stream, async, `stream_messages` on Anthropic). Use `block`,
  `flag`, or `log` for streams.

See the `StreamGuard` module docstring for the technical details of the
hold-back window, scan sequencing, and the enforcement state machine.
