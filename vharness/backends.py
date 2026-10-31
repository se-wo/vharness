"""Model backends (SPEC 9.1, R-MOD-05). A backend runs one agent and returns one result.

The Claude backend uses the Claude Agent SDK with:
  - only Read/Grep/Glob, guarded by a PreToolUse hook (R-SAFE-01..03);
  - no settings, hooks, plugins, skills or MCP servers from disk (R-SAFE-04);
  - structured output enforced by a JSON schema (R-AGT-02).
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field

from . import schemas
from .guard import ALLOWED_TOOLS, DENIED_TOOLS, make_pre_tool_hook

# Usage-limit and rate-limit refusals (R-RL-01). Checked before the generic API error text.
RATE_LIMIT_RE = re.compile(
    r"(usage limit|limit reached|hit your limit|rate_limit_error|rate limit|rate-limit|too many requests|"
    r"\b429\b|out of extra usage|weekly limit|5-hour limit)",
    re.IGNORECASE,
)
RESET_EPOCH_RE = re.compile(r"\|(\d{10})\b")  # "Claude AI usage limit reached|1793400000"

# Text that signals a provider/API failure even inside a "successful" stream (R-AGT-08).
API_ERROR_RE = re.compile(
    r"(API Error|api_error|overloaded_error|Overloaded|"
    r"Internal server error|internal_server_error|Request timed out|ECONNRESET|socket hang up|"
    r"\b5\d\d\b.{0,40}(error|status)|Credit balance is too low|authentication_error)",
    re.IGNORECASE,
)


@dataclass
class HarnessTool:
    """A backend-neutral tool that the harness implements (for example `sandbox_run`)."""
    name: str
    description: str
    input_schema: dict
    handler: object  # async (dict) -> dict (JSON-serializable result)


@dataclass
class AgentRequest:
    agent_id: str
    role: str
    model: str
    system: str
    prompt: str
    schema: dict
    cwd: str
    max_turns: int = 60
    timeout_s: int = 1800
    effort: str | None = None
    tools: list = field(default_factory=list)  # HarnessTool


@dataclass
class AgentResult:
    ok: bool
    output: dict | None = None
    error: str | None = None
    error_kind: str | None = None  # backend | api_text | malformed | timeout | rate_limit
    turns: int = 0
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    duration_ms: int = 0
    raw_text: str = ""
    denials: list = field(default_factory=list)
    resets_at: float | None = None  # unix time when a rate limit resets, if known

    @property
    def retryable(self):
        return self.error_kind in ("backend", "api_text", "timeout")


def rate_limited(text, errors=None, http_status=None, event_resets_at=None, event_rejected=False):
    """R-RL-01: return (True, resets_at) when a failure is a usage-limit or rate-limit refusal."""
    blob = " ".join([text or ""] + [str(e) for e in (errors or [])])
    if not (event_rejected or http_status == 429 or RATE_LIMIT_RE.search(blob)):
        return False, None
    resets_at = event_resets_at
    if resets_at is None and (m := RESET_EPOCH_RE.search(blob)):
        resets_at = float(m.group(1))
    return True, resets_at


def classify(output, result_text, is_error, subtype, errors, schema):
    """Turn raw backend output into (ok, error_kind, error). Shared by all backends."""
    if is_error:
        return False, "backend", f"backend reported error ({subtype}): {'; '.join(errors or [])[:500]}"
    if output is None:
        if result_text and API_ERROR_RE.search(result_text):
            return False, "api_text", f"API error text in result: {result_text[:300]}"
        if subtype and subtype != "success":
            return False, "backend", f"agent ended with {subtype}"
        return False, "malformed", "agent returned no structured output"
    if not isinstance(output, dict):
        return False, "malformed", "structured output is not a JSON object"
    problems = schemas.validate(output, schema)
    if problems:
        return False, "malformed", "schema: " + " | ".join(problems[:10])
    return True, None, None


class ClaudeBackend:
    name = "claude"

    def __init__(self, cli_path=None):
        self.cli_path = cli_path

    async def run(self, req: AgentRequest) -> AgentResult:
        from claude_agent_sdk import (ClaudeAgentOptions, HookMatcher, RateLimitEvent, ResultMessage, create_sdk_mcp_server,
                                      query, tool)

        mcp_servers, extra = {}, []
        if req.tools:
            sdk_tools = []
            for t in req.tools:
                def wrap(t=t):
                    async def run_tool(args):
                        try:
                            result = await t.handler(args)
                            return {"content": [{"type": "text", "text": json.dumps(result, indent=1)}]}
                        except Exception as exc:  # report to the agent, never crash the session
                            return {"content": [{"type": "text", "text": f"error: {exc}"}], "is_error": True}
                    return tool(t.name, t.description, t.input_schema)(run_tool)
                sdk_tools.append(wrap())
                extra.append(f"mcp__vharness__{t.name}")
            mcp_servers["vharness"] = create_sdk_mcp_server("vharness", tools=sdk_tools)

        options = ClaudeAgentOptions(
            tools=list(ALLOWED_TOOLS),
            allowed_tools=list(ALLOWED_TOOLS) + extra,
            disallowed_tools=list(DENIED_TOOLS),
            permission_mode="dontAsk",
            setting_sources=[],
            strict_mcp_config=True,
            mcp_servers=mcp_servers,
            plugins=[],
            cwd=req.cwd,
            model=req.model,
            system_prompt=req.system,
            max_turns=req.max_turns,
            output_format={"type": "json_schema", "schema": req.schema},
            hooks={"PreToolUse": [HookMatcher(matcher=None, hooks=[make_pre_tool_hook(req.cwd, tuple(extra))])]},
            cli_path=self.cli_path,
        )
        if req.effort:
            options.effort = req.effort

        start = time.monotonic()
        final = None
        texts = []
        limit = {"rejected": False, "resets_at": None}

        async def prompt_stream():
            # Streaming input mode is required for SDK hooks.
            yield {"type": "user", "message": {"role": "user", "content": req.prompt}}

        async def consume():
            nonlocal final
            async for message in query(prompt=prompt_stream(), options=options):
                if isinstance(message, ResultMessage):
                    final = message
                    continue  # drain the stream; breaking early leaves the SDK generator open
                if isinstance(message, RateLimitEvent):
                    info = message.rate_limit_info
                    if info.status == "rejected":
                        limit["rejected"] = True
                        limit["resets_at"] = info.resets_at or info.overage_resets_at
                    continue
                for block in getattr(message, "content", None) or []:
                    text = getattr(block, "text", None)
                    if isinstance(text, str):
                        texts.append(text)

        try:
            await asyncio.wait_for(consume(), timeout=req.timeout_s)
        except asyncio.TimeoutError:
            return AgentResult(False, error=f"timeout after {req.timeout_s}s", error_kind="timeout",
                               duration_ms=int((time.monotonic() - start) * 1000))
        except Exception as exc:  # CLI/process/transport failure
            text = f"{type(exc).__name__}: {exc}"
            hit, resets_at = rate_limited(text, event_resets_at=limit["resets_at"], event_rejected=limit["rejected"])
            return AgentResult(False, error=text[:1000], error_kind="rate_limit" if hit else "backend", resets_at=resets_at,
                               duration_ms=int((time.monotonic() - start) * 1000))

        duration = int((time.monotonic() - start) * 1000)
        if final is None:
            hit, resets_at = rate_limited("\n".join(texts[-3:]), event_resets_at=limit["resets_at"], event_rejected=limit["rejected"])
            return AgentResult(False, error="no result message", error_kind="rate_limit" if hit else "backend",
                               resets_at=resets_at, duration_ms=duration)
        usage = final.usage or {}
        result_text = final.result or "\n".join(texts[-3:])
        output = final.structured_output
        if isinstance(output, str):
            try:
                output = json.loads(output)
            except ValueError:
                output = None
        ok, kind, err = classify(output, result_text, final.is_error, final.subtype, final.errors, req.schema)
        resets_at = None
        if not ok:
            hit, resets_at = rate_limited(result_text, final.errors, getattr(final, "api_error_status", None),
                                          limit["resets_at"], limit["rejected"])
            if hit:
                kind, err = "rate_limit", f"rate limit: {(result_text or '; '.join(final.errors or []))[:300]}"
        return AgentResult(
            ok, output=output if ok else None, error=err, error_kind=kind,
            turns=final.num_turns or 0, cost_usd=final.total_cost_usd or 0.0,
            input_tokens=(usage.get("input_tokens") or 0) + (usage.get("cache_read_input_tokens") or 0)
            + (usage.get("cache_creation_input_tokens") or 0),
            output_tokens=usage.get("output_tokens") or 0,
            duration_ms=duration, raw_text=result_text or "",
            denials=list(final.permission_denials or []), resets_at=resets_at,
        )


class ScriptedBackend:
    """Deterministic backend for tests (SPEC 12.1).

    `responder(req)` returns a dict (the structured output), a string (raw
    result text with no structured output), an AgentResult, or raises.
    """

    name = "scripted"

    def __init__(self, responder, turns=10):
        self.responder = responder
        self.turns = turns
        self.requests = []

    async def run(self, req):
        self.requests.append(req)
        await asyncio.sleep(0)
        try:
            out = self.responder(req)
            if asyncio.iscoroutine(out):
                out = await out
        except Exception as exc:
            return AgentResult(False, error=str(exc), error_kind="backend")
        if isinstance(out, AgentResult):
            return out
        if isinstance(out, str):
            ok, kind, err = classify(None, out, False, "success", None, req.schema)
            hit, resets_at = rate_limited(out)
            if hit:
                return AgentResult(False, error=f"rate limit: {out[:300]}", error_kind="rate_limit", turns=1, raw_text=out,
                                   resets_at=resets_at)
            return AgentResult(ok, error=err, error_kind=kind, turns=1, raw_text=out)
        turns = out.pop("__turns__", self.turns) if isinstance(out, dict) else self.turns
        ok, kind, err = classify(out, "", False, "success", None, req.schema)
        return AgentResult(ok, output=out if ok else None, error=err, error_kind=kind, turns=turns, cost_usd=0.01,
                           input_tokens=len(req.prompt) // 4, output_tokens=200)


def make_backend(name):
    if name == "claude":
        return ClaudeBackend()
    raise ValueError(f"unknown backend {name!r}")
