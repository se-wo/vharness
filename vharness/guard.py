"""Path guard for agent tool calls (R-SAFE-01..03, R-SAFE-09).

Every tool call is checked before it runs. Only Read, Grep and Glob are allowed,
and every path argument must resolve (after symlinks) inside the target root.
"""

import os

ALLOWED_TOOLS = ("Read", "Grep", "Glob")
# Harness-internal tools with no file system access (the SDK's structured-output channel).
INTERNAL_TOOLS = ("StructuredOutput",)
# Built-in tools that must never be available to an agent.
DENIED_TOOLS = (
    "Bash", "BashOutput", "KillShell", "Write", "Edit", "MultiEdit", "NotebookEdit",
    "WebFetch", "WebSearch", "Task", "Agent", "TodoWrite", "Skill", "SlashCommand",
    "ExitPlanMode", "EnterPlanMode", "Monitor", "ToolSearch",
)
PATH_KEYS = ("file_path", "path", "notebook_path")


def _inside(path, root):
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def resolve_inside(candidate, root):
    """Return the real path of `candidate` if it is inside `root`, else None."""
    real_root = os.path.realpath(root)
    joined = candidate if os.path.isabs(candidate) else os.path.join(real_root, candidate)
    real = os.path.realpath(joined)
    return real if _inside(real, real_root) else None


def check_tool_call(tool_name, tool_input, root, extra_tools=()):
    """Return (allowed, reason) for one tool call.

    `extra_tools` are harness tools (such as the sandbox) that validate their own input.
    """
    if tool_name in INTERNAL_TOOLS or tool_name in extra_tools:
        return True, ""
    if tool_name not in ALLOWED_TOOLS:
        return False, f"tool {tool_name!r} is not allowed; only {', '.join(ALLOWED_TOOLS)} are available"
    tool_input = tool_input or {}
    for key in PATH_KEYS:
        value = tool_input.get(key)
        if value in (None, ""):
            continue
        if not isinstance(value, str) or resolve_inside(value, root) is None:
            return False, f"path {value!r} is outside the target root"
    if tool_name in ("Glob", "Grep"):
        for key in ("pattern", "glob"):
            value = tool_input.get(key)
            if tool_name == "Grep" and key == "pattern":
                continue  # a regex, not a path
            if isinstance(value, str) and (os.path.isabs(value) or value.startswith("~") or ".." in value.split("/")):
                return False, f"{key} {value!r} may escape the target root"
    return True, ""


def make_pre_tool_hook(root, extra_tools=()):
    """Build an Agent SDK PreToolUse hook that enforces check_tool_call."""

    async def hook(input_data, tool_use_id, context):
        allowed, reason = check_tool_call(input_data.get("tool_name"), input_data.get("tool_input"), root, extra_tools)
        if allowed:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"vharness path guard: {reason}",
            }
        }

    return hook
