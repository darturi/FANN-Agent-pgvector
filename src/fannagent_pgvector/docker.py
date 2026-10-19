import re
import subprocess

from fannagent.api import AgentError


def docker(*args, input_text=None, sensitive=False, postgres_errors=False, timeout_seconds=None):
    try:
        process = subprocess.run(
            ["docker", *map(str, args)], input=input_text, capture_output=True, text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        # Never expose command parameters, stdin, or partial private output.
        action = str(args[0]) if args else "command"
        message = ("private PostgreSQL bootstrap timed out; clean this run and prepare anew"
                   if sensitive else f"Docker {action} timed out after {timeout_seconds:g} seconds")
        raise AgentError(message) from None
    # Single-user PostgreSQL can report SQL errors yet exit successfully.
    failed = process.returncode or (
        postgres_errors and re.search(r"\b(?:ERROR|FATAL|PANIC):", process.stdout + process.stderr)
    )
    if failed:
        if sensitive:
            raise AgentError("private PostgreSQL bootstrap failed; clean this run and prepare anew")
        raise AgentError("Docker operation failed: " + process.stderr[-2000:])
    if sensitive:
        return ""
    return process.stdout.strip()
