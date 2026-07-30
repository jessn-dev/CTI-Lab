#!/usr/bin/env python3
"""
Build-time patch for shelLM's Ollama client.

llama3.2:3b (via Ollama /api/chat) occasionally prepends a literal "assistant"
role-label line to its content. shelLM's own output cleaning is commented out
upstream, so that label leaks straight to the attacker's terminal (visible as a
stray "assistant" line before each response). We strip a *leading* "assistant"
label at the one chokepoint every model response flows through — the client's
return value — being careful to never strip "user" (that can be legit output,
e.g. the answer to `whoami`).

Idempotent + pinned: runs against a fixed upstream commit (see Dockerfile).
"""
import sys

PATH = "/opt/shelLM/shelLMv2/LLM_Plugins/api_clients/ollama_client.py"

HELPER = '''

def _strip_role_prefix(text):
    """Drop a single leading 'assistant' role label some models echo. Only at the
    very start, and only when followed by whitespace/EOL, so real output that
    merely starts with the word is left alone. Never strips 'user'."""
    t = text.lstrip()
    if t[:9].lower() == "assistant" and (len(t) == 9 or t[9] in " \\t\\r\\n"):
        t = t[9:].lstrip(" \\t\\r\\n")
    return t

'''

TARGET = 'content = (msg.get("content") or "").strip()'
REPLACEMENT = 'content = _strip_role_prefix((msg.get("content") or "").strip())'


def main():
    with open(PATH, "r", encoding="utf-8") as f:
        src = f.read()

    if "_strip_role_prefix" in src:
        print("[patch] already applied; skipping.")
        return

    if TARGET not in src:
        print(f"[patch] ERROR: anchor not found in {PATH} (upstream changed?).",
              file=sys.stderr)
        sys.exit(1)

    # Insert the helper just before the class definition.
    src = src.replace("\nclass OllamaClient", HELPER + "\nclass OllamaClient", 1)
    # Wrap the returned content so the leading label is stripped.
    src = src.replace(TARGET, REPLACEMENT, 1)

    with open(PATH, "w", encoding="utf-8") as f:
        f.write(src)
    print("[patch] stripped leading 'assistant' role label in ollama_client.py")


if __name__ == "__main__":
    main()
