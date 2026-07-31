#!/usr/bin/env python3
"""
Phase A - AI Threat Analyst (offline SOAR).

Reads the Wazuh detections produced by the lab (SSH brute force, FIM drops,
Active Response bans), hands them to an LLM, and writes a structured
MITRE ATT&CK threat report. Runs offline on logs - it is NOT in the attack
path, so there is no latency or prompt-injection risk.

Provider is pluggable via LLM_PROVIDER (gemini | ollama | claude | groq). The
analysis prompt and event extraction are provider-agnostic; only the transport
differs, so each backend is a single function. gemini = free tier; ollama =
local/offline/private (PII guardrail optional); claude = highest quality;
groq = free tier, very fast (OpenAI-compatible, open models).

Input (first that works):
  --input <file>                     explicit alerts.json (newline-delimited)
  else: docker exec wazuh.manager cat /var/ossec/logs/alerts/alerts.json

Output:
  reports/threat_report_<UTC timestamp>.md

Config (via .env / environment):
  LLM_PROVIDER      default "gemini"   (gemini | ollama | claude | groq)
  REDACT_PII        default true       pseudonymise IPs/users/hashes before egress

  # gemini (free tier)
  GEMINI_API_KEY    required for gemini (free key: https://aistudio.google.com)
  GEMINI_MODEL      default "gemini-2.5-flash"
  GEMINI_MAX_RPM    default 10   sliding-window req/min cap (free tier ~15)
  GEMINI_MAX_RETRIES default 4   429/5xx retries with exponential backoff

  # ollama (local, offline, private - REDACT_PII optional)
  OLLAMA_BASE_URL   default "http://localhost:11434"
  OLLAMA_MODEL      default "llama3.2:3b"

  # claude (Anthropic, highest quality - keep REDACT_PII on)
  ANTHROPIC_API_KEY required for claude (https://console.anthropic.com)
  CLAUDE_MODEL      default "claude-opus-5"  (set claude-haiku-4-5 for cheap/fast)
  CLAUDE_MAX_TOKENS default 8192
  CLAUDE_MAX_RETRIES default 4

  # groq (free tier, very fast, OpenAI-compatible - keep REDACT_PII on)
  GROQ_API_KEY      required for groq (free key: https://console.groq.com)
  GROQ_MODEL        default "llama-3.3-70b-versatile"
  GROQ_MAX_TOKENS   default 8192
  GROQ_MAX_RETRIES  default 4
"""

import os
import re
import sys
import json
import time
import argparse
import datetime
import subprocess

try:
    import requests
except ImportError:
    print("[!] 'requests' missing. Run: pip install -r requirements.txt")
    sys.exit(1)

# Optional .env loading (python-dotenv is in requirements).
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

ALERTS_IN_MANAGER = "/var/ossec/logs/alerts/alerts.json"
MANAGER_CONTAINER = "wazuh.manager"
# Cap what we send so the prompt stays small/cheap. Lower it (ANALYST_MAX_EVENTS)
# to fit a provider's per-request token limit - e.g. Groq's free tier is 12k TPM.
MAX_EVENTS = int(os.environ.get("ANALYST_MAX_EVENTS", "50"))

# repo root is two dirs up from this file (src/soar/threat_report.py).
REPORT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reports")
RATE_STATE = os.path.join(REPORT_DIR, ".rate_state.json")


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_bool(name, default=True):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------
# 1. Gather detections
# --------------------------------------------------------------------------
def load_raw_alerts(input_path=None):
    """Return the raw alerts.json text (newline-delimited JSON)."""
    if input_path:
        try:
            with open(input_path) as f:
                return f.read()
        except OSError as exc:
            print(f"[!] could not read {input_path}: {exc}")
            sys.exit(1)

    # Pull from the running manager container.
    try:
        proc = subprocess.run(
            ["docker", "exec", MANAGER_CONTAINER, "cat", ALERTS_IN_MANAGER],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    except FileNotFoundError:
        print("[!] docker not found and no --input given. Nothing to analyse.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] timed out reading alerts from the manager.")
        sys.exit(1)

    if proc.returncode != 0:
        print("[!] could not read alerts from wazuh.manager "
              f"({proc.stderr.decode(errors='ignore').strip()}).")
        print("    Is the stack up? Try: --input <path to alerts.json>")
        sys.exit(1)
    return proc.stdout.decode(errors="ignore")


def extract_events(raw):
    """Parse newline-delimited alert JSON into a compact, relevant list."""
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        rule = alert.get("rule", {})
        level = rule.get("level", 0)
        groups = rule.get("groups", [])

        # Focus on the ATTACK, not baseline noise. Keep SSH auth, FIM, attacks,
        # and active-response events (plus anything critical), and explicitly
        # drop policy-monitoring chatter (SCA/CIS, rootcheck) that would bloat
        # the prompt and dilute the report.
        NOISE = {"sca", "rootcheck", "policy_monitoring", "syscollector"}
        SIGNAL = {"authentication_failed", "authentication_failures",
                  "authentication_success", "sshd", "syscheck",
                  "attacks", "active_response",
                  # Phase C adaptive engagement: attacker tier + tripwire decisions
                  # (the per-command category rules stay out to avoid bloat).
                  "engagement"}
        if any(g in NOISE for g in groups):
            continue
        interesting = any(g in SIGNAL for g in groups) or level >= 10
        if not interesting:
            continue

        data = alert.get("data", {})
        syscheck = alert.get("syscheck", {})
        events.append({
            "time": alert.get("timestamp", ""),
            "rule_id": rule.get("id"),
            "level": level,
            "desc": rule.get("description", ""),
            "groups": groups,
            "srcip": data.get("srcip") or data.get("src_ip"),
            "user": data.get("dstuser") or data.get("srcuser"),
            "agent": alert.get("agent", {}).get("name"),
            "fim_path": syscheck.get("path"),
            "fim_sha256": syscheck.get("sha256_after"),
        })

    # Most recent MAX_EVENTS (alerts.json is chronological).
    return events[-MAX_EVENTS:]


# --------------------------------------------------------------------------
# 2. Build the analysis prompt
# --------------------------------------------------------------------------
def build_prompt(events):
    header = (
        "You are a senior SOC threat analyst. Below are detection events from a "
        "Wazuh SIEM monitoring an SSH honeypot. Produce a concise incident report "
        "in GitHub-flavoured Markdown with these sections:\n"
        "1. **Executive Summary** (2-3 sentences).\n"
        "2. **Attack Timeline** mapped to the Cyber Kill Chain.\n"
        "3. **MITRE ATT&CK Techniques** — a table of Technique | ID | Evidence.\n"
        "4. **Indicators of Compromise** — source IPs, dropped files + hashes, "
        "created accounts.\n"
        "5. **Severity** — Low/Medium/High/Critical with one-line justification.\n"
        "6. **Recommended Actions** — 3-5 concrete defensive steps.\n"
        "Base every claim only on the events. Do not invent data. If a field is "
        "absent, say so.\n\n"
        "DETECTION EVENTS (JSON):\n"
    )
    return header + json.dumps(events, indent=2)


# --------------------------------------------------------------------------
# 2b. Egress guardrail: pseudonymise IOCs before they leave the host
# --------------------------------------------------------------------------
# The LLM does not need real attacker IPs, usernames, or file hashes to map
# behaviour to MITRE ATT&CK. We replace each unique sensitive value with a
# stable token (IP_1, USER_1, HASH_1), send only tokens to the provider, then
# substitute the real values back into the finished report locally. Google (or
# any third-party backend) never sees the raw IOCs. Disable with REDACT_PII=false.
SENSITIVE_FIELDS = {
    "srcip": "IP",
    "user": "USER",
    "fim_sha256": "HASH",
    "agent": "HOST",
}


def sanitize_events(events):
    """Return (tokenised_events, {token: real_value}) for de-tokenising later."""
    mapping = {}
    counters = {}
    reverse = {}  # real_value -> token, so the same value maps consistently

    def tokenize(prefix, value):
        if value in reverse:
            return reverse[value]
        counters[prefix] = counters.get(prefix, 0) + 1
        token = f"{prefix}_{counters[prefix]}"
        reverse[value] = token
        mapping[token] = value
        return token

    clean = []
    for ev in events:
        c = dict(ev)
        for field, prefix in SENSITIVE_FIELDS.items():
            val = c.get(field)
            if val:
                c[field] = tokenize(prefix, str(val))
        clean.append(c)
    return clean, mapping


def restore_tokens(text, mapping):
    """Substitute real IOC values back into the finished report.

    Replace longest tokens first so IP_1 doesn't corrupt IP_10.
    """
    for token in sorted(mapping, key=len, reverse=True):
        text = text.replace(token, mapping[token])
    return text


# --------------------------------------------------------------------------
# 2c. Rate-limit guardrail: never blow the provider's free-tier quota
# --------------------------------------------------------------------------
# Two layers: a persisted sliding-window throttle across runs (so repeated
# invocations can't exceed GEMINI_MAX_RPM requests/minute), plus 429 retry with
# exponential backoff that honours a Retry-After header.
def _load_call_times():
    try:
        with open(RATE_STATE) as f:
            return [float(t) for t in json.load(f)]
    except (OSError, ValueError, TypeError):
        return []


def _save_call_times(times):
    os.makedirs(REPORT_DIR, exist_ok=True)
    try:
        with open(RATE_STATE, "w") as f:
            json.dump(times, f)
    except OSError:
        pass


def throttle(max_rpm):
    """Block until making a call keeps us under max_rpm in any 60s window."""
    if max_rpm <= 0:
        return
    now = time.time()
    times = [t for t in _load_call_times() if now - t < 60]
    if len(times) >= max_rpm:
        wait = 60 - (now - times[0]) + 0.5
        if wait > 0:
            print(f"[*] rate-limit guardrail: {len(times)} calls in the last "
                  f"minute (cap {max_rpm}); waiting {wait:.0f}s...")
            time.sleep(wait)
        now = time.time()
        times = [t for t in times if now - t < 60]
    times.append(now)
    _save_call_times(times)


# --------------------------------------------------------------------------
# 3. LLM backends (pluggable)
# --------------------------------------------------------------------------
def analyze_gemini(prompt):
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key or api_key == "YOUR_GEMINI_KEY_HERE":
        print("[!] GEMINI_API_KEY not set. Get a free key at "
              "https://aistudio.google.com and put it in .env")
        sys.exit(1)

    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    max_rpm = _env_int("GEMINI_MAX_RPM", 10)      # free tier ~15 RPM; stay under
    max_retries = _env_int("GEMINI_MAX_RETRIES", 4)
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={api_key}")
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        # gemini-2.5-flash is a "thinking" model: its reasoning tokens count
        # against maxOutputTokens and were truncating the report. We don't need
        # the model's private reasoning for a summary, so disable it
        # (thinkingBudget=0) and give the visible report a generous budget.
        "generationConfig": {
            "temperature": 0.2,
            # Headroom so that even if the model ignores thinkingBudget and
            # spends reasoning tokens, the visible report still completes.
            "maxOutputTokens": 16384,
            "thinkingConfig": {"thinkingBudget": 0},
        },
    }

    print(f"[*] Sending {len(prompt)} chars to Gemini ({model})...")
    for attempt in range(1, max_retries + 1):
        throttle(max_rpm)  # sliding-window cap across runs
        try:
            resp = requests.post(url, json=body, timeout=120)
        except requests.RequestException as exc:
            print(f"[!] network error contacting Gemini: {exc}")
            sys.exit(1)

        if resp.status_code == 429:
            # Honour Retry-After if present, else exponential backoff.
            retry_after = resp.headers.get("Retry-After")
            delay = int(retry_after) if (retry_after or "").isdigit() else min(60, 2 ** attempt)
            if attempt >= max_retries:
                print(f"[!] Gemini rate limit (429) after {max_retries} tries. "
                      "Wait a minute and re-run, or lower GEMINI_MAX_RPM.")
                sys.exit(1)
            print(f"[*] 429 rate limited; backing off {delay}s "
                  f"(retry {attempt}/{max_retries - 1})...")
            time.sleep(delay)
            continue

        if resp.status_code in (400, 403):
            print(f"[!] Gemini auth/request error {resp.status_code}: "
                  f"{resp.text[:300]}")
            sys.exit(1)
        if resp.status_code >= 500:
            if attempt >= max_retries:
                print(f"[!] Gemini server error {resp.status_code}, giving up.")
                sys.exit(1)
            delay = min(60, 2 ** attempt)
            print(f"[*] server error {resp.status_code}; retry in {delay}s...")
            time.sleep(delay)
            continue
        if resp.status_code != 200:
            print(f"[!] Gemini HTTP {resp.status_code}: {resp.text[:300]}")
            sys.exit(1)

        try:
            cand = resp.json()["candidates"][0]
            # Join ALL text parts - the model may split the report across
            # several parts; taking only parts[0] silently truncates it.
            parts = cand.get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts if "text" in p)

            # gemini-2.5-flash intermittently ignores thinkingBudget and spends
            # the whole output budget on reasoning, truncating the report
            # (finishReason MAX_TOKENS). It's non-deterministic, so a fresh
            # request usually returns a complete (STOP) response - just retry.
            if cand.get("finishReason") == "MAX_TOKENS" and attempt < max_retries:
                print(f"[*] report truncated (model over-thought); retrying "
                      f"{attempt}/{max_retries - 1}...")
                time.sleep(1)
                continue

            if not text:
                print(f"[!] empty Gemini response ({cand.get('finishReason')}).")
                sys.exit(1)
            if cand.get("finishReason") == "MAX_TOKENS":
                print("[*] still truncated after retries; using partial report.")
            return text
        except (KeyError, IndexError):
            print(f"[!] unexpected Gemini response shape: {resp.text[:300]}")
            sys.exit(1)

    print("[!] exhausted retries contacting Gemini.")
    sys.exit(1)


def analyze_ollama(prompt):
    """Local model via Ollama (offline, free, private). Nothing leaves the host,
    so the PII egress guardrail is optional here - set REDACT_PII=false to send
    raw IOCs to the local model. threat_report runs on the host, so the default
    endpoint is localhost (not host.docker.internal)."""
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    model = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
    url = f"{base}/api/chat"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0.2},
    }
    print(f"[*] Sending {len(prompt)} chars to Ollama ({model}) at {base}...")
    try:
        resp = requests.post(url, json=body, timeout=300)  # local model is slow
    except requests.RequestException as exc:
        print(f"[!] cannot reach Ollama at {base}: {exc}\n"
              "    Is `ollama serve` running and the model pulled "
              f"(`ollama pull {model}`)?")
        sys.exit(1)
    if resp.status_code != 200:
        print(f"[!] Ollama HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    text = (resp.json().get("message", {}).get("content") or "").strip()
    if not text:
        print("[!] empty Ollama response.")
        sys.exit(1)
    return text


def analyze_claude(prompt):
    """Anthropic Claude via the Messages API (raw HTTP, matching the Gemini path
    so no new dependency). Highest-quality reports. The PII egress guardrail
    (sanitize_events) stays in front of this remote backend - keep REDACT_PII on.

    CLAUDE_MODEL defaults to the most capable model; set it to a cheaper/faster
    one (e.g. claude-haiku-4-5) for high-volume runs."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key or api_key == "YOUR_ANTHROPIC_KEY_HERE":
        print("[!] ANTHROPIC_API_KEY not set. Get a key at "
              "https://console.anthropic.com and put it in .env")
        sys.exit(1)

    model = os.environ.get("CLAUDE_MODEL", "claude-opus-5")
    max_tokens = _env_int("CLAUDE_MAX_TOKENS", 8192)
    max_retries = _env_int("CLAUDE_MAX_RETRIES", 4)
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0.2,
        "messages": [{"role": "user", "content": prompt}],
    }

    print(f"[*] Sending {len(prompt)} chars to Claude ({model})...")
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=120)
        except requests.RequestException as exc:
            print(f"[!] network error contacting Claude: {exc}")
            sys.exit(1)

        # 429 (rate limit) and 529 (overloaded) are retryable with backoff.
        if resp.status_code in (429, 529) or resp.status_code >= 500:
            if attempt >= max_retries:
                print(f"[!] Claude {resp.status_code} after {max_retries} tries; giving up.")
                sys.exit(1)
            retry_after = resp.headers.get("retry-after")
            delay = int(retry_after) if (retry_after or "").isdigit() else min(60, 2 ** attempt)
            print(f"[*] Claude {resp.status_code}; backing off {delay}s "
                  f"(retry {attempt}/{max_retries - 1})...")
            time.sleep(delay)
            continue
        if resp.status_code in (400, 401, 403):
            print(f"[!] Claude auth/request error {resp.status_code}: {resp.text[:300]}")
            sys.exit(1)
        if resp.status_code != 200:
            print(f"[!] Claude HTTP {resp.status_code}: {resp.text[:300]}")
            sys.exit(1)

        data = resp.json()
        # content is a list of blocks; join the text blocks (ignore any others).
        text = "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text").strip()
        if data.get("stop_reason") == "max_tokens":
            print("[*] Claude hit max_tokens; report may be truncated "
                  "(raise CLAUDE_MAX_TOKENS).")
        if not text:
            print(f"[!] empty Claude response (stop_reason={data.get('stop_reason')}).")
            sys.exit(1)
        return text

    print("[!] exhausted retries contacting Claude.")
    sys.exit(1)


def analyze_groq(prompt):
    """Groq (OpenAI-compatible API) - free tier, very fast inference on open
    models (Llama etc). Remote backend, so keep REDACT_PII on. Matches the
    raw-HTTP style of the other backends; no new dependency."""
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key or api_key == "YOUR_GROQ_KEY_HERE":
        print("[!] GROQ_API_KEY not set. Get a free key at "
              "https://console.groq.com and put it in .env")
        sys.exit(1)

    model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
    max_tokens = _env_int("GROQ_MAX_TOKENS", 8192)
    max_retries = _env_int("GROQ_MAX_RETRIES", 4)
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0.2,
        "messages": [{"role": "user", "content": prompt}],
    }

    print(f"[*] Sending {len(prompt)} chars to Groq ({model})...")
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=120)
        except requests.RequestException as exc:
            print(f"[!] network error contacting Groq: {exc}")
            sys.exit(1)

        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt >= max_retries:
                print(f"[!] Groq {resp.status_code} after {max_retries} tries; giving up.")
                sys.exit(1)
            retry_after = resp.headers.get("retry-after")
            delay = int(float(retry_after)) if (retry_after or "").replace(".", "", 1).isdigit() \
                else min(60, 2 ** attempt)
            print(f"[*] Groq {resp.status_code}; backing off {delay}s "
                  f"(retry {attempt}/{max_retries - 1})...")
            time.sleep(delay)
            continue
        if resp.status_code in (400, 401, 403):
            print(f"[!] Groq auth/request error {resp.status_code}: {resp.text[:300]}")
            sys.exit(1)
        if resp.status_code != 200:
            print(f"[!] Groq HTTP {resp.status_code}: {resp.text[:300]}")
            sys.exit(1)

        try:
            choice = resp.json()["choices"][0]
            text = (choice.get("message", {}).get("content") or "").strip()
        except (KeyError, IndexError):
            print(f"[!] unexpected Groq response shape: {resp.text[:300]}")
            sys.exit(1)
        if choice.get("finish_reason") == "length":
            print("[*] Groq hit the token limit; report may be truncated "
                  "(raise GROQ_MAX_TOKENS).")
        if not text:
            print(f"[!] empty Groq response (finish_reason={choice.get('finish_reason')}).")
            sys.exit(1)
        return text

    print("[!] exhausted retries contacting Groq.")
    sys.exit(1)


def analyze(prompt):
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    dispatch = {
        "gemini": analyze_gemini,
        "ollama": analyze_ollama,
        "claude": analyze_claude,
        "groq": analyze_groq,
    }
    fn = dispatch.get(provider)
    if fn is None:
        print(f"[!] unsupported LLM_PROVIDER '{provider}'. "
              "Use 'gemini', 'ollama', 'claude', or 'groq'.")
        sys.exit(1)
    return fn(prompt)


# --------------------------------------------------------------------------
# 4. Main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="AI threat analyst for the lab.")
    ap.add_argument("--input", help="path to a Wazuh alerts.json file "
                    "(default: pull from the wazuh.manager container)")
    args = ap.parse_args()

    print("[*] Gathering Wazuh detections...")
    events = extract_events(load_raw_alerts(args.input))
    if not events:
        print("[!] No relevant detections found. Run the simulation first "
              "(./start_lab.sh), give Wazuh a minute, then re-run.")
        sys.exit(0)
    print(f"[*] {len(events)} relevant events collected.")

    # Egress guardrail: pseudonymise IOCs before they leave the host.
    redact = _env_bool("REDACT_PII", True)
    if redact:
        sent_events, mapping = sanitize_events(events)
        print(f"[*] PII guardrail ON: {len(mapping)} IOC value(s) tokenised "
              "before egress (restored locally in the report).")
    else:
        sent_events, mapping = events, {}
        print("[*] PII guardrail OFF (REDACT_PII=false): raw IOCs will be sent.")

    report = analyze(build_prompt(sent_events))
    if mapping:
        report = restore_tokens(report, mapping)  # put real IOCs back locally

    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_path = os.path.join(REPORT_DIR, f"threat_report_{stamp}.md")
    privacy = ("IOCs pseudonymised before egress; restored locally"
               if redact else "raw IOCs sent to provider (REDACT_PII=false)")
    with open(out_path, "w") as f:
        f.write(f"# Threat Intelligence Report\n")
        f.write(f"_Generated {stamp} — {len(events)} events analysed_\n")
        f.write(f"_Privacy: {privacy}_\n\n")
        f.write(report)
        f.write("\n")

    print(f"\n[+] Report written -> {out_path}\n")
    print(report[:1200])
    if len(report) > 1200:
        print("\n... (truncated; see the file for the full report)")


if __name__ == "__main__":
    main()
