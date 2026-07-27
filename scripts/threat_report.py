#!/usr/bin/env python3
"""
Phase A - AI Threat Analyst (offline SOAR).

Reads the Wazuh detections produced by the lab (SSH brute force, FIM drops,
Active Response bans), hands them to an LLM, and writes a structured
MITRE ATT&CK threat report. Runs offline on logs - it is NOT in the attack
path, so there is no latency or prompt-injection risk.

Provider is pluggable via LLM_PROVIDER (default: gemini). The analysis prompt
and event extraction are provider-agnostic; only the transport differs, so
swapping to a local model or Claude later is a single function.

Input (first that works):
  --input <file>                     explicit alerts.json (newline-delimited)
  else: docker exec wazuh.manager cat /var/ossec/logs/alerts/alerts.json

Output:
  reports/threat_report_<UTC timestamp>.md

Config (via .env / environment):
  LLM_PROVIDER      default "gemini"
  GEMINI_API_KEY    required for gemini (free key: https://aistudio.google.com)
  GEMINI_MODEL      default "gemini-2.5-flash"
  GEMINI_MAX_RPM    default 10   sliding-window req/min cap (free tier ~15)
  GEMINI_MAX_RETRIES default 4   429/5xx retries with exponential backoff
  REDACT_PII        default true pseudonymise IPs/users/hashes before egress
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
MAX_EVENTS = 50  # cap what we send so the prompt stays small/cheap

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
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
                  "attacks", "active_response"}
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


def analyze(prompt):
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    if provider == "gemini":
        return analyze_gemini(prompt)
    # Hooks for later: "ollama", "claude". Kept intentionally simple.
    print(f"[!] unsupported LLM_PROVIDER '{provider}'. Use 'gemini'.")
    sys.exit(1)


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
