# Roadmap / Deferred Work

Tracked so we don't lose it. Newest intent at top.

## Deferred — Pluggable LLM backend (Phase A)
**Status: ON HOLD (deliberate).** Decided 2026-07-27.

`scripts/threat_report.py` currently ships **Gemini only**. The code is already
shaped for more backends — `analyze()` switches on `LLM_PROVIDER`, and
`analyze_gemini()` is self-contained — but we are **not** building the other
backends yet.

When we pick this back up, add:
- **`analyze_ollama()`** — local model (Ollama + Llama/Mistral), fully offline,
  zero cost, no data leaves the host. This is the privacy-first default we
  discussed; with a local backend, `REDACT_PII` can be relaxed since nothing is
  sent to a third party. On macOS run Ollama native (Metal GPU) and point the
  script at `http://host.docker.internal:11434`; Docker-Ollama on Mac is CPU-only.
- **`analyze_claude()`** — Anthropic Claude (Haiku 4.5 for cheap/fast, Opus 5
  for best quality). Batch API halves cost. Highest-quality reports.

Selection stays via `LLM_PROVIDER` (`gemini` | `ollama` | `claude`). Keep the
egress guardrail (`sanitize_events` / `restore_tokens`) in front of any remote
backend; it can be skipped for `ollama`.

## Done
- Phase A analyst (Gemini backend) with rate-limit + PII-egress guardrails.
- Core lab: Wazuh SIEM + honeypot agent, real brute-force sim, Active Response,
  VirusTotal FIM integration.

## Later / ideas
- **Phase B** — LLM SSH shell honeypot (fork beelzebub/shelLM): world-state JSON
  for consistency, command cache for latency, prompt-injection guard, Wazuh
  ingest. See chat notes.
- **Phase C** — adaptive engagement (escalate fake surface by attacker
  sophistication). NOT "detect zero-day".
