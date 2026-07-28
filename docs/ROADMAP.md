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

## Phase B — AI-generated honeypots (the big vision)

> Mirrored in the portal: `docs/index.html` → **Roadmap → Future: AI Honeypots**.
> Keep the two in sync.

**Why.** Static honeypots (like the one this lab ships) eventually get
*fingerprinted* — an attacker notices there's no real filesystem, no legitimate
traffic, no human behaviour, and leaves. An AI-driven honeypot instead
hallucinates a convincing, ever-changing environment, keeping the attacker
engaged and the intelligence flowing.

**Core architecture**
- **LLM shell** — a model fine-tuned on shell commands / attacker behaviour
  answers each command with realistic output (the "brain").
- **GANs** — generate synthetic environments, configs, and service banners so
  each honeypot instance looks unique with minimal manual setup.
- **Prompt engineering + fine-tuning** — tailor responses per protocol
  (SSH/HTTP/SMTP) and simulate the vulnerabilities most likely to attract
  attackers.

**Real-time adaptation**
- **Command/response simulation** under tight latency (pruning, quantisation,
  caching) so the illusion never lags.
- **Reinforcement learning** — agent in an MDP: observe state (commands/session)
  → act (response) → update policy from reward (did the deception hold?). Learns
  to prolong engagement and extract more intel.
- **Dynamic environment generation** — procedurally mutate the fake network,
  services, and logs on the fly so the decoy can't be pinned down.

**Operational workflow** — engage → log + behaviour analysis (TTPs, predict next
move) → federated (anonymised) intel sharing → autonomous multi-agent
orchestration writing NL threat reports.

**Concrete build path on THIS lab (the foundation is already here):**
The pieces an AI honeypot needs already exist — a real SSH honeypot, a
`paramiko` attack harness, a SIEM ingesting every event, and Python SOAR acting
on detections. The realistic increments:
1. **LLM shell** — fork [beelzebub] / [shelLM] and replace the static `sshd` with
   an LLM-driven fake shell in an isolated container (no real FS, no real exec).
   Add a **world-state JSON** the model must respect (fixes consistency — the #1
   hard problem), a **deterministic command cache** for common commands (fixes
   latency), and a **prompt-injection guard** (attackers jailbreak the honeypot).
   Ship transcripts into Wazuh like the real honeypot.
   - Live/per-command model: cheap + fast (e.g. Haiku 4.5 / a local model);
     route only novel commands to the LLM.
2. **Consistency + latency are the real problems**, not plausibility — design for
   them from day one. Read the shelLM paper for the documented findings.

## Phase C — adaptive engagement
Escalate the fake surface / verbosity based on observed attacker sophistication
(command complexity, tooling) to extract more TTPs before shutting down.
**NOT** "detect a zero-day in real time" — that's an unsolved problem; don't
oversell it.

## Benefits (why the whole direction is worth it)
Realism & adaptability (beats fingerprinting), scalability (auto-generate many),
lower operational overhead (less manual config), richer intelligence and fewer
false positives (continuous learning).

[beelzebub]: https://github.com/mariocandela/beelzebub
[shelLM]: https://github.com/stratosphereips/shelLM
