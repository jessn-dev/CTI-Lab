ol# Roadmap / Deferred Work

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
- **Phase B1 — beelzebub LLM honeypot.** LLM-driven SSH shell (local Ollama), in
  its own compose file, with a sidecar Wazuh agent forwarding events as rule
  100301. Core lab unaffected. See README §7c.

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

### Build path — two tools, two roles

Most of what an AI honeypot needs already exists here: a real SSH honeypot, a
`paramiko` attack harness, a SIEM ingesting every event, and Python SOAR acting
on detections. We implement **both** [beelzebub] and [shelLM], each for a
different job (not two copies of the same SSH honeypot):

- **[beelzebub]** gives breadth. It's a Go honeypot framework: YAML-defined
  services across SSH, HTTP, and TCP, a built-in LLM plugin (OpenAI or Ollama),
  and Prometheus metrics.
- **[shelLM]** gives depth. It's a Python LLM SSH shell from Stratosphere IPS,
  built around session **consistency** (prompt engineering + memory so `cat file`
  matches an earlier `ls`).

**B1 — beelzebub (breadth + orchestration).**
- Add beelzebub to the Docker network as a multi-protocol decoy: SSH, HTTP, TCP,
  each defined in YAML.
- Point its LLM plugin at a local model (Ollama) so it stays free and offline.
- Scrape its Prometheus metrics; ship its logs into Wazuh as a new log source.
- Fastest win: multi-protocol coverage and metrics for little code.

**B2 — shelLM (depth) + the benchmark.**
- Run shelLM as a second SSH honeypot on its own port (e.g. 2223), beside
  beelzebub's SSH on 2222.
- Both feed the same Wazuh SIEM. Compare which keeps an attacker engaged longer
  and which stays consistent across a session (the metric that actually matters).
- This A/B is the headline: two LLM honeypot strategies, one SIEM, measured. Few
  projects do it.

**Guardrails for both (design in from day one).**
- **Sandbox.** The LLM describes output; it never executes attacker commands. No
  real filesystem, no real exec.
- **Consistency.** A world-state store (shelLM's whole focus) so responses agree
  across a session. This is the number-one hard problem.
- **Latency.** A deterministic command cache for common commands (`ls`, `whoami`,
  `uname`); only novel commands reach the model.
- **Prompt-injection guard.** Attackers type "ignore previous instructions"
  straight into the shell. Filter or refuse without breaking the illusion.
- **Cost cap.** Bots send thousands of commands. Budget-limit live inference, or
  use a local model.

**Model choice.** Live per-command work wants something cheap and fast (a local
model via Ollama, or a Haiku-class model); route only the interesting commands to
it. Offline transcript analysis can use a stronger model.

**Consistency and latency are the real problems, not plausibility.** Design for
them first. The shelLM paper documents the findings.

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
