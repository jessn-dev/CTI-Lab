# Roadmap / Deferred Work

Tracked so we don't lose it. Newest intent at top.

## Pluggable LLM backend (Phase A) — DONE (2026-07-31)
`src/soar/threat_report.py` now supports four backends via `LLM_PROVIDER`
(`gemini` | `ollama` | `claude` | `groq`); the prompt + event extraction are
shared, each transport is one function:
- **`analyze_gemini()`** — free tier (default). Sliding-window rate-limit + 429
  retry + PII egress guardrail.
- **`analyze_ollama()`** — local model (Ollama), fully offline, zero cost, no data
  leaves the host, so `REDACT_PII` is optional. `OLLAMA_BASE_URL` defaults to
  `http://localhost:11434` (the analyst runs on the host, not in Docker).
  *Tested live with `llama3.2:3b`.*
- **`analyze_claude()`** — Anthropic Claude (`CLAUDE_MODEL` default `claude-opus-5`;
  set `claude-haiku-4-5` for cheap/fast). Raw Messages API (no new dependency),
  429/529/5xx retry. Keep `REDACT_PII` on. *Written, not yet run live (needs
  `ANTHROPIC_API_KEY`).*
- **`analyze_groq()`** — Groq free tier, very fast inference on open models
  (`GROQ_MODEL` default `llama-3.3-70b-versatile`). OpenAI-compatible raw HTTP
  (no new dependency), 429/5xx retry. Keep `REDACT_PII` on. *Verified live
  2026-08-01: full report written to `reports/`.*

Live-run status of the remote backends (2026-08-01): **gemini** and **ollama**
verified end to end; **groq** verified end to end; **claude** exercised end to end
up to the API — request built, PII guardrail applied (10 IOCs tokenised), 4684
chars sent — and rejected with `400 invalid_request_error: Your credit balance is
too low`. That is an account/billing state, not a code path: the error handling
printed it cleanly and exited. Re-run `LLM_PROVIDER=claude ./bin/report.sh` once
the account has credit to close it out.

The egress guardrail (`sanitize_events` / `restore_tokens`) stays in front of the
remote backends; it can be skipped for `ollama`. See README §6b.

## Done
- Phase A analyst (Gemini backend) with rate-limit + PII-egress guardrails.
- Core lab: Wazuh SIEM + honeypot agent, real brute-force sim, Active Response,
  VirusTotal FIM integration.
- **Phase B1 — beelzebub LLM honeypot.** LLM-driven SSH shell (local Ollama), in
  its own compose file, with a sidecar Wazuh agent forwarding events as rule
  100301. Core lab unaffected. See README §7c.
- **Phase B2 (Part 1) — shelLM LLM honeypot.** Consistency-focused LLM SSH shell
  (Stratosphere IPS) on port 2224, exposed via a real `sshd` `ForceCommand` into
  the shelLM chatbot, local Ollama, baked Wazuh agent forwarding sessions as rule
  100311. Core lab unaffected. See README §7d. Part 2 (the shelLM-vs-beelzebub
  benchmark) shipped too, with the side-by-side SIEM panels added 2026-07-31.
- **shelLM per-command visibility (2026-08-01).** `services/shelLM/patch_command_log.py`
  patches `input(prompt)` in `LinuxSSHbot.py` at build time to append one JSON
  event per command (with the session's `srcip`/`tier`/`persona`) to the file the
  agent already tails. Rules 100314 + categories 100315-100319 mirror the snoopy
  ones, kept in `shellm_*` groups (deliberately **not** `deep_attack`, which would
  bleed into the 100401 tier correlation). Verified live.
- **snoopy noise filter (2026-08-01).** A `filter_chain` in `/etc/snoopy.ini`
  excludes the SIEM's own process trees (`wazuh-modulesd`, `wazuh-logcollec` —
  note the 15-char comm truncation — `wazuh-agentd`, `wazuh-execd`,
  `wazuh-syscheckd`, `wazuh-control`). A full `attack.sh --profile skilled` run now
  writes ~45 snoopy lines instead of ~780, more than half of them the attacker's,
  with the whole tier/tripwire/AR chain unchanged.

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
- **Part 1 (DONE).** shelLM runs as a third SSH honeypot on port **2224**, beside
  the static honeypot (2222) and beelzebub (2323). It's a stdin/stdout LLM shell
  chatbot, so a real `sshd` `ForceCommand`s every login into it. Sessions feed the
  same Wazuh SIEM as rule 100311. See README §7d.
- **Part 2 (DONE).** Benchmark shelLM vs beelzebub: same commands, same model
  (`llama3.2:3b`), scored on session consistency (`src/redteam/benchmark.py`,
  `./bin/benchmark.sh`). Result over 3 trials: **shelLM 12/12, beelzebub 9/12** —
  beelzebub fails the `ls`-listing probe every trial (its `ls` doesn't reflect a
  file it just wrote), shelLM passes it every trial. Breadth vs depth, measured.
  See README §7d.
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

**Phase C-1 — DONE.** The "always ban" SOAR is now adaptive:
- **Command visibility** — `snoopy` (LD_PRELOAD) logs every command (incl.
  non-interactive exec + recon with no FIM trace) with the SSH client IP →
  category rules 100410-100415 (recon/cred/ingress/persistence/evasion).
- **Tiering** — native Wazuh correlation: 100400 OPPORTUNIST (repeated recon),
  100401 SKILLED (2+ beyond-recon actions).
- **Engage** — SKILLED fires `src/soar/engage.py`, which plants decoy lures
  (fake `id_rsa`/`backup_db.sql`/`credentials.txt`) and holds the ban.
- **Tripwire + disengage** — reading a lure trips 100402 (lvl 13) → `active_defense`
  bans the srcip. Demo: `./bin/attack.sh --profile skilled|noise`. See README §7e.

**Phase C-2 — DONE (2026-07-31).** The tier now also drives the *LLM* surface:
- `src/soar/persona.py` (a third Active-Response script, fires on 100400/100401)
  writes `<TIER> <epoch>` per source IP into a shared docker volume
  (`tier-state`), which the shelLM container mounts read-only.
- shelLM's `run.sh` reads it at login: SKILLED → `Tier_skilled` (a busy
  `jump-01.corp.local` with backups, service accounts and the same lure files
  `engage.py` plants), OPPORTUNIST → `Tier_opportunist` (a bare 1-vCPU VM with
  nothing on it), no/expired tier → `Eman_v1`. Personas live in
  `services/shelLM/personalities/`.
- Session history is wiped (`--cleaned`) **only** on a persona switch, so shelLM
  keeps its cross-session consistency except when the box deliberately changes.
- The choice is visible in the SIEM: rule `100312` (SKILLED) / `100313`
  (OPPORTUNIST). Verified live end-to-end: `attack.sh --profile skilled` → tier
  published → SSH to 2224 answered as `jump-01.corp.local` → 100312 alert.
- Keys on source IP: tier up from one address, visit shelLM from another, and you
  get the default box. Honest limitation, not a bug.

**Phase C-2 follow-ups (2026-08-01).**
- `simulate_attacks.py` gained **Phase 8**: the skilled profile now ends by walking
  into shelLM, so the adapted persona is part of the automated demo (and skips
  cleanly when the add-on is down). Verified: one run fires 5763 + 100411/100400/
  100401/100402 + 100312 + 100314/100315/100316.
- `src/redteam/persona_check.py` scores the personas per tier — fidelity, leakage,
  and a consistency canary. Leakage 0 both ways; fidelity varies run to run on a
  3B model. It immediately caught a real prompt bug: the OPPORTUNIST persona's
  "nothing here is interesting" framing bled into command availability
  (`bash: echo: command not found`), now scoped to content only.
- Agent enrollment: authd's `force.disconnected_time` is now **disabled**. It
  required a stale record to be marked disconnected first (~30-60 s of missed
  keepalives), so rebuilding a honeypot image faster than that left the fresh
  container unenrolled — alive, answering SSH, forwarding nothing. Both entrypoints
  now retry enrollment 3× and print a loud NOT ENROLLED banner with the fix.
  Verified by two back-to-back rebuilds: both enrolled on the first attempt.

## Benefits (why the whole direction is worth it)
Realism & adaptability (beats fingerprinting), scalability (auto-generate many),
lower operational overhead (less manual config), richer intelligence and fewer
false positives (continuous learning).

[beelzebub]: https://github.com/mariocandela/beelzebub
[shelLM]: https://github.com/stratosphereips/shelLM
