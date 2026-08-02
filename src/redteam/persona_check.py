#!/usr/bin/env python3
"""
Adaptive-persona check — does the tier actually change the LLM surface? (Phase C-2)

benchmark.py measures shelLM *against beelzebub*. This measures shelLM against
*itself*: the same honeypot, the same model, three different attacker tiers.

For each tier it publishes the tier the way the lab really does — by running
src/soar/persona.py (the Active-Response script) inside the honeypot container —
then SSHes into shelLM and scores the session on:

  fidelity  how many of that persona's expected markers show up
            (SKILLED: corporate jump host, backups, service accounts;
             OPPORTUNIST: a bare, unremarkable cloud VM)
  leakage   markers of the *other* persona showing up (should be 0)
  canary    one write -> read-back -> listing probe, so a richer persona is not
            bought with a loss of the session consistency shelLM exists for
  says no   a nonexistent binary and a nonexistent file must still error - a
            persona that tells the model to keep the attacker digging can stop
            saying "no" at all (the OPPORTUNIST persona once had the mirror bug
            and refused a real `echo`)

Honest framing: a handful of sessions against a 3B model, not a statistical
evaluation. It answers "did the surface actually change, did it stay coherent,
and does it still say no", not "how good is the deception". Fidelity swings
between trials, which is why the report prints every trial's score next to the
mean instead of smoothing it away.

  python3 src/redteam/persona_check.py                 # 3 trials x 3 tiers
  python3 src/redteam/persona_check.py --tiers SKILLED --trials 5
  python3 src/redteam/persona_check.py --no-canary     # faster, drops the consistency probe

Needs shelLM up (compose/shellm.yml) and, to set tiers, the honeypot container.
Writes a scored Markdown report + transcripts to reports/.
"""
import argparse
import json
import os
import random
import string
import subprocess
import sys
import time
from datetime import datetime

import paramiko

HOST = os.environ.get("SHELLM_HOST", "127.0.0.1")
PORT = int(os.environ.get("SHELLM_PORT", "2224"))
USER, PW = "root", "toor"

# The container that owns the Active-Response script + the tier-state volume.
HONEYPOT_CONTAINER = os.environ.get("HONEYPOT_CONTAINER", "linux-honeypot")
AR_SCRIPT = "/var/ossec/active-response/bin/persona.py"
TIER_DIR = "/var/lib/tier-state"

# Tier -> the rule that raises it (what persona.py keys on) + what we expect the
# resulting persona to look like. Markers are lowercase substrings.
TIERS = {
    "SKILLED": {
        "rule": "100401",
        "persona": "Tier_skilled",
        "markers": ["corp.local", "jump-01", "backup", "svc_backup", "/opt/app",
                    "credentials", "ops"],
    },
    "OPPORTUNIST": {
        "rule": "100400",
        "persona": "Tier_opportunist",
        # A bare box is measured mainly by what is NOT there (leakage == 0);
        # these are the few positive tells its prompt does commit to.
        "markers": ["ubuntu", "1vcpu", "/home/ubuntu"],
    },
    "NONE": {
        "rule": None,          # no tier published; shelLM falls back to Eman_v1
        "persona": "Eman_v1",
        "markers": [],         # nothing specific to expect from the default box
    },
}


def rand(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def read_until_idle(chan, idle=5.0, hard=120.0):
    """Read until no new bytes for `idle`s (the local model is slow)."""
    buf = b""
    start = last = time.time()
    while time.time() - start < hard:
        if chan.recv_ready():
            data = chan.recv(65535)
            if data:
                buf += data
                last = time.time()
        elif time.time() - last > idle and buf:
            break
        else:
            time.sleep(0.15)
    return buf.decode(errors="replace")


def docker(*args, check=True):
    """Run a docker command, returning stdout (empty string on failure)."""
    try:
        out = subprocess.run(("docker",) + args, capture_output=True, text=True,
                             timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        if check:
            print(f"[!] docker {' '.join(args)}: {exc}")
        return ""
    if out.returncode != 0 and check:
        print(f"[!] docker {' '.join(args)} failed: {out.stderr.strip()[:200]}")
    return out.stdout


def set_tier(tier):
    """Publish (or clear) the tier for our source IP, via the real AR script.

    We do not know which IP shelLM will see us as, so clear the whole state dir
    first and let persona.py write for every plausible client IP the docker
    bridge might present. Cheap, and it keeps the AR contract as the only writer.
    """
    docker("exec", HONEYPOT_CONTAINER, "sh", "-c", f"rm -f {TIER_DIR}/*")
    if tier == "NONE":
        return True

    rule = TIERS[tier]["rule"]
    srcips = client_ips()
    if not srcips:
        print("[!] could not determine a source IP to publish the tier for.")
        return False

    for ip in srcips:
        msg = ('{"command":"add","parameters":{"alert":{"rule":{"id":"%s"},'
               '"data":{"srcip":"%s"}}}}' % (rule, ip))
        docker("exec", "-i", HONEYPOT_CONTAINER, "sh", "-c",
               f"echo '{msg}' | {AR_SCRIPT}")
    published = docker("exec", HONEYPOT_CONTAINER, "ls", TIER_DIR).split()
    return bool(published)


def client_ips():
    """Source IPs shelLM might see this script as.

    Ground truth first: whatever srcip shelLM recorded for the last login (its own
    SIEM feed). Falling back to the container's default gateway, read from
    /proc/net/route because the image has no iproute2.
    """
    ips = []

    last = docker("exec", "shellm", "sh", "-c",
                  "grep session_start /var/log/shellm.json | tail -1",
                  check=False).strip()
    if last:
        try:
            ip = json.loads(last.splitlines()[-1]).get("srcip", "")
            if ip and ip != "unknown":
                ips.append(ip)
        except ValueError:
            pass

    # /proc/net/route: destination 00000000 = default; gateway is little-endian hex.
    route = docker("exec", "shellm", "cat", "/proc/net/route", check=False)
    for line in route.splitlines()[1:]:
        f = line.split()
        if len(f) > 2 and f[1] == "00000000":
            try:
                raw = int(f[2], 16)
            except ValueError:
                continue
            gw = ".".join(str((raw >> (8 * i)) & 0xFF) for i in range(4))
            ips.append(gw)
            # Docker Desktop presents the host as the gateway subnet's .1 address.
            ips.append(gw.rsplit(".", 1)[0] + ".1")
            break

    return list(dict.fromkeys(ips))


def bootstrap_srcip():
    """Make shelLM record one session so we know the IP it sees us as.

    run.sh writes the session-start line before launching the model, so this
    costs a login and nothing else. Needed on a freshly rebuilt container, where
    the log is empty and the container gateway is not the address a Docker
    Desktop host actually arrives from.
    """
    have = docker("exec", "shellm", "sh", "-c",
                  "grep -c session_start /var/log/shellm.json || true",
                  check=False).strip()
    if have.isdigit() and int(have) > 0:
        return
    print("[*] no prior shelLM session on record - opening one to learn our source IP...")
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(HOST, port=PORT, username=USER, password=PW,
                  look_for_keys=False, allow_agent=False, timeout=25)
        c.invoke_shell()
        time.sleep(3)
        c.close()
    except Exception as exc:
        print(f"[!] bootstrap login failed: {exc}")


def probe_session(tier, canary_probe=True):
    """One SSH session against shelLM. Returns (transcript, timings, results)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=USER, password=PW,
                   look_for_keys=False, allow_agent=False, timeout=25)
    chan = client.invoke_shell(term="xterm", width=120, height=40)

    transcript = []
    start = time.time()
    banner = read_until_idle(chan)
    transcript.append(("<login>", banner))
    warmup = time.time() - start

    canary = f"CANARY_{rand()}"
    fname = f"note_{rand()}.txt"
    cmds = ["hostname", "ls -la /root", "cat /etc/passwd"]
    if canary_probe:
        cmds += [f"echo {canary} > /tmp/{fname}", f"cat /tmp/{fname}", "ls /tmp"]

    # Discipline probes: a persona that tells the model to keep the attacker
    # digging can bleed into never saying "no" - inventing a binary that does not
    # exist, or narrating a file that was never there. The OPPORTUNIST persona had
    # the mirror of this bug (it refused a real `echo`), so both directions get
    # measured, on every tier.
    ghost_cmd = f"zqx_{rand()}"
    ghost_file = f"/root/{rand()}_notthere.txt"
    cmds += [ghost_cmd, f"cat {ghost_file}"]

    latencies = []
    for cmd in cmds:
        t0 = time.time()
        chan.send(cmd + "\n")
        out = read_until_idle(chan)
        latencies.append(time.time() - t0)
        transcript.append((cmd, out))

    client.close()

    text = "\n".join(o for _, o in transcript).lower()
    markers = TIERS[tier]["markers"]
    hits = [m for m in markers if m in text]

    # Leakage: the other tier's *distinctive* markers turning up here.
    other = "OPPORTUNIST" if tier == "SKILLED" else "SKILLED"
    leaked = [m for m in TIERS[other]["markers"] if m in text] if markers else []

    ghost_cmd_out = transcript[-2][1].lower()
    ghost_file_out = transcript[-1][1].lower()
    says_no_cmd = "not found" in ghost_cmd_out
    says_no_file = ("no such file" in ghost_file_out
                    or "not found" in ghost_file_out)

    readback = ls_agrees = None
    if canary_probe:
        # Counting back past the two discipline probes: ... write, read, list,
        # ghost_cmd, ghost_file.
        readback = canary.lower() in transcript[-4][1].lower()
        ls_agrees = fname.lower() in transcript[-3][1].lower()

    return {
        "tier": tier,
        "transcript": transcript,
        "warmup": warmup,
        "latency": sum(latencies) / len(latencies) if latencies else 0.0,
        "markers_expected": markers,
        "markers_hit": hits,
        "leaked": leaked,
        "readback": readback,
        "ls_agrees": ls_agrees,
        "says_no_cmd": says_no_cmd,
        "says_no_file": says_no_file,
    }


def persona_logged():
    """What persona shelLM actually selected, straight from its SIEM feed."""
    out = docker("exec", "shellm", "sh", "-c",
                 "tail -20 /var/log/shellm.json | grep session_start | tail -1",
                 check=False)
    if not out.strip():
        return "?"
    try:
        ev = json.loads(out.strip().splitlines()[-1])
    except ValueError:
        return "?"
    return f"{ev.get('tier', '?')}/{ev.get('persona', '?')}"


def summarize(tier, trials):
    """Fold N trials of one tier into the numbers worth reporting."""
    exp = len(TIERS[tier]["markers"])
    fids = [len(t["markers_hit"]) for t in trials]

    def rate(key):
        vals = [t[key] for t in trials if t[key] is not None]
        return (sum(1 for v in vals if v), len(vals))

    return {
        "tier": tier,
        "served": trials[-1]["served"],
        "n": len(trials),
        "expected": exp,
        "fidelity_mean": sum(fids) / len(fids),
        "fidelity_each": fids,
        "leaked_total": sum(len(t["leaked"]) for t in trials),
        "readback": rate("readback"),
        "ls_agrees": rate("ls_agrees"),
        "says_no_cmd": rate("says_no_cmd"),
        "says_no_file": rate("says_no_file"),
        "warmup": sum(t["warmup"] for t in trials) / len(trials),
        "latency": sum(t["latency"] for t in trials) / len(trials),
        "markers_union": sorted({m for t in trials for m in t["markers_hit"]}),
        "leaked_union": sorted({m for t in trials for m in t["leaked"]}),
        "trials": trials,
    }


def emit_report(summaries, outdir, trials_n):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(outdir, f"persona_check_{ts}.md")

    def frac(pair):
        hit, total = pair
        return f"{hit}/{total}" if total else "-"

    lines = [
        "# Adaptive persona check (Phase C-2)",
        "",
        f"Generated {datetime.utcnow().isoformat()}Z · shelLM on port {PORT} · "
        f"{trials_n} trial(s) per tier",
        "",
        "Same honeypot, same model, one persona per attacker tier.",
        "",
        "- **Fidelity** — expected persona markers seen (mean over trials).",
        "- **Leakage** — the *other* persona's markers bleeding in. Want 0.",
        "- **Canary** — write -> read back -> listing agrees: shelLM's core property,",
        "  which a richer persona must not cost us.",
        "- **Says no** — a persona that keeps the attacker digging can stop saying",
        "  \"no\" at all. These probe a nonexistent binary and a nonexistent file;",
        "  a real shell errors on both. (The OPPORTUNIST persona once had the mirror",
        "  bug: it refused a *real* `echo`.)",
        "",
        "A low-value persona is judged mainly by *absence*: its fidelity count is",
        "small by design, and the number that matters is leakage 0.",
        "",
        "| Tier | Persona served | Fidelity | Leakage | Canary read-back | `ls` agrees | Says no: cmd | Says no: file | Warm-up | Mean latency |",
        "|------|----------------|----------|---------|------------------|-------------|--------------|---------------|---------|--------------|",
    ]
    for s in summaries:
        fid = (f"{s['fidelity_mean']:.1f}/{s['expected']}" if s["expected"] else "n/a")
        if s["expected"] and s["n"] > 1:
            fid += " (" + ",".join(str(f) for f in s["fidelity_each"]) + ")"
        lines.append(
            f"| {s['tier']} | {s['served']} | {fid} | {s['leaked_total']} | "
            f"{frac(s['readback'])} | {frac(s['ls_agrees'])} | "
            f"{frac(s['says_no_cmd'])} | {frac(s['says_no_file'])} | "
            f"{s['warmup']:.1f}s | {s['latency']:.1f}s |")

    lines += ["", "## Markers seen (union over trials)", ""]
    for s in summaries:
        lines.append(f"- **{s['tier']}** ({s['served']}): "
                     f"{', '.join(s['markers_union']) or '(none)'}"
                     + (f" · leaked: {', '.join(s['leaked_union'])}"
                        if s["leaked_union"] else ""))

    lines += ["", "## Transcripts", ""]
    for s in summaries:
        for i, t in enumerate(s["trials"], 1):
            lines += [f"### {s['tier']} → {s['served']} (trial {i})", "", "```"]
            for cmd, out in t["transcript"]:
                lines.append(f"$ {cmd}")
                lines.append(out.strip())
            lines += ["```", ""]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def main():
    ap = argparse.ArgumentParser(description="Score shelLM's adaptive personas")
    ap.add_argument("--tiers", nargs="+", default=["SKILLED", "OPPORTUNIST", "NONE"],
                    choices=list(TIERS), help="which tiers to probe")
    ap.add_argument("--trials", type=int, default=3,
                    help="sessions per tier (a 3B model varies run to run; one "
                         "session is an anecdote, not a measurement)")
    ap.add_argument("--no-canary", action="store_true",
                    help="skip the consistency probe (faster)")
    ap.add_argument("--outdir", default="reports")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    bootstrap_srcip()

    summaries = []
    for tier in args.tiers:
        print(f"\n=== tier {tier} ({args.trials} trial(s)) ===")
        if not set_tier(tier):
            print(f"[!] could not publish tier {tier}; skipping.")
            continue

        trials = []
        for i in range(1, args.trials + 1):
            # The tier is read at login, so nothing to wait for beyond the connect.
            try:
                r = probe_session(tier, canary_probe=not args.no_canary)
            except Exception as exc:
                print(f"[!] trial {i} failed for {tier}: {exc}")
                continue
            r["served"] = persona_logged()
            trials.append(r)
            exp = len(r["markers_expected"])
            print(f"[*] trial {i}: served {r['served']}  "
                  f"fidelity {len(r['markers_hit'])}/{exp}  "
                  f"leaked {len(r['leaked'])}  "
                  f"says-no {int(r['says_no_cmd'])}/{int(r['says_no_file'])}")

        if trials:
            summaries.append(summarize(tier, trials))

    if not summaries:
        print("[!] no successful runs.")
        sys.exit(1)

    for s in summaries:
        print(f"[=] {s['tier']}: fidelity {s['fidelity_mean']:.1f}/{s['expected']}"
              f"  leakage {s['leaked_total']}  "
              f"says-no cmd {s['says_no_cmd'][0]}/{s['says_no_cmd'][1]}, "
              f"file {s['says_no_file'][0]}/{s['says_no_file'][1]}")

    path = emit_report(summaries, args.outdir, args.trials)
    print(f"\n[+] Report written -> {os.path.abspath(path)}")


if __name__ == "__main__":
    main()
