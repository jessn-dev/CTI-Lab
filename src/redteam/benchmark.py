#!/usr/bin/env python3
"""
shelLM vs beelzebub — LLM honeypot benchmark (Phase B2, Part 2).

Runs the SAME command sequence against both LLM SSH honeypots, on the SAME local
model, and scores them on the metric that actually distinguishes them: session
**consistency**. beelzebub answers each command as an independent LLM call
(breadth, largely stateless); shelLM carries session history (depth). We measure
whether a file written earlier can be read back, whether `ls` agrees, whether
`cd` sticks, and whether an env var is recalled — plus response latency and how
"engaged" (non-error, substantive) each shell stays.

Both honeypots must be up (compose/shellm.yml + compose/beelzebub.yml) with the
native Ollama running. Weak login is root:toor on both.

  python3 src/redteam/benchmark.py            # both, default ports
  python3 src/redteam/benchmark.py --only shelLM

Writes a scored Markdown report + full transcripts to reports/.
"""
import argparse
import os
import random
import statistics
import string
import sys
import time
from datetime import datetime

import paramiko

TARGETS = {
    "shelLM": 2224,
    "beelzebub": 2323,
}
USER, PW, HOST = "root", "toor", "127.0.0.1"


def rand(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def read_until_idle(chan, idle=4.0, hard=60.0):
    """Read until no new bytes for `idle`s (LLM is slow), capped at `hard`s."""
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


def clean(text):
    """Drop shell-prompt lines and shelLM's role-echo so substring checks on the
    actual command output aren't fooled by the echoed prompt/command."""
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s in ("assistant", "user"):
            continue
        if s.endswith("$") or s.endswith("#"):   # a bare prompt line
            continue
        out.append(s)
    return "\n".join(out)


def build_plan():
    """A fixed sequence with randomized canaries so the model can't have memorized
    them. Each probe records what a *consistent* shell must echo back later."""
    canary = f"CANARY_{rand()}"
    fname = f"note_{rand()}.txt"
    envval = f"val_{rand()}"
    # (command, probe_key_or_None, expected_substring_or_None)
    plan = [
        ("whoami",                              None, None),
        ("uname -a",                            None, None),
        (f"echo {canary} > /tmp/{fname}",       None, None),          # write
        (f"cat /tmp/{fname}",                   "file_readback", canary),   # read it back
        ("ls -la /tmp",                         "ls_agreement", fname),      # listing agrees
        ("cd /etc",                             None, None),
        ("pwd",                                 "cd_persist", "/etc"),       # cwd stuck
        (f"export BENCH={envval}",              None, None),
        ("echo $BENCH",                         "env_recall", envval),       # env recalled
    ]
    return plan


def run_target(name, port, gif=None):
    print(f"\n{'='*60}\n  {name}  (127.0.0.1:{port})\n{'='*60}")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=port, username=USER, password=PW,
              look_for_keys=False, allow_agent=False, timeout=20)
    chan = c.invoke_shell(term="xterm", width=120, height=40)

    warm_start = time.time()
    banner = read_until_idle(chan, idle=5.0, hard=90.0)
    warmup = time.time() - warm_start

    plan = build_plan()
    transcript = [f"# {name} transcript\n\n[connect] warmup {warmup:.1f}s\n{banner}"]
    latencies = []
    probes = {}          # key -> (passed, expected, got)
    substantive = 0

    for cmd, pkey, expect in plan:
        chan.send(cmd + "\n")
        t0 = time.time()
        out = read_until_idle(chan, idle=4.0, hard=60.0)
        dt = time.time() - t0
        latencies.append(dt)
        body = clean(out)
        transcript.append(f"\n$ {cmd}    ({dt:.1f}s)\n{out.strip()}")

        # "substantive" = a non-empty response that isn't an obvious refusal/error
        low = body.lower()
        if body and not any(t in low for t in
                            ("connection closed", "connection to remote host",
                             "network is unreachable", "[ollama", "traceback")):
            substantive += 1

        if pkey:
            passed = expect.lower() in body.lower()
            probes[pkey] = (passed, expect, body[:200])
            print(f"  probe {pkey:<14} {'PASS' if passed else 'FAIL':<4} "
                  f"(want '{expect}')  {dt:.1f}s")
        else:
            print(f"  cmd   {cmd:<28} {dt:.1f}s")

    chan.send("exit\n")
    time.sleep(0.5)
    c.close()

    passes = sum(1 for p in probes.values() if p[0])
    result = {
        "name": name,
        "port": port,
        "warmup_s": warmup,
        "n_cmds": len(plan),
        "substantive": substantive,
        "_latencies": latencies,
        "consistency_pass": passes,
        "consistency_total": len(probes),
        "probes": probes,
        "transcript": "\n".join(transcript),
    }
    return result


def aggregate(name, port, runs):
    """Fold N single-run results for one target into averaged metrics."""
    probe_keys = ["file_readback", "ls_agreement", "cd_persist", "env_recall"]
    trials = len(runs)
    probe_pass = {k: sum(1 for r in runs if r["probes"].get(k, (False,))[0])
                  for k in probe_keys}
    all_lat = [x for r in runs for x in r["_latencies"]]
    return {
        "name": name,
        "port": port,
        "trials": trials,
        "n_cmds": runs[0]["n_cmds"],
        "probe_keys": probe_keys,
        "probe_pass": probe_pass,                       # key -> passes out of `trials`
        "consistency_pass": sum(probe_pass.values()),
        "consistency_total": len(probe_keys) * trials,
        "substantive_mean": statistics.mean(r["substantive"] for r in runs),
        "lat_mean": statistics.mean(all_lat) if all_lat else 0,
        "lat_median": statistics.median(all_lat) if all_lat else 0,
        "warmup_mean": statistics.mean(r["warmup_s"] for r in runs),
        "transcript": "\n\n".join(r["transcript"] for r in runs),
    }


def emit_report(results, outdir, trials):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(outdir, exist_ok=True)
    probe_keys = ["file_readback", "ls_agreement", "cd_persist", "env_recall"]
    lines = []
    lines.append("# LLM Honeypot Benchmark — shelLM vs beelzebub")
    lines.append(f"\n_Generated {datetime.now():%Y-%m-%d %H:%M:%S} · model `llama3.2:3b` "
                 f"(same for both) · {trials} trial(s) · via `src/redteam/benchmark.py`_\n")
    lines.append("## Consistency (the differentiator)\n")
    lines.append(f"Pass count over {trials} trial(s) — higher is better.\n")
    lines.append("| Probe | " + " | ".join(r["name"] for r in results) + " |")
    lines.append("|---|" + "---|" * len(results))
    labels = {
        "file_readback": "File read-back (`cat` matches earlier `echo`)",
        "ls_agreement": "Listing agrees (`ls` shows the written file)",
        "cd_persist": "Directory persists (`cd` then `pwd`)",
        "env_recall": "Env recall (`export` then `echo $VAR`)",
    }
    for k in probe_keys:
        row = [labels[k]]
        for r in results:
            row.append(f"{r['probe_pass'][k]}/{r['trials']}")
        lines.append("| " + " | ".join(row) + " |")
    lines.append("\n**Overall consistency:** " +
                 " · ".join(f"{r['name']} {r['consistency_pass']}/{r['consistency_total']}"
                            f" ({100*r['consistency_pass']//max(r['consistency_total'],1)}%)"
                            for r in results))

    lines.append("\n## Engagement & latency\n")
    lines.append("| Metric | " + " | ".join(r["name"] for r in results) + " |")
    lines.append("|---|" + "---|" * len(results))
    lines.append("| Commands answered substantively (avg) | " +
                 " | ".join(f"{r['substantive_mean']:.1f}/{r['n_cmds']}" for r in results) + " |")
    lines.append("| Mean response latency (s) | " +
                 " | ".join(f"{r['lat_mean']:.1f}" for r in results) + " |")
    lines.append("| Median response latency (s) | " +
                 " | ".join(f"{r['lat_median']:.1f}" for r in results) + " |")
    lines.append("| First-response warmup (s, avg) | " +
                 " | ".join(f"{r['warmup_mean']:.1f}" for r in results) + " |")

    lines.append("\n## Reading it\n")
    lines.append("- **Consistency** is shelLM's whole pitch: session memory so a file "
                 "shown by `ls` can be `cat`-ed. beelzebub answers each command as an "
                 "independent LLM call (breadth over depth), so it tends to fail the "
                 "read-back / listing probes — by design, not as a bug.")
    lines.append("- Same model for both, so this compares **honeypot design**, not the "
                 "model. On a small local model (`llama3.2:3b`) even shelLM's "
                 "consistency is probabilistic — a bigger model would score higher.")
    lines.append("- Both feed the same Wazuh SIEM (beelzebub → rule 100301, "
                 "shelLM → rule 100311), so these sessions are also visible in Discover.")

    report = "\n".join(lines) + "\n"
    rpath = os.path.join(outdir, f"benchmark_{ts}.md")
    with open(rpath, "w") as f:
        f.write(report)
    # transcripts
    tpath = os.path.join(outdir, f"benchmark_{ts}_transcripts.md")
    with open(tpath, "w") as f:
        for r in results:
            f.write(r["transcript"] + "\n\n" + "-" * 70 + "\n\n")
    return rpath, tpath, report


def main():
    ap = argparse.ArgumentParser(description="shelLM vs beelzebub LLM honeypot benchmark")
    ap.add_argument("--only", choices=list(TARGETS), help="benchmark just one target")
    ap.add_argument("--trials", type=int, default=3,
                    help="runs per target, averaged (default 3; reduces small-model noise)")
    ap.add_argument("--outdir", default="reports", help="where to write the report")
    args = ap.parse_args()

    targets = {args.only: TARGETS[args.only]} if args.only else TARGETS
    results = []
    for name, port in targets.items():
        runs = []
        for t in range(1, args.trials + 1):
            print(f"\n### {name} — trial {t}/{args.trials}")
            try:
                runs.append(run_target(name, port))
            except Exception as e:
                print(f"[!] {name} trial {t} failed: {type(e).__name__}: {e}")
        if runs:
            results.append(aggregate(name, port, runs))

    if not results:
        print("[!] No results (are the honeypots up? "
              "docker compose -f compose/shellm.yml -f compose/beelzebub.yml up -d)")
        sys.exit(1)

    rpath, tpath, report = emit_report(results, args.outdir, args.trials)
    print("\n" + report)
    print(f"[+] report      -> {rpath}")
    print(f"[+] transcripts -> {tpath}")


if __name__ == "__main__":
    main()
