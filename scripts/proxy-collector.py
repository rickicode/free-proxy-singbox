#!/usr/bin/env python3
"""
/opt/proxy-collector.py
Pull pre-verified live proxies from free-proxy-singbox GitHub repo and update
sing-box config. No re-testing needed — all proxies already pass TCP + live
test + GeoIP on GitHub Actions.

Flow:
  1. Fetch live-proxies.json from GitHub raw
  2. Keep existing free-* proxies with clash delay <500ms
  3. Pull fresh candidates from GitHub output (already live-tested)
  4. Assign country-based tags with local numbering
  5. Build PROXY-FREE + per-country groups (US, SG, ID, ...)
  6. Update selectors, restart sing-box
"""
import json, subprocess, time, urllib.request, os, sys, urllib.parse, random
from collections import OrderedDict, Counter

# ── Config ──────────────────────────────────────────────────────────────────
CONFIG        = "/etc/sing-box/config.json"
SINGBOX       = "/usr/local/bin/sing-box"
GITHUB_RAW    = "https://raw.githubusercontent.com/rickicode/free-proxy-singbox/main/output/live-proxies.json"

KEEP_MS       = 500       # keep existing proxy if clash delay < this
MAX_FREE      = 40        # max outbounds in PROXY-FREE
TARGET_GROUPS = {"US","SG","ID","JP","KR","HK","DE","FR","GB","CA","AU","IN","NL","BR"}

# ── Helpers ──────────────────────────────────────────────────────────────────
def info(msg):  print(f"  \033[36m→\033[0m {msg}")
def ok(msg):    print(f"  \033[32m✓\033[0m {msg}")
def fail(msg):  print(f"  \033[31m✗\033[0m {msg}")

def run(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str),
                          capture_output=True, text=True, **kw)

def load_config():
    with open(CONFIG) as f:
        return json.load(f)

def save_config(c):
    with open(CONFIG, "w") as f:
        json.dump(c, f, indent=2)

# ── 1. Fetch from GitHub ────────────────────────────────────────────────────
def fetch_github_proxies():
    """Fetch live-proxies.json — all proxies already TCP + live + GeoIP verified."""
    try:
        req = urllib.request.Request(GITHUB_RAW, headers={"User-Agent": "curl/8.0"})
        data = json.loads(urllib.request.urlopen(req, timeout=30).read())
        proxies = data.get("proxies", [])
        print(f"\n[fetch] GitHub: {len(proxies)} proxies ({data.get('generated_at','?')})")
        cc_counts = Counter(p["country_code"] for p in proxies)
        print(f"[fetch] Countries: {dict(cc_counts.most_common())}")
        return proxies
    except Exception as e:
        print(f"  \033[31m✗\033[0m GitHub fetch failed: {e}")
        return []

# ── 2. Keep-alive via clash API ─────────────────────────────────────────────
def clash_delay(tag, timeout_ms=3000):
    """Quick delay check via local clash API — lightweight, no sing-box restart."""
    try:
        url = f"http://127.0.0.1:9090/proxies/{urllib.parse.quote(tag)}/delay?timeout={timeout_ms}&url=http://cp.cloudflare.com/generate_204"
        r = json.loads(urllib.request.urlopen(url, timeout=5).read())
        return r.get("delay", 9999)
    except:
        return 9999

def keep_existing(config):
    """Test existing free-* proxies via clash API. Keep if delay < KEEP_MS."""
    existing = [o for o in config["outbounds"] if o["tag"].startswith("free-")]
    if not existing:
        return [], set(), {}

    print(f"\n── Keep-alive: {len(existing)} existing ──")
    kept = []
    for ob in existing:
        delay = clash_delay(ob["tag"])
        if delay < KEEP_MS:
            kept.append(ob)
            ok(f"{ob['tag']:35} {delay}ms")
        else:
            fail(f"{ob['tag']:35} {delay}ms")

    kept_servers = {(o["server"], o["server_port"]) for o in kept}
    # Extract country code from kept tags (free-US-1 → US)
    kept_cc = {}
    for o in kept:
        parts = o["tag"].split("-")
        if len(parts) >= 2:
            kept_cc[o["tag"]] = parts[1]  # free-US-1 → US

    print(f"  Kept: {len(kept)} / {len(existing)}")
    return kept, kept_servers, kept_cc

# ── 3. Pick fresh from GitHub ───────────────────────────────────────────────
def pick_fresh(github_proxies, kept_servers, slots_needed):
    """Pick candidates from GitHub output, excluding servers already kept."""
    candidates = [
        p for p in github_proxies
        if (p["server"], p["server_port"]) not in kept_servers
    ]
    print(f"\n── Fresh candidates: {len(candidates)} available, need {slots_needed} ──")

    if not candidates or slots_needed <= 0:
        return []

    # Prioritize target countries, shuffle within each
    random.shuffle(candidates)
    candidates.sort(key=lambda p: (
        0 if p.get("country_code") in TARGET_GROUPS else 1,
    ))

    selected = candidates[:slots_needed]
    cc_counts = Counter(p.get("country_code", "XX") for p in selected)
    for cc, n in sorted(cc_counts.items()):
        print(f"  {cc}: {n}")
    return selected

def build_outbounds(kept_obs, fresh_proxies, kept_cc):
    """Build a list of outbounds with numbered tags: free-US-1, free-SG-1, etc."""
    # Collect all
    all_items = []

    # Kept outbounds (already have tags, keep them)
    for ob in kept_obs:
        all_items.append({
            "outbound": ob,
            "country": kept_cc.get(ob["tag"], ob.get("_cc", "XX")),
            "keep_tag": ob["tag"],
        })

    # Fresh proxies (new tags needed)
    for p in fresh_proxies:
        all_items.append({
            "outbound": dict(p["outbound"]),
            "country": p.get("country_code", "XX"),
            "keep_tag": None,
        })

    # Group by country
    by_cc = OrderedDict()
    for item in all_items:
        cc = item["country"]
        if cc not in by_cc:
            by_cc[cc] = []
        by_cc[cc].append(item)

    # Assign tags: kept proxies keep original tag, fresh get new tag
    outbounds = []
    cc_count = {}
    for cc in sorted(by_cc.keys()):
        for item in by_cc[cc]:
            if item["keep_tag"]:
                # Keep original tag
                outbounds.append(item["outbound"])
                # Extract number from existing tag to update counter
                parts = item["keep_tag"].split("-")
                if len(parts) >= 3 and parts[2].isdigit():
                    n = int(parts[2])
                    cc_count[cc] = max(cc_count.get(cc, 0), n)
            else:
                cc_count[cc] = cc_count.get(cc, 0) + 1
                ob = item["outbound"]
                ob["tag"] = f"free-{cc}-{cc_count[cc]}"
                outbounds.append(ob)

    # Re-count for display
    final_counts = Counter()
    for ob in outbounds:
        parts = ob["tag"].split("-")
        if len(parts) >= 2:
            final_counts[parts[1]] += 1

    print(f"\n  Final: {len(outbounds)} proxies across {len(final_counts)} countries")
    for cc, n in sorted(final_counts.items()):
        print(f"    free-{cc}: {n}")

    return outbounds

def update_config(config, free_obs):
    """Remove old free-* + PROXY-* groups, add new ones, update selectors."""

    # Collect all PROXY-* group names to remove
    proxy_groups = {f"PROXY-{cc}" for cc in TARGET_GROUPS}
    proxy_groups.add("PROXY-FREE")

    # Remove old free-* outbounds and PROXY-* groups
    config["outbounds"] = [
        o for o in config["outbounds"]
        if not o["tag"].startswith("free-")
        and o["tag"] not in proxy_groups
    ]

    # Add new free outbounds
    config["outbounds"].extend(free_obs)

    # Group by country
    free_tags = [o["tag"] for o in free_obs]
    cc_groups = OrderedDict()
    for ob in free_obs:
        parts = ob["tag"].split("-")
        if len(parts) >= 2:
            cc = parts[1]
            if cc not in cc_groups:
                cc_groups[cc] = []
            cc_groups[cc].append(ob["tag"])

    # Add PROXY-FREE urltest
    if free_tags:
        config["outbounds"].append({
            "type": "urltest", "tag": "PROXY-FREE",
            "outbounds": free_tags,
            "url": "http://cp.cloudflare.com/generate_204",
            "interval": "10m", "tolerance": 100,
        })

    # Add per-country urltest groups
    for cc in TARGET_GROUPS:
        tags = cc_groups.get(cc, [])
        if tags:
            config["outbounds"].append({
                "type": "urltest", "tag": f"PROXY-{cc}",
                "outbounds": tags,
                "url": "http://cp.cloudflare.com/generate_204",
                "interval": "10m", "tolerance": 100,
            })

    # Add groups to all selectors
    new_groups = ["PROXY-FREE"] + sorted(
        f"PROXY-{cc}" for cc in TARGET_GROUPS if cc in cc_groups
    )
    has_bf = any(ob["tag"].startswith("bf-") for ob in config["outbounds"])

    for o in config["outbounds"]:
        if o["type"] == "selector":
            for g in new_groups:
                if g not in o["outbounds"] and g != o["tag"]:
                    o["outbounds"].append(g)
            if has_bf and "PROXY-BARRYFAR" not in o["outbounds"]:
                o["outbounds"].append("PROXY-BARRYFAR")

# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    config = load_config()
    if not config:
        print("Cannot read config"); sys.exit(1)

    # Step 1: keep existing via clash API
    kept_obs, kept_servers, kept_cc = keep_existing(config)
    slots_needed = MAX_FREE - len(kept_obs)

    if slots_needed <= 0:
        print(f"\nPool full ({len(kept_obs)} >= {MAX_FREE}), keeping current.")
        free_obs = build_outbounds(kept_obs, [], kept_cc)
    else:
        # Step 2: fetch from GitHub
        all_proxies = fetch_github_proxies()
        if not all_proxies:
            print("No data from GitHub, keeping existing.")
            free_obs = build_outbounds(kept_obs, [], kept_cc)
        else:
            # Step 3: pick fresh
            fresh = pick_fresh(all_proxies, kept_servers, slots_needed)
            # Step 4: build outbounds with tags
            free_obs = build_outbounds(kept_obs, fresh, kept_cc)

    # Step 5: update config
    print(f"\n── Updating config ──")
    update_config(config, free_obs)

    # Step 6: validate + restart
    save_config(config)
    r = run([SINGBOX, "check", "-c", CONFIG])
    if r.returncode != 0:
        print(f"  \033[31m✗\033[0m Config error: {r.stdout.strip()}")
        sys.exit(1)

    run(["systemctl", "restart", "sing-box"])
    time.sleep(2)
    status = run(["systemctl", "is-active", "sing-box"]).stdout.strip()

    # Count per country
    cc_counts = Counter()
    for ob in free_obs:
        parts = ob["tag"].split("-")
        if len(parts) >= 2:
            cc_counts[parts[1]] += 1
    groups_str = ", ".join(f"PROXY-{k}({v})" for k, v in sorted(cc_counts.items()))

    print(f"\n  \033[32m✓\033[0m sing-box: {status} | {len(free_obs)} free proxies")
    print(f"  Groups: {groups_str}")


if __name__ == "__main__":
    main()
