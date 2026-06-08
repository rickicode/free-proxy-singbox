#!/usr/bin/env python3
"""
/opt/warp-refresh.py
Re-register WARP1 + WARP2 accounts via wgcf dan update sing-box config.
Jadwal: cron tiap 2 hari (0 */48 * * *)

Flow:
  1. wgcf generate → keypair baru
  2. wgcf register --accept-tos → daftar ke Cloudflare
  3. wgcf generate → dapatkan WireGuard config
  4. Parse private_key + addresses
  5. Update endpoint di /etc/sing-box/config.json
  6. Restart sing-box
"""
import json, subprocess, os, sys, time, re, tempfile

CONFIG    = "/etc/sing-box/config.json"
CRED_FILE = "/opt/warp-creds.json"
SINGBOX   = "/usr/local/bin/sing-box"
WGCF      = "/usr/local/bin/wgcf"

def info(msg):  print(f"  \033[36m→\033[0m {msg}")
def ok(msg):    print(f"  \033[32m✓\033[0m {msg}")
def fail(msg):  print(f"  \033[31m✗\033[0m {msg}")

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def ensure_wgcf():
    """Download wgcf binary if not found."""
    if os.path.exists(WGCF):
        return
    info("Downloading wgcf...")
    arch = run(["uname", "-m"]).stdout.strip()
    a = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, "amd64")
    url = f"https://github.com/ViRb3/wgcf/releases/latest/download/wgcf_{a}"
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
        data = urllib.request.urlopen(req, timeout=30).read()
        with open(WGCF, "wb") as f:
            f.write(data)
        os.chmod(WGCF, 0o755)
        ok(f"wgcf installed: {WGCF}")
    except Exception as e:
        fail(f"Download wgcf failed: {e}")
        sys.exit(1)


def register_via_wgcf():
    """Daftar WARP baru via wgcf. Return (privkey, addr_v4, addr_v6, client_id)."""
    work = tempfile.mkdtemp(prefix="warp-")
    try:
        # Generate keypair
        r = run([WGCF, "generate"], cwd=work)
        if r.returncode != 0:
            return None, f"generate failed: {r.stderr.strip()[:100]}"

        # Register (non-interactive)
        r = run([WGCF, "register", "--accept-tos"], cwd=work)
        if r.returncode != 0:
            err = r.stderr.strip()
            if "429" in err:
                return None, "RATE_LIMITED"
            return None, f"register failed: {err[:100]}"

        # Generate config
        r = run([WGCF, "generate"], cwd=work)
        if r.returncode != 0:
            return None, f"config generate failed: {r.stderr.strip()[:100]}"

        # Baca account file untuk client_id
        account = {}
        acct_file = os.path.join(work, "wgcf-account.toml")
        if os.path.exists(acct_file):
            with open(acct_file) as f:
                for line in f:
                    if "device_id" in line:
                        account["id"] = line.split("=")[-1].strip().strip('"')

        # Parse config
        conf_file = os.path.join(work, "wgcf-profile.conf")
        if not os.path.exists(conf_file):
            return None, "wgcf-profile.conf not found"

        with open(conf_file) as f:
            conf = f.read()

        priv = re.search(r"PrivateKey\s*=\s*(\S+)", conf)
        addr = re.search(r"Address\s*=\s*(\S+)", conf)
        if not priv or not addr:
            return None, "cannot parse wgcf config"

        addrs = addr.group(1).split(",")
        addr_v4 = addrs[0].strip()
        addr_v6 = addrs[1].strip() if len(addrs) > 1 else ""

        return {
            "private_key": priv.group(1),
            "address_v4": addr_v4,
            "address_v6": addr_v6,
            "client_id": account.get("id", ""),
        }, None
    finally:
        # Bersihkan temp
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def load_creds():
    if os.path.exists(CRED_FILE):
        try:
            with open(CRED_FILE) as f:
                return json.load(f)
        except: pass
    return {}

def save_creds(creds):
    with open(CRED_FILE, "w") as f:
        json.dump(creds, f, indent=2)


def refresh_warp(label, ep_tag):
    """Refresh satu akun WARP."""
    info(f"Registering {label} ({ep_tag})...")

    result, err = register_via_wgcf()
    if err == "RATE_LIMITED":
        fail(f"Rate limited — coba lagi nanti")
        return False
    if err:
        fail(f"{err}")
        return False
    if not result:
        fail(f"Gagal register")
        return False

    ok(f"{result['address_v4']} / {result['address_v6'][:30]}...")

    # Update config
    with open(CONFIG) as f:
        c = json.load(f)

    found = False
    for ep in c.get("endpoints", []):
        if ep["tag"] == ep_tag:
            ep["private_key"] = result["private_key"]
            ep["address"] = [result["address_v4"], result["address_v6"]]
            found = True
            break

    if not found:
        fail(f"Endpoint {ep_tag} tidak ditemukan di config")
        return False

    with open(CONFIG, "w") as f:
        json.dump(c, f, indent=2)

    # Simpan credential
    creds = load_creds()
    creds[label] = {
        "private_key": result["private_key"],
        "address_v4": result["address_v4"],
        "address_v6": result["address_v6"],
        "client_id": result.get("client_id", ""),
        "refreshed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_creds(creds)
    return True


def ensure_deps():
    """Install dependencies: wireguard-tools (wg) + wgcf binary."""
    # wireguard-tools for wg genkey/wg pubkey
    r = run(["which", "wg"])
    if r.returncode != 0:
        info("Installing wireguard-tools...")
        run(["apt-get", "install", "-y", "-qq", "wireguard-tools"])
        ok("wireguard-tools installed")
    # wgcf binary
    ensure_wgcf()


def main():
    force = "--force" in sys.argv
    print(f"\n  \033[1mWARP Refresh\033[0m")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")

    ensure_deps()

    # Freshness check
    creds = load_creds()
    w1_ok = w2_ok = False

    if not force and creds:
        for label, ep in [("WARP1", "warp-ep"), ("WARP2", "warp2-ep")]:
            last = creds.get(label, {}).get("refreshed_at", "")
            if last:
                try:
                    t = time.mktime(time.strptime(last, "%Y-%m-%dT%H:%M:%SZ"))
                    days = (time.time() - t) / 86400
                    if days < 2:
                        ok(f"{label} masih fresh ({days:.1f} hari)")
                        if label == "WARP1": w1_ok = True
                        else: w2_ok = True
                except: pass

    if w1_ok and w2_ok:
        print(f"  \033[33m→\033[0m Kedua WARP masih fresh. Gunakan --force untuk paksa refresh.\n")
        return

    rate_limited = False
    for label, ep in [("WARP1", "warp-ep"), ("WARP2", "warp2-ep")]:
        ok_flag = w1_ok if label == "WARP1" else w2_ok
        if ok_flag:
            continue
        print()
        if not refresh_warp(label, ep):
            rate_limited = True
        time.sleep(2)

    # Validate + restart
    print()
    r = run([SINGBOX, "check", "-c", CONFIG])
    if r.returncode != 0:
        fail(f"Config error: {r.stdout.strip()}")
        sys.exit(1)

    run(["systemctl", "restart", "sing-box"])
    time.sleep(2)
    s = run(["systemctl", "is-active", "sing-box"]).stdout.strip()
    ok(f"sing-box: {s}")

    # Tampilkan hasil
    creds = load_creds()
    for label in ["WARP1", "WARP2"]:
        d = creds.get(label, {})
        if d:
            print(f"  {label}: {d.get('address_v4','')} / {d.get('address_v6','')[:30]}...")

    if rate_limited:
        print(f"\n  \033[33m⚠\033[0m Beberapa akun kena rate limit. Akan dicoba lagi di cron berikutnya.\n")


if __name__ == "__main__":
    main()
