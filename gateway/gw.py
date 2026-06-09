#!/usr/bin/env python3
"""
/opt/gw.py — Gateway Manager (sing-box + WARP)
Run without args for interactive menu, or: gw <command> [args]

Setup jaringan dilakukan otomatis saat `gw install` dengan auto-detect
interface WAN/LAN. Konfigurasi tersimpan di /opt/gateway-config.json.
"""
import json, sys, os, subprocess, urllib.request, tarfile, tempfile, shutil, time

# ── Paths ───────────────────────────────────────────────────────────────────
SINGBOX_BIN   = "/usr/local/bin/sing-box"
SINGBOX_CFG   = "/etc/sing-box/config.json"
SINGBOX_UI    = "/etc/sing-box/ui"
TPROXY_SCRIPT = "/usr/local/bin/tproxy-setup"
SERVICE_FILE  = "/etc/systemd/system/sing-box.service"
STORAGE       = "/opt/proxy-rules.json"
GW_CFG        = "/opt/gateway-config.json"
RULES_DIR     = "/opt/rules"
COMPILED_DIR  = "/opt/rules/compiled"
LOG_FILE      = "/var/log/sing-box.log"
SINGBOX_VER   = "1.13.13"

META_BASE   = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite"
PROXY_AWARE_SELECTORS = {"GLOBAL", "GOOGLE", "OPENAI", "IPCHECK", "PORT-1010", "PORT-1011", "PORT-1012"}
MANAGED_SELECTORS = PROXY_AWARE_SELECTORS | {"WAN"}

# WARP credentials — jangan hardcode! Di-load dari /opt/warp-creds.json
# (dibikin otomatis oleh warp-refresh.py saat install)
WARP_PUBKEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WARP_CREDS  = "/opt/warp-creds.json"


def load_warp_creds():
    """Load WARP credentials dari warp-creds.json. Fallback placeholder."""
    fallback = {
        "WARP1": {"private_key": "", "address_v4": "172.16.0.2/32", "address_v6": "2606:4700:110::/128"},
        "WARP2": {"private_key": "", "address_v4": "172.16.0.3/32", "address_v6": "2606:4700:110::1/128"},
    }
    if os.path.exists(WARP_CREDS):
        try:
            with open(WARP_CREDS) as f:
                data = json.load(f)
            return {
                k: {
                    "private_key": data.get(k, {}).get("private_key", ""),
                    "address_v4": data.get(k, {}).get("address_v4", fallback[k]["address_v4"]),
                    "address_v6": data.get(k, {}).get("address_v6", fallback[k]["address_v6"]),
                }
                for k in ["WARP1", "WARP2"]
            }
        except:
            pass
    return fallback


# ═════════════════════════════════════════════════════════════════════════════
#  NETWORK CONFIG — auto-detect + simpan di /opt/gateway-config.json
# ═════════════════════════════════════════════════════════════════════════════

def load_net_config():
    """Load gateway network config from /opt/gateway-config.json.
    Returns dict dengan default fallback jika file tidak ada."""
    defaults = {
        "wan_if": "eth0",
        "wan2_if": "eth1",
        "lan_if": "eth2",
        "lan_subnet": "192.168.92.0/24",
        "lan_ip": "192.168.92.1/24",
        "tproxy_port": 7893,
        "clash_port": 9090,
        "mixed_port": 7890,
    }
    if os.path.exists(GW_CFG):
        try:
            with open(GW_CFG) as f:
                return {**defaults, **json.load(f)}
        except: pass
    return dict(defaults)

def save_net_config(cfg):
    os.makedirs(os.path.dirname(GW_CFG), exist_ok=True)
    with open(GW_CFG, "w") as f:
        json.dump(cfg, f, indent=2)

def detect_network():
    """Auto-detect WAN interface (default route) and candidate LAN interfaces."""
    net = {}

    # WAN: ambil dari default route
    r = run("ip route show default", capture=True, check=False)
    parts = r.stdout.strip().split()
    wan = parts[4] if len(parts) >= 5 else "eth0"

    # Semua interface non-loopback
    r = run("ip -br addr show", capture=True)
    interfaces = []
    for line in r.stdout.strip().splitlines():
        parts = line.split()
        name = parts[0]
        if name == "lo" or name.startswith(("singtun", "tun", "docker")):
            continue
        ip = parts[1] if len(parts) > 1 and parts[1] != "DOWN" else ""
        interfaces.append((name, ip))

    # Kandidat LAN: bukan WAN, punya IP private
    lan_candidates = []
    for name, ip in interfaces:
        if name == wan:
            continue
        if ip and ip.startswith(("192.168.", "10.", "172.")):
            lan_candidates.append(name)

    print(f"\n  {bold('Network Detection')}")
    print(f"  WAN interface detected: {wan}")
    net["wan_if"] = ask(f"WAN interface", wan)

    if lan_candidates:
        print(f"  LAN candidate(s): {', '.join(lan_candidates)}")
        default_lan = lan_candidates[0]
    else:
        default_lan = "eth2"
        print(f"  No LAN interface detected with private IP.")
    net["lan_if"] = ask(f"LAN interface", default_lan)

    # Cek IP existing di LAN interface
    r = run(f"ip -br addr show {net['lan_if']}", capture=True, check=False)
    parts = r.stdout.strip().split()
    existing_ip = ""
    for p in parts[1:]:
        if "/" in p:
            existing_ip = p
            break

    print(f"  LAN current IP: {existing_ip or '(none)'}")
    default_subnet = existing_ip.rsplit(".", 1)[0] + ".0/24" if existing_ip else "192.168.92.0/24"
    default_lan_ip = existing_ip or default_subnet.rsplit(".", 1)[0] + ".1/24"

    net["lan_subnet"] = ask("LAN subnet CIDR", default_subnet)
    net["lan_ip"] = ask("LAN interface IP", default_lan_ip)

    return net

def setup_network(net):
    """Apply network config: set LAN IP, enable forwarding, NAT."""
    # Set LAN IP jika belum ada
    existing = run(f"ip -br addr show {net['lan_if']}", capture=True, check=False).stdout.strip()
    if net["lan_ip"] not in existing:
        info(f"Setting IP {net['lan_ip']} on {net['lan_if']}...")
        run(f"ip addr add {net['lan_ip']} dev {net['lan_if']}", check=False)
        ok(f"LAN IP set: {net['lan_ip']}")

    # IP forwarding
    run("sysctl -w net.ipv4.ip_forward=1", capture=True)
    with open("/etc/sysctl.d/99-gateway.conf", "w") as f:
        f.write("net.ipv4.ip_forward=1\n")

    # NAT MASQUERADE
    run(f"iptables -t nat -C POSTROUTING -s {net['lan_subnet']} -o {net['wan_if']} -j MASQUERADE 2>/dev/null || "
        f"iptables -t nat -A POSTROUTING -s {net['lan_subnet']} -o {net['wan_if']} -j MASQUERADE")
    run("apt-get install -y -qq iptables-persistent 2>/dev/null; netfilter-persistent save 2>/dev/null",
        check=False)
    ok("IP forwarding + NAT ready")

    save_net_config(net)


# ═════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def run(cmd, check=True, capture=False):
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check,
                          capture_output=capture, text=True)

def ok(msg):    print(f"\033[32m✓\033[0m {msg}")
def info(msg):  print(f"\033[36m→\033[0m {msg}")
def err(msg):   print(f"\033[31m✗\033[0m {msg}")
def bold(s):    return f"\033[1m{s}\033[0m"
def ask(prompt, default=""):
    try:
        return input(f"  {prompt} [{default}]: ").strip() or default
    except (EOFError, KeyboardInterrupt):
        return default

def load_storage():
    if os.path.exists(STORAGE):
        with open(STORAGE) as f:
            return json.load(f)
    return []

def save_storage(rules):
    with open(STORAGE, "w") as f:
        json.dump(rules, f, indent=2)


# ═════════════════════════════════════════════════════════════════════════════
#  CONFIG BUILDER
# ═════════════════════════════════════════════════════════════════════════════

def build_config():
    """Build base sing-box config. Preserves dynamic outbounds (PROXY-*)."""
    net = load_net_config()
    creds = load_warp_creds()
    # Auto-generate WARP keys jika creds belum ada (install fresh)
    for k in ["WARP1", "WARP2"]:
        if not creds[k]["private_key"]:
            try:
                priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True).stdout.strip()
                if priv:
                    creds[k]["private_key"] = priv
            except:
                pass
    managed = load_storage()

    # Dynamic outbounds (PROXY-*, free-*) dikelola oleh proxy-collector.
    # Jangan di-preserve di base config — nanti ditambah otomatis.
    wan_if = net.get("wan_if", "eth0")
    wan2_if = net.get("wan2_if", "eth1")
    base_choices = ["DIRECT", "WAN", "WAN-AUTO", "WAN1", "WAN2", "WARP", "WARP1", "WARP2"]

    return {
        "log": {"level": "info", "output": LOG_FILE, "timestamp": True},
        "dns": {
            "servers": [{"type": "udp", "tag": "local", "server": "1.1.1.1"}],
            "strategy": "ipv4_only"
        },
        "experimental": {"clash_api": {
            "external_controller": f"0.0.0.0:{net['clash_port']}",
            "external_ui": SINGBOX_UI, "secret": "hijinet"
        }},
        "endpoints": [{
            "type": "wireguard", "tag": "warp-ep", "system": True,
            "name": "singtun0", "mtu": 1280,
            "address": [creds["WARP1"]["address_v4"], creds["WARP1"]["address_v6"]],
            "private_key": creds["WARP1"]["private_key"],
            "peers": [{"address": "engage.cloudflareclient.com", "port": 2408,
                       "public_key": WARP_PUBKEY,
                       "allowed_ips": ["0.0.0.0/0", "::/0"],
                       "persistent_keepalive_interval": 25}]
        }, {
            "type": "wireguard", "tag": "warp2-ep", "system": True,
            "name": "singtun1", "mtu": 1280,
            "address": [creds["WARP2"]["address_v4"], creds["WARP2"]["address_v6"]],
            "private_key": creds["WARP2"]["private_key"],
            "peers": [{"address": "engage.cloudflareclient.com", "port": 2408,
                       "public_key": WARP_PUBKEY,
                       "allowed_ips": ["0.0.0.0/0", "::/0"],
                       "persistent_keepalive_interval": 25}]
        }],
        "inbounds": [
            {"type": "tun", "tag": "tun-in",
             "address": ["172.19.0.1/30"],
             "auto_route": True, "strict_route": True, "stack": "system",
             "exclude_interface": ["singtun0", "singtun1", net["lan_if"]]},
            {"type": "tproxy", "tag": "tproxy-in",
             "listen": "0.0.0.0", "listen_port": net["tproxy_port"], "network": "tcp"},
            {"type": "tproxy", "tag": "tproxy-udp-in",
             "listen": "0.0.0.0", "listen_port": net["tproxy_port"], "network": "udp"},
            {"type": "mixed", "tag": "mixed-in",
             "listen": "0.0.0.0", "listen_port": net["mixed_port"]},
            {"type": "mixed", "tag": "mixed-1010",
             "listen": "0.0.0.0", "listen_port": 1010},
            {"type": "mixed", "tag": "mixed-1011",
             "listen": "0.0.0.0", "listen_port": 1011},
            {"type": "mixed", "tag": "mixed-1012",
             "listen": "0.0.0.0", "listen_port": 1012},
        ],
        "outbounds": [
            {"type": "direct", "tag": "DIRECT"},
            {"type": "direct", "tag": "WAN1", "bind_interface": wan_if},
            {"type": "direct", "tag": "WAN2", "bind_interface": wan2_if},
            {"type": "selector", "tag": "WAN",
             "outbounds": ["WAN1", "WAN2"], "default": "WAN1"},
            {"type": "urltest", "tag": "WAN-AUTO",
             "outbounds": ["WAN1", "WAN2"],
             "url": "http://cp.cloudflare.com/generate_204",
             "interval": "30s", "tolerance": 50},
            {"type": "block", "tag": "BLOCK"},
            {"type": "direct", "tag": "WARP1", "bind_interface": "singtun0"},
            {"type": "direct", "tag": "WARP2", "bind_interface": "singtun1"},
            {"type": "urltest", "tag": "WARP",
             "outbounds": ["WARP1", "WARP2"],
             "url": "http://cp.cloudflare.com/generate_204",
             "interval": "3m", "tolerance": 50},
            {"type": "selector", "tag": "GLOBAL",
             "outbounds": base_choices,
             "default": "DIRECT"},
            {"type": "selector", "tag": "GOOGLE",
             "outbounds": base_choices, "default": "DIRECT"},
            {"type": "selector", "tag": "OPENAI",
             "outbounds": base_choices, "default": "WARP"},
            {"type": "selector", "tag": "IPCHECK",
             "outbounds": base_choices, "default": "WARP"},
            {"type": "selector", "tag": "PORT-1010",
             "outbounds": base_choices, "default": "WARP"},
            {"type": "selector", "tag": "PORT-1011",
             "outbounds": base_choices, "default": "WARP2"},
            {"type": "selector", "tag": "PORT-1012",
             "outbounds": base_choices, "default": "WARP1"},
        ],
        "route": {
            "auto_detect_interface": True,
            "rule_set": [
                {"type": "remote", "tag": "community-speedtest", "format": "binary",
                 "url": f"{META_BASE}/speedtest.srs",
                 "download_detour": "DIRECT", "update_interval": "24h"},
                {"type": "local", "tag": "local-ip-check", "format": "binary",
                 "path": f"{COMPILED_DIR}/ip-check.srs"},
                {"type": "remote", "tag": "community-openai", "format": "binary",
                 "url": f"{META_BASE}/openai.srs",
                 "download_detour": "DIRECT", "update_interval": "24h"},
                {"type": "remote", "tag": "community-anthropic", "format": "binary",
                 "url": f"{META_BASE}/anthropic.srs",
                 "download_detour": "DIRECT", "update_interval": "24h"},
                {"type": "remote", "tag": "community-google", "format": "binary",
                 "url": f"{META_BASE}/google.srs",
                 "download_detour": "DIRECT", "update_interval": "24h"},
                {"type": "remote", "tag": "community-google-play", "format": "binary",
                 "url": f"{META_BASE}/google-play.srs",
                 "download_detour": "DIRECT", "update_interval": "24h"},
                {"type": "remote", "tag": "community-youtube", "format": "binary",
                 "url": f"{META_BASE}/youtube.srs",
                 "download_detour": "DIRECT", "update_interval": "24h"},
            ],
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                # Tailscale/control-plane/CGNAT must never go through WARP or proxies.
                {"domain_suffix": ["tailscale.com", "tailscale.io", "ts.net"], "outbound": "DIRECT"},
                {"ip_cidr": ["100.64.0.0/10"], "outbound": "DIRECT"},
                {"network": "udp", "port": 41641, "outbound": "DIRECT"},
                {"ip_is_private": True, "outbound": "DIRECT"},
                {"inbound": ["mixed-1010"], "outbound": "PORT-1010"},
                {"inbound": ["mixed-1011"], "outbound": "PORT-1011"},
                {"inbound": ["mixed-1012"], "outbound": "PORT-1012"},
                *[{"domain": [r["host"]], "outbound": r["outbound"]} for r in managed],
                {"rule_set": ["community-openai", "community-anthropic"], "outbound": "OPENAI"},
                {"rule_set": ["community-google", "community-google-play",
                              "community-youtube"], "outbound": "GOOGLE"},
                {"rule_set": ["community-speedtest", "local-ip-check"], "outbound": "IPCHECK"},
            ],
            "final": "GLOBAL",
        },
    }


def apply_config(restart=True):
    cfg = build_config()

    # Preserve dynamic proxy pool managed by proxy-collector.
    # build_config() is only the base gateway config; do not wipe free-* / PROXY-*.
    if os.path.exists(SINGBOX_CFG):
        try:
            with open(SINGBOX_CFG) as f:
                old = json.load(f)
            dynamic = []
            custom_selectors = []
            for o in old.get("outbounds", []):
                tag = o.get("tag", "")
                if tag.startswith("free-") or tag.startswith("PROXY-"):
                    dynamic.append(o)
                elif o.get("type") == "selector" and tag not in MANAGED_SELECTORS:
                    custom_selectors.append(o)
            if dynamic:
                existing_tags = {o.get("tag") for o in cfg.get("outbounds", [])}
                cfg["outbounds"].extend(o for o in dynamic if o.get("tag") not in existing_tags)
                groups = sorted(o["tag"] for o in dynamic if o.get("tag", "").startswith("PROXY-"))
                for o in cfg.get("outbounds", []):
                    if o.get("type") == "selector" and o.get("tag") in PROXY_AWARE_SELECTORS:
                        base = [x for x in o.get("outbounds", []) if not x.startswith("PROXY-")]
                        o["outbounds"] = base + groups
                cfg["outbounds"].extend(custom_selectors)
        except Exception as e:
            print(f"  \033[33m!\033[0m Preserve dynamic proxies skipped: {e}")

    os.makedirs(os.path.dirname(SINGBOX_CFG), exist_ok=True)
    with open(SINGBOX_CFG, "w") as f:
        json.dump(cfg, f, indent=2)
    r = run([SINGBOX_BIN, "check", "-c", SINGBOX_CFG], check=False, capture=True)
    if r.returncode != 0:
        err("Config error: " + r.stdout.strip())
        return False
    if restart:
        run(["systemctl", "restart", "sing-box"], check=False)
        time.sleep(2)
        if run(["systemctl", "is-active", "sing-box"], check=False, capture=True).stdout.strip() == "active":
            ok("sing-box restarted")
            return True
        err("sing-box failed — check: journalctl -u sing-box -n 20")
        return False
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  COMPILE RULES
# ═════════════════════════════════════════════════════════════════════════════

def _compile_rules():
    os.makedirs(COMPILED_DIR, exist_ok=True)
    ip_check_json = f"{RULES_DIR}/ip-check.json"
    if not os.path.exists(ip_check_json):
        os.makedirs(RULES_DIR, exist_ok=True)
        rule = {"version": 2, "rules": [{
            "domain": ["ifconfig.co", "ifconfig.me", "icanhazip.com",
                       "wtfismyip.com", "checkip.amazonaws.com"],
            "domain_suffix": ["ipinfo.io", "ip-api.com", "ipify.org",
                              "ipwho.is", "browserleaks.com", "dnsleaktest.com",
                              "ipleak.net", "whoer.net", "whatismyipaddress.com",
                              "api.ipify.org", "api.ip.sb", "ipapi.co"],
        }]}
        with open(ip_check_json, "w") as f:
            json.dump(rule, f, indent=2)
    for jf in os.listdir(RULES_DIR):
        if not jf.endswith(".json"):
            continue
        src = os.path.join(RULES_DIR, jf)
        out = os.path.join(COMPILED_DIR, jf.replace(".json", ".srs"))
        r = run([SINGBOX_BIN, "rule-set", "compile", "--output", out, src],
                check=False, capture=True)
        if r.returncode == 0:
            ok(f"Compiled {jf}")
        else:
            err(f"Compile {jf}: {r.stderr.strip()}")


# ═════════════════════════════════════════════════════════════════════════════
#  INSTALL
# ═════════════════════════════════════════════════════════════════════════════

def cmd_install():
    info("Installing sing-box gateway...")
    net = load_net_config()

    # ── Network setup (auto-detect + prompt) ─────────────────────────────
    detected = detect_network()
    setup_network(detected)
    net = detected  # use fresh config

    # ── Download sing-box ─────────────────────────────────────────────────
    if not os.path.exists(SINGBOX_BIN):
        arch = run("uname -m", capture=True).stdout.strip()
        a = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, "amd64")
        url = (f"https://github.com/SagerNet/sing-box/releases/download/"
               f"v{SINGBOX_VER}/sing-box-{SINGBOX_VER}-linux-{a}.tar.gz")
        info(f"Downloading sing-box {SINGBOX_VER}...")
        with tempfile.TemporaryDirectory() as tmp:
            tgz = os.path.join(tmp, "sb.tar.gz")
            urllib.request.urlretrieve(url, tgz)
            with tarfile.open(tgz) as t:
                for m in t.getmembers():
                    if m.name.endswith("/sing-box"):
                        m.name = "sing-box"
                        t.extract(m, tmp)
                        break
            shutil.copy(os.path.join(tmp, "sing-box"), SINGBOX_BIN)
            os.chmod(SINGBOX_BIN, 0o755)
        ok(f"sing-box {SINGBOX_VER} installed")
    else:
        ok("sing-box already installed")

    # ── Dirs & user ──────────────────────────────────────────────────────
    run("id singbox &>/dev/null || useradd -r -s /bin/false singbox", check=False)
    os.makedirs("/etc/sing-box", exist_ok=True)
    os.makedirs(COMPILED_DIR, exist_ok=True)
    run("touch /var/log/sing-box.log && chown singbox:singbox /var/log/sing-box.log")
    ok("Dirs & user ready")

    # ── Tools: wireguard + wgcf ────────────────────────────────────────────
    run(["apt-get", "install", "-y", "-qq", "wireguard-tools"])
    ok("wireguard-tools installed")

    # ── YACD UI ──────────────────────────────────────────────────────────
    if not os.path.exists(os.path.join(SINGBOX_UI, "index.html")):
        info("Downloading YACD UI...")
        yacd_url = ("https://github.com/MetaCubeX/Yacd-meta/archive/"
                    "refs/heads/gh-pages.tar.gz")
        with tempfile.TemporaryDirectory() as tmp:
            tgz = os.path.join(tmp, "yacd.tar.gz")
            urllib.request.urlretrieve(yacd_url, tgz)
            with tarfile.open(tgz) as t:
                t.extractall(tmp)
            extracted = next(d for d in os.listdir(tmp)
                             if os.path.isdir(os.path.join(tmp, d)))
            if os.path.exists(SINGBOX_UI):
                shutil.rmtree(SINGBOX_UI)
            shutil.copytree(os.path.join(tmp, extracted), SINGBOX_UI)
        ok("YACD UI installed")

    # ── TProxy script ────────────────────────────────────────────────────
    with open(TPROXY_SCRIPT, "w") as f:
        f.write(f'''#!/bin/bash
# TProxy: traffic dari LAN {net["lan_if"]} -> sing-box :{net["tproxy_port"]}
TPROXY_PORT={net["tproxy_port"]}; TPROXY_MARK=0x01; LAN_IF={net["lan_if"]}
flush() {{
    iptables -t mangle -D PREROUTING -i $LAN_IF -j SING_BOX 2>/dev/null
    iptables -t mangle -F SING_BOX 2>/dev/null
    iptables -t mangle -X SING_BOX 2>/dev/null
    ip rule del fwmark $TPROXY_MARK table 100 2>/dev/null
    ip route del local default dev lo table 100 2>/dev/null
}}
[ "$1" = "stop" ] && {{ flush; echo "TProxy removed"; exit 0; }}
flush
ip rule add fwmark $TPROXY_MARK table 100
ip route add local default dev lo table 100
iptables -t mangle -N SING_BOX
iptables -t mangle -A SING_BOX -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A SING_BOX -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A SING_BOX -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A SING_BOX -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A SING_BOX -d 100.64.0.0/10 -j RETURN
iptables -t mangle -A SING_BOX -d {net['lan_subnet']} -j RETURN
iptables -t mangle -A SING_BOX -p tcp -j TPROXY --tproxy-mark $TPROXY_MARK --on-port $TPROXY_PORT
iptables -t mangle -A SING_BOX -p udp -j TPROXY --tproxy-mark $TPROXY_MARK --on-port $TPROXY_PORT
iptables -t mangle -A PREROUTING -i $LAN_IF -j SING_BOX
echo "TProxy applied"
''')
    os.chmod(TPROXY_SCRIPT, 0o755)
    ok("TProxy script installed")

    # ── systemd service ──────────────────────────────────────────────────
    with open(SERVICE_FILE, "w") as f:
        f.write(f"""[Unit]
Description=sing-box
After=network.target

[Service]
User=singbox
Group=singbox
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart={SINGBOX_BIN} run -c {SINGBOX_CFG}
ExecStartPost={TPROXY_SCRIPT}
ExecStopPost={TPROXY_SCRIPT} stop
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
""")
    run("systemctl daemon-reload")
    ok("systemd service configured")

    # ── Build config + rules + apply ─────────────────────────────────────
    _compile_rules()

    # Backup dynamic outbounds
    bak_file = SINGBOX_CFG + ".bak"
    if os.path.exists(SINGBOX_CFG):
        shutil.copy2(SINGBOX_CFG, bak_file)

    apply_config()
    run("systemctl enable sing-box", capture=True)

    # Restore dynamic proxies from backup
    if os.path.exists(bak_file):
        info("Restoring dynamic outbounds...")
        try:
            with open(bak_file) as f:
                bak = json.load(f)
            with open(SINGBOX_CFG) as f:
                c = json.load(f)
            dyn_obs = [o for o in bak["outbounds"] if o["tag"].startswith("bf-")]
            dyn_sel = [o for o in bak["outbounds"] if o["tag"].startswith("PROXY-")]
            if dyn_obs or dyn_sel:
                c["outbounds"].extend(dyn_obs + dyn_sel)
                proxy_tags = [s["tag"] for s in dyn_sel]
                for o in c["outbounds"]:
                    if o["type"] == "selector":
                        for pt in proxy_tags:
                            if pt not in o["outbounds"]:
                                o["outbounds"].append(pt)
                with open(SINGBOX_CFG, "w") as f:
                    json.dump(c, f, indent=2)
                r = run([SINGBOX_BIN, "check", "-c", SINGBOX_CFG],
                        check=False, capture=True)
                if r.returncode == 0:
                    run(["systemctl", "restart", "sing-box"], check=False)
                    ok(f"Restored {len(dyn_obs)} dyn outbounds + {len(dyn_sel)} selectors")
                else:
                    err("Restore failed, using fresh config")
        except Exception as e:
            err(f"Restore error: {e}")
        os.remove(bak_file)

    ip = run("hostname -I", capture=True).stdout.split()[0]
    print()
    # ── Install proxy-collector ──────────────────────────────────────────
    collector_py = "/opt/proxy-collector.py"
    collector_url = "https://raw.githubusercontent.com/rickicode/free-proxy-singbox/main/scripts/proxy-collector.py"
    if not os.path.exists(collector_py):
        info("Downloading proxy-collector.py...")
        try:
            req = urllib.request.Request(collector_url, headers={"User-Agent": "curl/8.0"})
            data = urllib.request.urlopen(req, timeout=30).read()
            with open(collector_py, "wb") as f:
                f.write(data)
            os.chmod(collector_py, 0o755)
            ok("proxy-collector.py installed")
        except Exception as e:
            err(f"Download proxy-collector failed: {e}")
    else:
        ok("proxy-collector.py already exists")

    # Download warp-refresh.py
    warp_py = "/opt/warp-refresh.py"
    if not os.path.exists(warp_py):
        warp_url = "https://raw.githubusercontent.com/rickicode/free-proxy-singbox/main/scripts/warp-refresh.py"
        try:
            req = urllib.request.Request(warp_url, headers={"User-Agent": "curl/8.0"})
            data = urllib.request.urlopen(req, timeout=30).read()
            with open(warp_py, "wb") as f:
                f.write(data)
            os.chmod(warp_py, 0o755)
            ok("warp-refresh.py installed")
        except Exception as e:
            err(f"Download warp-refresh.py failed: {e}")
    else:
        ok("warp-refresh.py already exists")

    # Initial warp refresh — generate WARP creds
    info("Generating initial WARP credentials...")
    run(["python3", warp_py, "--force"], check=False)
    ok("WARP credentials generated")

    # Set up cron
    cron_job = "0 */5 * * * /usr/bin/python3 /opt/proxy-collector.py >> /var/log/proxy-collector.log 2>&1"
    existing = run("crontab -l 2>/dev/null", capture=True, check=False).stdout
    if collector_py not in existing:
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(existing + cron_job + "\n")
            tmp = f.name
        run(f"crontab {tmp}", check=False)
        os.unlink(tmp)
        ok("Cron set: proxy-collector tiap 5 jam")
    else:
        ok("Cron already set")

    # Set up warp-refresh cron (tiap 2 hari)
    warp_cron = "0 0 */2 * * /usr/bin/python3 /opt/warp-refresh.py >> /var/log/warp-refresh.log 2>&1"
    if warp_cron not in existing:
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(existing + "\n" + warp_cron + "\n")
            tmp = f.name
        run(f"crontab {tmp}", check=False)
        os.unlink(tmp)
        ok("Cron set: warp-refresh tiap 2 hari")
    else:
        ok("Cron already set")

    # Initial run
    if os.path.exists(collector_py):
        info("Running initial proxy collection (--force)...")
        run(["python3", collector_py, "--force"], check=False)

    ip = run("hostname -I", capture=True).stdout.split()[0]
    print()
    ok("Installation complete!")
    info(f"WAN  : {net['wan_if']} ({ip})")
    info(f"LAN  : {net['lan_if']} ({net['lan_ip']})")
    info(f"NAT  : {net['lan_subnet']} -> {net['wan_if']}")
    info(f"YACD : http://{ip}:{net['clash_port']}/ui/")
    info(f"Proxy: {ip}:{net['mixed_port']}")
    info(f"Proxies: 40+ free proxy dari GitHub (auto-update tiap 5 jam)")


# ═════════════════════════════════════════════════════════════════════════════
#  SERVICE COMMANDS
# ═════════════════════════════════════════════════════════════════════════════

def cmd_status():
    net = load_net_config()
    svc = run(["systemctl", "is-active", "sing-box"], check=False, capture=True).stdout.strip()
    color = "\033[32m" if svc == "active" else "\033[31m"
    print(f"\n  sing-box : {color}{svc}\033[0m")

    # External IP via proxy
    r = run(f"curl -s --proxy http://127.0.0.1:{net['mixed_port']} "
            f"--max-time 5 ifconfig.co/json", capture=True, check=False)
    try:
        d = json.loads(r.stdout)
        print(f"  External : {d.get('ip','-')} | {d.get('asn_org','-')} | {d.get('city','-')}")
    except:
        print("  External : (unavailable)")

    # NAT
    nat = run(f"iptables -t nat -C POSTROUTING -s {net['lan_subnet']} "
              f"-o {net['wan_if']} -j MASQUERADE",
              check=False, capture=True).returncode == 0
    print(f"  NAT      : {'ON' if nat else 'OFF'}")
    print(f"  Rules    : {len(load_storage())} managed")

    # WARP interfaces
    for iface in ["singtun0", "singtun1"]:
        r2 = run(f"ip -br addr show {iface} 2>/dev/null", capture=True, check=False)
        if r2.stdout.strip():
            parts = r2.stdout.split()
            ip4 = parts[1] if len(parts) > 1 else "?"
            ip6 = next((p for p in parts[2:] if "2606" in p), "-")
            print(f"  {iface}  : {ip4} | {ip6}")

    print(f"  YACD     : http://0.0.0.0:{net['clash_port']}/ui/")
    print(f"  Config   : {GW_CFG}\n")


def cmd_start():
    run(["systemctl", "start", "sing-box"])
    ok("sing-box started")

def cmd_stop():
    run(["systemctl", "stop", "sing-box"])
    ok("sing-box stopped")

def cmd_restart():
    apply_config()

def cmd_enable():
    run(["systemctl", "enable", "sing-box"])
    ok("enabled on boot")

def cmd_disable():
    run(["systemctl", "disable", "sing-box"])
    ok("disabled")

def cmd_logs():
    os.execvp("journalctl", ["journalctl", "-u", "sing-box", "-f", "--no-pager"])

def cmd_compile():
    _compile_rules()
    apply_config()


def cmd_rule(args=None):
    if args is None:
        args = sys.argv[2:]
    if not args or args[0] == "list":
        rules = load_storage()
        if not rules:
            print("  No managed rules.")
            return
        print(f"\n  {'#':<4} {'HOST':<40} OUTBOUND\n  " + "-" * 58)
        for i, r in enumerate(rules, 1):
            print(f"  {i:<4} {r['host']:<40} {r['outbound']}")
        print()
    elif args[0] == "add" and len(args) == 3:
        host, ob = args[1], args[2]
        rules = load_storage()
        for r in rules:
            if r["host"] == host:
                r["outbound"] = ob
                save_storage(rules)
                ok(f"Updated: {host} -> {ob}")
                apply_config()
                return
        rules.append({"host": host, "outbound": ob})
        save_storage(rules)
        ok(f"Added: {host} -> {ob}")
        apply_config()
    elif args[0] == "remove" and len(args) == 2:
        rules = load_storage()
        new = [r for r in rules if r["host"] != args[1]]
        if len(new) < len(rules):
            save_storage(new)
            ok(f"Removed: {args[1]}")
            apply_config()
        else:
            err(f"Not found: {args[1]}")
    else:
        print("  Usage: gw rule list | add <host> <outbound> | remove <host>")


def cmd_mode(args=None):
    if args is None:
        args = sys.argv[2:]
    with open(SINGBOX_CFG) as f:
        c = json.load(f)
    if not args:
        for o in c["outbounds"]:
            if o["tag"] == "GLOBAL":
                print(f"  GLOBAL default: {o.get('default')}")
                return
    mode = args[0].upper()
    for o in c["outbounds"]:
        if o["tag"] == "GLOBAL":
            o["default"] = mode
    with open(SINGBOX_CFG, "w") as f:
        json.dump(c, f, indent=2)
    run(["systemctl", "restart", "sing-box"], check=False)
    ok(f"GLOBAL default -> {mode}")


def cmd_update_proxies():
    updater = "/opt/proxy-collector.py"
    if os.path.exists(updater):
        run(["python3", updater])
    else:
        err("proxy-collector.py not found")


COLLECTOR_STATE  = "/opt/.proxy-collector-state.json"
COLLECTOR_LOG    = "/opt/proxy-collector-last-run.json"


def cmd_collector_status():
    print(f"\n  {bold('Collector Status')}")
    state = {}
    if os.path.exists(COLLECTOR_STATE):
        with open(COLLECTOR_STATE) as f:
            state = json.load(f)
    last_run = state.get("last_run_at", "never")
    last_gen = state.get("last_generated_at", "-")
    print(f"  Last run    : {last_run}")
    print(f"  Last scan   : {last_gen}")

    # Baca dari local log — no need hit GitHub
    log = {}
    if os.path.exists(COLLECTOR_LOG):
        with open(COLLECTOR_LOG) as f:
            log = json.load(f)
    if log:
        r_gen = log.get("github_scan_at", "")
        r_live = log.get("total_proxies", "?")
        countries = log.get("countries", {})
        print(f"  Remote scan : {r_gen}")
        print(f"  Remote data : {r_live} live proxies across {len(countries)} countries")
        if countries:
            cc_list = ", ".join(f"{v['flag']} {k}({v['count']})" for k, v in sorted(countries.items()))
            print(f"  Countries   : {cc_list}")
        if last_gen == r_gen:
            print(f"  \033[32m✓\033[0m Fresh\n")
        else:
            print(f"  \033[33m!\033[0m Stale — run `gw update-proxies`\n")


def cmd_net_config():
    """Show current network config and allow re-config."""
    net = load_net_config()
    print(f"\n  {bold('Network Config (' + GW_CFG + ')')}")
    print(f"  WAN       : {net['wan_if']}")
    print(f"  LAN       : {net['lan_if']} ({net['lan_ip']})")
    print(f"  Subnet    : {net['lan_subnet']}")
    print(f"  TProxy    : :{net['tproxy_port']}")
    print(f"  Clash API : :{net['clash_port']}")
    print(f"  Mixed     : :{net['mixed_port']}")
    if ask("Re-configure?", "no") == "yes":
        detected = detect_network()
        setup_network(detected)
        ok("Network config updated")
        apply_config()


def cmd_warp_refresh():
    """Re-register WARP1 + WARP2 accounts via warp-refresh.py."""
    script = "/opt/warp-refresh.py"
    if os.path.exists(script):
        run(["python3", script] + ([sys.argv[2]] if len(sys.argv) > 2 and sys.argv[2] == "--force" else []))
    else:
        # Download jika belum ada
        url = "https://raw.githubusercontent.com/rickicode/free-proxy-singbox/main/scripts/warp-refresh.py"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
            data = urllib.request.urlopen(req, timeout=30).read()
            with open(script, "wb") as f:
                f.write(data)
            os.chmod(script, 0o755)
            ok("warp-refresh.py downloaded")
            run(["python3", script])
        except Exception as e:
            err(f"Download warp-refresh.py failed: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ═════════════════════════════════════════════════════════════════════════════

def interactive():
    while True:
        print(f"""
{bold('═══ Gateway Manager ═══')}
  1) Status
  2) Start / Stop / Restart
  3) Rule management
  4) Mode (GLOBAL default)
  5) Update proxies (free proxies)
  6) Collector status
  w) Warp refresh (2 hari)
  7) Network config
  8) Compile local rules
  9) Live logs
  i) Install / reinstall
  0) Exit
""")
        choice = ask("Choose", "0").strip()

        if choice == "1":
            cmd_status()
        elif choice == "2":
            print("\n  1) Start  2) Stop  3) Restart")
            a = ask("Choose", "3")
            if a == "1":
                cmd_start()
            elif a == "2":
                cmd_stop()
            else:
                cmd_restart()
        elif choice == "3":
            print(f"\n{bold('── Rule Management ──')}\n  1) List  2) Add  3) Remove\n")
            a = ask("Choose", "1")
            if a == "1":
                cmd_rule(["list"])
            elif a == "2":
                host = ask("Host")
                if host:
                    ob = ask("Outbound", "WARP")
                    cmd_rule(["add", host, ob])
            elif a == "3":
                cmd_rule(["list"])
                host = ask("Host to remove")
                if host:
                    cmd_rule(["remove", host])
        elif choice == "4":
            cmd_mode()
            m = ask("New GLOBAL default")
            if m:
                cmd_mode([m])
        elif choice == "5":
            cmd_update_proxies()
        elif choice == "6":
            cmd_collector_status()
        elif choice in ("w", "W"):
            cmd_warp_refresh()
        elif choice == "7":
            cmd_net_config()
        elif choice == "8":
            cmd_compile()
        elif choice == "9":
            cmd_logs()
        elif choice in ("i", "I"):
            if ask("Install / reinstall? (yes/no)", "no") == "yes":
                cmd_install()
        elif choice == "0":
            break


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

CMDS = {
    "install": cmd_install, "status": cmd_status,
    "start": cmd_start, "stop": cmd_stop, "restart": cmd_restart,
    "enable": cmd_enable, "disable": cmd_disable, "logs": cmd_logs,
    "rule": cmd_rule, "mode": cmd_mode, "net-config": cmd_net_config,
    "compile": cmd_compile, "update-proxies": cmd_update_proxies,
    "collector-status": cmd_collector_status,
    "warp-refresh": cmd_warp_refresh,
}

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        interactive()
    elif args[0] in CMDS:
        CMDS[args[0]]()
    else:
        print("Commands: " + ", ".join(CMDS))
