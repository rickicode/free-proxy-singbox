#!/usr/bin/env python3
"""
/opt/gw.py — Gateway Manager (sing-box + WARP)
Run without args for interactive menu, or: gw <command> [args]
"""
import json, sys, os, subprocess, urllib.request, tarfile, tempfile, shutil, time

# ── Config ──────────────────────────────────────────────────────────────────
SINGBOX_BIN   = "/usr/local/bin/sing-box"
SINGBOX_CFG   = "/etc/sing-box/config.json"
SINGBOX_UI    = "/etc/sing-box/ui"
TPROXY_SCRIPT = "/usr/local/bin/tproxy-setup"
SERVICE_FILE  = "/etc/systemd/system/sing-box.service"
STORAGE       = "/opt/proxy-rules.json"
RULES_DIR     = "/opt/rules"
COMPILED_DIR  = "/opt/rules/compiled"
LOG_FILE      = "/var/log/sing-box.log"
SINGBOX_VER   = "1.13.13"

LAN_IF      = "ens19"
LAN_SUBNET  = "192.168.92.0/24"
WAN_IF      = "eth0"
TPROXY_PORT = 7893
CLASH_PORT  = 9090
MIXED_PORT  = 7890

META_BASE   = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite"

# WARP1 credentials
W1_PRIVKEY = "qEqVXpiY9Te8mbmw02wVl7wa/gg0qqc2UoUbjuKC6VE="
W1_ADDR4   = "172.16.0.2/32"
W1_ADDR6   = "2606:4700:110:8091:88d4:9c22:b64d:65a1/128"
# WARP2 credentials
W2_PRIVKEY = "+KauKf1ZD8XsgClXa1e4I0+136kupoPKc/2+jZUZQmg="
W2_ADDR4   = "172.16.0.2/32"
W2_ADDR6   = "2606:4700:110:867b:6df0:9ec1:84dd:481f/128"
WARP_PUBKEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

# ── Helpers ──────────────────────────────────────────────────────────────────
def run(cmd, check=True, capture=False):
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check,
                          capture_output=capture, text=True)

def ok(msg):    print(f"\033[32m✓\033[0m {msg}")
def info(msg):  print(f"\033[36m→\033[0m {msg}")
def err(msg):   print(f"\033[31m✗\033[0m {msg}")
def bold(s):    return f"\033[1m{s}\033[0m"
def ask(prompt, default=""):
    try: return input(f"  {prompt} [{default}]: ").strip() or default
    except (EOFError, KeyboardInterrupt): return default

def load_storage():
    if os.path.exists(STORAGE):
        with open(STORAGE) as f: return json.load(f)
    return []

def save_storage(rules):
    with open(STORAGE, "w") as f: json.dump(rules, f, indent=2)

# ── Config builder ───────────────────────────────────────────────────────────
def build_config():
    """Build base sing-box config. Preserves dynamic outbounds (bf-*, PROXY-*)."""
    managed = load_storage()

    # Load existing dynamic outbounds to preserve
    dynamic_obs = []
    dynamic_selectors = []
    if os.path.exists(SINGBOX_CFG):
        try:
            with open(SINGBOX_CFG) as f:
                cur = json.load(f)
            dynamic_obs = [o for o in cur["outbounds"]
                           if o["tag"].startswith("bf-")]
            dynamic_selectors = [o for o in cur["outbounds"]
                                  if o["tag"].startswith("PROXY-")]
        except: pass

    proxy_tags = [o["tag"] for o in dynamic_selectors]
    base_choices = ["WARP", "WARP1", "WARP2", "DIRECT"] + proxy_tags

    cfg = {
        "log": {"level": "info", "output": LOG_FILE, "timestamp": True},
        "dns": {
            "servers": [{"type": "udp", "tag": "local", "server": "1.1.1.1"}],
            "strategy": "ipv4_only"
        },
        "experimental": {"clash_api": {
            "external_controller": f"0.0.0.0:{CLASH_PORT}",
            "external_ui": SINGBOX_UI, "secret": ""
        }},
        "endpoints": [
            {"type":"wireguard","tag":"warp-ep","system":True,"name":"singtun0","mtu":1280,
             "address":[W1_ADDR4,W1_ADDR6],"private_key":W1_PRIVKEY,
             "peers":[{"address":"engage.cloudflareclient.com","port":2408,
                       "public_key":WARP_PUBKEY,"allowed_ips":["0.0.0.0/0","::/0"],
                       "persistent_keepalive_interval":25}]},
            {"type":"wireguard","tag":"warp2-ep","system":True,"name":"singtun1","mtu":1280,
             "address":[W2_ADDR4,W2_ADDR6],"private_key":W2_PRIVKEY,
             "peers":[{"address":"engage.cloudflareclient.com","port":2408,
                       "public_key":WARP_PUBKEY,"allowed_ips":["0.0.0.0/0","::/0"],
                       "persistent_keepalive_interval":25}]},
        ],
        "inbounds": [
            {"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"auto_route":True,
             "strict_route":True,"stack":"system",
             "exclude_interface":["singtun0","singtun1",LAN_IF]},
            {"type":"tproxy","tag":"tproxy-in","listen":"0.0.0.0",
             "listen_port":TPROXY_PORT,"network":"tcp"},
            {"type":"tproxy","tag":"tproxy-udp-in","listen":"0.0.0.0",
             "listen_port":TPROXY_PORT,"network":"udp"},
            {"type":"mixed","tag":"mixed-in","listen":"0.0.0.0","listen_port":MIXED_PORT},
        ],
        "outbounds": [
            {"type":"direct","tag":"DIRECT"},
            {"type":"block","tag":"BLOCK"},
            {"type":"direct","tag":"WARP1","bind_interface":"singtun0"},
            {"type":"direct","tag":"WARP2","bind_interface":"singtun1"},
            {"type":"urltest","tag":"WARP","outbounds":["WARP1","WARP2"],
             "url":"http://cp.cloudflare.com/generate_204","interval":"3m","tolerance":50},
            *dynamic_obs,
            *dynamic_selectors,
            {"type":"selector","tag":"GLOBAL",
             "outbounds":["DIRECT","WARP","WARP1","WARP2"]+proxy_tags,"default":"DIRECT"},
            {"type":"selector","tag":"GOOGLE",
             "outbounds":base_choices,"default":"DIRECT"},
            {"type":"selector","tag":"OPENAI",
             "outbounds":base_choices,"default":"WARP"},
            {"type":"selector","tag":"IPCHECK",
             "outbounds":base_choices,"default":"WARP"},
        ],
        "route": {
            "auto_detect_interface": True,
            "rule_set": [
                {"type":"remote","tag":"community-speedtest","format":"binary",
                 "url":f"{META_BASE}/speedtest.srs",
                 "download_detour":"DIRECT","update_interval":"24h"},
                {"type":"local","tag":"local-ip-check","format":"binary",
                 "path":f"{COMPILED_DIR}/ip-check.srs"},
                {"type":"remote","tag":"community-openai","format":"binary",
                 "url":f"{META_BASE}/openai.srs",
                 "download_detour":"DIRECT","update_interval":"24h"},
                {"type":"remote","tag":"community-anthropic","format":"binary",
                 "url":f"{META_BASE}/anthropic.srs",
                 "download_detour":"DIRECT","update_interval":"24h"},
                {"type":"remote","tag":"community-google","format":"binary",
                 "url":f"{META_BASE}/google.srs",
                 "download_detour":"DIRECT","update_interval":"24h"},
                {"type":"remote","tag":"community-google-play","format":"binary",
                 "url":f"{META_BASE}/google-play.srs",
                 "download_detour":"DIRECT","update_interval":"24h"},
                {"type":"remote","tag":"community-youtube","format":"binary",
                 "url":f"{META_BASE}/youtube.srs",
                 "download_detour":"DIRECT","update_interval":"24h"},
            ],
            "rules": [
                {"action":"sniff"},
                {"protocol":"dns","action":"hijack-dns"},
                {"ip_is_private":True,"outbound":"DIRECT"},
                *[{"domain":[r["host"]],"outbound":r["outbound"]} for r in managed],
                {"rule_set":["community-openai","community-anthropic"],"outbound":"OPENAI"},
                {"rule_set":["community-google","community-google-play",
                             "community-youtube"],"outbound":"GOOGLE"},
                {"rule_set":["community-speedtest","local-ip-check"],"outbound":"IPCHECK"},
            ],
            "final": "GLOBAL"
        }
    }
    return cfg

def apply_config(restart=True):
    cfg = build_config()
    os.makedirs(os.path.dirname(SINGBOX_CFG), exist_ok=True)
    with open(SINGBOX_CFG, "w") as f: json.dump(cfg, f, indent=2)
    r = run([SINGBOX_BIN,"check","-c",SINGBOX_CFG], check=False, capture=True)
    if r.returncode != 0:
        err("Config error: " + r.stdout.strip()); return False
    if restart:
        run(["systemctl","restart","sing-box"], check=False)
        time.sleep(2)
        if run(["systemctl","is-active","sing-box"],check=False,capture=True).stdout.strip()=="active":
            ok("sing-box restarted"); return True
        err("sing-box failed — check: journalctl -u sing-box -n 20"); return False
    return True

# ── Install ───────────────────────────────────────────────────────────────────
def cmd_install():
    info("Installing sing-box gateway...")

    if not os.path.exists(SINGBOX_BIN):
        arch = run("uname -m", capture=True).stdout.strip()
        a = {"x86_64":"amd64","aarch64":"arm64"}.get(arch,"amd64")
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VER}/sing-box-{SINGBOX_VER}-linux-{a}.tar.gz"
        info(f"Downloading sing-box {SINGBOX_VER}...")
        with tempfile.TemporaryDirectory() as tmp:
            tgz = os.path.join(tmp,"sb.tar.gz")
            urllib.request.urlretrieve(url, tgz)
            with tarfile.open(tgz) as t:
                for m in t.getmembers():
                    if m.name.endswith("/sing-box"):
                        m.name="sing-box"; t.extract(m,tmp); break
            shutil.copy(os.path.join(tmp,"sing-box"), SINGBOX_BIN)
            os.chmod(SINGBOX_BIN, 0o755)
        ok(f"sing-box {SINGBOX_VER} installed")
    else:
        ok("sing-box already installed")

    run("id singbox &>/dev/null || useradd -r -s /bin/false singbox", check=False)
    os.makedirs("/etc/sing-box", exist_ok=True)
    os.makedirs(COMPILED_DIR, exist_ok=True)
    run("touch /var/log/sing-box.log && chown singbox:singbox /var/log/sing-box.log")
    ok("Dirs & user ready")

    if not os.path.exists(os.path.join(SINGBOX_UI,"index.html")):
        info("Downloading YACD UI...")
        yacd_url = "https://github.com/MetaCubeX/Yacd-meta/archive/refs/heads/gh-pages.tar.gz"
        with tempfile.TemporaryDirectory() as tmp:
            tgz = os.path.join(tmp,"yacd.tar.gz")
            urllib.request.urlretrieve(yacd_url, tgz)
            with tarfile.open(tgz) as t: t.extractall(tmp)
            extracted = next(d for d in os.listdir(tmp) if os.path.isdir(os.path.join(tmp,d)))
            if os.path.exists(SINGBOX_UI): shutil.rmtree(SINGBOX_UI)
            shutil.copytree(os.path.join(tmp,extracted), SINGBOX_UI)
        ok("YACD UI installed")

    with open(TPROXY_SCRIPT,"w") as f:
        f.write(f"""#!/bin/bash
TPROXY_PORT={TPROXY_PORT}; TPROXY_MARK=0x01; LAN_IF={LAN_IF}
flush() {{
    iptables -t mangle -D PREROUTING -i $LAN_IF -j SING_BOX 2>/dev/null
    iptables -t mangle -F SING_BOX 2>/dev/null; iptables -t mangle -X SING_BOX 2>/dev/null
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
iptables -t mangle -A SING_BOX -p tcp -j TPROXY --tproxy-mark $TPROXY_MARK --on-port $TPROXY_PORT
iptables -t mangle -A SING_BOX -p udp -j TPROXY --tproxy-mark $TPROXY_MARK --on-port $TPROXY_PORT
iptables -t mangle -A PREROUTING -i $LAN_IF -j SING_BOX
echo "TProxy applied"
""")
    os.chmod(TPROXY_SCRIPT, 0o755)

    with open(SERVICE_FILE,"w") as f:
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

    run("sysctl -w net.ipv4.ip_forward=1", capture=True)
    with open("/etc/sysctl.d/99-gateway.conf","w") as f: f.write("net.ipv4.ip_forward=1\n")
    run(f"iptables -t nat -C POSTROUTING -s {LAN_SUBNET} -o {WAN_IF} -j MASQUERADE 2>/dev/null || "
        f"iptables -t nat -A POSTROUTING -s {LAN_SUBNET} -o {WAN_IF} -j MASQUERADE")
    run("apt-get install -y -qq iptables-persistent 2>/dev/null; netfilter-persistent save 2>/dev/null",
        check=False)
    ok("IP forwarding + NAT ready")

    _compile_rules()

    # Backup dynamic outbounds before apply_config overwrites
    bak_file = SINGBOX_CFG + ".bak"
    if os.path.exists(SINGBOX_CFG):
        import shutil as _sh; _sh.copy2(SINGBOX_CFG, bak_file)

    apply_config()
    run("systemctl enable sing-box", capture=True)

    # Restore dynamic proxies (bf-*, PROXY-*) from backup
    if os.path.exists(bak_file):
        info("Restoring dynamic outbounds...")
        try:
            with open(bak_file) as f: bak = json.load(f)
            with open(SINGBOX_CFG) as f: c = json.load(f)
            dyn_obs = [o for o in bak["outbounds"] if o["tag"].startswith("bf-")]
            dyn_sel = [o for o in bak["outbounds"] if o["tag"].startswith("PROXY-")]
            if dyn_obs:
                c["outbounds"].extend(dyn_obs + dyn_sel)
                proxy_tags = [s["tag"] for s in dyn_sel]
                for o in c["outbounds"]:
                    if o["type"] == "selector":
                        for pt in proxy_tags:
                            if pt not in o["outbounds"]: o["outbounds"].append(pt)
                with open(SINGBOX_CFG,"w") as f: json.dump(c,f,indent=2)
                r = run([SINGBOX_BIN,"check","-c",SINGBOX_CFG],check=False,capture=True)
                if r.returncode == 0:
                    run(["systemctl","restart","sing-box"],check=False)
                    ok(f"Restored {len(dyn_obs)} dynamic outbounds + {len(dyn_sel)} selectors")
                else:
                    err("Restore failed, using fresh config")
        except Exception as e:
            err(f"Restore error: {e}")
        os.remove(bak_file)

    ip = run("hostname -I", capture=True).stdout.split()[0]
    print()
    ok("Installation complete!")
    info(f"YACD: http://{ip}:{CLASH_PORT}/ui/")
    info(f"Proxy: {ip}:{MIXED_PORT}")

def _compile_rules():
    os.makedirs(COMPILED_DIR, exist_ok=True)
    ip_check_json = f"{RULES_DIR}/ip-check.json"
    if not os.path.exists(ip_check_json):
        os.makedirs(RULES_DIR, exist_ok=True)
        rule = {"version":2,"rules":[{
            "domain":["ifconfig.co","ifconfig.me","icanhazip.com","wtfismyip.com","checkip.amazonaws.com"],
            "domain_suffix":["ipinfo.io","ip-api.com","ipify.org","ipwho.is","browserleaks.com",
                             "dnsleaktest.com","ipleak.net","whoer.net","whatismyipaddress.com"]}]}
        with open(ip_check_json,"w") as f: json.dump(rule,f,indent=2)
    for jf in os.listdir(RULES_DIR):
        if not jf.endswith(".json"): continue
        src = os.path.join(RULES_DIR,jf)
        out = os.path.join(COMPILED_DIR,jf.replace(".json",".srs"))
        r = run([SINGBOX_BIN,"rule-set","compile","--output",out,src],check=False,capture=True)
        if r.returncode==0: ok(f"Compiled {jf}")
        else: err(f"Compile {jf}: {r.stderr.strip()}")

# ── Service commands ──────────────────────────────────────────────────────────
def cmd_status():
    svc = run(["systemctl","is-active","sing-box"],check=False,capture=True).stdout.strip()
    color = "\033[32m" if svc=="active" else "\033[31m"
    print(f"\n  sing-box : {color}{svc}\033[0m")
    r = run("curl -s --proxy http://127.0.0.1:7890 --max-time 5 ifconfig.co/json",
            capture=True,check=False)
    try:
        d = json.loads(r.stdout)
        print(f"  External : {d.get('ip','-')} | {d.get('asn_org','-')} | {d.get('city','-')}")
    except: print("  External : (unavailable)")
    nat = run(f"iptables -t nat -C POSTROUTING -s {LAN_SUBNET} -o {WAN_IF} -j MASQUERADE",
              check=False,capture=True).returncode==0
    print(f"  NAT      : {'ON' if nat else 'OFF'}")
    print(f"  Rules    : {len(load_storage())} managed")
    for iface in ["singtun0","singtun1"]:
        r2 = run(f"ip -br addr show {iface} 2>/dev/null",capture=True,check=False)
        if r2.stdout.strip():
            parts = r2.stdout.split()
            ip6 = next((p for p in parts[2:] if "2606" in p),"-")
            print(f"  {iface}  : {parts[1] if len(parts)>1 else '?'} | {ip6}")
    print(f"  YACD     : http://0.0.0.0:{CLASH_PORT}/ui/\n")

def cmd_start():   run(["systemctl","start","sing-box"]);   ok("sing-box started")
def cmd_stop():    run(["systemctl","stop","sing-box"]);    ok("sing-box stopped")
def cmd_restart(): apply_config()
def cmd_enable():  run(["systemctl","enable","sing-box"]);  ok("enabled on boot")
def cmd_disable(): run(["systemctl","disable","sing-box"]); ok("disabled")
def cmd_logs():    os.execvp("journalctl",["journalctl","-u","sing-box","-f","--no-pager"])
def cmd_compile(): _compile_rules(); apply_config()

def cmd_rule(args=None):
    if args is None: args = sys.argv[2:]
    if not args or args[0]=="list":
        rules = load_storage()
        if not rules: print("  No managed rules."); return
        print(f"\n  {'#':<4} {'HOST':<40} OUTBOUND\n  "+"-"*58)
        for i,r in enumerate(rules,1): print(f"  {i:<4} {r['host']:<40} {r['outbound']}")
        print()
    elif args[0]=="add" and len(args)==3:
        host,ob = args[1],args[2]
        rules = load_storage()
        for r in rules:
            if r["host"]==host:
                r["outbound"]=ob; save_storage(rules); ok(f"Updated: {host} → {ob}"); apply_config(); return
        rules.append({"host":host,"outbound":ob}); save_storage(rules)
        ok(f"Added: {host} → {ob}"); apply_config()
    elif args[0]=="remove" and len(args)==2:
        rules = load_storage(); new=[r for r in rules if r["host"]!=args[1]]
        if len(new)<len(rules): save_storage(new); ok(f"Removed: {args[1]}"); apply_config()
        else: err(f"Not found: {args[1]}")
    else:
        print("  Usage: gw rule list | add <host> <outbound> | remove <host>")

def cmd_mode(args=None):
    if args is None: args = sys.argv[2:]
    with open(SINGBOX_CFG) as f: c = json.load(f)
    if not args:
        for o in c["outbounds"]:
            if o["tag"]=="GLOBAL": print(f"  GLOBAL default: {o.get('default')}"); return
    mode = args[0].upper()
    for o in c["outbounds"]:
        if o["tag"]=="GLOBAL": o["default"]=mode
    with open(SINGBOX_CFG,"w") as f: json.dump(c,f,indent=2)
    run(["systemctl","restart","sing-box"],check=False)
    ok(f"GLOBAL default → {mode}")

def cmd_update_proxies():
    updater = "/opt/proxy-collector.py"
    if os.path.exists(updater): run(["python3",updater])
    else: err("proxy-collector.py not found")

COLLECTOR_STATE_FILE = "/opt/.proxy-collector-state.json"
GITHUB_SUMMARY = "https://raw.githubusercontent.com/rickicode/free-proxy-singbox/main/output/latest-summary.json"


def cmd_collector_status():
    """Show collector freshness status."""
    print(f"\n  {bold('Collector Status')}")

    # Local state
    local = {}
    if os.path.exists(COLLECTOR_STATE_FILE):
        with open(COLLECTOR_STATE_FILE) as f:
            local = json.load(f)

    last_run = local.get("last_run_at", "never")
    last_gen = local.get("last_generated_at", "-")

    print(f"  Last run    : {last_run}")
    print(f"  Last scan   : {last_gen}")

    # Remote check
    try:
        req = urllib.request.Request(GITHUB_SUMMARY, headers={"User-Agent": "curl/8.0"})
        remote = json.loads(urllib.request.urlopen(req, timeout=10).read())
        remote_gen = remote.get("generated_at", "")
        r_candidates = remote.get("candidate_count", "?")
        r_live = remote.get("live_count", "?")
        print(f"  Remote scan : {remote_gen}")
        print(f"  Remote data : {r_candidates} candidates, {r_live} live proxies")

        if last_gen == remote_gen:
            print(f"  \033[32m✓\033[0m Fresh — collector sudah pakai data terbaru\n")
        else:
            print(f"  \033[33m!\033[0m Stale — GitHub punya data baru, jalankan `gw update-proxies`\n")
    except Exception as e:
        print(f"  \033[31m✗\033[0m Cannot reach GitHub: {e}\n")

# ── Interactive menu ──────────────────────────────────────────────────────────
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
  7) Compile local rules
  8) Live logs
  9) Install / reinstall
  0) Exit
""")
        choice = ask("Choose","0").strip()

        if choice=="1":
            cmd_status()
        elif choice=="2":
            print("\n  1) Start  2) Stop  3) Restart")
            a = ask("Choose","3")
            if a=="1": cmd_start()
            elif a=="2": cmd_stop()
            else: cmd_restart()
        elif choice=="3":
            print(f"\n{bold('── Rule Management ──')}\n  1) List  2) Add  3) Remove\n")
            a = ask("Choose","1")
            if a=="1": cmd_rule(["list"])
            elif a=="2":
                host = ask("Host")
                if host:
                    ob = ask("Outbound (WARP/DIRECT/GLOBAL/PROXY-BARRYFAR)","WARP")
                    cmd_rule(["add",host,ob])
            elif a=="3":
                cmd_rule(["list"]); host=ask("Host to remove")
                if host: cmd_rule(["remove",host])
        elif choice=="4":
            cmd_mode()
            print("\n  Available: DIRECT, WARP, WARP1, WARP2, PROXY-BARRYFAR")
            m = ask("New GLOBAL default")
            if m: cmd_mode([m])
        elif choice=="5":
            cmd_update_proxies()
        elif choice=="6":
            cmd_collector_status()
        elif choice=="7":
            cmd_compile()
        elif choice=="8":
            cmd_logs()
        elif choice=="9":
            if ask("Reinstall? (yes/no)","no")=="yes": cmd_install()
        elif choice=="0":
            break

# ── Main ──────────────────────────────────────────────────────────────────────
CMDS = {
    "install":cmd_install,"status":cmd_status,
    "start":cmd_start,"stop":cmd_stop,"restart":cmd_restart,
    "enable":cmd_enable,"disable":cmd_disable,"logs":cmd_logs,
    "rule":cmd_rule,"mode":cmd_mode,
    "compile":cmd_compile,"update-proxies":cmd_update_proxies,
    "collector-status":cmd_collector_status,
}

if __name__=="__main__":
    args = sys.argv[1:]
    if not args: interactive()
    elif args[0] in CMDS: CMDS[args[0]]()
    else: print("Commands: "+", ".join(CMDS))
