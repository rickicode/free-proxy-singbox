# Gateway VPS State — 192.168.90.78

> **Last updated:** 2026-06-08  
> **Repo:** `github.com/rickicode/free-proxy-singbox`  
> **Branch:** `main`

## Arsitektur
- VPS sebagai **internet gateway** untuk LAN `192.168.92.0/24`
- Interface: `eth0` (WAN1, 192.168.90.78), `eth1` (WAN2 DHCP), `eth2` (LAN, 192.168.92.1)
- Traffic LAN → **TProxy** (port 7893) → sing-box → outbound
- NAT MASQUERADE aktif: `192.168.92.0/24 → eth0`
- IP Forwarding: ON (`/etc/sysctl.d/99-gateway.conf`)

## sing-box
- Binary: `/usr/local/bin/sing-box` v1.13.13
- Config: `/etc/sing-box/config.json`
- Service: `systemd sing-box.service` (enabled, auto-restart)
- Log: `/var/log/sing-box.log` (level: info)
- YACD UI: `http://192.168.90.78:9090/ui/` (no secret)
- Mixed proxy: port `7890` (HTTP/SOCKS5)

## Outbounds / Selectors

```
DIRECT          → koneksi langsung ISP
BLOCK           → drop
WARP1           → direct via singtun0 (Cloudflare WARP akun 1)
WARP2           → direct via singtun1 (Cloudflare WARP akun 2)
WARP            → urltest WARP1+WARP2 (auto pilih tercepat, interval 3m)
free-{CC}-{N}   → proxy publik dari GitHub scan (trojan/vless/vmess/ss)
PROXY-FREE      → urltest semua free-* (auto pilih tercepat)
PROXY-{CC}      → urltest per-country (US, SG, ID, JP, KR...)
```

### Selectors (pilih manual di YACD)
| Selector | Default | Pilihan |
|----------|---------|---------|
| GLOBAL   | DIRECT  | DIRECT, WARP, WARP1, WARP2, PROXY-FREE, PROXY-* |
| GOOGLE   | DIRECT  | WARP, WARP1, WARP2, DIRECT, PROXY-FREE, PROXY-* |
| OPENAI   | WARP    | WARP, WARP1, WARP2, DIRECT, PROXY-FREE, PROXY-* |
| IPCHECK  | WARP    | WARP, WARP1, WARP2, DIRECT, PROXY-FREE, PROXY-* |

## Route Rules
```
sniff → action
dns → hijack-dns
ip_is_private → DIRECT
managed rules (dari gw rule add)
community-openai + anthropic → OPENAI
community-google + play + youtube → GOOGLE
community-speedtest + local-ip-check → IPCHECK
final → GLOBAL
```

## WARP Credentials
- **WARP1**: privkey `qEqVXpiY9Te8mbmw02wVl7wa/gg0qqc2UoUbjuKC6VE=`
  - addr: `172.16.0.2/32`, `2606:4700:110:8091:88d4:9c22:b64d:65a1/128`
  - interface: `singtun0`
- **WARP2**: privkey `+KauKf1ZD8XsgClXa1e4I0+136kupoPKc/2+jZUZQmg=`
  - addr: `172.16.0.2/32`, `2606:4700:110:867b:6df0:9ec1:84dd:481f/128`
  - interface: `singtun1`
  - account file: `/opt/warp2/wgcf-account.toml`
- public key (keduanya): `bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=`

## Rule Sets
| Tag | Sumber | Keterangan |
|-----|--------|-----------|
| community-speedtest | MetaCubeX remote | speedtest.net & ookla |
| community-openai | MetaCubeX remote | openai.com, chatgpt.com |
| community-anthropic | MetaCubeX remote | claude.ai, anthropic.com |
| community-google | MetaCubeX remote | google.com |
| community-google-play | MetaCubeX remote | play.google.com |
| community-youtube | MetaCubeX remote | youtube.com |
| local-ip-check | `/opt/rules/compiled/ip-check.srs` | ifconfig.co, ipinfo.io, dll |

## Scripts di /opt/

| File | Fungsi |
|------|--------|
| `/opt/gw.py` | **Main CLI** — install, status, rule, mode |
| `/opt/proxy-collector.py` | Pull proxy dari GitHub → update sing-box config |
| `/opt/proxy-rules.json` | Storage managed rules (dari `gw rule add`) |
| `/opt/rules/ip-check.json` | Source rule ip-check (compile ke .srs) |
| `/opt/rules/compiled/ip-check.srs` | Compiled binary rule |

### CLI: `gw`
```bash
gw                    # interactive menu
gw status             # status + external IP + NAT
gw start|stop|restart
gw enable|disable
gw logs               # follow log live
gw rule list|add|remove
gw mode <DIRECT|WARP|...>   # ganti GLOBAL default
gw update-proxies     # jalankan proxy-collector manual
gw compile            # recompile local rule sets
gw install            # install ulang dari nol
```

## Cron
```
0 */5 * * *  /usr/bin/python3 /opt/proxy-collector.py
             >> /var/log/proxy-collector.log 2>&1
```

## Alur Proxy

```
GitHub Actions (tiap 12 jam)
  ↓ freeproxy.py scan → live-proxies.json
  ↓ (TCP + live + GeoIP sudah diverifikasi)
VPS: proxy-collector.py (tiap 5 jam via cron)
  ↓
  1. Fetch live-proxies.json dari GitHub raw
  2. Clash API → keep free-* dgn delay <500ms
  3. Ambil fresh proxy dari GitHub (trust, no re-test)
  4. Tag: free-US-1, free-SG-2, free-NL-3, ...
  5. Build PROXY-FREE + PROXY-US/SG/ID/...
  6. Update selector + restart sing-box
```

## Catatan Penting
- Semua proxy dari GitHub sudah **TCP + live + GeoIP** terverifikasi oleh GitHub Actions.
- `proxy-collector.py` hanya keep-alive via clash API lokal — tidak perlu re-test.
- `gw rule add/remove` aman — tidak reset dynamic outbounds.
- `gw install` akan reset semua — gunakan hanya jika server fresh.
- LAN client cukup set: IP static `192.168.92.x/24`, gateway `192.168.92.1`, DNS `1.1.1.1`
