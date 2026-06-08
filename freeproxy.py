#!/usr/bin/env python3
import argparse
import base64
import json
import os
import random
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_BINARY = ROOT / "bin" / "sing-box"
DEFAULT_OUTPUT = ROOT / "output" / "live-proxies.json"

SOURCES = [
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/ss.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
]

SUPPORTED_SCHEMES = ("trojan://", "vless://", "vmess://", "ss://")
DEFAULT_TIMEOUT_TCP = 4
DEFAULT_TIMEOUT_LIVE = 10
DEFAULT_TCP_WORKERS = 128
DEFAULT_LIVE_WORKERS = 16
DEFAULT_RANDOM_SEED = 1337
DEFAULT_SHARD_COUNT = 4
DEFAULT_TARGET_COUNTRIES = ("ID", "SG", "US")
DEFAULT_IP_CHECK_URL = "https://ifconfig.co"
DEFAULT_GROUPS = ("PROXY-FREE", "PROXY-ID", "PROXY-SG", "PROXY-US")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect live free proxies and emit sing-box/YACD-ready output."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Fetch, verify, geoip, and save live proxies.")
    scan.add_argument("--binary", default=str(DEFAULT_BINARY))
    scan.add_argument("--output", default=str(DEFAULT_OUTPUT))
    scan.add_argument("--tcp-timeout", type=int, default=DEFAULT_TIMEOUT_TCP)
    scan.add_argument("--live-timeout", type=int, default=DEFAULT_TIMEOUT_LIVE)
    scan.add_argument("--tcp-workers", type=int, default=DEFAULT_TCP_WORKERS)
    scan.add_argument("--live-workers", type=int, default=DEFAULT_LIVE_WORKERS)
    scan.add_argument("--ip-check-url", default=DEFAULT_IP_CHECK_URL)
    scan.add_argument("--seed", type=int, default=DEFAULT_RANDOM_SEED)
    scan.add_argument("--shard-index", type=int, default=0)
    scan.add_argument("--shard-count", type=int, default=DEFAULT_SHARD_COUNT)
    scan.add_argument(
        "--target-countries",
        default=",".join(DEFAULT_TARGET_COUNTRIES),
        help="Comma separated list for dedicated groups, default: ID,SG,US",
    )
    return parser.parse_args()


def ensure_binary(binary_path: Path):
    if not binary_path.exists():
        raise SystemExit(f"sing-box binary not found: {binary_path}")
    if not os.access(binary_path, os.X_OK):
        raise SystemExit(f"sing-box binary is not executable: {binary_path}")


def decode_if_base64_blob(text):
    compact = "".join(text.split())
    if not compact:
        return text
    if any(prefix in text for prefix in SUPPORTED_SCHEMES):
        return text
    try:
        decoded = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode(errors="ignore")
        if any(prefix in decoded for prefix in SUPPORTED_SCHEMES):
            return decoded
    except Exception:
        return text
    return text


def extract_supported_lines(raw_text):
    lines = []
    decoded = decode_if_base64_blob(raw_text)
    for line in decoded.splitlines():
        item = line.strip()
        if item.startswith(SUPPORTED_SCHEMES):
            lines.append(item)
    return lines


def fetch_lines():
    lines = []
    for url in SOURCES:
        try:
            raw = urllib.request.urlopen(url, timeout=30).read().decode(errors="ignore")
            fetched = extract_supported_lines(raw)
            print(f"[fetch] {url} -> {len(fetched)} supported lines")
            lines.extend(fetched)
        except Exception as exc:
            print(f"[fetch] failed {url}: {exc}")
    return lines


def parse_common_fragment(body):
    body, fragment = (body.split("#", 1) + [""])[:2] if "#" in body else (body, "")
    return body, urllib.parse.unquote(fragment).strip()


def parse_trojan(line, index):
    body, source_name = parse_common_fragment(line[9:].strip())
    pw_host, params_str = body.split("?", 1) if "?" in body else (body, "")
    at = pw_host.rfind("@")
    if at < 0:
        return None
    password = urllib.parse.unquote(pw_host[:at])
    host, port = pw_host[at + 1 :].rsplit(":", 1)
    params = dict(urllib.parse.parse_qsl(params_str.replace("&amp;", "&")))
    transport = params.get("type", "tcp") or "tcp"
    if transport not in {"tcp", "ws", "grpc"}:
        return None
    outbound = {
        "type": "trojan",
        "tag": f"candidate-{index}",
        "server": host.strip("[]"),
        "server_port": int(port),
        "password": password,
        "tls": {
            "enabled": True,
            "insecure": True,
            "server_name": params.get("sni", host.strip("[]")),
        },
    }
    if transport == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": params.get("path", "/"),
            "headers": {"Host": params.get("host", host.strip("[]"))},
        }
    elif transport == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": params.get("serviceName", ""),
        }
    return {
        "protocol": "trojan",
        "source_name": source_name,
        "source_line": line,
        "outbound": outbound,
    }


def parse_vless(line, index):
    body, source_name = parse_common_fragment(line[8:].strip())
    user_host, params_str = body.split("?", 1) if "?" in body else (body, "")
    at = user_host.rfind("@")
    if at < 0:
        return None
    user = urllib.parse.unquote(user_host[:at])
    host, port = user_host[at + 1 :].rsplit(":", 1)
    params = dict(urllib.parse.parse_qsl(params_str.replace("&amp;", "&")))
    security = params.get("security", "tls")
    transport = params.get("type", "tcp") or "tcp"
    outbound = {
        "type": "vless",
        "tag": f"candidate-{index}",
        "server": host.strip("[]"),
        "server_port": int(port),
        "uuid": user,
        "flow": params.get("flow", ""),
    }
    if security == "tls":
        outbound["tls"] = {
            "enabled": True,
            "insecure": True,
            "server_name": params.get("sni", host.strip("[]")),
        }
    if transport == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": params.get("path", "/"),
            "headers": {"Host": params.get("host", host.strip("[]"))},
        }
    elif transport == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": params.get("serviceName", ""),
        }
    elif transport == "httpupgrade":
        outbound["transport"] = {
            "type": "httpupgrade",
            "host": [params.get("host", host.strip("[]"))],
            "path": params.get("path", "/"),
        }
    return {
        "protocol": "vless",
        "source_name": source_name,
        "source_line": line,
        "outbound": outbound,
    }


def parse_vmess(line, index):
    body = line[8:].strip()
    try:
        decoded = base64.b64decode(body + "=" * (-len(body) % 4)).decode(errors="ignore")
        data = json.loads(decoded)
    except Exception:
        return None
    host = data.get("add")
    port = data.get("port")
    if not host or not port:
        return None
    transport = data.get("net", "tcp") or "tcp"
    outbound = {
        "type": "vmess",
        "tag": f"candidate-{index}",
        "server": host.strip("[]"),
        "server_port": int(port),
        "uuid": data.get("id"),
        "security": data.get("scy", "auto"),
        "alter_id": int(data.get("aid", 0)),
    }
    tls_flag = str(data.get("tls", "")).lower()
    if tls_flag in {"tls", "1", "true"}:
        outbound["tls"] = {
            "enabled": True,
            "insecure": True,
            "server_name": data.get("sni") or data.get("host") or host.strip("[]"),
        }
    if transport == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": data.get("path", "/") or "/",
            "headers": {"Host": data.get("host", host.strip("[]"))},
        }
    elif transport == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": data.get("path", ""),
        }
    elif transport == "http":
        outbound["transport"] = {
            "type": "http",
            "host": [data.get("host", host.strip("[]"))],
            "path": data.get("path", "/") or "/",
        }
    return {
        "protocol": "vmess",
        "source_name": data.get("ps", ""),
        "source_line": line,
        "outbound": outbound,
    }


def parse_ss(line, index):
    body, source_name = parse_common_fragment(line[5:].strip())
    plugin = None
    if "?" in body:
        body, query = body.split("?", 1)
        params = dict(urllib.parse.parse_qsl(query.replace("&amp;", "&")))
        plugin = params.get("plugin")
    if "@" not in body:
        decoded = base64.b64decode(body + "=" * (-len(body) % 4)).decode(errors="ignore")
        if "@" not in decoded:
            return None
        user_info, host_port = decoded.rsplit("@", 1)
    else:
        user_info, host_port = body.rsplit("@", 1)
        try:
            user_info = base64.b64decode(user_info + "=" * (-len(user_info) % 4)).decode(errors="ignore")
        except Exception:
            pass
    if ":" not in user_info or ":" not in host_port:
        return None
    method, password = user_info.split(":", 1)
    host, port = host_port.rsplit(":", 1)
    outbound = {
        "type": "shadowsocks",
        "tag": f"candidate-{index}",
        "server": host.strip("[]"),
        "server_port": int(port),
        "method": method,
        "password": password,
    }
    if plugin:
        return None
    return {
        "protocol": "shadowsocks",
        "source_name": source_name,
        "source_line": line,
        "outbound": outbound,
    }


def parse_line(line, index):
    try:
        if line.startswith("trojan://"):
            return parse_trojan(line, index)
        if line.startswith("vless://"):
            return parse_vless(line, index)
        if line.startswith("vmess://"):
            return parse_vmess(line, index)
        if line.startswith("ss://"):
            return parse_ss(line, index)
        return None
    except Exception:
        return None


def candidate_key(item):
    outbound = item["outbound"]
    return (
        outbound["type"],
        outbound["server"],
        outbound["server_port"],
        outbound.get("uuid", ""),
        outbound.get("password", ""),
        outbound.get("method", ""),
        json.dumps(outbound.get("transport", {}), sort_keys=True),
    )


def dedupe_candidates(parsed):
    seen = set()
    unique = []
    for item in parsed:
        key = candidate_key(item)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def slice_shard(items, shard_index, shard_count):
    if shard_count < 1:
        raise SystemExit("shard-count must be >= 1")
    if shard_index < 0 or shard_index >= shard_count:
        raise SystemExit("shard-index must be within [0, shard-count)")
    return [item for pos, item in enumerate(items) if pos % shard_count == shard_index]


def tcp_ok(host, port, timeout_sec):
    try:
        sock = socket.create_connection((host, port), timeout=timeout_sec)
        sock.close()
        return True
    except Exception:
        return False


def run_tcp_filter(candidates, tcp_timeout, tcp_workers):
    passed = []
    with ThreadPoolExecutor(max_workers=tcp_workers) as executor:
        future_map = {
            executor.submit(
                tcp_ok,
                candidate["outbound"]["server"],
                candidate["outbound"]["server_port"],
                tcp_timeout,
            ): candidate
            for candidate in candidates
        }
        for future in as_completed(future_map):
            candidate = future_map[future]
            try:
                if future.result():
                    passed.append(candidate)
            except Exception:
                pass
    return passed


def build_temp_config(outbound, listen_port):
    return {
        "log": {"level": "warn"},
        "dns": {"servers": [{"type": "udp", "tag": "local", "server": "1.1.1.1"}]},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            }
        ],
        "outbounds": [{"type": "direct", "tag": "DIRECT"}, outbound],
        "route": {"final": outbound["tag"]},
    }


def live_test(binary_path, candidate, listen_port, live_timeout, ip_check_url):
    outbound = dict(candidate["outbound"])
    config = build_temp_config(outbound, listen_port)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(config, handle)
        temp_config = handle.name

    proc = None
    try:
        proc = subprocess.Popen(
            [str(binary_path), "run", "-c", temp_config],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        result = subprocess.run(
            [
                "curl",
                "-sS",
                "--proxy",
                f"http://127.0.0.1:{listen_port}",
                "--max-time",
                str(live_timeout),
                ip_check_url,
            ],
            capture_output=True,
            text=True,
        )
        external_ip = result.stdout.strip()
        if external_ip and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", external_ip):
            return external_ip
        return None
    except Exception:
        return None
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.unlink(temp_config)
        except OSError:
            pass


def geoip_single(ip):
    try:
        request = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=query,country,countryCode,regionName,city,isp"
        )
        row = json.loads(urllib.request.urlopen(request, timeout=10).read())
        return {
            "country_code": row.get("countryCode", "XX"),
            "country": row.get("country", "Unknown"),
            "region": row.get("regionName", ""),
            "city": row.get("city", ""),
            "isp": row.get("isp", ""),
        }
    except Exception:
        return {
            "country_code": "XX",
            "country": "Unknown",
            "region": "",
            "city": "",
            "isp": "",
        }


def run_live_filter(binary_path, candidates, live_workers, live_timeout, ip_check_url):
    live_records = []
    with ThreadPoolExecutor(max_workers=live_workers) as executor:
        future_map = {}
        for index, candidate in enumerate(candidates, start=1):
            future = executor.submit(
                live_test,
                binary_path,
                candidate,
                19000 + index,
                live_timeout,
                ip_check_url,
            )
            future_map[future] = candidate

        for future in as_completed(future_map):
            candidate = future_map[future]
            outbound = candidate["outbound"]
            external_ip = None
            try:
                external_ip = future.result()
            except Exception:
                external_ip = None
            if not external_ip:
                print(f"[live] no {outbound['server']}:{outbound['server_port']}")
                continue
            geo = geoip_single(external_ip)
            candidate["external_ip"] = external_ip
            candidate["geo"] = geo
            live_records.append(candidate)
            print(
                f"[live] ok {outbound['server']}:{outbound['server_port']} -> "
                f"{external_ip} [{geo['country_code']}]"
            )
    return live_records


def sanitize_name(value):
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    clean = re.sub(r"-{2,}", "-", clean).strip("-")
    return clean or "proxy"


def build_proxy_record(index, candidate):
    outbound = dict(candidate["outbound"])
    geo = candidate["geo"]
    suffix = sanitize_name(candidate["source_name"] or outbound["server"])
    tag = f"FREE-{geo['country_code']}-{index:04d}-{suffix}"
    outbound["tag"] = tag
    return {
        "tag": tag,
        "name": f"{geo['country_code']} {outbound['type']} {outbound['server']}:{outbound['server_port']}",
        "protocol": candidate["protocol"],
        "country_code": geo["country_code"],
        "country": geo["country"],
        "region": geo["region"],
        "city": geo["city"],
        "isp": geo["isp"],
        "server": outbound["server"],
        "server_port": outbound["server_port"],
        "external_ip": candidate["external_ip"],
        "source_name": candidate["source_name"],
        "source_line": candidate["source_line"],
        "outbound": outbound,
    }


def build_groups(records, target_countries):
    groups = {"PROXY-FREE": [record["tag"] for record in records]}
    for code in target_countries:
        groups[f"PROXY-{code}"] = [record["tag"] for record in records if record["country_code"] == code]
    return groups


def build_singbox_snapshot(records, groups):
    outbounds = [{"type": "direct", "tag": "DIRECT"}, {"type": "block", "tag": "BLOCK"}]
    outbounds.extend(record["outbound"] for record in records)
    for group_name in DEFAULT_GROUPS:
        tags = groups.get(group_name, [])
        if not tags:
            continue
        outbounds.append(
            {
                "type": "urltest",
                "tag": group_name,
                "outbounds": tags,
                "url": "http://cp.cloudflare.com/generate_204",
                "interval": "5m",
                "tolerance": 100,
            }
        )
    selectable = ["DIRECT"] + [group for group in DEFAULT_GROUPS if groups.get(group)]
    outbounds.append(
        {
            "type": "selector",
            "tag": "GLOBAL",
            "outbounds": selectable,
            "default": "DIRECT",
        }
    )
    return {
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": "",
            }
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 7890,
            }
        ],
        "outbounds": outbounds,
        "route": {"auto_detect_interface": True, "final": "GLOBAL"},
    }


def scan(args):
    binary_path = Path(args.binary).resolve()
    output_path = Path(args.output).resolve()
    target_countries = tuple(x.strip().upper() for x in args.target_countries.split(",") if x.strip())

    ensure_binary(binary_path)
    lines = fetch_lines()
    random.Random(args.seed).shuffle(lines)
    parsed = [parse_line(line, index) for index, line in enumerate(lines, start=1)]
    parsed = [item for item in parsed if item]
    parsed = dedupe_candidates(parsed)
    shard_items = slice_shard(parsed, args.shard_index, args.shard_count)
    print(f"[scan] total parsed unique candidates: {len(parsed)}")
    print(f"[scan] shard {args.shard_index + 1}/{args.shard_count}: {len(shard_items)} candidates")

    tcp_pass = run_tcp_filter(shard_items, args.tcp_timeout, args.tcp_workers)
    print(f"[scan] tcp ok: {len(tcp_pass)}")

    live_candidates = run_live_filter(
        binary_path=binary_path,
        candidates=tcp_pass,
        live_workers=args.live_workers,
        live_timeout=args.live_timeout,
        ip_check_url=args.ip_check_url,
    )

    records = [build_proxy_record(index, candidate) for index, candidate in enumerate(live_candidates, start=1)]
    records.sort(key=lambda item: (item["country_code"], item["protocol"], item["server"], item["server_port"]))
    for index, record in enumerate(records, start=1):
        suffix = record["tag"].split("-", 3)[3]
        record["tag"] = f"FREE-{record['country_code']}-{index:04d}-{suffix}"
        record["outbound"]["tag"] = record["tag"]

    groups = build_groups(records, target_countries)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": args.seed,
        "shard_index": args.shard_index,
        "shard_count": args.shard_count,
        "source_count": len(SOURCES),
        "candidate_count": len(parsed),
        "tcp_ok_count": len(tcp_pass),
        "live_count": len(records),
        "target_countries": list(target_countries),
        "groups": groups,
        "proxies": records,
        "singbox": build_singbox_snapshot(records, groups),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2))
    print(f"[done] saved {len(records)} live proxies to {output_path}")


def main():
    args = parse_args()
    if args.command == "scan":
        scan(args)


if __name__ == "__main__":
    main()
