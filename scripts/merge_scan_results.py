#!/usr/bin/env python3
import argparse
import json
import time
from pathlib import Path

DEFAULT_GROUPS = ("PROXY-FREE", "PROXY-ID", "PROXY-SG", "PROXY-US")


def parse_args():
    parser = argparse.ArgumentParser(description="Merge sharded free proxy scan results.")
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def load_payloads(input_dir):
    files = sorted(Path(input_dir).glob("*.json"))
    if not files:
        raise SystemExit(f"no shard files found in {input_dir}")
    return [json.loads(path.read_text()) for path in files]


def dedupe_proxies(payloads):
    deduped = {}
    for payload in payloads:
        for proxy in payload.get("proxies", []):
            key = (
                proxy["protocol"],
                proxy["server"],
                proxy["server_port"],
                proxy["external_ip"],
                proxy["outbound"].get("uuid", ""),
                proxy["outbound"].get("password", ""),
                proxy["outbound"].get("method", ""),
            )
            current = deduped.get(key)
            if current is None or proxy["tag"] < current["tag"]:
                deduped[key] = proxy
    proxies = list(deduped.values())
    proxies.sort(key=lambda item: (item["country_code"], item["protocol"], item["server"], item["server_port"]))
    for index, proxy in enumerate(proxies, start=1):
        suffix = proxy["tag"].split("-", 3)[3]
        proxy["tag"] = f"FREE-{proxy['country_code']}-{index:04d}-{suffix}"
        proxy["outbound"]["tag"] = proxy["tag"]
    return proxies


def build_groups(proxies, target_countries):
    groups = {"PROXY-FREE": [proxy["tag"] for proxy in proxies]}
    for code in target_countries:
        groups[f"PROXY-{code}"] = [proxy["tag"] for proxy in proxies if proxy["country_code"] == code]
    return groups


def build_singbox_snapshot(proxies, groups):
    outbounds = [{"type": "direct", "tag": "DIRECT"}, {"type": "block", "tag": "BLOCK"}]
    outbounds.extend(proxy["outbound"] for proxy in proxies)
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


def main():
    args = parse_args()
    payloads = load_payloads(args.input_dir)
    target_countries = payloads[0].get("target_countries", ["ID", "SG", "US"])
    proxies = dedupe_proxies(payloads)
    groups = build_groups(proxies, target_countries)
    merged = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_count": max(payload.get("source_count", 0) for payload in payloads),
        "candidate_count": sum(payload.get("candidate_count", 0) for payload in payloads),
        "tcp_ok_count": sum(payload.get("tcp_ok_count", 0) for payload in payloads),
        "live_count": len(proxies),
        "target_countries": target_countries,
        "groups": groups,
        "proxies": proxies,
        "singbox": build_singbox_snapshot(proxies, groups),
    }
    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(merged, indent=2))
    print(f"saved merged output to {output_path}")
    print(f"live_count: {len(proxies)}")


if __name__ == "__main__":
    main()
