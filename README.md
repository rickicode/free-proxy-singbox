# free-proxy-singbox

Repo ini bertugas sebagai producer daftar proxy publik yang benar-benar live.

Fungsi repo:

- fetch semua kandidat proxy dari source publik
- parse `trojan://`, `vless://`, `vmess://`, `ss://`
- cek TCP kandidat
- cek live kandidat dengan binary `sing-box` lokal
- deteksi negara exit IP
- tulis hasil akhir ke JSON yang bisa dibaca langsung lewat raw GitHub URL
- commit hasil scan otomatis lewat GitHub Actions setiap 12 jam

Repo ini tidak bertugas mengelola gateway host. Sistem gateway lain cukup membaca hasil scan dari repo ini.

## Output

File utama:

- `output/live-proxies.json`
  berisi metadata scan, daftar proxy live, group selector, dan snapshot `singbox`
- `output/live-proxies.singbox.json`
  berisi blok config `sing-box` yang siap dipakai sebagai source config
- `output/latest-summary.json`
  ringkasan kecil hasil scan terbaru

Naming proxy:

- format tag: `FREE-{COUNTRY}-{INDEX}-{SUFFIX}`
- contoh: `FREE-US-0003-ShadowsocksM-XX`

Group yang dihasilkan:

- `PROXY-FREE`
- `PROXY-ID`
- `PROXY-SG`
- `PROXY-US`
- `GLOBAL`

## Cara kerja

1. Ambil semua kandidat dari semua source.
2. Parse ke format outbound `sing-box`.
3. Dedupe kandidat.
4. Bagi kandidat ke shard untuk GitHub Actions.
5. Jalankan TCP test paralel.
6. Jalankan live test paralel memakai `bin/sing-box`.
7. Saat live test sukses, langsung lookup GeoIP.
8. Tulis hasil shard.
9. Merge semua shard.
10. Replace file output final lalu commit jika ada perubahan.

## GitHub Actions

Workflow: `.github/workflows/free-proxy-scan.yml`

- trigger manual `workflow_dispatch`
- trigger terjadwal tiap 12 jam
- 4 shard paralel
- merge hasil shard
- commit hasil terbaru ke branch repo

File yang akan di-replace di setiap run:

- `output/live-proxies.json`
- `output/live-proxies.singbox.json`
- `output/latest-summary.json`

Jika isi file tidak berubah, workflow tidak membuat commit baru.

## Menjalankan lokal

Siapkan binary:

```bash
./get-singbox.sh
```

Jalankan scan penuh:

```bash
python3 freeproxy.py scan
```

Jalankan satu shard manual:

```bash
python3 freeproxy.py scan --shard-index 0 --shard-count 4
```

## Catatan operasional

- live test tidak memakai service sistem
- setiap kandidat dites dengan config sementara
- hasil `output/live-proxies.singbox.json` bisa dipakai consumer lain untuk YACD/sing-box
- file `wg.py` yang lama bukan bagian alur utama repo ini

Lihat [AGENTS.md](/workspaces/free-proxy-singbox/AGENTS.md:1) untuk aturan perubahan repo dan [CONTEXT.md](/workspaces/free-proxy-singbox/CONTEXT.md:1) untuk konteks arsitektur.
