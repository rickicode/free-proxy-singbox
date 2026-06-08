# AGENTS

Aturan kerja agent untuk repo `free-proxy-singbox`.

## Scope

Repo ini hanya untuk:

- mengumpulkan proxy publik yang live
- mengubah hasilnya ke format data yang bisa dikonsumsi sistem lain
- mempublikasikan hasil scan lewat file di repo

Repo ini bukan tempat untuk:

- mengelola gateway host
- mengubah aturan routing host produksi
- menjalankan service `sing-box` sistem

## Prinsip perubahan

- pertahankan `freeproxy.py` sebagai scanner utama
- pertahankan output final di `output/live-proxies.json`
- pertahankan snapshot config di `output/live-proxies.singbox.json`
- perubahan schema output harus dijaga backward-compatible sebisa mungkin
- jika schema harus berubah, dokumentasikan di `README.md` dan `CONTEXT.md`

## GitHub Actions

- workflow utama ada di `.github/workflows/free-proxy-scan.yml`
- workflow harus tetap:
  - scan paralel
  - merge hasil shard
  - replace output final
  - commit hasil jika berubah
- hindari dependensi berat yang tidak perlu di runner GitHub

## Validasi minimum

Setelah edit kode Python:

```bash
python3 -m py_compile freeproxy.py scripts/merge_scan_results.py
```

Saat menyentuh schema atau flow output, uji minimal:

```bash
python3 freeproxy.py scan --shard-index 0 --shard-count 64 --tcp-workers 32 --live-workers 4 --output output/test-shard.json
python3 scripts/merge_scan_results.py --input-dir merged-input --output output/live-proxies.json
```

## Output contract

Output final diharapkan tetap punya field inti berikut:

- `generated_at`
- `candidate_count`
- `tcp_ok_count`
- `live_count`
- `groups`
- `proxies`
- `singbox`

Setiap item `proxies` diharapkan tetap punya:

- `tag`
- `protocol`
- `country_code`
- `server`
- `server_port`
- `external_ip`
- `outbound`

## Naming

- tag proxy format utama: `FREE-{COUNTRY}-{INDEX}-{SUFFIX}`
- group utama: `PROXY-FREE`, `PROXY-ID`, `PROXY-SG`, `PROXY-US`

## Catatan

- bila menambah source baru, pastikan source benar-benar raw text dan stabil
- bila menambah protokol baru, output harus tetap kompatibel dengan format outbound `sing-box`
- jangan hapus file output dari repo `.gitignore`; file output memang harus ter-commit
