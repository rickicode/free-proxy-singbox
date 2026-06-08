# Context

## Tujuan repo

`free-proxy-singbox` adalah repo producer hasil scan proxy live.

Repo ini dipakai untuk:

- menjalankan scan proxy publik otomatis lewat GitHub Actions
- menyimpan hasil scan terbaru langsung di repo
- menyediakan URL raw GitHub yang bisa dibaca gateway atau tool lain

## Batasan

- repo ini tidak mengatur host gateway
- repo ini tidak mengurus routing policy produksi
- repo ini tidak menjalankan `sing-box` sebagai daemon
- repo ini hanya memakai binary `sing-box` untuk menguji kandidat proxy

## Kontrak consumer

Consumer eksternal diharapkan membaca salah satu dari:

- `output/live-proxies.json`
- `output/live-proxies.singbox.json`

Use case umum:

- gateway builder menarik raw JSON lalu membangun config produksi
- dashboard membaca summary/group/proxy count
- operator meninjau daftar proxy aktif berdasarkan negara

## Flow scan

1. Fetch semua source.
2. Extract semua URI proxy yang didukung.
3. Parse ke outbound format `sing-box`.
4. Dedupe kandidat.
5. Split ke shard.
6. TCP test paralel.
7. Live test paralel memakai binary `bin/sing-box`.
8. Saat hidup, ambil `external_ip`.
9. Lookup GeoIP dari `external_ip`.
10. Bentuk tag proxy, groups, dan snapshot `singbox`.
11. Merge hasil shard.
12. Commit hasil terbaru.

## Data penting

Field output penting:

- `groups.PROXY-FREE` = semua tag proxy live
- `groups.PROXY-ID` = tag proxy exit negara Indonesia
- `groups.PROXY-SG` = tag proxy exit negara Singapore
- `groups.PROXY-US` = tag proxy exit negara United States
- `singbox` = snapshot config YACD/sing-box-ready

## Naming proxy

Proxy ditag dengan pola:

`FREE-{COUNTRY}-{INDEX}-{SUFFIX}`

Contoh:

- `FREE-FR-0001-VPsave`
- `FREE-US-0003-ShadowsocksM-XX`

Arti:

- `FREE` = hasil dari scanner ini
- `COUNTRY` = country code exit IP
- `INDEX` = urutan setelah merge final
- `SUFFIX` = nama sumber atau identitas singkat kandidat

## Workflow GitHub Actions

Workflow saat ini:

- jalan tiap 12 jam
- 4 shard paralel
- merge hasil
- replace file output final
- commit dan push otomatis jika ada perubahan

## Hal yang perlu dijaga

- output final harus stabil dan mudah dibaca consumer
- perubahan format outbound harus kompatibel dengan `sing-box`
- log sukses scan idealnya tetap menampilkan IP dan country code
