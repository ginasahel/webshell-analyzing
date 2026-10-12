# SOC Lab — Operation: Silent Shell 🐚

Lab investigasi untuk melatih **SOC Analyst**. Peserta memakai **OpenSearch
Dashboards** (dashboard visualisasi siap-pakai + Discover) untuk membongkar
serangan **web shell PHP**, lalu **submit jawaban 8 task di platform eksternal**:

> 📝 **Submit jawaban:** https://hack.redlimit.id/soc-lab

Lab ini **fokus pada visualisasi/investigasi data** — tidak ada form submit di
dalam lab. Satu kontainer berisi OpenSearch + OpenSearch Dashboards + data dummy
yang ter-seed otomatis, mengekspos **satu port**, jadi langsung cocok untuk PaaS
(ngelinx.com, dll).

```
┌──────────────── container (port $PORT, default 5601) ────────────────┐
│  OpenSearch Dashboards  ◀── visualisasi + Discover (yang dilihat user) │
│        │                                                               │
│   OpenSearch  ◀── seeder: data dummy + dashboard siap-pakai (otomatis) │
└──────────────────────────────────────────────────────────────────────┘
```

## Struktur

| Path | Keterangan |
|---|---|
| `Dockerfile` | image single-container untuk PaaS & lokal |
| `allinone/entrypoint.sh` | start OpenSearch → Dashboards → seeder |
| `allinone/opensearch_dashboards.yml` | OSD, `defaultRoute` → dashboard investigasi |
| `config/opensearch.yml` | OpenSearch single-node, security off |
| `seeder/seed.py` | generator data + pembuat index pattern, 9 visualisasi, 1 dashboard (stdlib) |
| `docker-compose.yml` | menjalankan image yang sama secara lokal (port 5601) |
| `setup.sh` / `teardown.sh` | helper lokal |
| `CHALLENGE.md` | brief peserta + 8 task (untuk diunggah ke platform submit) |
| `SOLUTION.md` | **kunci jawaban** (khusus instruktur) |

## Dashboard yang dibuat otomatis
Saat Dashboards dibuka, langsung tampil **"SOC Lab — Investigasi Web Shell"**:
panel brief (berisi tautan submit), total event, distribusi status code, timeline
event, Top Source IP, Top URL, asal negara IP, **tabel file `.php` di `/uploads`
yang berhasil (200)**, dan **login gagal per IP (brute-force)**. Peserta juga bisa
pakai **Discover** untuk query manual (DQL).

---

## Jalankan lokal

```bash
./setup.sh          # build + start, tunggu siap
# buka http://localhost:5601/
./teardown.sh       # stop   (--purge untuk hapus image)
```
Build pertama mengunduh ~1 GB (tarball OpenSearch+Dashboards), butuh beberapa
menit. Sediakan **±2 GB RAM**. `setup.sh` otomatis menaikkan `vm.max_map_count`
dan memakai `sudo docker` bila perlu. Peserta masuk tanpa login sebagai **anonymous read-only**.

---

## Deploy ke PaaS (ngelinx.com)

ngelinx mendukung deploy dari **GitHub / Docker / Nixpacks** dengan deteksi build
& port otomatis. Lab ini adalah **satu `Dockerfile`** yang mengekspos satu port
(Dashboards).

1. Push folder ini ke repo GitHub (lihat "Push ke GitHub").
2. ngelinx: **New App → from GitHub**, pilih repo (branch `main`). Build auto →
   memakai `Dockerfile` root.
3. **Environment variables** (opsional):
   | Var | Default | Fungsi |
   |---|---|---|
   | `PORT` | `5601` | port publik; di-inject PaaS → dihormati entrypoint |
   | `EVENT_COUNT` | `9000` | banyak noise → tingkat kesulitan |
   | `OPENSEARCH_JAVA_OPTS` | `-Xms512m -Xmx512m` | heap; naikkan bila RAM besar |
   | `SCENARIO_DAY` | `2026-10-10` | tanggal insiden |
4. **Resource**: beri **≥ 2 GB RAM**. Protokol **HTTP**.
5. Deploy → akses domain ngelinx → dashboard investigasi tampil otomatis.

> Data di-seed ulang setiap start (deterministik, jawaban selalu sama). Tidak
> perlu volume. Boot pertama ~1–2 menit sampai Dashboards + dashboard siap.

### Push ke GitHub
```bash
cd /home/ubuntu/soc-lab/challenge-2
git init -b main && git add . && git commit -m "SOC lab: Operation Silent Shell"
git remote add origin git@github.com:<user>/<repo>.git
git push -u origin main
```

---

## Task & submit jawaban
8 task (brief lengkap di `CHALLENGE.md`) **dikerjakan & disubmit di
https://hack.redlimit.id/soc-lab**, bukan di lab. Kunci jawaban + query
pembuktian + penjelasan red herring ada di `SOLUTION.md`.

## Akses & keamanan
- **Peserta = anonymous READ-ONLY.** Security plugin OpenSearch AKTIF. Pengunjung
  masuk tanpa login (anonymous), dipetakan ke role read-only (`soc_viewer` +
  Global tenant `kibana_all_read`). Mereka bisa melihat dashboard & query bebas di
  Discover, tapi **tidak bisa menulis/menghapus data, dashboard, maupun visualisasi**
  — via UI, API saved-object, maupun Dev Tools. Jadi satu peserta iseng tidak bisa
  merusak lab untuk yang lain.
- **Admin internal.** OpenSearch REST (`:9200`) memakai user `admin`/`admin` &
  `kibanaserver`/`kibanaserver` (kredensial demo) — **tidak diekspos ke publik**
  (hanya dipakai di dalam container; yang terekspos hanya Dashboards). Seeder
  memakai admin untuk memuat data & membuat dashboard.
- **REST tanpa TLS, transport TLS self-signed** (internal). HTTPS publik ditangani
  ngelinx. Lab ini untuk **latihan** — jangan untuk produksi/data nyata.
- Tidak ada web shell sungguhan: hanya **jejak log** simulasi untuk latihan deteksi.
