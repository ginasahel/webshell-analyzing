# 🕵️ Operation: Silent Shell — Brief Peserta

## Skenario
Kamu **SOC Analyst** di **Nusacommerce** (toko online). Tim IT melapor server web
berperilaku aneh: proses mencurigakan berjalan sebagai user web server dan file
asing muncul di folder `uploads`. Dugaan: **seseorang berhasil menanam web shell
PHP** dan bisa menjalankan perintah di server. Bongkar rantai serangannya.

## Lingkungan (lab)
- Buka **OpenSearch Dashboards** (URL lab dari instruktur). Tanpa login.
- Saat dibuka, dashboard **"SOC Lab — Investigasi Web Shell"** tampil otomatis
  (timeline, top IP, status code, tabel file `.php` di `/uploads`, login gagal, dst).
- Butuh query manual? Buka menu **Discover**.
- **Index:**
  - `nusacommerce-web-access*` — log akses web (siapa mengakses URL apa)
  - `nusacommerce-auth*` — log login panel admin/user
- ⏰ Insiden **10 Oktober 2026 (UTC)**. Time range sudah otomatis ke tanggal itu;
  jika kosong set manual `2026-10-10` → `2026-10-11`.

## 📝 Submit jawaban
Kerjakan 8 task di bawah, lalu **submit jawabannya di:**
**https://hack.redlimit.id/soc-lab**
(Lab hanya untuk investigasi — tidak ada form submit di dalam lab.)

## Field penting
| Field | Arti |
|---|---|
| `source.ip` | IP pengakses |
| `url.path` / `url.original` | URL (tanpa / dengan query) |
| `url.query` | query string (mis. `cmd=id`) |
| `url.extension` | ekstensi (`php`, `jpg`, …) |
| `http.request.method` | GET / POST |
| `http.response.status_code` | 200 sukses · 403/404 gagal |
| `http.request.body.bytes` | ukuran body (upload besar = body besar) |
| `user_agent.original` | identitas client |
| `event.action` (auth) | `login_failed` / `login_success` |
| `user.name` (auth) | akun login |

## 8 Task (total 150 poin)
| # | Fase | Pertanyaan | Poin |
|---|---|---|---|
| 1 | Initial Access | Dari IP mana serangan brute-force panel admin berasal? | 10 |
| 2 | Initial Access | Akun apa yang berhasil dikompromikan? | 10 |
| 3 | Initial Access | Berapa kali IP pelaku gagal login sebelum berhasil? | 15 |
| 4 | Initial Access | Pukul berapa (UTC, HH:MM) login berhasil pertama dari IP pelaku? | 15 |
| 5 | Execution | Endpoint (URL path) mana yang disalahgunakan untuk upload? | 20 |
| 6 | Persistence | Apa path lengkap file web shell yang ditanam? | 25 |
| 7 | Execution | Perintah pertama apa (nilai `cmd`) yang dijalankan via web shell? | 25 |
| 8 | Command & Control | URL mana yang dihubungi (wget) untuk unduh payload tahap-2? | 30 |

> Tips: jawaban sejati memenuhi **seluruh** rantai — brute-force `admin` →
> `login_success` → `POST` upload (200) → file `.php` di `/uploads/` yang
> dieksekusi (200) dengan `?cmd=`. Abaikan scanner yang hanya menghasilkan 404.

Contoh query DQL di Discover:
```
url.original : *uploads* and url.extension : "php" and http.response.status_code : 200
event.action : "login_failed"
source.ip : "x.x.x.x"
```
