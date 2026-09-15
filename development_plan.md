# Plan Development Aplikasi Mobile & Backend - DevTester.id

## 📌 Ringkasan Proyek

| Parameter | Keterangan |
| :--- | :--- |
| **Landing Page** | [https://devtester.id](https://devtester.id) |
| **Nilai Utama (Value Prop)** | Platform Crowdsourced Testing untuk Memenuhi Syarat Google Play (12 Tester Aktif selama 14 Hari Closed Testing) |
| **Target Platform** | Android (Flutter Mobile App) |
| **Backend Architecture** | Rust Monolith (Axum Framework + Tokio Runtime) |
| **Database** | Neon DB (Serverless PostgreSQL) |
| **Target Deployment** | Render.com Web Service (Starter Plan - Bekas Service Lama) |
| **Mekanisme Ekonomi** | Sistem Kredit ("Saling Bantu": Tes aplikasi dev lain untuk dapat kredit / Beli Kredit Paket Starter/Pro) |
| **Timeline** | 4 Fase Development |

---

## 🎯 Anchor Features DevTester.id

Berdasarkan analisis fitur di landing page `devtester.id`:

1. **Submit Aplikasi Closed Testing**: Developer mendaftarkan URL opt-in Google Play Closed Testing (membutuhkan 100 kredit).
2. **Matching Tester Otomatis**: Menghubungkan aplikasi terdaftar dengan minimal 12 tester terverifikasi dari komunitas.
3. **Daily Check-in & Feedback (14 Hari)**: Tester mengunduh, membuka aplikasi harian, dan memberikan masukan/umpan balik terstruktur.
4. **Sistem Kredit "Saling Bantu" (Gamification)**: Tester mendapatkan kredit setiap kali menguji aplikasi developer lain, yang bisa digunakan untuk menguji aplikasi miliknya sendiri.
5. **Dashboard Monitoring 14 Hari**: Pantau progress durasi 14 hari dan grafik keaktifan 12 tester secara real-time.
6. **Laporan Kepatuhan Google Play**: Ringkasan laporan pengujian terstruktur untuk syarat rilis publik Google Play.
7. **Monetisasi / Beli Kredit**: Top-up kredit (Paket Starter Rp49k / Pro Rp199k).

---

## 🏗️ Arsitektur & Technology Stack

### 1. Frontend (Mobile App - Android)
* **Framework**: Flutter (Dart)
* **State Management**: Riverpod / BLoC
* **Networking**: Dio (dengan JWT Interceptor)
* **Local Storage**: `flutter_secure_storage` (Token Auth) & `Isar`/`Hive` (Offline Caching)
* **UI Framework**: Material 3 (Brutalist Modern Style / Palette Purple & Yellow khas DevTester.id)

### 2. Backend (Rust Monolith Service)
* **Language**: Rust
* **Web Framework**: Axum
* **Async Runtime**: Tokio
* **Database Driver / ORM**: SQLx (Compile-time checked SQL queries & async connection pool)
* **Authentication**: JWT (`jsonwebtoken`) + Password Hashing (`argon2`)
* **Serialization**: `serde` & `serde_json`

### 3. Database (Neon DB - PostgreSQL Schema Core)
* `users` (id, email, password_hash, role, credits_balance, created_at)
* `applications` (id, developer_id, app_name, playstore_link, status, required_testers, start_date, end_date)
* `tester_assignments` (id, application_id, tester_id, status, assigned_at)
* `daily_checkins` (id, assignment_id, day_number, feedback_text, screenshot_url, is_verified, checked_at)
* `credit_transactions` (id, user_id, amount, type [EARNED/SPENT/PURCHASED/BONUS], description, created_at)
* `credit_packages` (id, name, price, credits, bonus_credits)

---

## 🚀 Timeline Development (4 Fase)

```
┌───────────────────────────────────────────────────────────────────────────┐
│                      ROADMAP DEVELOPMENT 4 FASE                           │
├───────────────┬─────────────────┬───────────────────┬─────────────────────┤
│    FASE 1     │     FASE 2      │      FASE 3       │       FASE 4        │
│ Architecture  │ Core Features & │  14-Day Tracker,  │ Monetization, Polish│
│   & Setup     │ Credit Engine   │ Render Deployment │  & Android Release  │
└───────────────┴─────────────────┴───────────────────┴─────────────────────┘
```

---

### 🟢 Fase 1: Fondasi Arsitektur, DB Schema & Environment Setup

#### **Backend (Rust Monolith - Axum)**
- [ ] Inisialisasi proyek Rust (`cargo new --bin devtester-backend`).
- [ ] Konfigurasi dependensi pada `Cargo.toml`:
  - `axum`, `tokio`, `sqlx` (features: `postgres`, `runtime-tokio-native-tls`, `chrono`, `uuid`), `serde`, `jsonwebtoken`, `argon2`, `dotenvy`, `tracing`.
- [ ] Setup koneksi ke **Neon DB** menggunakan `sqlx::PgPool` (Connection String SSL `sslmode=require`).
- [ ] Buat skema migrasi database (`sqlx migrate`):
  - Tabel `users`, `applications`, `tester_assignments`, `daily_checkins`, `credit_transactions`.
- [ ] Buat Dockerfile multi-stage build (stage 1: `cargo build --release`, stage 2: `debian:bookworm-slim`) untuk deployment Render.com Starter Plan.
- [ ] Implementasi health check endpoint (`GET /health`).

#### **Mobile (Flutter Android)**
- [ ] Inisialisasi proyek Flutter (Target Android).
- [ ] Setup struktur folder berbasis fitur (*Feature-First Architecture*):
  - `lib/src/features/auth`
  - `lib/src/features/developer_dashboard` (Submit & Monitor App)
  - `lib/src/features/tester_community` (Browse Apps to Test)
  - `lib/src/features/credits` (Saldo & History Kredit)
  - `lib/src/core/network` & `lib/src/core/theme`
- [ ] Konfigurasi `Dio` client & `flutter_secure_storage`.
- [ ] Setup Design System (Skema Warna Khas DevTester: Purple `#6C5CE7`, Yellow `#FDCB6E`, Dark Text, Card Border Style).

---

### 🔵 Fase 2: Auth, Credit Engine & Submit/Matching Aplikasi

#### **Backend (Rust Monolith)**
- [ ] **Modul Autentikasi**:
  - `POST /api/v1/auth/register` (Bonus 50 kredit pendaftaran awal)
  - `POST /api/v1/auth/login` (Return JWT Token)
- [ ] **Modul Kredit ("Saling Bantu Engine")**:
  - `GET /api/v1/credits/balance` (Cek saldo kredit)
  - `GET /api/v1/credits/history` (Riwayat transaksi kredit)
  - Logic Ledger: Potong 100 kredit saat submit aplikasi; Tambah kredit saat tester menyelesaikan tugas harian.
- [ ] **Modul Submit Aplikasi & Matching**:
  - `POST /api/v1/apps` (Submit URL Closed Testing Google Play)
  - `GET /api/v1/apps/available` (List aplikasi yang butuh tester bagi komunitas)
  - `POST /api/v1/apps/:id/join` (Tester mendaftar menjadi 1 dari 12 tester terverifikasi).

#### **Mobile (Flutter Android)**
- [ ] Screen Auth (Login & Register).
- [ ] **Layar Tester (Komunitas Tester Aktif)**:
  - List aplikasi yang tersedia untuk diuji.
  - Detail aplikasi + Tombol "Mulai Pengujian" (membuka link Opt-in Play Store).
- [ ] **Layar Developer (Submit Aplikasi)**:
  - Form Submit Aplikasi (Nama, URL Play Store, Kebutuhan Tester).
  - Indikator kecukupan kredit (Peringatan jika kredit < 100).
- [ ] Widget Widget Saldo Kredit & Status Keanggotaan.

---

### 🟡 Fase 3: 14-Day Testing Tracker, Daily Check-in & Render Deployment

#### **Backend (Rust Monolith)**
- [ ] **Modul Daily Check-in & Feedback**:
  - `POST /api/v1/checkins` (Tester submit laporan harian + feedback catatan/screenshot).
  - Otomatisasi reward kredit ke tester setelah check-in tervalidasi.
- [ ] **Modul Monitoring & Report**:
  - `GET /api/v1/apps/:id/progress` (Progress bar Hari ke-X dari 14 hari, & statistik keaktifan 12 tester).
  - `GET /api/v1/apps/:id/report` (Laporan terstruktur untuk pengajuan rilis Play Store).
- [ ] **Deployment ke Render.com (Starter Tier)**:
  - Hubungkan repositori Git ke Render Web Service Starter Plan.
  - Set Environment Variables: `DATABASE_URL` (Neon DB Pooled Port 6543), `JWT_SECRET`, `RUST_LOG=info`.

#### **Mobile (Flutter Android)**
- [ ] **Layar Daily Testing (Tugas Harian Tester)**:
  - List aplikasi yang sedang diuji aktif.
  - Form Check-in Harian (Ulasan/Feedback harian & upload screenshot bukti pengujian).
- [ ] **Layar Dashboard Monitoring Developer**:
  - Tampilan visual progress bar 14 Hari (seperti pada screenshot landing page).
  - Counter "12 Tester Terhubung & Aktif".
  - Tab "Laporan Testing Terstruktur" (bisa di-copy/export).
- [ ] Integrasi API Production Render.com (`https://devtester-backend.onrender.com`).

---

### 🔴 Fase 4: Beli Kredit (Monetisasi), Testing & Android Release

#### **Backend & Monetisasi**
- [ ] **Modul Beli Kredit / Paket**:
  - `GET /api/v1/packages` (List Paket: Starter Rp49k / Pro Rp199k).
  - Integration Payment Gateway (Midtrans/Xendit) atau Webhook Verifikasi Pembayaran Top-up.
- [ ] **Optimasi Rust Monolith**:
  - Setting SQLx Connection Pool limit (`max_connections(10)`).
  - Rate limiting & CORS configuration (`tower-http`).

#### **Mobile (Flutter Android) & Release**
- [ ] Layar Pembelian / Top-up Kredit (Pilihan Paket Starter, Pro, Studio).
- [ ] Testing komprehensif pada berbagai perangkat Android (Android 8.0 - Android 14+).
- [ ] Optimasi Build Flutter:
  - `flutter build apk --split-per-abi` atau Android App Bundle (`.aab`).
  - Code obfuscation (`--obfuscate --split-debug-info`).
- [ ] **Integrasi Landing Page `devtester.id`**:
  - Tambahkan tombol CTA di landing page: **"Download Aplikasi Android (APK)"** untuk langsung menghubungkan developer/tester ke aplikasi Flutter.

---

## 💡 Catatan Teknis Penting

1. **Efisiensi Memory Rust di Render Starter Plan**: Rust Monolith Axum hanya mengonsumsi memory ~15-30 MB RAM. Ini membuat backend DevTester.id berjalan sangat cepat dan efisien tanpa pernah kehabisan resource di Render.com Starter Plan.
2. **Neon DB Connection Pooling**: Pastikan string koneksi `DATABASE_URL` menggunakan port `6543` (Pooled Connection) agar koneksi serverless Neon DB tetap stabil saat terjadi banyak check-in harian concurrent dari para tester.
3. **Play Store Deep Link**: Di aplikasi Flutter, gunakan package `url_launcher` untuk langsung mengarahkan tester ke URL Opt-in / Closed Testing link Google Play Store developer.
