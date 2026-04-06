# ✅ Báo Cáo Trạng Thái Hệ Thống — TOTP 2FA Demo
# System Status Report — TOTP 2FA Demo

> **Thời gian kiểm tra / Checked at:** 2026-04-06 13:35 (GMT+7)  
> **Server:** `http://localhost:5000`  
> **Project:** `d:\TDTU\Sem2-2526\InfoSec\mfa-demo`

---

## 🧪 Tests: **31/31 PASSED** (0 failed)

```
31 passed, 1 warning in 4.94s
```

| Nhóm Test | # Tests | Kết quả |
|-----------|---------|---------|
| `TestCrypto` — AES-256-GCM encryption | 7 | ✅ All passed |
| `TestTOTPVerification` — RFC 6238 logic | 5 | ✅ All passed |
| `TestPasswordHashing` — Argon2id | 5 | ✅ All passed |
| `TestRegister` — API endpoint | 5 | ✅ All passed |
| `TestLogin` — API endpoint | 6 | ✅ All passed |
| `TestVerifyTotp` — TOTP + replay guard | 3 | ✅ All passed |

Chạy lại tests:

```bash
python -m pytest tests/ -v
```

---

## 🚀 Server: **Đang chạy tại `http://localhost:5000`**

### Trang HTML

| Trang | URL | Trạng thái |
|-------|-----|-----------|
| Đăng nhập | `/login` | ✅ HTTP 200 |
| Đăng ký | `/register` | ✅ HTTP 200 |
| Xác thực MFA | `/verify-mfa` | ✅ HTTP 200 (countdown timer hoạt động) |
| Đăng ký 2FA | `/enroll-2fa` | ✅ HTTP 200 |
| Dashboard | `/dashboard` | ✅ HTTP 302 → redirect `/login` (đúng, chưa auth) |

### API Endpoints

| Endpoint | Method | Trạng thái | Ghi chú |
|----------|--------|-----------|---------|
| `/api/status` | GET | ✅ HTTP 200 | `{"authenticated": false}` khi chưa login |
| `/api/register` | POST | ✅ HTTP 201 | Tạo user + băm Argon2id |
| `/api/login` | POST | ✅ HTTP 200 | Mật khẩu đúng: trả `session_token` |
| `/api/login` (sai MK) | POST | ✅ HTTP 401 | `"Invalid username or password"` |
| `/api/verify-totp` | POST | ✅ HTTP 401 | Session sai: `"Session expired or invalid"` |
| `/api/enroll-2fa` | POST | ✅ HTTP 200 | Trả QR code base64 + manual secret |
| `/api/confirm-2fa` | POST | ✅ HTTP 200 | Lưu secret AES-256-GCM vào DB |
| `/api/logout` | POST | ✅ HTTP 200 | Xóa session |
| `/api/login-history` | GET | ✅ HTTP 200 | 20 lần đăng nhập gần nhất |

---

## 🔐 Tính Năng Bảo Mật Đã Triển Khai

| Tính năng | Kỹ thuật | Trạng thái |
|-----------|----------|-----------|
| Mã hóa TOTP secret | AES-256-GCM + PBKDF2 (600K vòng) | ✅ Hoạt động |
| Băm mật khẩu | Argon2id (OWASP 2023) | ✅ Hoạt động |
| Chống replay attack | SHA-256 token hash + UNIQUE INDEX | ✅ Hoạt động |
| Dung sai đồng hồ | `valid_window=1` (±30s, RFC 6238 §5.2) | ✅ Hoạt động |
| Giới hạn tốc độ IP | flask-limiter | ✅ Hoạt động |
| Khóa tài khoản bậc 1 | 5 lần thất bại → khóa 15 phút | ✅ Hoạt động |
| Khóa tài khoản bậc 2 | 10 lần thất bại → khóa 1 giờ | ✅ Hoạt động |
| Khóa tài khoản bậc 3 | 20 lần thất bại → khóa 24 giờ | ✅ Hoạt động |
| Bảo vệ CSRF | flask-wtf | ✅ (tắt ở dev mode) |

---

## 📁 Cấu Trúc File Đã Tạo

```
mfa-demo/
├── app/
│   ├── __init__.py              ✅ Flask app factory
│   ├── config.py                ✅ Cấu hình từ .env
│   ├── core/
│   │   ├── crypto.py            ✅ AES-256-GCM + PBKDF2
│   │   ├── auth.py              ✅ Argon2id hashing
│   │   └── totp_engine.py       ✅ RFC 6238 + replay guard + QR
│   ├── models/
│   │   └── database.py          ✅ SQLite connection
│   ├── middleware/
│   │   └── rate_limiter.py      ✅ Rate limiting + lockout 3 bậc
│   ├── routes/
│   │   ├── auth_routes.py       ✅ 9 API endpoints
│   │   └── page_routes.py       ✅ HTML page routing
│   ├── templates/
│   │   ├── base.html            ✅
│   │   ├── login.html           ✅ Dark glassmorphism
│   │   ├── register.html        ✅
│   │   ├── verify_totp.html     ✅ Countdown timer + 6-digit input
│   │   ├── enroll_2fa.html      ✅ 3-step wizard + QR code
│   │   └── dashboard.html       ✅ Security stats + login history
│   └── static/
│       ├── css/styles.css       ✅ Full design system
│       └── js/
│           ├── login.js         ✅
│           ├── verify.js        ✅ Auto-advance + paste support
│           └── enroll.js        ✅
├── database/
│   └── schema.sql               ✅ 4 tables + security indexes
├── attacks/
│   ├── attack_bruteforce.py     ✅ Sequential + Random + Parallel
│   ├── attack_replay.py         ✅ 4 test scenarios
│   └── attack_clock_skew.py     ✅ -180s đến +180s analysis
├── tests/
│   ├── test_totp_engine.py      ✅ 20 tests
│   └── test_auth_routes.py      ✅ 11 tests
├── docs/
│   ├── IMPLEMENTATION_PLAN_EN.md
│   ├── IMPLEMENTATION_PLAN_VI.md
│   └── STATUS_REPORT.md         ← file này
├── run.py                       ✅
├── requirements.txt             ✅
└── .env.example                 ✅
```

---

## ⚠️ Các bước cần làm để demo đầy đủ

### Bước 1: Tạo tài khoản và enroll 2FA

1. Mở trình duyệt → `http://localhost:5000/register`
2. Nhập username, email, password → nhấn **Create Account & Setup 2FA**
3. Ở trang `/enroll-2fa`: mở Google Authenticator, quét QR code
4. Nhập mã 6 số từ app → nhấn **Confirm & Enable 2FA**

### Bước 2: Test luồng đăng nhập hoàn chỉnh

1. Vào `http://localhost:5000/login`
2. Nhập username + password → nhấn **Sign In**
3. Nhập mã TOTP từ Google Authenticator → nhấn **Verify Code**
4. Vào được Dashboard ✅

### Bước 3: Chạy Attack Simulations

> Cần có `session_token` (từ bước login) và `secret` (từ bước enroll).

```bash
# Scenario 1: Brute-Force
python attacks/attack_bruteforce.py --target http://localhost:5000 --max-attempts 50

# Scenario 2: Token Replay (cần thay TOKEN và SECRET)
python attacks/attack_replay.py \
  --target http://localhost:5000 \
  --session-token <session_token_tu_login> \
  --secret <base32_secret_tu_enroll>

# Scenario 3: Clock Skew Analysis (cần thay TOKEN và SECRET)
python attacks/attack_clock_skew.py \
  --target http://localhost:5000 \
  --session-token <session_token_tu_login> \
  --secret <base32_secret_tu_enroll> \
  --verify-impl
```

### Bước 4: Chạy lại toàn bộ test suite

```bash
python -m pytest tests/ -v --tb=short
```

---

## 🔑 Lệnh khởi động lại server

```bash
cd d:\TDTU\Sem2-2526\InfoSec\mfa-demo
python run.py
```

Server sẽ khởi động ở `http://0.0.0.0:5000` với debug mode.

---

*Báo cáo tạo bởi Antigravity AI — TDTU InfoSec Topic 9 Demo*
