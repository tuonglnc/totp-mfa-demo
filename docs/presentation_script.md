# 🛡️ SCRIPTS THUYẾT TRÌNH: TOTP-MFA ATTACK DEMO

## Tổng quan hệ thống

> [!NOTE]
> Hệ thống TOTP-MFA Demo triển khai xác thực 2 yếu tố theo chuẩn **RFC 6238** với 3 lớp bảo vệ chính:
> 1. **Mã hóa bí mật** — AES-256-GCM (secret được mã hóa at-rest)
> 2. **Chống replay** — SHA-256 token tracking trong database
> 3. **Chống brute-force** — Rate limiting + Progressive account lockout

**Công nghệ sử dụng:** Flask (Python), SQLite, PyOTP, Argon2id (password hashing)

---

## 📋 Kết quả tổng hợp 3 kịch bản

| # | Kịch bản | Tấn công thành công? | Verdict |
|---|----------|---------------------|---------|
| 1 | Brute-Force (Sequential, Random, Parallel) | ❌ **KHÔNG** | `PROTECTED` — Account locked sau 5 attempts |
| 2 | Token Replay Attack | ❌ **KHÔNG** | `SECURE` — Replay bị chặn hoàn toàn |
| 3 | Clock Skew / Drift Analysis | ❌ **KHÔNG** | `SECURE` — Chỉ chấp nhận ±30s (valid_window=1) |

> [!IMPORTANT]
> **Kết luận: Cả 3 kịch bản tấn công đều THẤT BẠI.** Hệ thống bảo vệ hoạt động đúng như thiết kế.

---

# KỊCH BẢN 1: BRUTE-FORCE ATTACK

## 1.1 Bối cảnh tấn công

**Giả định:** Attacker đã có username + password của nạn nhân (qua phishing, credential stuffing, hoặc data breach). Attacker cố gắng đoán mã OTP 6 chữ số.

**Không gian khóa:** 1,000,000 mã (000000 → 999999)

## 1.2 Demo — Chạy lệnh

```bash
cd attacks && python attack_bruteforce.py --mode all --max-attempts 30
```

## 1.3 Kết quả thực tế

### Scenario 1A: Sequential Brute-Force (tuần tự 000000, 000001, ...)

```
  [   5] OTP=000004 -> HTTP 423
  [!] ACCOUNT LOCKED after 5 attempts!
      Retry after: 900s
```

| Metric | Giá trị |
|--------|---------|
| Tổng attempts | 5 |
| Thời gian | 1.53s |
| Tốc độ | 3.3 req/s |
| HTTP 401 (sai mã) | 4 lần |
| HTTP 423 (khóa tài khoản) | 1 lần |
| **Kết quả** | **PROTECTED — Account locked** |

### Scenario 1B: Random Brute-Force (mã ngẫu nhiên)

```
  [   1] OTP=645943 -> HTTP 401
  [   2] OTP=759525 -> HTTP 401
  [   3] OTP=210471 -> HTTP 401
  [   4] OTP=351505 -> HTTP 401
  [   5] OTP=404705 -> HTTP 423
  [!] LOCKED (HTTP 423) after 5 attempts
```

**Kết quả:** Tương tự — **LOCKED sau 5 attempts**.

### Scenario 1C: Parallel Brute-Force (5 threads đồng thời)

```
  HTTP 401 (Unauthorized): 9x
  HTTP 423 (Locked):       1x
  HTTP 429 (Rate Limited): 20x
```

**Kết quả:** Bị chặn bởi **CẢ HAI** cơ chế — rate limiting VÀ account lockout.

## 1.4 Phân tích toán học

```
OTP keyspace:            1,000,000 (6 digits)
Attempts before lockout: 5
P(đoán đúng trước khi bị lock) = 5/1,000,000 = 0.0005%
Thời gian crack (ước tính):     69.4 ngày
```

## 1.5 Cơ chế bảo vệ (giải thích code)

**Layer 1 — Rate Limiting** (Flask-Limiter):
- 20 requests/phút trên `/api/verify-totp`
- Ngăn chặn high-speed enumeration

**Layer 2 — Progressive Account Lockout:**

| Tier | Số lần sai | Thời gian khóa |
|------|-----------|----------------|
| 1 | 5 failures | 15 phút |
| 2 | 10 failures | 1 giờ |
| 3 | 20 failures | 24 giờ |

**Hiệu quả kết hợp:**
- Attacker chỉ được thử **4 mã** trước khi bị khóa
- P(thành công) = 4/1,000,000 = **0.0004%** mỗi lần thử
- Thời gian để đạt 50% xác suất thành công: **~10 năm**

---

# KỊCH BẢN 2: TOKEN REPLAY ATTACK

## 2.1 Bối cảnh tấn công

**Giả định:** Attacker quan sát/đánh cắp mã OTP hợp lệ (shoulder-surfing, MITM, phishing). Nạn nhân dùng mã đó đăng nhập thành công. Attacker cố **tái sử dụng** cùng mã OTP đó.

## 2.2 Demo — Chạy lệnh

```bash
cd attacks && python attack_replay.py
```

## 2.3 Kết quả 4 bài test

| Test | Mã OTP | HTTP Status | Kết quả |
|------|--------|-------------|---------|
| **Test 1:** Sử dụng lần đầu (hợp lệ) | 554135 | 200 ✅ | `OK` — Đăng nhập thành công |
| **Test 2:** Replay ngay lập tức | 554135 | 401 🚫 | `BLOCKED` — "Code already used" |
| **Test 3:** Replay sau 5 giây | 554135 | 401 🚫 | `BLOCKED` — "Code already used" |
| **Test 4:** Mã khác (cửa sổ kế tiếp) | 277748 | 200 ✅ | `OK` — Mã mới được chấp nhận |

> **Verdict: `SECURE` — Replay attacks are fully blocked**

## 2.4 Cơ chế bảo vệ — Code Flow

```
User submits OTP
    │
    ▼
[1] Format check (phải đúng 6 chữ số)
    │
    ▼
[2] Replay check ← Kiểm tra bảng used_tokens (SHA-256 hash)
    │                Quét ALL time-steps trong valid_window
    │                → Nếu đã dùng → REJECT ngay
    ▼
[3] TOTP verify (RFC 6238 + hmac.compare_digest)
    │
    ▼
[4] Register used token → INSERT vào used_tokens
    │                      UNIQUE INDEX đảm bảo race-condition safe
    ▼
SUCCESS
```

**Chi tiết kỹ thuật:**

1. **Pre-verification check:** Server kiểm tra bảng `used_tokens` TRƯỚC KHI verify crypto. Tra cứu O(1) qua UNIQUE INDEX `(user_id, token_hash, time_step)`.

2. **Token hashing:** Server lưu `SHA-256(code)`, KHÔNG lưu plaintext. Attacker có quyền đọc DB cũng không khôi phục được mã đã dùng.

3. **Multi-step scanning:** Replay check quét **tất cả** time-steps trong `valid_window` (±1). Ngăn replay mã từ cửa sổ 30s liền kề.

4. **Database-level enforcement:** `UNIQUE INDEX` đảm bảo dưới race conditions (2 request cùng mã đến đồng thời), chỉ 1 request thành công. `INSERT OR IGNORE` cho request thứ 2 fail im lặng.

---

# KỊCH BẢN 3: CLOCK SKEW / DRIFT ANALYSIS

## 3.1 Bối cảnh tấn công

**Giả định:** Attacker phân tích hệ thống chấp nhận mã OTP trong phạm vi thời gian nào. Nếu window quá rộng → nhiều mã hợp lệ đồng thời → tăng xác suất brute-force.

**Nguyên nhân thực tế gây clock skew:**
- Điện thoại ở chế độ máy bay (không đồng bộ NTP)
- Phần cứng cũ (RTC drift ~1-2 phút/tháng)
- VM clock drift (hypervisor pausing)

## 3.2 Demo — Chạy lệnh

```bash
cd attacks && python attack_clock_skew.py --range 90 --step 30
```

## 3.3 Kết quả — Bản đồ cửa sổ chấp nhận

```
    Offset |   Step |      OTP |         Result | HTTP
  ---------+--------+----------+----------------+-----
       -90s |     -3 |   632041 |       REJECTED | 401
       -60s |     -2 |   887836 |       REJECTED | 401
       -30s |     -1 |   812613 |       ACCEPTED | 200  ← window trước
        +0s |     +0 |   493664 |       REJECTED | 401  ← trùng mã enrollment (replay blocked!)
       +30s |     +1 |   666375 |       ACCEPTED | 200  ← window sau
       +60s |     +2 |   076233 |       REJECTED | 401
       +90s |     +3 |   330701 |       REJECTED | 401
```

**Phạm vi chấp nhận:** `-30s` đến `+30s` (tổng cộng 60s tolerance)

## 3.4 Bảng phân tích Security Trade-off

| valid_window | Tolerance | Số mã hợp lệ đồng thời | P(brute per window) |
|-------------|-----------|------------------------|---------------------|
| 0 | ±0s (exact) | 1 mã | 1/1,000,000 = 0.0001% |
| **1 (mặc định)** | **±30s** | **3 mã** | **3/1,000,000 = 0.0003%** |
| 2 | ±60s | 5 mã | 5/1,000,000 = 0.0005% |
| 3 | ±90s | 7 mã | 7/1,000,000 = 0.0007% |

> [!TIP]
> **Khuyến nghị:** `valid_window=1` (cấu hình hiện tại) là tối ưu theo RFC 6238 §5.2.
> - Xử lý được NTP drift thông thường (phones sync trong ±5s)
> - Chỉ 3 mã hợp lệ đồng thời (ảnh hưởng bảo mật không đáng kể)
> - Dùng được ngay cả khi đồng hồ điện thoại lệch ±30s

---

# UNIT TESTS — 17/17 PASSED ✅

```bash
python -m pytest tests/test_totp_engine.py -v
```

| Module | Tests | Kết quả |
|--------|-------|---------|
| `TestCrypto` (AES-256-GCM) | 7 tests | ✅ All passed |
| `TestTOTPVerification` | 5 tests | ✅ All passed |
| `TestPasswordHashing` (Argon2id) | 5 tests | ✅ All passed |

**Các test quan trọng:**
- Encrypt → Decrypt roundtrip: ✅
- Tampered ciphertext bị reject: ✅
- Wrong key bị reject: ✅
- Hash token deterministic + unique: ✅
- Old code (3+ steps) bị reject: ✅
- Adjacent window (±1 step) được accept: ✅
- Argon2id hashes unique (different salts): ✅

---

# KẾT LUẬN TỔNG HỢP

## Tại sao 3 kịch bản tấn công đều thất bại?

### 🔒 Defense-in-Depth Architecture

```
┌─────────────────────────────────────────┐
│           TOTP MFA System               │
│                                         │
│  Layer 1: Rate Limiting (Flask-Limiter) │ ← Chặn high-speed attacks
│  Layer 2: Account Lockout (Progressive) │ ← Chặn persistent attacks
│  Layer 3: Replay Prevention (SHA-256)   │ ← Chặn token reuse
│  Layer 4: Clock Window Control (±30s)   │ ← Giới hạn attack surface
│  Layer 5: Encryption at Rest (AES-256)  │ ← Bảo vệ secrets trong DB
│  Layer 6: Password Hashing (Argon2id)   │ ← Chống credential theft
│                                         │
└─────────────────────────────────────────┘
```

### Bảng tổng kết

| Kịch bản | Cơ chế chặn chính | Thời gian để crack (ước tính) |
|----------|-------------------|------------------------------|
| Brute-Force | Account lockout sau 5 attempts | **~69 ngày** (lý thuyết) / **~10 năm** (thực tế với lockout) |
| Replay | SHA-256 token tracking + UNIQUE INDEX | **Không thể** — mã đã dùng bị reject vĩnh viễn |
| Clock Skew | valid_window=1 (chỉ ±30s) | Chỉ 3 mã hợp lệ cùng lúc — P = 0.0003% |

> [!CAUTION]
> **Lưu ý quan trọng:** Demo này chỉ dùng cho mục đích giáo dục. KHÔNG sử dụng các script tấn công trên hệ thống không thuộc quyền sở hữu của bạn.
