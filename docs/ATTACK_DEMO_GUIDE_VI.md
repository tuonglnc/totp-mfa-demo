# TOTP 2FA - Huong Dan Demo 3 Kich Ban Tan Cong

> Mon: Bao Mat Thong Tin - TDTU  
> Chu de: Trien khai va phan tich TOTP (RFC 6238)  
> Muc dich: **Giao duc** - Chi chay tren he thong cua ban than.

---

## Noi Dung

1. [Chuan bi moi truong](#1-chuan-bi-moi-truong)
2. [Kich ban 1: Brute-Force (Doan ma OTP)](#2-kich-ban-1-brute-force)
3. [Kich ban 2: Replay (Tai su dung ma OTP)](#3-kich-ban-2-replay)
4. [Kich ban 3: Clock Skew (Lệch dong ho)](#4-kich-ban-3-clock-skew)
5. [Tong ket](#5-tong-ket)

---

## 1. Chuẩn bị môi trường

### 1.1 Cài đặt dependencies

```bash
cd totp-mfa-demo
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 1.2 Cấu hình biến môi trường

Tạo file `.env` (nếu chưa có):

```env
SECRET_KEY=your-secret-key-here
TOTP_MASTER_KEY=demo-master-key-2026-change-in-production
FLASK_ENV=development
```

> **Lưu ý:** `TOTP_MASTER_KEY` phải cố định để server khởi động lại vẫn decrypt được secret đã lưu. Nếu không set, mỗi lần restart server sẽ generate key mới → mất toàn bộ TOTP secrets.

### 1.3 Khởi động server

```bash
python run.py
```

Server chạy tại `http://localhost:5000`. Giữ terminal này mở trong suốt quá trình demo.

### 1.4 Chạy attack scripts

Mở **terminal thứ 2** và chạy từng script:

```bash
# Kich ban 1
python attacks/attack_bruteforce.py

# Kich ban 2
python attacks/attack_replay.py

# Kich ban 3
python attacks/attack_clock_skew.py
```

Mỗi script **tự động** tạo user, enroll 2FA, và chạy test. Không cần thao tác thủ công.

---

## 2. Kịch bản 1: Brute-Force

### 2.1 Mô tả tấn công

**Mục tiêu:** Đoán mã OTP 6 chữ số bằng cách thử lần lượt tất cả 1.000.000 khả năng (000000 → 999999) trong vòng 30 giây (thời gian hiệu lực của 1 OTP).

**Giả định tấn công:**
1. Attacker đã có username/password của victim (qua phishing, credential stuffing, data breach)
2. Attacker đã vượt qua Phase 1 (password login) và có `session_token` chờ TOTP
3. Attacker cần đoán đúng mã TOTP trong 30s trước khi nó hết hạn

### 2.2 Cách chạy

```bash
# Chay che do tuan tu (mac dinh)
python attacks/attack_bruteforce.py

# Chay tat ca 3 che do
python attacks/attack_bruteforce.py --mode all

# Chay che do song song voi 10 threads
python attacks/attack_bruteforce.py --mode parallel --threads 10
```

### 2.3 Output kỳ vọng

```
=================================================================
  Scenario 1: TOTP Brute-Force Attack
=================================================================
  Target: http://localhost:5000
  Time:   2026-05-13 10:30:00
  WARNING: Educational purpose only - test only on YOUR OWN system!

--- Setting up target user: bf_victim_12345 ---
  [+] User 'bf_victim_12345' registered
  [+] TOTP secret generated: JBSWY3DPEHPK...
  [+] 2FA confirmed (code: 482901)
  [+] Pending 2FA session: a1b2c3d4-e5f6...

============================================================
  SCENARIO 1A: Sequential Brute-Force
  Trying codes 000000 to 000049
============================================================
  [   1] OTP=000000 -> HTTP 401
  [   2] OTP=000001 -> HTTP 401
  [   3] OTP=000002 -> HTTP 401
  [   4] OTP=000003 -> HTTP 401
  [   5] OTP=000004 -> HTTP 423

  [!] ACCOUNT LOCKED after 5 attempts!
      Retry after: 900s

============================================================
  ATTACK ANALYSIS
============================================================
  Mode:           sequential
  Total attempts: 5
  Elapsed:        0.82s
  Rate:           6.1 req/s

  Outcome:
    [PROTECTED]  Account locked after 5 attempts

  HTTP Status Distribution:
    HTTP 401 (Unauthorized): 4x
    HTTP 423 (Locked): 1x

  Mathematical Analysis:
    OTP keyspace:           1,000,000 (6 digits)
    Attempts before block:  5
    P(guess in 30s window) = 0.000183%
    P(guess before lockout) = 0.000500%
    Windows needed to scan: 200,000
    Expected time to crack: 69.4 days
```

### 2.4 Phân tích kỹ thuật

#### Cơ chế phòng thủ có trong hệ thống

| Lớp phòng thủ | Cài đặt | Hiệu quả |
|---|---|---|
| **IP Rate Limiting** | 20 req/phút trên `/api/verify-totp` | Chậm tốc độ brute-force xuống 0.33 req/s |
| **Account Lockout Tier 1** | 5 failures → khóa 15 phút | Attacker chỉ có 4 lần đoán |
| **Account Lockout Tier 2** | 10 failures → khóa 1 giờ | Phòng thủ sâu (defense in depth) |
| **Account Lockout Tier 3** | 20 failures → khóa 24 giờ | Yêu cầu admin can thiệp |

#### Luồng xử lý trong code

```
Client gửi OTP → Server nhận request
    │
    ├─ (1) Flask-Limiter check IP rate limit → 429 nếu vượt 20 req/phút
    │
    ├─ (2) check_account_lockout(user_id) → 423 nếu account bị khóa
    │
    ├─ (3) verify_totp() → so sánh HMAC-SHA1
    │       ├─ Sai → record_failed_attempt() → tăng counter
    │       │         ├─ count >= 5  → lock 15 phút + return 423
    │       │         ├─ count >= 10 → lock 1 giờ + return 423
    │       │         └─ count >= 20 → lock 24 giờ + return 423
    │       └─ Đúng → reset_failed_attempts(0) + return 200
    │
    └─ Code: app/routes/auth_routes.py:167-244
        app/middleware/rate_limiter.py:75-115
```

#### Tại sao Brute-Force không khả thi?

```
Không có bảo vệ:
  1.000.000 codes / 30s window = cần 33.333 req/s
  Tại 100 req/s → xong trong 2.8 giờ

Có bảo vệ (hệ thống này):
  4 lần đoán / 15 phút (sau khi lockout)
  P(success) = 4/1.000.000 = 0.0004% mỗi chu kỳ
  Số chu kỳ cần 50% xác suất = 173.287 chu kỳ
  Thời gian = 173.287 × 15 phút ≈ 17.8 NĂM
```

#### Giả định để tấn công thành công (nếu KHÔNG có bảo vệ)

1. Biết username/password victim
2. Server KHÔNG có rate limiting
3. Server KHÔNG có account lockout
4. Tốc độ mạng đủ nhanh để thử >33.333 OTP/giây
5. Đoán được trong đúng 30s window của OTP

---

## 3. Kịch bản 2: Replay

### 3.1 Mô tả tấn công

**Mục tiêu:** Tái sử dụng một mã OTP đã quan sát được (thông qua shoulder-surfing, chụp màn hình, MITM, phishing page) để xác thực lần 2.

**Giả định tấn công:**
1. Attacker quan sát được mã OTP hợp lệ của victim
2. Victim xác thực thành công với mã đó
3. Attacker nhanh chóng dùng lại mã OTP đó ngay lập tức

### 3.2 Cách chạy

```bash
python attacks/attack_replay.py
```

### 3.3 Output kỳ vọng

```
=================================================================
  Scenario 2: TOTP Replay Attack
=================================================================
  Target: http://localhost:5000
  Time:   2026-05-13 10:30:00
  WARNING: Educational purpose only - test only on YOUR OWN system!

--- Setting up target user: rp_victim_67890 ---
  [+] User 'rp_victim_67890' registered
  [+] TOTP secret generated: KR4V2RANBXUW...
  [+] 2FA confirmed (code: 715839)
  [+] Pending 2FA session: f3a4b5c6-d7e8...
  [*] Waiting 8s for next TOTP window (avoid enrollment code conflict)...

============================================================
  SCENARIO 2: Token Replay Attack Tests
============================================================
  Current OTP:  482901
  Time step:    12345678
  Window ends:  22s remaining

  TEST 1: First Use (Legitimate Authentication)
  [First Use] Code: 482901
  [First Use] -> HTTP 200 [OK] Authentication successful.

  TEST 2: Immediate Replay (Same Code, New Session)
  [Immediate Replay] Code: 482901
  [Immediate Replay] -> HTTP 401 [BLOCKED] This code has already been used.

  TEST 3: Delayed Replay (Same Code, 5s Later)
  [Delayed Replay] Waiting 5s...
  [Delayed Replay] Code: 482901
  [Delayed Replay] -> HTTP 401 [BLOCKED] This code has already been used.

  TEST 4: Adjacent Window Code (Different, Unused Code)
  [*] Using code from next time step: 204856
  [Adjacent Window] Code: 204856
  [Adjacent Window] -> HTTP 200 [OK] Authentication successful.

============================================================
  REPLAY ATTACK ANALYSIS
============================================================
  First Use                Code: 482901  HTTP 200 [OK]
                          Authentication successful.

  Immediate Replay         Code: 482901  HTTP 401 [BLOCKED]
                          This code has already been used.

  Delayed Replay           Code: 482901  HTTP 401 [BLOCKED]
                          This code has already been used.

  Adjacent Window          Code: 204856  HTTP 200 [OK]
                          Authentication successful.

  Verdict: SECURE - Replay attacks are fully blocked
```

### 3.4 Phân tích kỹ thuật

#### Cơ chế Replay Prevention

Hệ thống sử dụng bảng `used_tokens` trong database để theo dõi mọi OTP đã sử dụng:

```sql
CREATE TABLE used_tokens (
    user_id      INTEGER NOT NULL,
    token_hash   TEXT NOT NULL,       -- SHA-256(otp_code)
    time_step    INTEGER NOT NULL,    -- floor(unix_time / 30)
    used_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- UNIQUE INDEX ngăn chặn race condition
CREATE UNIQUE INDEX idx_used_tokens
    ON used_tokens(user_id, token_hash, time_step);
```

#### Luồng xử lý (4 bước)

```
Client gửi OTP code
    │
    ├─ Bước 1: Format validation
    │   Kiểm tra: đúng 6 chữ số?
    │
    ├─ Bước 2: Pre-verification REPLAY CHECK ← quan trọng nhất
    │   hash = SHA-256(code)
    │   FOR each step in [current-1, current, current+1]:
    │       IF (user_id, hash, step) EXISTS in used_tokens:
    │           RETURN 401 "This code has already been used"
    │
    ├─ Bước 3: TOTP verification (RFC 6238)
    │   pyotp.verify(code, valid_window=1)
    │   Sử dụng hmac.compare_digest() (timing-safe)
    │
    └─ Bước 4: Register used token (nếu bước 3 thành công)
        INSERT INTO used_tokens (user_id, token_hash, time_step)
        → UNIQUE INDEX đảm bảo không insert trùng
```

#### Tại sao test cần fresh session token cho mỗi lần?

```
Sau khi verify thành công, server XÓA session token:
    del _pending_2fa[session_token]    # auth_routes.py:232

→ Session token không còn tồn tại
→ Nếu dùng lại session token cũ → 401 "Session expired"
→ NHƯNG điều này KHÔNG chứng minh được replay prevention hoạt động

→ Giải pháp: Mỗi test case gọi /api/login để lấy session token mới
→ Lần dùng code cũ với session mới → 401 "already used"
→ Đây mới thực sự là replay detection đang hoạt động
```

#### Tại sao lưu SHA-256(hash) thay vì plaintext OTP?

```
Nếu lưu plaintext OTP:
  → Attacker đọc DB → biết được OTP nào đã dùng
  → Có thể suy ra pattern hoặc thông tin hữu ích

Lưu SHA-256(code):
  → One-way: không thể đảo ngược từ hash → OTP
  → OTP chỉ có 6 chữ số, collision gần như không xảy ra
  → Đủ cho mục đích exact-match lookup
  → An toàn ngay cả khi attacker có read access vào DB
```

#### Giả định để tấn công thành công (nếu KHÔNG có replay prevention)

1. Attacker quan sát được OTP hợp lệ
2. Server KHÔNG track used tokens
3. Gửi lại OTP trong vòng 30s (trước khi hết hạn)
4. Có pending session token hợp lệ

---

## 4. Kịch bản 3: Clock Skew

### 4.1 Mô tả tấn công

**Mục tiêu:** Xác định khoảng chấp nhận (acceptance window) của server bằng cách thử OTP tại các offset thời gian khác nhau. Đây không hẳn là "tấn công" mà là **đánh giá bảo mật** — xem hệ thống chấp nhận bao nhiêu mã OTP đồng thời.

**Nguyên nhân lệch đồng hồ thực tế:**
- Điện thoại ở chế độ máy bay (không NTP sync)
- Thiết bị cũ có RTC (Real-Time Clock) kém chính xác
- VM/Hypervisor pause gây nhảy thời gian
- Cấu hình timezone sai (lệch 1 giờ)

### 4.2 Cách chạy

```bash
# Mac dinh: test +-90s, buoc 30s
python attacks/attack_clock_skew.py

# Test rộng hơn: +-120s, buoc 15s
python attacks/attack_clock_skew.py --range 120 --step 15

# Test narrow: +-60s, buoc 30s
python attacks/attack_clock_skew.py --range 60 --step 30
```

### 4.3 Output kỳ vọng

```
=================================================================
  Scenario 3: TOTP Clock Skew Analysis
=================================================================
  Target: http://localhost:5000
  Time:   2026-05-13 10:30:00
  WARNING: Educational purpose only - test only on YOUR OWN system!

--- Setting up target user: cs_victim_11111 ---
  [+] User 'cs_victim_11111' registered
  [+] TOTP secret generated: MFRGGZDFMY2W...
  [+] 2FA confirmed (code: 628405)
  [+] Pending 2FA session: c9d0e1f2-a3b4...

============================================================
  SCENARIO 3: Clock Skew / Drift Analysis
============================================================
  Testing offsets: -90s to +90s (step: 30s)
  Server time step: 12345678
  Window remaining: 15s

  Offset |  Step |     OTP |         Result | HTTP
  --------+--------+--------+---------------+-----
   -90s   |    -3 | 394821 |      REJECTED  | 401
   -60s   |    -2 | 628405 |      REJECTED  | 401
   -30s   |    -1 | 482901 |      ACCEPTED  | 200
      0s  |     0 | 715839 |      ACCEPTED  | 200
   +30s  |     +1 | 204856 |      ACCEPTED  | 200
   +60s  |    +2 | 913742 |      REJECTED  | 401
   +90s  |    +3 | 582019 |      REJECTED  | 401

============================================================
  CLOCK SKEW ANALYSIS RESULTS
============================================================
  Accepted offset range: -30s to +30s
    Equivalent time steps: -1 to +1
    Total accepted range: 60s
    Active valid codes: 3

  Total tested:    7
  Accepted:        3
  Rejected:        4
  Account locked:  False
```

### 4.4 Phân tích kỹ thuật

#### TOTP Time Step (RFC 6238)

```
TOTP = HOTP(K, T)
với T = floor(current_unix_time / 30)

Ví dụ:
  Unix time: 1715610000
  Time step: 1715610000 / 30 = 57187000

  Server (valid_window=1) chấp nhận:
    Step 57186999 (T-1, offset -30s) → OTP_A
    Step 57187000 (T,   offset   0s) → OTP_B
    Step 57187001 (T+1, offset +30s) → OTP_C

  → 3 mã OTP hợp lệ đồng thời
  → Attacker có 3/1,000,000 = 0.0003% cơ hội đoán đúng
```

#### Quản lý session token thông minh trong script

```
Quan trọng: session_token CHỈ bị xóa khi verify THÀNH CÔNG.

Verify THẤT BẠI (code sai):
  → Server return 401
  → session_token VẪN CÒN HỢP LỆ
  → Có thể dùng lại cho request tiếp theo

Verify THÀNH CÔNG (code đúng):
  → Server xóa session_token
  → Cần login lại để lấy session mới

Chiến lược script:
  1. Dùng 1 session cho TẤT CẢ code bị reject
  2. Chỉ login lấy session mới khi code được accept
  3. Với valid_window=1: tối đa 3 lần cần session mới
  4. Tiết kiệm request (tránh đụng rate limit login: 10/phút)
```

#### Bảng trade-off: valid_window vs Bảo mật

| valid_window | Khoảng chấp nhận | Số code hợp lệ | P(brute-force) | Trải nghiệm người dùng |
|---|---|---|---|---|
| 0 | +-0s (chính xác) | 1 | 0.0001% | Rất dễ lỗi (clock drift) |
| **1 (mặc định)** | **+-30s** | **3** | **0.0003%** | **Cân bằng tốt** |
| 2 | +-60s | 5 | 0.0005% | Thừa dư |
| 3 | +-90s | 7 | 0.0007% | Quá lỏng |

#### Tại sao valid_window=1 là lựa chọn tốt nhất?

```
1. NTP drift thông thường: +-5s (chấp nhận được)
2. Clock drift tồi tệ: +-30s (vẫn chấp nhận được)
3. Chỉ 3 code đồng thời → impact bảo mật cực nhỏ
4. Khuyến nghị RFC 6238 section 5.2
5. Google Authenticator, Authy, Microsoft Authenticator đều dùng mặc định này
```

#### Cách mã OTP được tạo tại offset (thuật toán)

```python
# attack_clock_skew.py:generate_totp_at_offset()

client_time = int(time.time()) + offset_seconds   # giả lập clock lệch
client_step = client_time // 30                     # TOTP time step

# RFC 4226 HOTP:
counter_bytes = struct.pack(">Q", client_step)      # big-endian 8 bytes
key = base64.b32decode(secret)                      # decode Base32 secret
hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

# Dynamic truncation:
offset = hmac_hash[-1] & 0x0F                       # 4 low bits of last byte
code_int = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
otp = code_int % 1_000_000                           # 6 digits
```

---

## 5. Tổng kết

### Bảng tổng hợp 3 kịch bản

| Kịch bản | Mức độ thực tế | Cơ chế phòng thủ | Kết quả demo |
|---|---|---|---|
| **Brute-Force** | Rất cao | Rate limit + Account lockout | Khóa sau 5 lần thử |
| **Replay** | Cao | used_tokens + SHA-256 hash + UNIQUE INDEX | Chặn tái sử dụng OTP |
| **Clock Skew** | Trung bình | valid_window=1 (RFC 6238) | Chấp nhận +-30s, reject ngoài range |

### Kiến trúc bảo mật nhiều lớp (Defense in Depth)

```
Layer 1: Transport
  HTTPS, HSTS, SameSite cookies → ngăn chặn MITM cơ bản

Layer 2: Authentication
  Argon2id password hashing (OWASP 2023 recommended)
  Timing-safe comparison (hmac.compare_digest)

Layer 3: Rate Limiting
  flask-limiter: IP-based (20 req/min on TOTP endpoint)
  Global: 200/day, 50/hour

Layer 4: Account Lockout
  Progressive tiers: 5→15min, 10→1h, 20→24h
  Per-user tracking (database-backed)

Layer 5: OTP Security
  AES-256-GCM encryption at rest (TOTP secrets)
  RFC 6238 compliant TOTP (pyotp library)
  Replay prevention (SHA-256 hash + UNIQUE INDEX)

Layer 6: Audit
  login_attempts table: full audit trail
  IP + User-Agent logging
```

### Giả định chung cho tất cả kịch bản

Tất cả 3 kịch bản đều giả định attacker **đã có username/password** của victim. TOTP bảo vệ **Layer 2** — ngay cả khi Layer 1 bị xâm phạm, attacker vẫn không thể vượt qua OTP verification.

### Các file quan trọng trong codebase

```
app/
├── core/
│   ├── totp_engine.py    # TOTP verify, replay prevention
│   ├── crypto.py         # AES-256-GCM, PBKDF2, SHA-256
│   └── auth.py           # Argon2id password hashing
├── routes/
│   └── auth_routes.py    # API endpoints, session management
├── middleware/
│   └── rate_limiter.py   # Rate limiting, account lockout
└── models/
    └── database.py       # SQLite, used_tokens table

attacks/
├── helpers.py            # Shared setup utilities
├── attack_bruteforce.py  # Scenario 1
├── attack_replay.py      # Scenario 2
└── attack_clock_skew.py  # Scenario 3

database/
└── schema.sql            # DB schema (used_tokens, login_attempts)
```
