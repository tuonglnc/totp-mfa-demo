# 🔍 PHÂN TÍCH CODE PHÒNG THỦ — "TÔI BIẾT MÌNH CODE GÌ"

> Tài liệu này trích dẫn **chính xác từng dòng code** trong dự án thực hiện việc chặn brute-force, rate limit, replay attack và clock skew. Mỗi cơ chế được chỉ rõ: **file nào, dòng nào, làm gì, tại sao**.

---

## MỤC LỤC

1. [Chặn Brute-Force — Progressive Account Lockout](#1-chặn-brute-force--progressive-account-lockout)
2. [Rate Limiting — Giới hạn tốc độ request](#2-rate-limiting--giới-hạn-tốc-độ-request)
3. [Chặn Replay Attack — Token đã dùng không dùng lại](#3-chặn-replay-attack--token-đã-dùng-không-dùng-lại)
4. [Clock Skew — Kiểm soát cửa sổ thời gian](#4-clock-skew--kiểm-soát-cửa-sổ-thời-gian)
5. [Mã hóa Secret — AES-256-GCM](#5-mã-hóa-secret--aes-256-gcm)
6. [Database Schema — Nền tảng dữ liệu](#6-database-schema--nền-tảng-dữ-liệu)
7. [Tổng kết Flow xác minh TOTP](#7-tổng-kết-flow-xác-minh-totp)

---

## 1. CHẶN BRUTE-FORCE — Progressive Account Lockout

### 1.1 Cấu hình lockout tiers

📄 **File:** [config.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/config.py#L43-L49)

```python
# ── Account Lockout ────────────────────────────────────────
LOCKOUT_TIER1_ATTEMPTS: int = int(os.environ.get("LOCKOUT_TIER1_ATTEMPTS", "5"))
LOCKOUT_TIER1_MINUTES: int = int(os.environ.get("LOCKOUT_TIER1_MINUTES", "15"))
LOCKOUT_TIER2_ATTEMPTS: int = int(os.environ.get("LOCKOUT_TIER2_ATTEMPTS", "10"))
LOCKOUT_TIER2_MINUTES: int = int(os.environ.get("LOCKOUT_TIER2_MINUTES", "60"))
LOCKOUT_TIER3_ATTEMPTS: int = int(os.environ.get("LOCKOUT_TIER3_ATTEMPTS", "20"))
LOCKOUT_TIER3_HOURS: int = int(os.environ.get("LOCKOUT_TIER3_HOURS", "24"))
```

**Giải thích:** Định nghĩa 3 mức khóa tài khoản leo thang. Sai 5 lần → khóa 15 phút. Sai 10 lần → khóa 1 giờ. Sai 20 lần → khóa 24 giờ. Các giá trị đọc từ `.env`, có thể tùy chỉnh mà không cần sửa code.

---

### 1.2 Logic ghi nhận lần sai và quyết định khóa

📄 **File:** [rate_limiter.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/middleware/rate_limiter.py#L75-L115)

```python
def record_failed_attempt(user_id: int) -> dict:
    cfg = current_app.config

    # Lấy số lần sai hiện tại từ DB
    row = query_one("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
    if row is None:
        return {"failed_attempts": 0}

    new_count = (row["failed_attempts"] or 0) + 1

    # Xác định mức khóa dựa trên số lần sai
    lockout_delta = None
    if new_count >= cfg["LOCKOUT_TIER3_ATTEMPTS"]:       # >= 20 lần
        lockout_delta = timedelta(hours=cfg["LOCKOUT_TIER3_HOURS"])    # khóa 24h
    elif new_count >= cfg["LOCKOUT_TIER2_ATTEMPTS"]:     # >= 10 lần
        lockout_delta = timedelta(minutes=cfg["LOCKOUT_TIER2_MINUTES"])  # khóa 1h
    elif new_count >= cfg["LOCKOUT_TIER1_ATTEMPTS"]:     # >= 5 lần
        lockout_delta = timedelta(minutes=cfg["LOCKOUT_TIER1_MINUTES"])  # khóa 15min

    now = datetime.now(timezone.utc)
    locked_until = (now + lockout_delta).isoformat() if lockout_delta else None

    # Cập nhật DB: tăng counter + set thời điểm hết khóa
    execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (new_count, locked_until, user_id),
    )
    ...
```

**Giải thích:** Mỗi lần xác minh OTP sai, hàm này được gọi. Nó tăng `failed_attempts` lên 1, rồi so sánh với ngưỡng tier. Nếu vượt ngưỡng → tính `locked_until` (thời điểm hết khóa) và ghi vào DB.

---

### 1.3 Kiểm tra tài khoản có đang bị khóa không

📄 **File:** [rate_limiter.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/middleware/rate_limiter.py#L38-L72)

```python
def check_account_lockout(user_id: int) -> dict | None:
    row = query_one("SELECT locked_until FROM users WHERE id = ?", (user_id,))
    if row is None or row["locked_until"] is None:
        return None   # Không bị khóa

    locked_until = datetime.fromisoformat(row["locked_until"])
    now = datetime.now(timezone.utc)

    if now < locked_until:
        delta = locked_until - now
        return {
            "locked": True,
            "locked_until": locked_until.isoformat(),
            "retry_after_seconds": int(delta.total_seconds()),
        }

    # Khóa đã hết hạn → reset counter
    execute(
        "UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?",
        (user_id,),
    )
    return None
```

**Giải thích:** Trước mỗi lần verify TOTP, hàm này kiểm tra cột `locked_until` trong DB. Nếu thời gian hiện tại < `locked_until` → từ chối, trả HTTP 423. Nếu khóa đã hết hạn → tự động reset counter về 0.

---

### 1.4 Nơi gọi — Trong route verify-totp

📄 **File:** [auth_routes.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/routes/auth_routes.py#L182-L228)

```python
@auth_bp.route("/verify-totp", methods=["POST"])
@limiter.limit("20 per minute")                    # ← Rate limit (xem phần 2)
def verify_totp():
    ...
    # CHECK LOCKOUT TRƯỚC KHI LÀM BẤT CỨ GÌ
    lockout = check_account_lockout(user_id)
    if lockout:
        return jsonify({
            "error": "Account is temporarily locked.",
            "retry_after_seconds": lockout["retry_after_seconds"],
        }), 423                                     # ← HTTP 423 Locked

    ...
    # SAU KHI VERIFY THẤT BẠI → GHI NHẬN LẦN SAI
    if not result["valid"]:
        lockout_info = record_failed_attempt(user_id)   # ← Tăng counter
        log_attempt(user_id, "totp", False)

        response = {"error": result["reason"], "failed_attempts": lockout_info.get("failed_attempts", 0)}
        if "locked_until" in lockout_info:
            response["retry_after_seconds"] = lockout_info["retry_after_seconds"]
            return jsonify(response), 423           # ← Khóa ngay nếu vượt ngưỡng

        return jsonify(response), 401

    # SAU KHI VERIFY THÀNH CÔNG → RESET COUNTER
    reset_failed_attempts(user_id)                  # ← Reset về 0
```

**Giải thích:** Đây là nơi mọi thứ được kết nối. Route `/api/verify-totp` kiểm tra lockout TRƯỚC, ghi nhận failed attempt SAU, và reset counter khi thành công.

---

## 2. RATE LIMITING — Giới hạn tốc độ request

### 2.1 Khởi tạo Flask-Limiter

📄 **File:** [rate_limiter.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/middleware/rate_limiter.py#L23-L28)

```python
limiter = Limiter(
    key_func=get_remote_address,         # Giới hạn theo IP address
    default_limits=["200 per day", "50 per hour"],  # Mặc định toàn app
    storage_uri="memory://",             # Lưu counter trong RAM
)
```

**Giải thích:** Flask-Limiter theo dõi số request từ mỗi IP. Mặc định: tối đa 200/ngày, 50/giờ cho mọi endpoint.

### 2.2 Rate limit trên từng endpoint

📄 **File:** [auth_routes.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/routes/auth_routes.py)

```python
@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per minute")          # ← Đăng ký: 5 lần/phút

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute")         # ← Đăng nhập: 10 lần/phút

@auth_bp.route("/verify-totp", methods=["POST"])
@limiter.limit("20 per minute")         # ← Xác minh OTP: 20 lần/phút

@auth_bp.route("/enroll-2fa", methods=["POST"])
@limiter.limit("3 per minute")          # ← Đăng ký 2FA: 3 lần/phút

@auth_bp.route("/confirm-2fa", methods=["POST"])
@limiter.limit("5 per minute")          # ← Xác nhận 2FA: 5 lần/phút
```

**Giải thích:** Mỗi endpoint nhạy cảm có rate limit riêng. Đặc biệt `/verify-totp` giới hạn 20 req/phút — nghĩa là tối đa ~10 mã OTP thử được trong 30 giây (1 TOTP window). Kết hợp với lockout sau 5 lần → attacker thực tế chỉ thử được **4 mã**.

### 2.3 Đăng ký limiter vào app

📄 **File:** [__init__.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/__init__.py#L20)

```python
def create_app() -> Flask:
    ...
    init_limiter(app)       # ← Kích hoạt rate limiting cho toàn app
    ...
```

---

## 3. CHẶN REPLAY ATTACK — Token đã dùng không dùng lại

### 3.1 Hàm hash token (không lưu plaintext)

📄 **File:** [crypto.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/core/crypto.py#L96-L114)

```python
def hash_token(token: str) -> str:
    """
    Compute SHA-256 hash of a TOTP token for replay-prevention storage.
    We never store OTP codes in plaintext in the used_tokens table.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
```

**Giải thích:** Mã OTP được hash bằng SHA-256 trước khi lưu vào DB. Nếu DB bị lộ, attacker chỉ thấy hash, không thấy mã gốc.

---

### 3.2 Kiểm tra replay TRƯỚC KHI verify

📄 **File:** [totp_engine.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/core/totp_engine.py#L161-L182)

```python
def verify_totp(self, secret, token, user_id, valid_window=1):
    # Step 1: Format check
    if not isinstance(token, str) or not token.isdigit() or len(token) != 6:
        return {"valid": False, "reason": "Token must be exactly 6 digits."}

    current_step = int(time.time()) // 30

    # Step 2: PRE-VERIFICATION REPLAY CHECK
    # Quét TẤT CẢ time-steps trong valid_window
    token_h = hash_token(token)
    for step_offset in range(-valid_window, valid_window + 1):  # -1, 0, +1
        check_step = current_step + step_offset
        if self._is_replayed(user_id, token_h, check_step):
            return {
                "valid": False,
                "reason": "This code has already been used. Wait for a new code.",
            }
    ...
```

**Giải thích:** **TRƯỚC KHI** kiểm tra mã OTP có đúng không, hệ thống kiểm tra sổ đen trước. Quét cả 3 time-step (trước, hiện tại, sau) để đảm bảo mã không bị replay từ cửa sổ liền kề.

---

### 3.3 Tra cứu sổ đen trong DB

📄 **File:** [totp_engine.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/core/totp_engine.py#L219-L227)

```python
def _is_replayed(self, user_id, token_hash, time_step):
    """Check if this (user, token_hash, time_step) combo was already used."""
    db = get_db()
    row = db.execute(
        "SELECT 1 FROM used_tokens "
        "WHERE user_id = ? AND token_hash = ? AND time_step = ?",
        (user_id, token_hash, time_step),
    ).fetchone()
    return row is not None
```

**Giải thích:** Query đơn giản vào bảng `used_tokens`. Nhờ UNIQUE INDEX nên tra cứu O(1).

---

### 3.4 Ghi vào sổ đen sau khi verify thành công

📄 **File:** [totp_engine.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/core/totp_engine.py#L196-L205)

```python
    # Step 4: Mark Token as Used (Replay Prevention)
    matched_step = self._find_matched_step(totp, token, current_step, valid_window)
    self._register_used_token(user_id, token_h, matched_step)

    return {"valid": True, "reason": "Authentication successful."}
```

📄 **File:** [totp_engine.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/core/totp_engine.py#L229-L243)

```python
def _register_used_token(self, user_id, token_hash, time_step):
    """Record a used token to prevent future replay."""
    db = get_db()
    try:
        db.execute(
            "INSERT OR IGNORE INTO used_tokens (user_id, token_hash, time_step) "
            "VALUES (?, ?, ?)",
            (user_id, token_hash, time_step),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
```

**Giải thích:** Sau khi OTP verify thành công, hash của mã được INSERT vào `used_tokens`. `INSERT OR IGNORE` đảm bảo nếu 2 request race condition cùng gửi → chỉ 1 cái thành công (nhờ UNIQUE INDEX).

---

### 3.5 UNIQUE INDEX chống race condition

📄 **File:** [schema.sql](file:///home/tuonglnc/repo/totp-mfa-demo/database/schema.sql#L38-L40)

```sql
-- Composite unique index enforces replay prevention at DB level
CREATE UNIQUE INDEX IF NOT EXISTS idx_used_tokens
    ON used_tokens(user_id, token_hash, time_step);
```

**Giải thích:** Đây là lớp phòng thủ cuối cùng ở tầng database. Ngay cả nếu code application có bug, database KHÔNG CHO PHÉP insert 2 dòng trùng `(user_id, token_hash, time_step)`.

---

## 4. CLOCK SKEW — Kiểm soát cửa sổ thời gian

### 4.1 Cấu hình valid_window

📄 **File:** [config.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/config.py#L33-L34)

```python
TOTP_VALID_WINDOW: int = 1     # ±1 time-step (±30s) — RFC 6238 §5.2
TOTP_PERIOD: int = 30          # seconds per OTP window
```

**Giải thích:** `valid_window=1` nghĩa là chấp nhận mã từ time-step trước (-30s), hiện tại (0s), và sau (+30s). Tổng cộng 3 mã hợp lệ cùng lúc.

---

### 4.2 Truyền valid_window vào engine

📄 **File:** [auth_routes.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/routes/auth_routes.py#L209-L214)

```python
    result = engine.verify_totp(
        secret=secret,
        token=totp_code,
        user_id=user_id,
        valid_window=current_app.config["TOTP_VALID_WINDOW"],  # ← Dùng config
    )
```

---

### 4.3 PyOTP verify với valid_window

📄 **File:** [totp_engine.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/core/totp_engine.py#L184-L194)

```python
    # Step 3: RFC 6238 TOTP Verification
    # pyotp.verify() uses hmac.compare_digest() internally (timing-safe)
    totp = pyotp.TOTP(secret)
    is_valid = totp.verify(token, valid_window=valid_window)

    if not is_valid:
        return {
            "valid": False,
            "reason": "Invalid code. Please check your authenticator app.",
            "time_step": current_step,
        }
```

**Giải thích:** `pyotp.verify(token, valid_window=1)` kiểm tra mã ở 3 time-step: `[current-1, current, current+1]`. Nếu mã khớp bất kỳ step nào → valid. Quan trọng: dùng `hmac.compare_digest()` (timing-safe) để tránh timing attack.

---

## 5. MÃ HÓA SECRET — AES-256-GCM

### 5.1 Derive key từ master key

📄 **File:** [crypto.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/core/crypto.py#L26-L42)

```python
_KDF_SALT = b"TDTU-InfoSec-MFA-v1-kdf-salt-2026"
_KDF_ITERATIONS = 600_000   # OWASP 2023 recommendation for PBKDF2-SHA256

def derive_key(master_key: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,            # 256 bits
        salt=_KDF_SALT,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(master_key.encode("utf-8"))
```

**Giải thích:** Master key từ `.env` được biến đổi thành AES key 256-bit qua PBKDF2 với 600,000 vòng lặp (chuẩn OWASP 2023). Attacker không thể brute-force master key.

---

### 5.2 Mã hóa TOTP secret

📄 **File:** [crypto.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/core/crypto.py#L45-L64)

```python
def encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(12)       # 96-bit IV — mỗi lần mã hóa dùng IV MỚI
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), associated_data=None)
    return ciphertext, iv
```

### 5.3 Giải mã + kiểm tra tamper

📄 **File:** [crypto.py](file:///home/tuonglnc/repo/totp-mfa-demo/app/core/crypto.py#L67-L93)

```python
def decrypt(ciphertext: bytes, iv: bytes, key: bytes) -> str:
    try:
        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(iv, ciphertext, associated_data=None)
        return plaintext_bytes.decode("utf-8")
    except InvalidTag:
        raise ValueError(
            "Decryption failed: ciphertext integrity check failed. "
            "Data may have been tampered with or the wrong key was used."
        )
```

**Giải thích:** AES-GCM cung cấp cả **confidentiality** (bảo mật) và **integrity** (toàn vẹn). Nếu ai sửa dữ liệu trong DB → `InvalidTag` → từ chối giải mã. TOTP secret KHÔNG BAO GIỜ lưu dạng plaintext.

---

## 6. DATABASE SCHEMA — Nền tảng dữ liệu

📄 **File:** [schema.sql](file:///home/tuonglnc/repo/totp-mfa-demo/database/schema.sql)

### Bảng `users` — Cột hỗ trợ lockout

```sql
CREATE TABLE IF NOT EXISTS users (
    ...
    locked_until TIMESTAMP NULL,       -- Thời điểm hết khóa (NULL = không khóa)
    failed_attempts INTEGER DEFAULT 0  -- Đếm số lần sai liên tiếp
);
```

### Bảng `used_tokens` — Sổ đen chống replay

```sql
CREATE TABLE IF NOT EXISTS used_tokens (
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,          -- SHA-256(otp_code)
    time_step INTEGER NOT NULL,        -- floor(unix_time / 30)
    ...
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_used_tokens
    ON used_tokens(user_id, token_hash, time_step);
```

### Bảng `login_attempts` — Audit trail

```sql
CREATE TABLE IF NOT EXISTS login_attempts (
    user_id INTEGER,
    ip_address TEXT NOT NULL,
    attempt_type TEXT NOT NULL,   -- 'password' | 'totp' | 'enroll'
    success BOOLEAN NOT NULL,
    ...
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time
    ON login_attempts(user_id, attempt_type, attempted_at);
```

---

## 7. TỔNG KẾT FLOW XÁC MINH TOTP

```
User gửi POST /api/verify-totp {session_token, totp_code}
│
├─ [rate_limiter] @limiter.limit("20 per minute")      ← Quá 20 req/min → HTTP 429
│
├─ [auth_routes] check_account_lockout(user_id)         ← Đang bị khóa → HTTP 423
│
├─ [totp_engine] Step 1: Format check                   ← Không phải 6 số → reject
│
├─ [totp_engine] Step 2: Replay check                   ← Mã đã dùng → reject
│   └─ _is_replayed() → SELECT FROM used_tokens
│
├─ [totp_engine] Step 3: TOTP verify                    ← Sai mã → reject
│   └─ pyotp.verify(token, valid_window=1)
│
├─ [totp_engine] Step 4: Register used token            ← Ghi sổ đen
│   └─ INSERT OR IGNORE INTO used_tokens
│
├─ [auth_routes] Nếu THẤT BẠI:
│   └─ record_failed_attempt(user_id)                   ← Tăng counter, có thể khóa
│
└─ [auth_routes] Nếu THÀNH CÔNG:
    └─ reset_failed_attempts(user_id)                   ← Reset counter về 0
```

### Bảng tóm tắt: File nào chặn gì?

| Cơ chế phòng thủ | File chính | Dòng quan trọng |
|-------------------|-----------|-----------------|
| **Rate Limiting** (IP-based) | `middleware/rate_limiter.py` | L24-28: `Limiter(key_func=get_remote_address)` |
| **Rate Limit per endpoint** | `routes/auth_routes.py` | L168: `@limiter.limit("20 per minute")` |
| **Account Lockout check** | `middleware/rate_limiter.py` | L38-72: `check_account_lockout()` |
| **Failed attempt counter** | `middleware/rate_limiter.py` | L75-115: `record_failed_attempt()` |
| **Lockout tiers config** | `config.py` | L44-49: `LOCKOUT_TIER1/2/3` |
| **Replay check** | `core/totp_engine.py` | L171-182: pre-verify replay scan |
| **Token hash (SHA-256)** | `core/crypto.py` | L96-114: `hash_token()` |
| **Used token storage** | `core/totp_engine.py` | L229-243: `_register_used_token()` |
| **UNIQUE INDEX (race-safe)** | `database/schema.sql` | L39-40: `idx_used_tokens` |
| **Clock window control** | `config.py` | L33: `TOTP_VALID_WINDOW = 1` |
| **TOTP verify with window** | `core/totp_engine.py` | L187: `totp.verify(token, valid_window=valid_window)` |
| **Secret encryption** | `core/crypto.py` | L45-64: AES-256-GCM encrypt |
| **Tamper detection** | `core/crypto.py` | L89-93: `InvalidTag` → reject |
