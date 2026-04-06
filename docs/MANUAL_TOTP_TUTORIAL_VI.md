# 🛠️ Hướng Dẫn Tự Code TOTP (Thủ Công)
### Từ Con Số 0 Để Hiểu Rõ Bản Chất TOTP (RFC 6238)

Tài liệu này sẽ hướng dẫn bạn từng bước tự viết thuật toán TOTP bằng Python cơ bản mà KHÔNG dùng thư viện `pyotp`. Việc này giúp bạn hiểu exacly (chính xác) những gì xảy ra bên dưới.

---

## 🧩 Bản Chất Của TOTP Là Gì?

TOTP (Time-Based One-Time Password) bản chất là một thuật toán băm (HMAC) nhận vào 2 tham số:
1. **Secret Key (K):** Một chuỗi bí mật (giữa server và app điện thoại).
2. **Time Counter (T):** Một con số đại diện cho thời gian hiện tại.

**Công thức lõi:**
> TOTP = DYNAMIC_TRUNCATE( HMAC-SHA1( SecretKey, TimeCounter ) ) % 1,000,000

---

## 🚀 Thực Hành: 5 Bước Tạo Mã 6 Số

Chúng ta sẽ tạo file `thu_cong_totp.py` với các bước sau:

### Bước 1: Khởi tạo và Import thư viện chuẩn
Chúng ta chỉ dùng các thư viện có sẵn của Python, không cài thêm gì cả.

```python
import time
import base64
import hmac
import hashlib
import struct

# 1. Khai báo Secret gốc (Lấy từ bước Enroll)
# Thường Authenticator app hiển thị dạng Base32 (A-Z, 2-7)
base32_secret = "JBSWY3DPEHPK3PXP" 

# Giải mã Base32 về dạng bytes thô để máy tính tính toán
secret_bytes = base64.b32decode(base32_secret)
```

### Bước 2: Tính toán bộ đếm thời gian (Time Counter)
TOTP thay đổi 30 giây một lần. Vậy làm sao server và điện thoại luôn chốt được 1 con số chung?
Họ dùng **Unix Time** (số giây tính từ 1/1/1970) chia nguyên cho 30.

```python
# Lấy số giây hiện tại
unix_time = int(time.time())

# Chia lấy phần nguyên cho 30 (Time Step)
time_counter = unix_time // 30

print(f"Unix time hiện tại: {unix_time}")
print(f"Time counter (T): {time_counter}")
```

### Bước 3: Đóng gói Time Counter thành byte
Để chạy thuật toán HMAC, cấu trúc `time_counter` (một số nguyên) phải được chuyển thành một mảng 8 bytes (chuẩn Big-Endian).

```python
# Dùng thư viện struct để pack (đóng gói) số nguyên thành 8 byte (định dạng ">Q")
counter_bytes = struct.pack(">Q", time_counter)
```

### Bước 4: Tạo mã băm HMAC-SHA1
Dùng Secret (bước 1) khóa lại Counter (bước 3) thông qua thuật toán SHA-1.

```python
# Tạo mã băm HMAC-SHA1. Kết quả là chuỗi 20 bytes (160 bits).
hmac_result = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
```

### Bước 5: Cắt xén động (Dynamic Truncation)
Mã băm HMAC-SHA1 sinh ra 20 bytes. Làm sao để biến 20 bytes này thành 6 chữ số?
RFC 4226 định nghĩa thuật toán **Dynamic Truncation** (cắt xén động):

1. **Tìm Điểm Cắt (Offset):** Lấy byte cuối cùng của mã băm (byte thứ 19), xem 4 bit cuối cùng của nó là số mấy (từ 0 đến 15).
2. **Lấy 4 bytes:** Từ Điểm Cắt đó, lặp 4 bytes liên tiếp.
3. **Loại bỏ bit dấu:** Biến 4 bytes thành số nguyên 32-bit dương.

```python
# 5.1: Tìm offset từ 4 bit cuối của byte cuối cùng
offset = hmac_result[-1] & 0x0F  

# 5.2: Trích xuất 4 byte từ vị trí offset
truncated_hash = hmac_result[offset : offset + 4]

# 5.3: Chuyển 4 byte thành số nguyên (bỏ bit dấu cao nhất bằng & 0x7FFFFFFF)
binary_code = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF
```

### Bước 6: Lấy 6 chữ số cuối cùng
Chia lấy phần dư cho 1.000.000 để lấy đúng 6 chữ số. Nếu mã bị ngắn (ví dụ: 5432), thêm số 0 ở đầu.

```python
# Lấy 6 số cuối
otp = binary_code % 1_000_000

# Format chuỗi đảm bảo đủ 6 số (ví dụ: '045123')
final_totp = f"{otp:06d}"

print(f"Mã TOTP của bạn là: {final_totp}")
```

---

## 💻 Toàn Bộ Code Gom Lại Dễ Hiểu

Tạo file `thu_cong_totp.py` và chạy:

```python
import time
import base64
import hmac
import hashlib
import struct

def generate_my_totp(base32_secret: str) -> str:
    # 1. Giải mã secret
    secret_bytes = base64.b32decode(base32_secret)
    
    # 2. Lấy bộ đếm thời gian T
    T = int(time.time()) // 30
    
    # 3. Đóng gói T thành 8 bytes
    T_bytes = struct.pack(">Q", T)
    
    # 4. Hash bằng HMAC-SHA1
    hmac_result = hmac.new(secret_bytes, T_bytes, hashlib.sha1).digest()
    
    # 5. Dynamic truncation (cắt xẻo để lấy 4 bytes ngẫu nhiên)
    offset = hmac_result[-1] & 0x0F
    code_32bit = struct.unpack(">I", hmac_result[offset:offset+4])[0] & 0x7FFFFFFF
    
    # 6. Lấy 6 chữ số
    return f"{code_32bit % 1000000:06d}"

if __name__ == "__main__":
    secret = "JBSWY3DPEHPK3PXP"
    print(f"Secret: {secret}")
    print(f"Current TOTP: {generate_my_totp(secret)}")
```

## 🤔 Vì sao bài tập này quan trọng?
1. **Hiểu bản chất đồng bộ:** TOTP hoàn toàn offline. Máy chủ và app chạy độc lập cùng đoạn code này, miễn là đồng hồ của họ giống nhau, họ sẽ ra cùng một kết quả.
2. **Hiểu vì sao lại quét QR:** Mã QR bản chất chỉ là 1 chuỗi `otpauth://totp/TDTU?secret=JBSWY3DPEHPK3PXP`. Quét QR là để đưa cái chữ `JBSWY3DPEHPK3PXP` vào điện thoại bạn mà không cần gõ tay.
3. **Hiểu về Time Skew (Lệch đồng hồ):** Khi ta gửi lên server, server không chỉ tính với `T` hiện tại, mà tính luôn cho `T-1` (30 giây trước) và `T+1` (30 giây sau) để lỡ đồng hồ điện thoại bạn chạy nhanh chậm 1 chút, nó vẫn khớp.
