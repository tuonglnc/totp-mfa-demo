# 🎮 Hướng Dẫn Chạy & Khám Phá Dự Án "Tất Tần Tật"
### Từ Giao Diện Đến Tấn Công Kịch Bản Thực Tế

Tài liệu này không nói lý thuyết nữa. Nó là một **quyển cẩm nang "cầm tay chỉ việc"** để bạn vừa bấm chạy phần mềm, vừa chọc phá hệ thống, và vừa nhìn thấy những lớp bảo mật bên dưới hoạt động ra sao. 

Nếu bạn làm đúng theo thứ tự này, bạn sẽ nắm được 100% cách hệ thống TOTP MFA này chạy!

---

## 🛑 BƯỚC 1: Khởi động nền tảng
*Bỏ qua nếu server của bạn đang chạy rồi.*

1. Mở terminal mới trong thư mục dự án `mfa-demo`.
2. Gõ lệnh: `python run.py`.
3. Bạn sẽ thấy dòng chữ `* Running on http://0.0.0.0:5000` (Server đã lên).

---

## 🧑‍💻 BƯỚC 2: Đóng vai Người Dùng Bình Thường (Luồng Web)

Hãy mở trình duyệt web và vào địa chỉ **`http://localhost:5000/register`**.

### 1. Đăng ký tài khoản
* **Hành động:** Điền bừa 1 user, ví dụ username=`nguoidung1`, email=`user1@tdtu.edu.vn`, password=`MatKhauManh123!`. Bấm nút "Create Account".
* **👉 Dưới nắp capo (Under the hood):** 
  - Khác với mật khẩu bị băm bằng MD5 lỗi thời, hệ thống đang dùng **Argon2id** băm mật khẩu của bạn rồi mới đẩy xuống SQL (`database/mfa_demo.db`).

### 2. Thiết lập 2FA (Enrollment)
* **Hành động:** Hệ thống tự động chuyển bạn sang `/enroll-2fa`. Bạn sẽ thấy một mã QR Code khổng lồ và một chuỗi ký tự bên dưới (ví dụ: `JBSWY3DPEHPK3PXP`).
* **Hành động:** Bạn hãy mở ứng dụng **Google Authenticator** trên điện thoại (hoặc Authy). Bấm nút "+" -> "Quét mã QR".
* **👉 Dưới nắp capo:** 
  - Mã QR thực chất chỉ là 1 đường link: `otpauth://totp/TDTU-InfoSec-MFA:user1@tdtu.edu.vn?secret=JBSWY3DPEHPK...`
  - Chuỗi chữ cái kia chính là **Secret (Khóa bí mật gốc)**.
  - Sau khi bạn bấm "Confirm" trên web, thay vì lưu `JBSWY...` vào cơ sở dữ liệu, code Python đang gọi thuật toán **AES-256-GCM** để dùng Key khổng lồ cấu hình trong `.env` mã hóa nó thành 1 mớ byte lộn xộn rồi mới giấu dưới DB.

* **Hành động:** Nhìn điện thoại, nhập 6 số đang hiển thị vào máy tính rồi ấn "Confirm & Enable 2FA". (Báo thành công là chuẩn).

### 3. Đăng nhập 2 Bước (Authentication)
* **Hành động:** Bạn bị văng ra trang `/login`. Hãy nhập username và password vừa nãy lại.
* **👉 Dưới nắp capo:** Server check `password` xem có khớp mã băm Argon2 không. Khớp! Nhưng nó phát hiện column `is_2fa_enabled` là `True`. Thế là nó KHÔNG cho bạn vào thẳng Dashboard. Nó trả về một vé tạm thời gọi là `session_token` rồi đá qua `/verify-mfa`.
* **Hành động:** Bạn nhập 6 số trên điện thoại vào form (chú ý vòng tròn đếm ngược, nhìn khá là xịn).
* **👉 Dưới nắp capo:** 
  1. Server cầm `session_token` -> biết là user1.
  2. Lôi mớ byte lộn xộn từ AES-256-GCM ra, giải mã lại thành secret `JBSWY...`.
  3. Áp dụng công thức ở bài hướng dẫn TOTP thủ công để kiểm tra xem 6 số bạn gõ có giống nó tự nhẩm hay không. Giống -> Cho vào `/dashboard`!

---

## 🥷 BƯỚC 3: Đóng vai Kẻ Tấn Công (Attack Scripts)

Đây là phần thú vị nhất! Chúng ta đã có `attack_bruteforce.py`, `attack_replay.py` và `attack_clock_skew.py`. 

**Chuẩn bị để tấn công:**
1. Mở một trình duyệt ẩn danh (Incognito), vào đăng nhập mồi lại từ đầu (`/login`).
2. Nhập đúng mật khẩu. Lúc nó hiển thị màn hình bắt nhập 6 ô vuông (nhập OTP), bạn nhấn phím **F12**, qua tab **Network** -> Bấm vào gói tin `login`.
3. Xem thẻ "Response". Bạn sẽ lấy được một chuỗi mã gọi là **`session_token`** (trông như `eyJhbGciOiJIUzI1...`). Copy lại nhé.
4. Lấy lại cái **Secret Base32** (cái đoạn chữ nhằng nhịt `JBSW...`) ở bước Enroll nãy bạn được phát.

Bây giờ mở giao diện dòng lệnh (Terminal/PowerShell) thứ hai lên nhé:

### 🧨 Tấn Công 1: Vét Cạn (Bruteforce Attack)

Bạn chôm được mật khẩu của nạn nhân. Bạn tới được màn hình bước 2 (nhập mã 6 số). Có 1.000.000 trường hợp (từ 000000 tới 999999). Bạn quyết định viết tool để bắn liên tục lỳ lợm vào máy chủ.

```bash
python attacks/attack_bruteforce.py --target http://localhost:5000 --max-attempts 50 --mode sequential
```

* **Hiện tượng:** Tool bắn ào ạt 000000, 000001, 000002...
* **👉 Dưới nắp capo:** Code Middleware `rate_limiter.py` của bạn đứng ra đỡ đạn đếm giùm "1 lần sai, 2 lần sai... 5 lần sai -> **BÙM!**". Nó trả về mã lỗi HTTP 429 và thông báo: Account bị khóa 15 phút. Vét cạn bất lực!

### 🔄 Tấn Công 2: Tấn Công Phát Lại (Replay Attack)

Cực kì nguy hiểm. Giả sử nạn nhân ngồi uống cafe, sau lưng là hacker quay trộm màn hình điện thoại. Bọn chúng đợi nạn nhân bấm nút "Đăng nhập", và nhanh tay gửi lại cái mã y xì đúc mã vừa rồi lên server khi đồng hồ còn thời gian.

```bash
# Sửa lại TOKEN và SECRET mà bạn đã copy nhé! Bỏ dấu <> đi.
python attacks/attack_replay.py \
  --target http://localhost:5000 \
  --session-token <TOKEN_CỦA_BẠN_ĐÃ_COPY> \
  --secret <SECRET_CỦA_BẠN>
```

* **Hiện tượng:** Máy báo *TEST 1: Hợp lệ (True)*, nhưng tới ngay *TEST 2 (Gửi đi lại 6 số ấy phát nữa)* -> Server gào lên báo *HTTP 401: Mã này đã được dùng*.
* **👉 Dưới nắp capo:** 
  - Tại bảng database `used_tokens` đang hoạt động. 
  - Lần thứ 1 gửi lên, server Hash băm 6 chữ số đó ra mã SHA-256 (ví dụ: `8a9c...`) lưu vô DB.
  - Lần thứ 2 hacker gửi lên 6 cụm y chang, server lục trong DB thấy "Ê cái mã băm này vừa chạy ở 30 giây nay rồi nha" -> Từ chối thẳng cẳng!

### ⏲️ Tấn Công 3: Thí nghiệm Lệch Đồng Hồ (Clock Skew Analysis)

Server và cái điện thoại của bạn là 2 vật thể trên trái đất khác nhau hoàn toàn, giờ của điện thoại bạn lỡ bị lệch (chạy rề rề trễ 1 phút) thì sao? Sẽ sinh ra sai số code. Nhưng nếu server hào phóng cho lệch cả một vùng rộng, sinh ra lỗ hổng.

```bash
python attacks/attack_clock_skew.py \
  --target http://localhost:5000 \
  --session-token <TOKEN_CỦA_BẠN> \
  --secret <SECRET_CỦA_BẠN> \
  --range 180 --step 15
```

* **Hiện tượng:** Script tự lùi đồng hồ máy tính thử giả danh lại mã OTP của 180 giây trước, 120 giây trước, rồi tiến lên 60 giây sau... Server chỉ `ACCEPTED` đúng những cái lệch loanh quanh giới hạn từ -30 đến +30 giây (một ô thời gian `valid_window=1` theo chuẩn RFC). Các cái lệch -60s hay +60s bị ăn ngay dấu ❌ `REJECTED`. 

---

## 🎯 TỔNG KẾT
Làm xong hết bước này, bạn sẽ nhận ra mọi tính năng từ Băm dữ liệu ẩn danh, giới hạn trượt thời gian, chặn truy cập IP đều kết nối lại thành một cỗ đại bác sừng sững mà các script đơn thuần kia không thể nào vượt qua. Chúc mừng bạn đã hiểu toàn bộ luồng Project 100%!
