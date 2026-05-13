# 🛡️ THUYẾT TRÌNH CHI TIẾT: BẢO MẬT XÁC THỰC 2 LỚP (TOTP-MFA)
## Dành cho mọi đối tượng — Không cần nền tảng kỹ thuật

---

# PHẦN 1: GIỚI THIỆU — "TẠI SAO CẦN XÁC THỰC 2 LỚP?"

## 1.1 Vấn đề với mật khẩu truyền thống

Hãy tưởng tượng bạn có một căn nhà. Mật khẩu giống như **chìa khóa cửa chính**. Nếu ai đó lấy được chìa khóa (hoặc làm giả), họ vào nhà bạn dễ dàng.

**Thực tế đáng lo ngại:**
- 😱 **81%** vụ xâm nhập dữ liệu xuất phát từ mật khẩu yếu hoặc bị đánh cắp (Verizon DBIR)
- 😱 Trung bình mỗi người dùng **13 mật khẩu giống nhau** cho nhiều tài khoản
- 😱 Mật khẩu có thể bị lộ qua: phishing email giả, keylogger, rò rỉ dữ liệu (data breach)

## 1.2 Giải pháp: Xác thực 2 lớp (2FA)

Xác thực 2 lớp giống như thêm **ổ khóa thứ hai** vào cửa nhà bạn. Ngay cả khi kẻ trộm có chìa khóa thứ nhất (mật khẩu), họ vẫn cần chìa khóa thứ hai (mã OTP từ điện thoại) mới vào được.

**Hai yếu tố xác thực:**

| Yếu tố | Ý nghĩa | Ví dụ |
|---------|---------|-------|
| 🧠 **Thứ bạn BIẾT** | Kiến thức chỉ bạn có | Mật khẩu |
| 📱 **Thứ bạn CÓ** | Vật lý chỉ bạn sở hữu | Điện thoại có app Google Authenticator |

→ Kẻ tấn công phải **đồng thời** có cả mật khẩu VÀ điện thoại của bạn mới đăng nhập được.

## 1.3 TOTP là gì? — Giải thích đơn giản

**TOTP = Time-based One-Time Password** (Mật khẩu dùng 1 lần theo thời gian)

Hãy tưởng tượng một **chiếc đồng hồ ma thuật** mà cả bạn và hệ thống cùng sở hữu:
- Cứ mỗi **30 giây**, đồng hồ hiển thị một **mã số 6 chữ số** mới
- Mã này chỉ có hiệu lực trong **30 giây** rồi biến mất
- Mã được tạo từ một **bí mật chung** (chìa khóa bí mật) mà chỉ điện thoại bạn và server biết

**Ví dụ thực tế:**
```
Lúc 10:00:00 → Mã là: 482913
Lúc 10:00:30 → Mã đổi thành: 751648
Lúc 10:01:00 → Mã đổi thành: 329507
```

Bạn mở app Google Authenticator, thấy mã `482913`, nhập vào trang web → Đăng nhập thành công!

---

# PHẦN 2: HỆ THỐNG DEMO — "CHÚNG TA XÂY DỰNG GÌ?"

## 2.1 Quy trình đăng nhập

```
BƯỚC 1: Nhập username + password
    ↓
    Hệ thống kiểm tra: "Mật khẩu đúng!"
    ↓
BƯỚC 2: Hệ thống yêu cầu mã OTP
    ↓
    Bạn mở app Authenticator → Thấy mã 6 số → Nhập vào
    ↓
    Hệ thống kiểm tra: "Mã đúng!"
    ↓
✅ ĐĂNG NHẬP THÀNH CÔNG
```

## 2.2 Các lớp bảo vệ (ví von dễ hiểu)

Hệ thống của chúng ta giống một **tòa nhà an ninh cao cấp** với nhiều lớp bảo vệ:

| Lớp | Ví von | Chức năng |
|-----|--------|-----------|
| 🚪 **Cửa chính** | Mật khẩu (Argon2id) | Chỉ người biết mật khẩu mới vào được |
| 🔐 **Cửa thứ 2** | Mã OTP (TOTP) | Phải có điện thoại mới mở được |
| 🚨 **Báo động** | Rate limiting | Gõ sai nhiều lần → chuông báo động kêu |
| 🔒 **Khóa cứng** | Account lockout | Gõ sai quá nhiều → khóa cửa 15 phút |
| 📹 **Camera** | Replay prevention | Dùng lại mã cũ → bị phát hiện ngay |
| 🗄️ **Két sắt** | AES-256-GCM encryption | Bí mật được cất trong két sắt mã hóa |

---

# PHẦN 3: THỬ NGHIỆM TẤN CÔNG

## Mục đích

Chúng ta sẽ **đóng vai kẻ tấn công** để thử 3 cách phá hệ thống:
1. **Đoán mã** (Brute-Force) — Thử tất cả các mã có thể
2. **Dùng lại mã** (Replay) — Nghe lén mã của người khác rồi dùng lại
3. **Lợi dụng lệch đồng hồ** (Clock Skew) — Kiểm tra hệ thống có chấp nhận mã cũ/mới không

---

# KỊCH BẢN 1: TẤN CÔNG ĐOÁN MÃ (BRUTE-FORCE)

## Bối cảnh — Câu chuyện

> **Tình huống:** Hacker tên An đã đánh cắp được mật khẩu của Bình qua email lừa đảo (phishing). Bây giờ An cần đoán mã OTP 6 chữ số để đăng nhập.

An nghĩ: *"Mã chỉ có 6 chữ số, từ 000000 đến 999999. Mình cứ thử hết!"*

## Câu hỏi đặt ra

> **"Liệu hacker có thể thử tất cả 1 triệu mã trong 30 giây không?"**

## Chạy demo

```bash
python attack_bruteforce.py --mode all --max-attempts 30
```

## Kết quả — Điều gì xảy ra?

### Thử nghiệm 1A: Đoán tuần tự (000000, 000001, 000002, ...)

```
Lần thử 1: Mã 000000 → ❌ Sai (HTTP 401)
Lần thử 2: Mã 000001 → ❌ Sai (HTTP 401)
Lần thử 3: Mã 000002 → ❌ Sai (HTTP 401)
Lần thử 4: Mã 000003 → ❌ Sai (HTTP 401)
Lần thử 5: Mã 000004 → 🔒 TÀI KHOẢN BỊ KHÓA! (HTTP 423)
                         → Phải đợi 900 giây (15 phút)
```

**→ Chỉ được thử 4 lần rồi bị khóa!**

### Thử nghiệm 1B: Đoán ngẫu nhiên

Hacker thử mã ngẫu nhiên thay vì tuần tự → **Kết quả tương tự: khóa sau 5 lần**

### Thử nghiệm 1C: Tấn công song song (5 luồng cùng lúc)

Hacker gửi 5 yêu cầu đồng thời → **Bị chặn bởi CẢ HAI cơ chế:**
- 🚨 **Rate limiting:** Quá nhiều request → bị từ chối (HTTP 429)
- 🔒 **Account lockout:** Sai quá nhiều → bị khóa (HTTP 423)

## Phân tích — Tại sao hacker không thể thắng?

### Bài toán xác suất (giải thích đơn giản)

Hãy tưởng tượng bạn có **1 triệu quả bóng** trong thùng, chỉ **1 quả màu đỏ**. Bạn được bốc **4 quả** rồi bị cấm bốc tiếp.

| Câu hỏi | Trả lời |
|----------|---------|
| Có bao nhiêu mã có thể? | 1,000,000 mã (000000 → 999999) |
| Được thử bao nhiêu lần? | 4 lần (trước khi bị khóa) |
| Xác suất đoán đúng? | 4/1,000,000 = **0.0004%** |
| Phải thử bao nhiêu đợt? | 250,000 đợt × 15 phút = **~7 năm** |

### Hệ thống khóa lũy tiến (giống phạt thẻ trong bóng đá)

| Số lần sai | Hình phạt | Ví von |
|-----------|-----------|--------|
| 5 lần | 🟡 Khóa 15 phút | Thẻ vàng đầu tiên |
| 10 lần | 🟠 Khóa 1 giờ | Thẻ vàng thứ hai |
| 20 lần | 🔴 Khóa 24 giờ | Thẻ đỏ — cần admin can thiệp |

### Kết luận kịch bản 1

> ✅ **Hệ thống AN TOÀN.** Brute-force là BẤT KHẢ THI vì hacker chỉ được thử 4 mã mỗi 15 phút. Để duyệt hết 1 triệu mã, hacker cần **khoảng 7-10 năm** — trong khi mã OTP đổi mới mỗi **30 giây**.

---

# KỊCH BẢN 2: TẤN CÔNG DÙNG LẠI MÃ (REPLAY ATTACK)

## Bối cảnh — Câu chuyện

> **Tình huống:** Hacker An ngồi sau lưng Bình trong quán cà phê. An nhìn thấy Bình nhập mã OTP `554135` để đăng nhập. An ghi nhớ mã này và lập tức thử dùng nó.

An nghĩ: *"Mình đã thấy mã rồi, cùng trong 30 giây này, mã vẫn còn hiệu lực!"*

## Câu hỏi đặt ra

> **"Nếu hacker nhìn thấy mã OTP hợp lệ, có thể dùng lại mã đó không?"**

## Chạy demo

```bash
python attack_replay.py
```

## Kết quả — 4 bài thử nghiệm

### Test 1: Bình đăng nhập (sử dụng hợp lệ)

```
Bình nhập mã: 554135
→ ✅ HTTP 200 — Đăng nhập thành công!
```

### Test 2: An dùng ngay cùng mã đó (replay tức thì)

```
An nhập mã:   554135 (cùng mã, cùng lúc)
→ 🚫 HTTP 401 — "Mã này đã được sử dụng. Hãy đợi mã mới."
```

**→ Bị chặn ngay lập tức!**

### Test 3: An đợi 5 giây rồi thử lại

```
An đợi 5 giây...
An nhập mã:   554135 (cùng mã, 5 giây sau)
→ 🚫 HTTP 401 — "Mã này đã được sử dụng. Hãy đợi mã mới."
```

**→ Vẫn bị chặn!**

### Test 4: Mã khác (mã mới, chưa dùng)

```
Hệ thống tạo mã mới: 277748 (mã của cửa sổ 30 giây kế tiếp)
→ ✅ HTTP 200 — Chấp nhận! (vì đây là mã mới, chưa ai dùng)
```

## Bảng tổng hợp

| Bài test | Mã OTP | Kết quả | Giải thích |
|----------|--------|---------|------------|
| Bình dùng lần đầu | 554135 | ✅ OK | Mã hợp lệ, chưa ai dùng |
| An dùng lại ngay | 554135 | 🚫 Chặn | Mã đã được Bình dùng rồi |
| An đợi 5s rồi dùng lại | 554135 | 🚫 Chặn | Vẫn bị nhận diện là mã cũ |
| Mã hoàn toàn mới | 277748 | ✅ OK | Mã khác, chưa ai dùng → chấp nhận |

## Cơ chế bảo vệ — Giải thích đơn giản

Hãy tưởng tượng hệ thống giống **cổng soát vé concert**:

1. **Khi Bình vào cổng:** Bảo vệ quét vé → ✅ Hợp lệ → Cho vào → **Đánh dấu vé đã dùng**
2. **Khi An đưa bản copy vé đó:** Bảo vệ quét → Máy báo: "Vé này đã quét rồi!" → 🚫 Không cho vào

**Chi tiết kỹ thuật (dành cho ai muốn hiểu sâu):**
- Khi mã OTP được dùng, hệ thống tạo **dấu vân tay số** (SHA-256 hash) của mã đó
- Dấu vân tay được lưu vào **sổ đen** trong cơ sở dữ liệu
- Mọi mã mới đều được kiểm tra sổ đen TRƯỚC KHI xác minh
- Sổ đen có khóa **chống trùng lặp** → ngay cả 2 request đến cùng lúc, chỉ 1 cái thành công

### Kết luận kịch bản 2

> ✅ **Hệ thống AN TOÀN.** Mỗi mã OTP chỉ dùng được **MỘT LẦN DUY NHẤT**. Kể cả hacker nhìn thấy mã, nếu nạn nhân đã dùng trước → mã đó trở thành **vô giá trị**.

---

# KỊCH BẢN 3: LỢI DỤNG LỆCH ĐỒNG HỒ (CLOCK SKEW)

## Bối cảnh — Câu chuyện

> **Tình huống:** Hacker An biết rằng mã OTP dựa vào thời gian. An thắc mắc: *"Nếu đồng hồ điện thoại lệch vài giây so với server thì sao? Hệ thống có chấp nhận mã cũ hoặc mã tương lai không?"*

Nếu hệ thống chấp nhận mã từ quá nhiều cửa sổ thời gian → nhiều mã hợp lệ cùng lúc → dễ đoán hơn.

## Câu hỏi đặt ra

> **"Hệ thống chấp nhận mã trong phạm vi thời gian bao rộng? Nếu quá rộng thì có nguy hiểm không?"**

## Ví von dễ hiểu

Hãy tưởng tượng bạn có **vé xe buýt** ghi giờ khởi hành **10:00**.

| Tình huống | Cho lên xe? | Tương đương |
|-----------|------------|-------------|
| Bạn đến lúc **9:28** (sớm 32 phút ❌) | ❌ Quá sớm | Mã OTP từ 2 bước trước |
| Bạn đến lúc **9:31** (sớm 29 giây ✅) | ✅ Chấp nhận | Mã OTP bước trước (valid_window) |
| Bạn đến lúc **10:00** (đúng giờ) | ✅ Chấp nhận | Mã OTP hiện tại |
| Bạn đến lúc **10:29** (trễ 29 giây ✅) | ✅ Chấp nhận | Mã OTP bước sau (valid_window) |
| Bạn đến lúc **10:32** (trễ 32 phút ❌) | ❌ Quá trễ | Mã OTP từ 2 bước sau |

→ Hệ thống cho phép **sai lệch ±30 giây** (1 bước thời gian), đủ linh hoạt mà vẫn an toàn.

## Chạy demo

```bash
python attack_clock_skew.py --range 90 --step 30
```

## Kết quả — Bản đồ cửa sổ chấp nhận

```
  Đồng hồ lệch  | Kết quả
  ───────────────┼──────────────
  -90 giây       | ❌ Từ chối    ← Quá cũ
  -60 giây       | ❌ Từ chối    ← Quá cũ
  -30 giây       | ✅ Chấp nhận  ← Trong phạm vi cho phép
    0 giây       | ❌ Từ chối    ← Mã trùng với mã enrollment (đã dùng)
  +30 giây       | ✅ Chấp nhận  ← Trong phạm vi cho phép
  +60 giây       | ❌ Từ chối    ← Quá mới
  +90 giây       | ❌ Từ chối    ← Quá mới
```

## Phân tích an toàn

### Bao nhiêu mã hợp lệ cùng lúc?

| Cấu hình | Phạm vi chấp nhận | Số mã hợp lệ | An toàn? |
|----------|-------------------|---------------|----------|
| Nghiêm ngặt (window=0) | Chỉ đúng 30s hiện tại | 1 mã | ⚠️ Quá chặt — hay bị lỗi khi đồng hồ lệch |
| **Mặc định (window=1)** | **±30 giây** | **3 mã** | **✅ Cân bằng tốt** |
| Thoải mái (window=2) | ±60 giây | 5 mã | ⚠️ Hơi rộng |
| Rất thoải mái (window=3) | ±90 giây | 7 mã | ❌ Quá rộng — tăng rủi ro |

### Tại sao chấp nhận ±30s là hợp lý?

**Nguyên nhân thực tế khiến đồng hồ bị lệch:**

| Nguyên nhân | Mức lệch thường gặp | Xử lý được? |
|-------------|---------------------|-------------|
| 📱 Điện thoại chế độ máy bay | 1-5 giây | ✅ Dư sức |
| 🖥️ Server trên máy ảo | 1-10 giây | ✅ Trong phạm vi |
| 📟 Thiết bị cũ, pin yếu | 10-30 giây | ✅ Vừa đủ |
| ✈️ Không đồng bộ NTP lâu ngày | 30-120 giây | ⚠️ Có thể lỗi |

### Kết luận kịch bản 3

> ✅ **Hệ thống AN TOÀN.** Phạm vi chấp nhận **±30 giây** (3 mã) là thiết lập chuẩn theo RFC 6238. Với chỉ 3 mã hợp lệ trong 1 triệu mã, xác suất đoán đúng chỉ là **0.0003%**.

---

# PHẦN 4: UNIT TESTS — KIỂM THỬ TỰ ĐỘNG

## Kết quả: 17/17 bài test ĐẠT ✅

| Nhóm test | Kiểm tra gì? | Số test | Kết quả |
|-----------|-------------|---------|---------|
| 🔐 Mã hóa (AES-256-GCM) | Mã hóa → giải mã đúng? Sửa đổi dữ liệu bị phát hiện? | 7 | ✅ Đạt hết |
| 🔑 Xác minh TOTP | Mã đúng được chấp nhận? Mã cũ bị từ chối? | 5 | ✅ Đạt hết |
| 🛡️ Mật khẩu (Argon2id) | Mật khẩu đúng xác minh OK? Mật khẩu sai bị từ chối? | 5 | ✅ Đạt hết |

---

# PHẦN 5: KẾT LUẬN TỔNG HỢP

## Bảng tổng kết 3 kịch bản

| Kịch bản | Cách tấn công | Kết quả | Lý do thất bại |
|----------|--------------|---------|----------------|
| 🔨 Brute-Force | Thử tất cả mã có thể | ❌ THẤT BẠI | Bị khóa tài khoản sau 5 lần sai |
| 🔄 Replay | Dùng lại mã đã thấy | ❌ THẤT BẠI | Mã đã dùng bị ghi sổ đen |
| ⏰ Clock Skew | Lợi dụng lệch đồng hồ | ❌ THẤT BẠI | Chỉ chấp nhận ±30s, rất hẹp |

## Mô hình bảo vệ nhiều lớp — Ví von "Tòa nhà an ninh"

```
┌──────────────────────────────────────────────┐
│              TÒA NHÀ AN NINH                 │
│                                              │
│  Tầng 6: 🗄️  Két sắt mã hóa (AES-256)      │  ← Bí mật được khóa trong két
│  Tầng 5: 🔑  Mật khẩu siêu mạnh (Argon2id)  │  ← Chìa khóa không thể sao chép
│  Tầng 4: ⏰  Cửa sổ thời gian hẹp (±30s)    │  ← Vé chỉ có hiệu lực 30 giây
│  Tầng 3: 📹  Camera chống dùng lại (Replay)  │  ← Vé đã quét không dùng lại được
│  Tầng 2: 🔒  Khóa cứng (Account Lockout)     │  ← Gõ sai 5 lần = khóa 15 phút
│  Tầng 1: 🚨  Báo động (Rate Limiting)        │  ← Gõ quá nhanh = chuông kêu
│                                              │
└──────────────────────────────────────────────┘
```

## Thông điệp cuối cùng

> 🎯 **Xác thực 2 lớp (2FA) với TOTP là một trong những biện pháp bảo mật hiệu quả nhất hiện nay.**
>
> Khi được triển khai đúng cách với đầy đủ các lớp bảo vệ (rate limiting, account lockout, replay prevention, encryption), hệ thống trở nên **gần như bất khả xâm phạm** trước các hình thức tấn công phổ biến.
>
> **Khuyến nghị:** Hãy bật 2FA trên TẤT CẢ tài khoản quan trọng của bạn (email, ngân hàng, mạng xã hội). Đó là cách đơn giản nhất để bảo vệ bản thân trên không gian mạng.
