import pyotp
import qrcode

# 1. Tạo secret key
secret = pyotp.random_base32()
print("Secret:", secret)

# 2. Tạo TOTP object
totp = pyotp.TOTP(secret)

# 3. Tạo URI cho Google Authenticator
uri = totp.provisioning_uri(name="katun@example.com", issuer_name="KatunDemo")

print("Scan QR code bằng Google Authenticator")

# 4. Tạo QR code
img = qrcode.make(uri)
img.save("qrcode.png")

print("QR code saved as qrcode.png")

# 5. Verify loop
while True:
    code = input("Nhập mã 6 số từ app: ")
    if totp.verify(code):
        print("✅ ĐÚNG – Đăng nhập thành công")
        break
    else:
        print("❌ Sai mã")
