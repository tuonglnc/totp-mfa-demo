import time
import hmac
import hashlib
import struct
import base64

# ====== INPUT ======
secret_base32 = "JBSWY3DPEHPK3PXP"
digits = 6
period = 30

# ====== STEP 1: decode secret ======
secret = base64.b32decode(secret_base32)

# ====== STEP 2: time counter ======
current_time = int(time.time())
counter = current_time // period

print("Unix time:", current_time)
print("Time counter:", counter)

# ====== STEP 3: convert counter to 8-byte big endian ======
counter_bytes = struct.pack(">Q", counter)

# ====== STEP 4: HMAC-SHA1 ======
hmac_hash = hmac.new(secret, counter_bytes, hashlib.sha1).digest()

# ====== STEP 5: dynamic truncation ======
offset = hmac_hash[-1] & 0x0F
binary_code = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7fffffff

# ====== STEP 6: mod 10^digits ======
otp = binary_code % (10 ** digits)

print("TOTP:", otp)