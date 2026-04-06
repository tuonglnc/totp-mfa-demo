import hmac
import hashlib
import struct
import base64

# ====== INPUT ======
secret_base32 = "JBSWY3DPEHPK3PXP"
counter = 1
digits = 6

# ====== STEP 1: decode secret ======
secret = base64.b32decode(secret_base32)

# ====== STEP 2: convert counter to 8-byte big endian ======
counter_bytes = struct.pack(">Q", counter)

# ====== STEP 3: HMAC-SHA1 ======
hmac_hash = hmac.new(secret, counter_bytes, hashlib.sha1).digest()

print("HMAC:", hmac_hash.hex())

# ====== STEP 4: dynamic truncation ======
offset = hmac_hash[-1] & 0x0F
print("Offset:", offset)

binary_code = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7fffffff

# ====== STEP 5: mod 10^digits ======
otp = binary_code % (10 ** digits)

print("HOTP:", otp)