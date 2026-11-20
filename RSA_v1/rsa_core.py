"""
Ý tưởng RSA:
  1. Người dùng chọn 2 số nguyên tố p và q.
  2. n   = p * q -> (n công khai)
  3. phi = (p - 1) * (q - 1) -> (giữ bí mật)
  4. Chọn e sao cho gcd(e, phi) = 1  -> KHÓA CÔNG KHAI = (e, n)
  5. Tính d sao cho (e * d) mod phi = 1  -> KHÓA BÍ MẬT = (d, n)

  Mã hóa : c = m^e mod n      (m là số đại diện cho 1 ký tự)
  Giải mã: m = c^d mod n
"""
# PHẦN 1: CÁC HÀM TOÁN HỌC CƠ BẢN

# Tim uoc chung lon nhat (gcd) cua 2 so nguyen a, b (thuat toan Euclid)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Kiem tra so nguyen to (thu chia tu 2 den can n)
def is_prime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True

# euclide mo rong tra ve (g, x, y) sao cho a*x + b*y = g = gcd(a, b), dung de tim nghich dao modun
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

# tim nghich dao modun: d sao cho (e * d) % phi = 1, chi ton tai khi gcd(e, phi) = 1
def mod_inverse(e, phi):
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("e và phi không nguyên tố cùng nhau, không có d")
    return x % phi

# Tinh (base ^ exp) % mod nhanh bang phuong phap binh phuong lien tiep
def mod_pow(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:            # bit hiện tại là 1 -> nhân vào kết quả
            result = (result * base) % mod
        base = (base * base) % mod  # bình phương base cho bit tiếp theo
        exp = exp // 2              # bỏ bit vừa xét
    return result

# PHẦN 2: TẠO KHÓA TỪ p VÀ q DO NGƯỜI DÙNG NHẬP
GIOI_HAN = 1000000000   # p, q không vượt quá 1 tỷ (để kiểm tra nguyên tố kịp thời)

# doi chuoi nhap thanh so nguyen, bao loi neu khong hop le
def parse_int(text, ten):
    try:
        return int(str(text).strip())
    except ValueError:
        raise ValueError(ten + " phải là một số nguyên")

# tao khoa RSA tu p va q, tra ve dict gom p, q, n, phi, e, d
def make_keys(p, q):
    # Kiểm tra đầu vào
    if p > GIOI_HAN or q > GIOI_HAN:
        raise ValueError("p và q không được lớn hơn 1.000.000.000")
    if not is_prime(p):
        raise ValueError("p = " + str(p) + " không phải số nguyên tố")
    if not is_prime(q):
        raise ValueError("q = " + str(q) + " không phải số nguyên tố")
    if p == q:
        raise ValueError("p và q phải khác nhau")

    # Bước 2, 3: tính n và phi
    n = p * q
    phi = (p - 1) * (q - 1)

    # Bước 4: chọn e (1 < e < phi và gcd(e, phi) = 1)
    e = 65537 if phi > 65537 else 3     # 65537 là e phổ biến
    while e < phi and gcd(e, phi) != 1:
        e += 2
    if e >= phi:
        raise ValueError("p và q quá nhỏ, không chọn được e. Hãy chọn số lớn hơn")

    # Bước 5: tính d
    d = mod_inverse(e, phi)

    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}

# PHẦN 3: BASE64 (đổi dãy byte -> chuỗi chữ cho gọn, tự viết)
# Base64: cứ 3 byte (24 bit) được chia thành 4 nhóm 6 bit,
# mỗi nhóm 6 bit ứng với 1 ký tự trong bảng.

BANG_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# tra ve list cac so 0..255 tu chuoi Base64, hoac nguoc lai
def base64_encode(data):
    out = ""
    i = 0
    while i < len(data):
        nhom = data[i:i + 3]  # lấy tối đa 3 byte
        b0 = nhom[0]
        b1 = nhom[1] if len(nhom) > 1 else 0
        b2 = nhom[2] if len(nhom) > 2 else 0
        v = b0 * 65536 + b1 * 256 + b2 # ghép thành số 24 bit

        out += BANG_BASE64[v // 262144 % 64] # 6 bit đầu
        out += BANG_BASE64[v // 4096 % 64]
        out += BANG_BASE64[v // 64 % 64] if len(nhom) > 1 else "="
        out += BANG_BASE64[v % 64] if len(nhom) > 2 else "="
        i += 3
    return out


def base64_decode(text):
    text = text.strip().replace(" ", "").replace("\n", "").rstrip("=")
    data = []
    i = 0
    while i < len(text):
        nhom = text[i:i + 4] # lấy tối đa 4 ký tự
        if len(nhom) == 1:
            raise ValueError("Bản mã Base64 không hợp lệ (bị thiếu ký tự)")
        v = 0
        for ch in nhom:
            vi_tri = BANG_BASE64.find(ch) # tìm giá trị 0..63 của ký tự
            if vi_tri < 0:
                raise ValueError("Bản mã Base64 chứa ký tự không hợp lệ: " + ch)
            v = v * 64 + vi_tri
        v = v * (64 ** (4 - len(nhom))) # bù cho nhóm cuối bị thiếu

        byte3 = [v // 65536 % 256, v // 256 % 256, v % 256]
        data += byte3[:len(nhom) - 1] # nhóm k ký tự cho k-1 byte
        i += 4
    return data

# so byte can de chua so n. Vi du: 4028033 can 3 byte
def byte_length(n):
    k = 0
    while n > 0:
        k += 1
        n = n // 256
    return k

# doi so x thanh list cac byte dung k byte, byte lon o dau
def int_to_bytes(x, k):
    out = [0] * k
    for i in range(k - 1, -1, -1):
        out[i] = x % 256
        x = x // 256
    return out

# nguoc lai voi int_to_bytes: doi list cac byte thanh so nguyen
def bytes_to_int(byte_list):
    x = 0
    for b in byte_list:
        x = x * 256 + b
    return x

# PHẦN 4: MÃ HÓA / GIẢI MÃ VĂN BẢN

# doi chuoi 'e, n' (hoac 'd, n') thanh 2 so nguyen
def parse_key(text):
    parts = text.replace(",", " ").split()
    if len(parts) != 2:
        raise ValueError("Khóa phải gồm 2 số, ví dụ: 65537, 123456789")
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        raise ValueError("Khóa chỉ được chứa số nguyên")
    if a <= 0 or b <= 1:
        raise ValueError("Khóa không hợp lệ")
    return a, b

# Mã hóa: mỗi ký tự -> mã số m -> c = m^e mod n -> k byte, ghép tất cả byte lại rồi đổi sang Base64
def encrypt_text(text, e, n):
    k = byte_length(n) # mỗi số c luôn chiếm đúng k byte
    all_bytes = []
    for ch in text:
        m = ord(ch) # đổi ký tự thành số, ví dụ 'A' -> 65
        if m >= n:
            raise ValueError("n = " + str(n) + " quá nhỏ để mã hóa ký tự '" + ch + "' (mã " + str(m) + "). Hãy chọn p, q lớn hơn")
        c = mod_pow(m, e, n)
        all_bytes += int_to_bytes(c, k)
    return base64_encode(all_bytes)

# Giải mã: Base64 -> byte -> tách mỗi k byte thành số c
# -> m = c^d mod n -> ký tự (chr).
def decrypt_text(cipher, d, n):
    k = byte_length(n)
    all_bytes = base64_decode(cipher)
    if len(all_bytes) % k != 0:
        raise ValueError("Bản mã không khớp với khóa (sai độ dài), hãy kiểm tra lại")

    chars = []
    for i in range(0, len(all_bytes), k):
        c = bytes_to_int(all_bytes[i:i + k])
        if c >= n:
            raise ValueError("Bản mã không khớp với khóa, hãy kiểm tra lại")
        m = mod_pow(c, d, n)
        try:
            chars.append(chr(m)) # đổi số về lại ký tự
        except (ValueError, OverflowError):
            raise ValueError("Giải mã ra ký tự không hợp lệ, có thể sai khóa")
    return "".join(chars)