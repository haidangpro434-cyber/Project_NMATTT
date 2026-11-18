"""AES-128 va AES-128-CBC tu cai dat bang Python (phuc vu hoc tap)."""

# ============================================================
# 1. PHEP TOAN GF(2^8) VA CAC BANG S-BOX
# ============================================================


def gf_mul(a, b):
    """Nhan hai byte trong GF(2^8), dung da thuc 0x11B."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return result


def gf_pow(a, power):
    """Tinh a^power trong GF(2^8) bang binh phuong lien tiep."""
    result = 1
    while power:
        if power & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        power >>= 1
    return result


def rotl8(value, shift):
    """Xoay 8 bit sang trai."""
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def create_sbox():
    """Tu tao S-Box theo nghich dao nhan va bien doi affine."""
    table = []
    for value in range(256):
        inverse = 0 if value == 0 else gf_pow(value, 254)
        mapped = (inverse ^ rotl8(inverse, 1) ^ rotl8(inverse, 2)
                  ^ rotl8(inverse, 3) ^ rotl8(inverse, 4) ^ 0x63)
        table.append(mapped)
    return table


def create_inv_sbox(sbox):
    """Tao bang S-Box nguoc tu S-Box."""
    inverse = [0] * 256
    for i, value in enumerate(sbox):
        inverse[value] = i
    return inverse


S_BOX = create_sbox()
INV_S_BOX = create_inv_sbox(S_BOX)

# Hang so Rcon dung trong Key Expansion AES-128.
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36]


# ============================================================
# 2. MO RONG KHOA AES-128
# ============================================================


def key_expansion(key):
    """Nhan khoa 16 byte, tra ve 11 Round Key (moi khoa 16 byte)."""
    if len(key) != 16:
        raise ValueError("AES-128 yeu cau khoa 16 byte.")

    # 4 Word dau tien duoc lay tu khoa goc.
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]

    # AES-128 can tong cong 44 Word.
    for i in range(4, 44):
        temp = words[i - 1][:]

        if i % 4 == 0:
            # RotWord -> SubWord -> XOR voi Rcon.
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[byte] for byte in temp]
            temp[0] ^= RCON[i // 4]

        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])

    # Moi 4 Word tao thanh mot Round Key.
    return [sum(words[i:i + 4], []) for i in range(0, 44, 4)]


# ============================================================
# 3. CAC PHEP BIEN DOI STATE 4x4
# ============================================================


def to_state(block):
    """Doi 16 byte thanh ma tran State 4x4 theo thu tu cot cua AES."""
    if len(block) != 16:
        raise ValueError("Moi khoi AES phai co 16 byte.")
    return [[block[col * 4 + row] for col in range(4)] for row in range(4)]


def from_state(state):
    """Doi State 4x4 ve 16 byte."""
    return bytes(state[row][col] for col in range(4) for row in range(4))


def add_round_key(state, round_key):
    """XOR State voi Round Key."""
    key_state = to_state(round_key)
    return [[state[r][c] ^ key_state[r][c] for c in range(4)]
            for r in range(4)]


def sub_bytes(state):
    """Thay moi byte bang gia tri tu S-Box (hoac S-Box nguoc)."""
    return [[S_BOX[value] for value in row] for row in state]


def inv_sub_bytes(state):
    return [[INV_S_BOX[value] for value in row] for row in state]


def shift_rows(state):
    """Hang 0 giu nguyen; cac hang 1, 2, 3 xoay trai 1, 2, 3 byte."""
    return [row[r:] + row[:r] for r, row in enumerate(state)]


def inv_shift_rows(state):
    """Phep ShiftRows nguoc: xoay phai 0, 1, 2, 3 byte."""
    return [row[-r:] + row[:-r] if r else row[:] for r, row in enumerate(state)]


def mix_columns(state):
    """Tron tung cot voi ma tran he so 02, 03, 01, 01."""
    result = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        result[0][c] = gf_mul(a[0], 2) ^ gf_mul(a[1], 3) ^ a[2] ^ a[3]
        result[1][c] = a[0] ^ gf_mul(a[1], 2) ^ gf_mul(a[2], 3) ^ a[3]
        result[2][c] = a[0] ^ a[1] ^ gf_mul(a[2], 2) ^ gf_mul(a[3], 3)
        result[3][c] = gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul(a[3], 2)
    return result


def inv_mix_columns(state):
    """Tron cot nguoc voi cac he so 0E, 0B, 0D, 09."""
    result = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        result[0][c] = gf_mul(a[0], 0x0E) ^ gf_mul(a[1], 0x0B) ^ gf_mul(a[2], 0x0D) ^ gf_mul(a[3], 0x09)
        result[1][c] = gf_mul(a[0], 0x09) ^ gf_mul(a[1], 0x0E) ^ gf_mul(a[2], 0x0B) ^ gf_mul(a[3], 0x0D)
        result[2][c] = gf_mul(a[0], 0x0D) ^ gf_mul(a[1], 0x09) ^ gf_mul(a[2], 0x0E) ^ gf_mul(a[3], 0x0B)
        result[3][c] = gf_mul(a[0], 0x0B) ^ gf_mul(a[1], 0x0D) ^ gf_mul(a[2], 0x09) ^ gf_mul(a[3], 0x0E)
    return result


# ============================================================
# 4. MA HOA VA GIAI MA MOT KHOI AES-128 (16 BYTE)
# ============================================================


def aes_encrypt(plaintext, key):
    """Ma hoa mot khoi 16 byte bang AES-128."""
    if len(plaintext) != 16 or len(key) != 16:
        raise ValueError("Plaintext va khoa AES-128 phai co 16 byte.")

    round_keys = key_expansion(key)
    state = add_round_key(to_state(plaintext), round_keys[0])

    # 9 vong dau: SubBytes, ShiftRows, MixColumns, AddRoundKey.
    for round_no in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_no])

    # Vong 10 khong co MixColumns.
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return from_state(state)


def aes_decrypt(ciphertext, key):
    """Giai ma mot khoi 16 byte bang AES-128."""
    if len(ciphertext) != 16 or len(key) != 16:
        raise ValueError("Ciphertext va khoa AES-128 phai co 16 byte.")

    round_keys = key_expansion(key)
    state = add_round_key(to_state(ciphertext), round_keys[10])

    # Giai ma tu vong 9 ve vong 1.
    for round_no in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_no])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return from_state(state)


# ============================================================
# 5. PADDING VA CHE DO CBC
# ============================================================


def pkcs7_pad(data):
    """Them padding de do dai du lieu la boi so cua 16 byte."""
    amount = 16 - (len(data) % 16)
    return data + bytes([amount] * amount)


def pkcs7_unpad(data):
    """Kiem tra va bo phan padding sau khi giai ma."""
    if not data or len(data) % 16 != 0:
        raise ValueError("Du lieu padding khong hop le.")
    amount = data[-1]
    if amount < 1 or amount > 16 or data[-amount:] != bytes([amount] * amount):
        raise ValueError("Padding khong hop le.")
    return data[:-amount]


def xor_blocks(block1, block2):
    """XOR hai khoi 16 byte."""
    if len(block1) != 16 or len(block2) != 16:
        raise ValueError("Hai khoi XOR phai co 16 byte.")
    return bytes(a ^ b for a, b in zip(block1, block2))


def aes_cbc_encrypt(data, key, iv):
    """Ma hoa CBC; tra ve (IV, ciphertext). IV phai gom 16 byte."""
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("Khoa va IV phai co 16 byte.")

    padded = pkcs7_pad(data)
    encrypted = bytearray()
    previous = iv

    for start in range(0, len(padded), 16):
        block = padded[start:start + 16]
        cipher_block = aes_encrypt(xor_blocks(block, previous), key)
        encrypted.extend(cipher_block)
        previous = cipher_block

    return iv, bytes(encrypted)


def aes_cbc_decrypt(ciphertext, key, iv):
    """Giai ma CBC va go padding."""
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("Khoa va IV phai co 16 byte.")
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext phai co do dai la boi so cua 16 byte.")

    plaintext = bytearray()
    previous = iv

    for start in range(0, len(ciphertext), 16):
        block = ciphertext[start:start + 16]
        plain_block = xor_blocks(aes_decrypt(block, key), previous)
        plaintext.extend(plain_block)
        previous = block

    return pkcs7_unpad(bytes(plaintext))
