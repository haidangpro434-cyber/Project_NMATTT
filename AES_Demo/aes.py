# PHAN 1: CAC PHEP TOAN GF(2^8)

# Ham nhan hai byte trong GF(2^8)
def gf_mul(a, b):
    result = 0

    while b > 0:
        if b & 1:
            result ^= a

        a <<= 1

        # Neu vuot qua 8 bit thi XOR voi 0x11B
        if a & 0x100:
            a ^= 0x11B

        b >>= 1

    return result


# Ham tinh luy thua trong GF(2^8)
def gf_pow(a, power):
    result = 1

    while power > 0:
        if power & 1:
            result = gf_mul(result, a)

        a = gf_mul(a, a)
        power >>= 1

    return result


# Ham xoay bit sang trai
def rotl8(value, shift):
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


# Tao bang S-Box
def create_sbox():
    sbox = []

    for i in range(256):

        # Tim nghich dao nhan
        if i == 0:
            inv = 0
        else:
            inv = gf_pow(i, 254)

        # Bien doi affine
        result = (
            inv ^
            rotl8(inv, 1) ^
            rotl8(inv, 2) ^
            rotl8(inv, 3) ^
            rotl8(inv, 4) ^
            0x63
        )

        sbox.append(result)

    return sbox


# Tao bang Inverse S-Box
def create_inv_sbox(sbox):
    inv_sbox = [0] * 256

    for i in range(256):
        inv_sbox[sbox[i]] = i

    return inv_sbox


# Khoi tao hai bang
S_BOX = create_sbox()
INV_S_BOX = create_inv_sbox(S_BOX)


# Kiem tra ket qua
if __name__ == "__main__":
    print("S-Box[0x53]:", hex(S_BOX[0x53]))
    print("Inv S-Box[0xED]:", hex(INV_S_BOX[0xED]))

    print("GF multiplication:",
          hex(gf_mul(0x57, 0x13)))

# PHAN 2 - Key Expansion cho AES-128

# Cac hang so vong cua AES-128
RCON = [
    0x00,
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
]


# Xoay trai cac byte trong mot Word
def rot_word(word):
    return word[1:] + word[:1]


# Thay the tung byte bang gia tri trong S-Box
def sub_word(word):
    result = []

    for byte in word:
        result.append(S_BOX[byte])

    return result


# XOR hai Word gom 4 byte
def xor_word(a, b):
    result = []

    for i in range(4):
        result.append(a[i] ^ b[i])

    return result


# Mo rong khoa AES-128
def key_expansion(key):

    # Kiem tra khoa phai co 16 byte
    if len(key) != 16:
        raise ValueError("AES-128 yeu cau khoa 16 byte")

    # Chia khoa ban dau thanh 4 Word
    words = []

    for i in range(4):
        word = []

        for j in range(4):
            word.append(key[i * 4 + j])

        words.append(word)

    # Tao them Word cho den khi du 44 Word
    for i in range(4, 44):
        # Lay Word ngay truoc
        temp = words[i - 1].copy()
        # Moi 4 Word thi thuc hien bien doi dac biet
        if i % 4 == 0:
            # Buoc 1: RotWord
            temp = rot_word(temp)
            # Buoc 2: SubWord
            temp = sub_word(temp)
            # Buoc 3: XOR voi Rcon
            rcon_value = [RCON[i // 4], 0, 0, 0]
            temp = xor_word(temp, rcon_value)
        # XOR voi Word cach 4 vi tri
        new_word = xor_word(words[i - 4], temp)
        words.append(new_word)

    # Gom 44 Word thanh 11 Round Key
    round_keys = []

    for i in range(11):
        round_key = []

        for j in range(4):
            round_key.extend(words[i * 4 + j])
        round_keys.append(round_key)
    return round_keys

# PHAN 3 - Xay dung cac ham AES co ban (SubBytes, ShiftRows, MixColumns, AddRoundKey)


# Chuyen 16 byte thanh ma tran State 4x4
def create_state(data):
    if len(data) != 16:
        raise ValueError("Du lieu AES phai co 16 byte")

    state = []

    for row in range(4):
        state.append([])
        for col in range(4):
            state[row].append(data[col * 4 + row])
    return state


# Chuyen State Matrix ve danh sach 16 byte
def state_to_bytes(state):
    data = []

    for col in range(4):
        for row in range(4):
            data.append(state[row][col])
    return data


# Thay the tung byte trong State bang S-Box
def sub_bytes(state):
    new_state = []

    for row in range(4):
        new_row = []

        for col in range(4):
            byte = state[row][col]
            new_byte = S_BOX[byte]
            new_row.append(new_byte)
        new_state.append(new_row)
    return new_state


# Phep thay the nguoc khi giai ma
def inv_sub_bytes(state):
    new_state = []

    for row in range(4):
        new_row = []
        for col in range(4):
            byte = state[row][col]
            new_byte = INV_S_BOX[byte]
            new_row.append(new_byte)
        new_state.append(new_row)
    return new_state


# Dich cac hang sang trai
def shift_rows(state):
    new_state = []

    for row in range(4):
        shift = row
        new_row = state[row][shift:] + state[row][:shift]
        new_state.append(new_row)
    return new_state


# Dich cac hang sang phai khi giai ma
def inv_shift_rows(state):
    new_state = []

    for row in range(4):
        shift = row
        new_row = state[row][-shift:] + state[row][:-shift] if shift != 0 else state[row][:]
        new_state.append(new_row)
    return new_state


# Bien doi tung cot trong State Matrix
def mix_columns(state):
    new_state = []

    for row in range(4):
        new_state.append([0] * 4)
    for col in range(4):
        a0 = state[0][col]
        a1 = state[1][col]
        a2 = state[2][col]
        a3 = state[3][col]
        new_state[0][col] = (
            gf_mul(a0, 0x02) ^
            gf_mul(a1, 0x03) ^
            a2 ^ a3
        )
        new_state[1][col] = (
            a0 ^
            gf_mul(a1, 0x02) ^
            gf_mul(a2, 0x03) ^
            a3
        )
        new_state[2][col] = (
            a0 ^ a1 ^
            gf_mul(a2, 0x02) ^
            gf_mul(a3, 0x03)
        )
        new_state[3][col] = (
            gf_mul(a0, 0x03) ^
            a1 ^ a2 ^
            gf_mul(a3, 0x02)
        )
    return new_state


# Phep MixColumns nguoc
def inv_mix_columns(state):
    new_state = []

    for row in range(4):
        new_state.append([0] * 4)
    for col in range(4):
        a0 = state[0][col]
        a1 = state[1][col]
        a2 = state[2][col]
        a3 = state[3][col]
        new_state[0][col] = (
            gf_mul(a0, 0x0E) ^
            gf_mul(a1, 0x0B) ^
            gf_mul(a2, 0x0D) ^
            gf_mul(a3, 0x09)
        )
        new_state[1][col] = (
            gf_mul(a0, 0x09) ^
            gf_mul(a1, 0x0E) ^
            gf_mul(a2, 0x0B) ^
            gf_mul(a3, 0x0D)
        )
        new_state[2][col] = (
            gf_mul(a0, 0x0D) ^
            gf_mul(a1, 0x09) ^
            gf_mul(a2, 0x0E) ^
            gf_mul(a3, 0x0B)
        )
        new_state[3][col] = (
            gf_mul(a0, 0x0B) ^
            gf_mul(a1, 0x0D) ^
            gf_mul(a2, 0x09) ^
            gf_mul(a3, 0x0E)
        )
    return new_state


# XOR State Matrix voi Round Key
def add_round_key(state, round_key):
    key_state = create_state(round_key)
    new_state = []

    for row in range(4):
        new_row = []
        for col in range(4):

            value = (
                state[row][col] ^
                key_state[row][col]
            )
            new_row.append(value)
        new_state.append(new_row)
    return new_state

# PHAN 4 - Hoan thien AES-128 voi cac vong ma hoa va giai ma

# AES-128 ENCRYPTION
def aes_encrypt(plaintext, key):
    # Kiem tra du lieu dau vao
    if len(plaintext) != 16:
        raise ValueError("Plaintext phai co 16 byte")
    if len(key) != 16:
        raise ValueError("AES-128 yeu cau khoa 16 byte")
    # Buoc 1: Sinh 11 Round Keys
    round_keys = key_expansion(key)
    # Buoc 2: Chuyen plaintext thanh State Matrix
    state = create_state(plaintext)
    # Buoc 3: AddRoundKey ban dau
    state = add_round_key(state, round_keys[0])
    # Buoc 4: Thuc hien vong 1 den vong 9
    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(
            state, round_keys[round_num]
        )
    # Buoc 5: Vong cuoi cung (vong 10)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    # Buoc 6: Chuyen State thanh Ciphertext
    ciphertext = state_to_bytes(state)
    return bytes(ciphertext)

# AES-128 DECRYPTION
def aes_decrypt(ciphertext, key):
    if len(ciphertext) != 16:
        raise ValueError("Ciphertext phai co 16 byte")
    if len(key) != 16:
        raise ValueError("AES-128 yeu cau khoa 16 byte")
    # Sinh lai Round Keys
    round_keys = key_expansion(key)
    # Chuyen Ciphertext thanh State Matrix
    state = create_state(ciphertext)
    # Bat dau tu Round Key 10
    state = add_round_key(state, round_keys[10])
    # Thuc hien cac vong giai ma tu 9 ve 1
    for round_num in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(
            state, round_keys[round_num]
        )
        state = inv_mix_columns(state)
    # Vong cuoi cung cua giai ma
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    # Chuyen State thanh Plaintext
    plaintext = state_to_bytes(state)
    return bytes(plaintext)

# Viet ham padding
def pkcs7_pad(data):
    block_size = 16
    # Tinh so byte can bo sung
    pad_len = block_size - (len(data) % block_size)
    # Tao cac byte padding
    padding = bytes([pad_len] * pad_len)
    # Noi padding vao du lieu ban dau
    return data + padding

# Viet ham unpadding
def pkcs7_unpad(data):
    if len(data) == 0:
        raise ValueError("Du lieu rong")
    if len(data) % 16 != 0:
        raise ValueError("Du lieu khong hop le")
    # Lay gia tri byte cuoi cung
    pad_len = data[-1]
    # Kiem tra kich thuoc padding
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding khong hop le")
    # Kiem tra cac byte padding
    for i in range(1, pad_len + 1):
        if data[-i] != pad_len:
            raise ValueError("Padding khong hop le")
    # Loai bo padding
    return data[:-pad_len]

def xor_blocks(block1, block2):
    result = []
    for i in range(16):
        result.append(block1[i] ^ block2[i])
    return bytes(result)

import secrets


def aes_cbc_encrypt(data, key):
    # Tao IV ngau nhien 16 byte
    iv = secrets.token_bytes(16)

    # Them padding
    data = pkcs7_pad(data)

    ciphertext = b""
    previous_block = iv

    # Xu ly tung khoi 16 byte
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        # XOR voi IV hoac khoi ma hoa truoc do
        block = xor_blocks(block, previous_block)
        # Ma hoa bang AES
        encrypted_block = aes_encrypt(block, key)
        ciphertext += encrypted_block
        # Luu khoi ma hoa hien tai
        previous_block = encrypted_block
    # Tra ve IV va ciphertext
    return iv, ciphertext

def aes_cbc_decrypt(ciphertext, key, iv):
    if len(iv) != 16:
        raise ValueError("IV phai co 16 byte")
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext khong hop le")

    plaintext = b""
    previous_block = iv

    # Xu ly tung khoi ciphertext
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        # Giai ma khoi hien tai
        decrypted_block = aes_decrypt(block, key)
        # XOR voi IV hoac khoi ciphertext truoc do
        original_block = xor_blocks(decrypted_block, previous_block)
        plaintext += original_block
        # Luu khoi ciphertext hien tai
        previous_block = block
    # Loai bo padding
    plaintext = pkcs7_unpad(plaintext)
    return plaintext

# Ham ma hoa File
from aes import aes_cbc_encrypt, aes_cbc_decrypt

def encrypt_file(input_path, output_path, key):
    # Doc noi dung file goc
    with open(input_path, "rb") as file:
        data = file.read()
    # Ma hoa du lieu
    iv, ciphertext = aes_cbc_encrypt(data, key)
    # Ghi IV va ciphertext vao file moi
    with open(output_path, "wb") as file:
        file.write(iv + ciphertext)
    print("Ma hoa file thanh cong!")

# Ham giai ma File
def decrypt_file(input_path, output_path, key):
    # Doc file da ma hoa
    with open(input_path, "rb") as file:
        encrypted_data = file.read()
    # Tach IV va ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    # Giai ma du lieu
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)
    # Ghi du lieu da giai ma
    with open(output_path, "wb") as file:
        file.write(plaintext)
    print("Giai ma file thanh cong!")