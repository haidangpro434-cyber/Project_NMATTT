
from aes import *

# Khoa AES-128
key = bytes.fromhex(
    "000102030405060708090A0B0C0D0E0F"
)

# Du lieu goc
plaintext = bytes.fromhex(
    "00112233445566778899AABBCCDDEEFF"
)

# Ma hoa
ciphertext = aes_encrypt(plaintext, key)

print("PLAINTEXT:")
print(plaintext.hex().upper())

print("\nKEY:")
print(key.hex().upper())

print("\nCIPHERTEXT:")
print(ciphertext.hex().upper())

# Giai ma
decrypted = aes_decrypt(ciphertext, key)

print("\nDECRYPTED:")
print(decrypted.hex().upper())


# Kiem tra ket qua ma hoa
expected = bytes.fromhex(
    "69C4E0D86A7B0430D8CDB78070B4C55A"
)

assert ciphertext == expected

# Kiem tra ket qua giai ma
assert decrypted == plaintext

print("\nAES-128 ENCRYPTION: PASS")
print("AES-128 DECRYPTION: PASS")


from aes import *

# Tao khoa AES 16 byte
key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")

# Du lieu thu nghiem
plaintext = b"Xin chao AES CBC"

# Ma hoa
iv, ciphertext = aes_cbc_encrypt(plaintext, key)

print("Du lieu ban dau:", plaintext)
print("IV:", iv.hex())
print("Ciphertext:", ciphertext.hex())

# Giai ma
decrypted = aes_cbc_decrypt(ciphertext, key, iv)

print("Du lieu sau giai ma:", decrypted)

# Kiem tra ket qua
if plaintext == decrypted:
    print("KIEM THU THANH CONG")
else:
    print("KIEM THU THAT BAI")


from aes_file import encrypt_file, decrypt_file

# Khoa AES 128 bit (16 byte)
key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")

# Duong dan cac file
input_file = "AES_Demo/Hop_dong.txt"
encrypted_file = "AES_Demo/Hop_dong.txt.enc"
decrypted_file = "AES_Demo/Hop_dong_khoi_phuc.txt"

# Ma hoa file
encrypt_file(input_file, encrypted_file, key)

# Giai ma file
decrypt_file(encrypted_file, decrypted_file, key)