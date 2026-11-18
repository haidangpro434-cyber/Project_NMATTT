"""Doc/ghi file va ket noi voi AES-128-CBC tu cai dat thu cong trong aes_core.py."""

from pathlib import Path
from aes_core import aes_cbc_encrypt, aes_cbc_decrypt


def encrypt_file(input_path, output_path, key, iv):
    """Ma hoa file; file dau ra co cau truc: IV (16 byte) + ciphertext."""
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        raise FileNotFoundError("Khong tim thay file dau vao.")
    if len(key) != 16:
        raise ValueError("AES-128 yeu cau khoa 16 byte.")
    if len(iv) != 16:
        raise ValueError("IV phai co 16 byte.")

    data = input_path.read_bytes()
    ciphertext_iv, ciphertext = aes_cbc_encrypt(data, key, iv)
    output_path.write_bytes(ciphertext_iv + ciphertext)
    return output_path


def decrypt_file(input_path, output_path, key):
    """Giai ma file co dinh dang IV (16 byte) + ciphertext."""
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        raise FileNotFoundError("Khong tim thay file ma hoa.")

    encrypted_data = input_path.read_bytes()

    # Can toi thieu 1 block IV va 1 block ciphertext.
    if len(encrypted_data) < 32 or (len(encrypted_data) - 16) % 16 != 0:
        raise ValueError("File ma hoa khong hop le hoac bi thieu du lieu.")

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)
    output_path.write_bytes(plaintext)
    return output_path
