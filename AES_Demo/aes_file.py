
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


def decrypt_file(input_path, output_path, key):

    # Doc file da ma hoa
    with open(input_path, "rb") as file:
        encrypted_data = file.read()

    # Kiem tra kich thuoc file
    if len(encrypted_data) < 32 or (len(encrypted_data) - 16) % 16 != 0:
        raise ValueError("File ma hoa khong hop le")

    # Tach IV va ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Giai ma
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)

    # Ghi du lieu da giai ma
    with open(output_path, "wb") as file:
        file.write(plaintext)

    print("Giai ma file thanh cong!")
