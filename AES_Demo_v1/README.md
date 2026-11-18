# AES File Security - ban code tay

## Cau truc
- `aes_core.py`: tu cai dat AES-128, GF(2^8), S-Box/Inverse S-Box, Key Expansion, cac phep bien doi State, ma hoa/giai ma mot block, PKCS#7 va CBC.
- `aes_file.py`: doc/ghi file va goi cac ham AES tu `aes_core.py`.
- `main.py`: giao dien Tkinter de chon file, nhap khoa, ma hoa va giai ma.
- `notebooks/AES_Thuat_toan.ipynb`: giai thich va minh hoa tung buoc thuat toan.

## Pham vi thu vien
Khong su dung PyCryptodome, cryptography, OpenSSL wrapper hay thu vien co san nao de thuc hien AES. Cac phep toan AES/CBC/Padding duoc viet thu cong.

`tkinter` dung lam giao dien; `pathlib` chi dung doc/ghi file; `secrets` trong `main.py` lay khoa va IV ngau nhien an toan tu he dieu hanh, khong thuc hien AES. IV duoc truyen vao ham `aes_cbc_encrypt(data, key, iv)` va duoc luu o 16 byte dau cua file `.enc`.

## Chay chuong trinh
```bash
python main.py
```
