
import tkinter as tk
from tkinter import filedialog, messagebox
from aes_file import encrypt_file, decrypt_file


# ==============================
# TAO CUA SO CHINH
# ==============================

window = tk.Tk()

window.title("AES File Security")
window.geometry("650x550")
window.resizable(False, False)

window.configure(bg="#F1F5F9")


# ==============================
# CAC HAM XU LY
# ==============================

def get_key():

    key_text = key_entry.get().strip()

    if len(key_text) != 32:
        messagebox.showerror(
            "Loi khoa",
            "Khoa AES-128 phai co 32 ky tu Hexadecimal!"
        )
        return None

    try:
        key = bytes.fromhex(key_text)
        return key

    except ValueError:
        messagebox.showerror(
            "Loi khoa",
            "Khoa chi duoc chua cac ky tu 0-9 va A-F!"
        )
        return None


def choose_file():

    file_path = filedialog.askopenfilename(
        title="Chon file can xu ly"
    )

    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

        status_label.config(
            text="Da chon file thanh cong",
            fg="#15803D"
        )


def encrypt_action():

    key = get_key()

    if key is None:
        return

    input_path = file_entry.get().strip()

    if not input_path:
        messagebox.showwarning(
            "Thong bao",
            "Vui long chon file can ma hoa!"
        )
        return

    output_path = filedialog.asksaveasfilename(
        title="Luu file da ma hoa",
        defaultextension=".enc",
        filetypes=[("Encrypted File", "*.enc")]
    )

    if not output_path:
        return

    try:
        encrypt_file(input_path, output_path, key)

        status_label.config(
            text="Ma hoa file thanh cong!",
            fg="#15803D"
        )

        messagebox.showinfo(
            "Thanh cong",
            "File da duoc ma hoa thanh cong!"
        )

    except Exception as error:

        status_label.config(
            text="Ma hoa that bai",
            fg="#DC2626"
        )

        messagebox.showerror(
            "Loi ma hoa",
            str(error)
        )


def decrypt_action():

    key = get_key()

    if key is None:
        return

    input_path = file_entry.get().strip()

    if not input_path:
        messagebox.showwarning(
            "Thong bao",
            "Vui long chon file can giai ma!"
        )
        return

    output_path = filedialog.asksaveasfilename(
        title="Luu file sau khi giai ma",
        defaultextension=".txt"
    )

    if not output_path:
        return

    try:
        decrypt_file(input_path, output_path, key)

        status_label.config(
            text="Giai ma file thanh cong!",
            fg="#15803D"
        )

        messagebox.showinfo(
            "Thanh cong",
            "File da duoc giai ma thanh cong!"
        )

    except Exception as error:

        status_label.config(
            text="Giai ma that bai",
            fg="#DC2626"
        )

        messagebox.showerror(
            "Loi giai ma",
            str(error)
        )


# ==============================
# PHAN TIEU DE
# ==============================

header = tk.Frame(
    window,
    bg="#183B59",
    height=110
)

header.pack(fill="x")

title_label = tk.Label(
    header,
    text="AES FILE SECURITY",
    font=("Arial", 23, "bold"),
    fg="white",
    bg="#183B59"
)

title_label.pack(pady=(23, 5))

subtitle_label = tk.Label(
    header,
    text="AES-128  |  CBC MODE  |  FILE PROTECTION",
    font=("Arial", 10),
    fg="#CBD5E1",
    bg="#183B59"
)

subtitle_label.pack()


# ==============================
# KHUNG NOI DUNG
# ==============================

content = tk.Frame(
    window,
    bg="#F1F5F9",
    padx=35,
    pady=20
)

content.pack(fill="both", expand=True)


# ==============================
# NHAP KHOA AES
# ==============================

key_label = tk.Label(
    content,
    text="KHOA AES-128",
    font=("Arial", 11, "bold"),
    bg="#F1F5F9",
    fg="#1E293B"
)

key_label.pack(anchor="w")

key_frame = tk.Frame(content, bg="#F1F5F9")
key_frame.pack(fill="x", pady=(8, 3))

key_entry = tk.Entry(
    key_frame,
    font=("Consolas", 12),
    show="*",
    relief="solid",
    bd=1
)

key_entry.pack(fill="x", ipady=9)

key_note = tk.Label(
    content,
    text="Nhap 32 ky tu Hexadecimal (16 byte)",
    font=("Arial", 9),
    fg="#64748B",
    bg="#F1F5F9"
)

key_note.pack(anchor="w", pady=(3, 18))


# ==============================
# CHON FILE
# ==============================

file_label = tk.Label(
    content,
    text="CHON TAI LIEU",
    font=("Arial", 11, "bold"),
    bg="#F1F5F9",
    fg="#1E293B"
)

file_label.pack(anchor="w")

file_frame = tk.Frame(content, bg="#F1F5F9")
file_frame.pack(fill="x", pady=8)

file_entry = tk.Entry(
    file_frame,
    font=("Arial", 10),
    relief="solid",
    bd=1
)

file_entry.pack(
    side="left",
    fill="x",
    expand=True,
    ipady=9
)

browse_button = tk.Button(
    file_frame,
    text="Chon file",
    font=("Arial", 10, "bold"),
    bg="#CBD5E1",
    fg="#1E293B",
    relief="flat",
    command=choose_file
)

browse_button.pack(
    side="right",
    padx=(8, 0),
    ipadx=10,
    ipady=5
)


# ==============================
# CAC NUT CHUC NANG
# ==============================

button_frame = tk.Frame(content, bg="#F1F5F9")
button_frame.pack(fill="x", pady=25)

encrypt_button = tk.Button(
    button_frame,
    text="MA HOA FILE",
    font=("Arial", 11, "bold"),
    bg="#166534",
    fg="white",
    activebackground="#14532D",
    relief="flat",
    command=encrypt_action
)

encrypt_button.pack(
    side="left",
    fill="x",
    expand=True,
    ipady=12,
    padx=(0, 8)
)

decrypt_button = tk.Button(
    button_frame,
    text="GIAI MA FILE",
    font=("Arial", 11, "bold"),
    bg="#1D4ED8",
    fg="white",
    activebackground="#1E40AF",
    relief="flat",
    command=decrypt_action
)

decrypt_button.pack(
    side="right",
    fill="x",
    expand=True,
    ipady=12,
    padx=(8, 0)
)


# ==============================
# TRANG THAI
# ==============================

status_frame = tk.Frame(
    content,
    bg="white",
    padx=12,
    pady=15
)

status_frame.pack(fill="x", pady=5)

status_title = tk.Label(
    status_frame,
    text="TRANG THAI HE THONG",
    font=("Arial", 10, "bold"),
    bg="white",
    fg="#334155"
)

status_title.pack(anchor="w")

status_label = tk.Label(
    status_frame,
    text="Dang cho thao tac...",
    font=("Arial", 10),
    bg="white",
    fg="#64748B"
)

status_label.pack(anchor="w", pady=(8, 0))


# ==============================
# CHAN TRANG
# ==============================

footer = tk.Label(
    window,
    text="AES-128 CBC | EDUCATIONAL DEMONSTRATION",
    font=("Arial", 9),
    fg="#64748B",
    bg="#F1F5F9"
)

footer.pack(pady=10)


# ==============================
# CHAY CHUONG TRINH
# ==============================

window.mainloop()
