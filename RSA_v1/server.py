"""
server.py - Máy chủ web nhỏ để nối giao diện HTML với thuật toán RSA.

Chạy:  python server.py
Mở trình duyệt:  http://localhost:8000

Chỉ dùng thư viện có sẵn của Python (http.server, json, pathlib).
Giao diện (index.html) gửi yêu cầu tới 3 địa chỉ:
    /api/generate  -> tạo khóa
    /api/encrypt   -> mã hóa
    /api/decrypt   -> giải mã
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import rsa_core

PORT = 8000
THU_MUC = Path(__file__).parent


class Handler(BaseHTTPRequestHandler):

    # --- Trình duyệt mở trang web ---
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            noi_dung = (THU_MUC / "index.html").read_bytes()
            self.gui(200, "text/html; charset=utf-8", noi_dung)
        else:
            self.gui(404, "text/plain; charset=utf-8", b"Khong tim thay")

    # --- Trang web gọi các hàm RSA ---
    def do_POST(self):
        try:
            do_dai = int(self.headers.get("Content-Length", 0))
            du_lieu = json.loads(self.rfile.read(do_dai) or b"{}")

            if self.path == "/api/generate":
                p = rsa_core.parse_int(du_lieu.get("p", ""), "p")
                q = rsa_core.parse_int(du_lieu.get("q", ""), "q")
                ket_qua = rsa_core.make_keys(p, q)

            elif self.path == "/api/encrypt":
                e, n = rsa_core.parse_key(du_lieu.get("key", ""))
                ket_qua = {"result": rsa_core.encrypt_text(du_lieu.get("text", ""), e, n)}

            elif self.path == "/api/decrypt":
                d, n = rsa_core.parse_key(du_lieu.get("key", ""))
                ket_qua = {"result": rsa_core.decrypt_text(du_lieu.get("text", ""), d, n)}

            else:
                self.gui_json(404, {"error": "Địa chỉ không tồn tại"})
                return

            self.gui_json(200, ket_qua)

        except ValueError as loi:       # lỗi do người dùng nhập sai
            self.gui_json(400, {"error": str(loi)})

    # --- Cho phép trang HTML mở từ nơi khác (vd Live Server cổng 5500) gọi tới đây ---
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # --- Hàm phụ để trả dữ liệu về trình duyệt ---
    def gui(self, ma, kieu, noi_dung):
        self.send_response(ma)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", kieu)
        self.send_header("Content-Length", str(len(noi_dung)))
        self.end_headers()
        self.wfile.write(noi_dung)

    def gui_json(self, ma, du_lieu):
        self.gui(ma, "application/json; charset=utf-8",
                 json.dumps(du_lieu).encode("utf-8"))


if __name__ == "__main__":
    print("Đang chạy tại http://localhost:%d  (nhấn Ctrl+C để dừng)" % PORT)
    HTTPServer(("localhost", PORT), Handler).serve_forever()
