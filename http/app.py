# -*- coding: utf-8 -*-
"""
    :author: Grey Li (李辉)
    :url: http://greyli.com
    :copyright: © 2018 Grey Li
    :license: MIT, see LICENSE for more details.
"""
import os
try:
    from urlparse import urlparse, urljoin
except ImportError:
    from urllib.parse import urlparse, urljoin

try:
    from jinja2 import escape
except ImportError:
    from markupsafe import escape

from jinja2.utils import generate_lorem_ipsum
from flask import Flask, make_response, request, redirect, url_for, abort, session, jsonify
from pyPresent import Present
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secret string')

CORS(app)

# get name value from query string and cookie
@app.route('/')
@app.route('/hello')
def hello():
    name = request.args.get('name')
    if name is None:
        name = request.cookies.get('name', 'Human')
    response = '<h1>Hello, %s!</h1>' % escape(name)  # escape name to avoid XSS
    # return different response according to the user's authentication status
    if 'logged_in' in session:
        response += '[Authenticated]'
    else:
        response += '[Not Authenticated]'
    return response

@app.route('/api/present/encrypt', methods=['POST'])
def present_encrypt():
    request_data = request.get_json()
    key = bytes.fromhex(request_data.get("key", "0123456789abcdef0123456789abcdef"))
    plain_text = request_data.get("plainText", "")
    
    # Nếu chuỗi trống, trả về lỗi
    if not plain_text:
        return jsonify({"error": "plainText cannot be empty"}), 400

    # Mã hóa từng khối 8 ký tự
    cipher = Present(key)  # Khởi tạo cipher
    encrypted_blocks = []
    
    # Xử lý chuỗi bằng cách chia thành các khối 8 ký tự
    while plain_text:
        block = plain_text[:8]  # Lấy 8 ký tự đầu tiên
        plain_text = plain_text[8:]  # Cắt bỏ 8 ký tự vừa xử lý
        
        # Nếu block chưa đủ 8 ký tự, thêm padding
        if len(block) < 8:
            block = block.ljust(8, '\0')  # Thêm ký tự '\0' (null) để đủ 8 ký tự

    
        # Mã hóa khối 8 ký tự
        encrypted = cipher.encrypt(block.encode('utf-8'))
        encrypted_blocks.append(encrypted.hex())
        
        encrypted_result = ''.join(encrypted_blocks)

    # Trả về kết quả mã hóa
    return jsonify({
        "encrypted": encrypted_result  # Danh sách các khối đã mã hóa
    })

@app.route('/api/present/decrypt', methods=['POST'])
def present_decrypt():
    request_data = request.get_json()
    key = bytes.fromhex(request_data.get("key", "0123456789abcdef0123456789abcdef"))
    encrypted_text = request_data.get("encryptedText", "")
    
    # Nếu chuỗi trống, trả về lỗi
    if not encrypted_text:
        return jsonify({"error": "encryptedText cannot be empty"}), 400

    cipher = Present(key)  # Khởi tạo cipher
    decrypted_blocks = []

    # Xử lý chuỗi mã hóa bằng cách chia thành các khối 16 ký tự (tương ứng 8 byte)
    while encrypted_text:
        block = encrypted_text[:16]  # Lấy 16 ký tự đầu tiên (1 block mã hóa)
        encrypted_text = encrypted_text[16:]  # Loại bỏ block đã xử lý

        # Chuyển block hex thành byte để giải mã
        encrypted_bytes = bytes.fromhex(block)
        
        # Giải mã block
        decrypted = cipher.decrypt(encrypted_bytes)
        
        # Chuyển byte thành chuỗi ký tự và loại bỏ padding
        decrypted_block = decrypted.decode('utf-8').rstrip('\0')
        decrypted_blocks.append(decrypted_block)
        decrypted_result = ''.join(decrypted_blocks)

    return jsonify({
        "plainText": decrypted_result
    })