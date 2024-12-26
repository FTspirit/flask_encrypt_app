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

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secret string')


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

    if len(plain_text) != 8:
        return jsonify({"error": "plainText must be exactly 8 characters long"}), 400

    plain = plain_text.encode('utf-8')

    cipher = Present(key)
    encrypted = cipher.encrypt(plain)
    enc_hex = encrypted.hex()
    
    return jsonify({
        "encrypted": enc_hex
    })

@app.route('/api/present/decrypt', methods=['POST'])
def present_decrypt():
    request_data = request.get_json()
    key = bytes.fromhex(request_data.get("key", "0123456789abcdef0123456789abcdef"))
    encrypted_text = request_data.get("encryptedText", "")

    if len(encrypted_text) != 16:
        return jsonify({"error": "encryptedText must be exactly 16 characters long"}), 400

    encrypted = bytes.fromhex(encrypted_text)

    cipher = Present(key)
    decrypted = cipher.decrypt(encrypted)
    plain_text = decrypted.decode('utf-8')
    
    return jsonify({
        "plainText": plain_text
    })
