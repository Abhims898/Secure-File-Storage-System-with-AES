import os
import datetime
from flask import Flask, request, render_template_string, send_file, redirect, url_for, flash
from crypto_utils import encrypt_file, decrypt_file
import hashlib

UPLOAD_FOLDER = "storage"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev_secret")

TEMPLATE = """
<!doctype html>
<title>Secure File Storage</title>
<h2>Upload & Encrypt</h2>
<form method=post enctype=multipart/form-data action="/upload">
  <input type=file name=file>
  <input type=submit value=Encrypt>
</form>
<h2>Decrypt & Download</h2>
<form method=post enctype=multipart/form-data action="/decrypt">
  <input type=file name=file>
  <input type=submit value=Decrypt>
</form>
<ul>
{% for f in files %}
<li><a href="{{ url_for('download', filename=f) }}">{{ f }}</a></li>
{% endfor %}
</ul>
"""

@app.route("/")
def index():
    files = os.listdir(UPLOAD_FOLDER)
    return render_template_string(TEMPLATE, files=files)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file:
        flash("No file uploaded")
        return redirect(url_for("index"))
    data = file.read()
    filename = file.filename
    enc_path = os.path.join(UPLOAD_FOLDER, filename + ".enc")
    with open(enc_path, "wb") as f:
        f.write(encrypt_file(data, filename))
    flash(f"Encrypted and stored {filename}")
    return redirect(url_for("index"))

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files.get("file")
    if not file:
        flash("No encrypted file uploaded")
        return redirect(url_for("index"))
    data = file.read()
    try:
        plain, meta = decrypt_file(data)
        out_name = meta["original_name"]
        out_path = os.path.join(UPLOAD_FOLDER, out_name)
        with open(out_path, "wb") as f:
            f.write(plain)
        flash(f"Decrypted {out_name} (SHA-256 verified)")
        return send_file(out_path, as_attachment=True)
    except Exception as e:
        flash(f"Decryption failed: {e}")
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
