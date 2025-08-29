import os
import io
import time
from flask import Flask, request, send_file, render_template_string, redirect, url_for, abort, flash

from werkzeug.utils import secure_filename
from crypto_utils import encrypt_blob, decrypt_blob

STORAGE_DIR = os.environ.get("STORAGE_DIR", "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(16))

INDEX_HTML = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Secure File Storage (AES-256-GCM)</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 2rem; max-width: 900px; }
      .card { border: 1px solid #ddd; border-radius: 14px; padding: 1rem 1.5rem; margin: 1rem 0; box-shadow: 0 3px 12px rgba(0,0,0,.06); }
      h1 { margin-top: 0; }
      .row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
      .full { grid-column: 1 / -1; }
      input[type=file] { padding: .5rem; }
      button { padding: .6rem 1rem; border-radius: 10px; border: 1px solid #333; background: white; cursor: pointer;}
      code { background: #f5f5f5; padding: 2px 6px; border-radius: 6px; }
      .hint { color: #666; font-size: 0.95rem; }
      .ok { color: #0a7d00; }
      .err { color: #a40000; }
      table { width: 100%; border-collapse: collapse; }
      th, td { border-bottom: 1px solid #eee; padding: .5rem; text-align: left; }
      .meta { font-size: .9rem; color: #444; }
    </style>
  </head>
  <body>
    <h1>Secure File Storage (AES-256-GCM)</h1>
    <p class="hint">Uploads are encrypted over HTTPS and sealed at rest with AES‑256‑GCM. 
    Per-file keys via HKDF; metadata is sealed inside the encrypted package.</p>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <p class="{{ category }}">{{ message }}</p>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <div class="card">
      <h2>Encrypt & Store</h2>
      <form action="{{ url_for('encrypt') }}" method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <button type="submit">Encrypt & Save</button>
      </form>
      <p class="hint">Saved files use the <code>.enc</code> format. Keep <code>MASTER_KEY_B64</code> secret.</p>
    </div>

    <div class="card">
      <h2>Decrypt a .enc File</h2>
      <form action="{{ url_for('decrypt_local') }}" method="post" enctype="multipart/form-data">
        <input type="file" name="encfile" accept=".enc,application/json" required>
        <button type="submit">Decrypt & Download</button>
      </form>
    </div>

    <div class="card">
      <h2>Stored Encrypted Files</h2>
      <table>
        <thead><tr><th>File</th><th>Actions</th></tr></thead>
        <tbody>
          {% for name in files %}
            <tr>
              <td>{{ name }}</td>
              <td>
                <a href="{{ url_for('download_enc', name=name) }}">download .enc</a> &nbsp;|&nbsp;
                <a href="{{ url_for('download_plain', name=name) }}">download decrypted</a>
              </td>
            </tr>
          {% else %}
            <tr><td colspan="2"><em>No files yet.</em></td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Server Health</h2>
      <p>Master Key present: <strong>{{ 'Yes' if master_key_ok else 'No' }}</strong></p>
      <p>Storage directory: <code>{{ storage_dir }}</code></p>
    </div>
  </body>
</html>
"""

@app.route("/")
def index():
    files = [f for f in os.listdir(STORAGE_DIR) if f.endswith(".enc")]
    master_key_ok = bool(os.getenv("MASTER_KEY_B64"))
    return render_template_string(INDEX_HTML, files=sorted(files), master_key_ok=master_key_ok, storage_dir=STORAGE_DIR)

@app.post("/encrypt")
def encrypt():
    if "file" not in request.files:
        abort(400, "no file provided")
    f = request.files["file"]
    if not f.filename:
        abort(400, "empty filename")
    filename = secure_filename(f.filename)
    data = f.read()
    pkg, metadata = encrypt_blob(filename, data)
    ts = int(time.time())
    safe_name = f"{ts}-{filename}.enc"
    out_path = os.path.join(STORAGE_DIR, safe_name)
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write(pkg.to_json())
    flash(f"Encrypted and saved as {safe_name}", "ok")
    return redirect(url_for("index"))

@app.post("/decrypt-local")
def decrypt_local():
    if "encfile" not in request.files:
        abort(400, "no file provided")
    f = request.files["encfile"]
    blob = f.read()
    try:
        plain, metadata = decrypt_blob(blob)
    except Exception as e:
        flash(f"Decryption failed: {e}", "err")
        return redirect(url_for("index"))
    return send_file(
        io.BytesIO(plain),
        as_attachment=True,
        download_name=metadata.get("filename", "decrypted.bin"),
    )

@app.get("/download/.enc/<path:name>")
def download_enc(name: str):
    path = os.path.join(STORAGE_DIR, name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=name, mimetype="application/json")

@app.get("/download/plain/<path:name>")
def download_plain(name: str):
    path = os.path.join(STORAGE_DIR, name)
    if not os.path.isfile(path):
        abort(404)
    with open(path, "rb") as fp:
        blob = fp.read()
    try:
        plain, metadata = decrypt_blob(blob)
    except Exception as e:
        abort(400, f"Decryption failed: {e}")
    return send_file(
        io.BytesIO(plain),
        as_attachment=True,
        download_name=metadata.get("filename", "decrypted.bin"),
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
